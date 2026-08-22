"""Regression tests for the supply-chain findings.

SEC-033  the MSI build verifies the embedded Python archive
SEC-034  the Ansible deploy does not run the collector as root by default
SEC-035  the deploy refuses a mutable git ref unless asked
SEC-036  the Windows deploy drops the task off SYSTEM
SEC-037  Windows tasks use win_command, not interpolated win_shell
SEC-040  GitHub Actions are pinned (enforced by pin_supply_chain --check)
SEC-041  release artifacts are signed, not only checksummed
SEC-042  the container image carries provenance and an SBOM
SEC-044  the container base image is pinned to a digest
SEC-045  SBOM.md does not claim artifacts CI never produces
CODE-034 changed_when is derived from output, not hardcoded true
"""

import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fh:
        return fh.read()


def _yaml(*parts):
    import yaml  # optional; tests that need it skip when absent
    return yaml.safe_load(_read(*parts))


class PinToolTest(unittest.TestCase):
    """SEC-040 / SEC-044 / SEC-033 enforcement."""

    def test_check_mode_runs_offline_and_reports(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "packaging", "pin_supply_chain.py"),
             "--check"],
            capture_output=True, text=True, cwd=REPO,
        )
        # Either everything is pinned (exit 0) or it names what is not (exit 1).
        self.assertIn(proc.returncode, (0, 1))
        if proc.returncode == 1:
            self.assertIn("UNPINNED", proc.stdout)

    def test_check_detects_a_mutable_action_ref(self):
        sys.path.insert(0, os.path.join(REPO, "packaging"))
        try:
            import pin_supply_chain as psc
        finally:
            sys.path.pop(0)
        m = psc._USES_RE.match("      - uses: actions/checkout@v4")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("action"), "actions/checkout")
        self.assertFalse(psc._SHA_RE.match(m.group("ref")))
        pinned = psc._USES_RE.match(
            "      - uses: actions/checkout@" + "a" * 40 + "  # v4"
        )
        self.assertTrue(psc._SHA_RE.match(pinned.group("ref")))

    def test_ci_enforces_the_pins(self):
        ci = _read(".github", "workflows", "ci.yml")
        self.assertIn("pin_supply_chain.py --check", ci)

    def test_dockerfile_documents_the_resolver_rather_than_a_fake_digest(self):
        dockerfile = _read("Dockerfile")
        self.assertIn("pin_supply_chain.py --write", dockerfile)
        from_lines = [
            l for l in dockerfile.splitlines() if l.strip().startswith("FROM ")
        ]
        self.assertTrue(from_lines)
        for line in from_lines:
            self.assertNotIn(
                "<digest>", line,
                "a placeholder digest would break every build; the resolver "
                "writes the real one",
            )

    def test_bootstrap_mode_warns_instead_of_failing(self):
        """The pins need a networked run that a pull request cannot provide.

        A check that is red on arrival for a reason nobody can fix from a PR is
        a check people stop reading, so it starts in warn mode and --write
        ratchets it to enforce.
        """

        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "packaging", "pin_supply_chain.py"),
             "--check"],
            capture_output=True, text=True, cwd=REPO,
            env={**os.environ, "GITHUB_ACTIONS": "true"},
        )
        sys.path.insert(0, os.path.join(REPO, "packaging"))
        try:
            import pin_supply_chain as psc
            enforcing = bool(psc.load_policy().get("enforce"))
        finally:
            sys.path.pop(0)
        if enforcing:
            self.assertEqual(proc.returncode, 0,
                             "enforcement is on, so everything must be pinned")
        else:
            self.assertEqual(proc.returncode, 0)
            self.assertIn("::warning::", proc.stdout)
            self.assertNotIn("::error::", proc.stdout)

    def test_enforce_flag_makes_it_fail_now(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "packaging", "pin_supply_chain.py"),
             "--check", "--enforce"],
            capture_output=True, text=True, cwd=REPO,
        )
        sys.path.insert(0, os.path.join(REPO, "packaging"))
        try:
            import pin_supply_chain as psc
            unpinned = (psc.check_actions() + psc.check_dockerfile()
                        + psc.check_python_embed(psc.default_python_version()))
        finally:
            sys.path.pop(0)
        self.assertEqual(proc.returncode, 1 if unpinned else 0)

    def test_policy_file_is_present_and_parsable(self):
        import json
        with open(os.path.join(REPO, "packaging", "supply-chain-policy.json"),
                  encoding="utf-8") as fh:
            policy = json.load(fh)
        self.assertIn("enforce", policy)
        self.assertIsInstance(policy["enforce"], bool)

    def test_dependabot_watches_actions_and_docker(self):
        cfg = _read(".github", "dependabot.yml")
        self.assertIn("github-actions", cfg)
        self.assertIn("docker", cfg)


class MsiPythonVerificationTest(unittest.TestCase):
    """SEC-033."""

    def setUp(self):
        self.script = _read("packaging", "windows", "build_msi.ps1")

    def test_archive_is_hashed_before_it_is_unpacked(self):
        hash_at = self.script.index("Get-FileHash")
        expand_at = self.script.index("Expand-Archive -Path $tmp")
        self.assertLess(
            hash_at, expand_at,
            "the archive must be verified before it is unpacked",
        )

    def test_missing_or_wrong_hash_aborts_the_build(self):
        self.assertIn("SHA256 mismatch for", self.script)
        self.assertIn("No SHA256 recorded for", self.script)
        self.assertIn("throw", self.script)

    def test_manifest_file_exists(self):
        manifest = _read("packaging", "windows", "python-embed-sha256.txt")
        self.assertIn("SEC-033", manifest)


class AnsibleHardeningTest(unittest.TestCase):
    """SEC-034 / SEC-035 / SEC-036 / SEC-037 / CODE-034."""

    def setUp(self):
        try:
            __import__("yaml")
        except ImportError:
            self.skipTest("PyYAML not installed")

    def test_deploy_does_not_default_to_root(self):
        allv = _yaml("ansible", "group_vars", "all.yml")
        self.assertFalse(
            allv["commatrix_run_as_root"],
            "the collector must not run as root by default (SEC-034)",
        )
        self.assertTrue(allv["commatrix_elevate"])

    def test_version_is_not_a_mutable_branch(self):
        allv = _yaml("ansible", "group_vars", "all.yml")
        self.assertNotIn(
            allv["commatrix_version"], allv["commatrix_mutable_refs"],
            "deploying from a branch means the fleet installs a moving target "
            "(SEC-035)",
        )
        self.assertFalse(allv["commatrix_allow_mutable_ref"])

    def test_deploy_asserts_against_a_mutable_ref(self):
        play = _yaml("ansible", "deploy.yml")[0]
        names = [t.get("name", "") for t in play["tasks"]]
        self.assertTrue(
            any("mutable git ref" in n for n in names),
            f"expected a guard task, got {names}",
        )

    def test_deploy_runs_elevate_linux(self):
        text = _read("ansible", "deploy.yml")
        self.assertIn("elevate-linux", text)

    def test_windows_deploy_runs_elevate_windows(self):
        text = _read("ansible", "deploy_windows.yml")
        self.assertIn("elevate-windows", text)

    def test_no_win_shell_with_interpolation(self):
        for name in ("deploy_windows.yml", "collect.yml", "report.yml",
                     "pull_and_report.yml"):
            path = os.path.join(REPO, "ansible", name)
            if not os.path.exists(path):
                continue
            text = _read("ansible", name)
            for lineno, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if "win_shell" in line:
                    self.fail(
                        f"ansible/{name}:{lineno} uses win_shell; use "
                        f"win_command with an argv list (SEC-037): {line.strip()}"
                    )

    def test_changed_when_is_not_blindly_true_for_installs(self):
        for name in ("deploy.yml", "deploy_windows.yml"):
            text = _read("ansible", name)
            for block in text.split("- name:"):
                code = "\n".join(
                    l for l in block.splitlines() if not l.lstrip().startswith("#")
                )
                if "changed_when: true" in code and (
                    "pip install" in code or "install.sh" in code
                ):
                    self.fail(
                        f"ansible/{name}: an install task hardcodes "
                        "changed_when: true, which breaks idempotence (CODE-034)"
                    )


class ReleaseIntegrityTest(unittest.TestCase):
    """SEC-041 / SEC-042 / SEC-045."""

    def setUp(self):
        self.release = _read(".github", "workflows", "release.yml")

    def test_container_build_emits_provenance_and_sbom(self):
        self.assertNotIn("provenance: false", self.release)
        self.assertNotIn("sbom: false", self.release)
        self.assertIn("provenance: mode=max", self.release)
        self.assertIn("sbom: true", self.release)

    def test_artifacts_are_signed_not_only_checksummed(self):
        self.assertIn("sha256sum * > SHA256SUMS", self.release)
        self.assertIn("cosign sign-blob", self.release)
        self.assertIn("cosign sign --yes", self.release)

    def test_signing_jobs_request_an_oidc_token(self):
        self.assertIn("id-token: write", self.release)

    def test_sbom_doc_does_not_promise_an_image_sbom_on_the_release(self):
        sbom = _read("SBOM.md")
        self.assertIn("attestation", sbom.lower())
        self.assertNotIn(
            "attached to the GitHub Release, including an image SBOM", sbom,
            "SBOM.md must not claim an artifact the release workflow does not "
            "produce (SEC-045)",
        )


if __name__ == "__main__":
    unittest.main()
