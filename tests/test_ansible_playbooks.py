"""The deployment glue, actually parsed and run rather than eyeballed.

ansible/collect.yml referenced `ansible.windows.win_fetch`, a module that does
not exist and never has, so the Windows snapshot play could not be parsed --
let alone collect anything. Nothing caught it because nothing ever asked
Ansible to look at these files.

These tests skip cleanly when ansible is not installed; the `ansible` CI job
installs it (with the collections in ansible/requirements.yml) so the checks
actually run on every commit.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "packaging"))
import check_ansible  # noqa: E402
sys.path.pop(0)

ANSIBLE = shutil.which("ansible-playbook")


def _load(name):
    with open(os.path.join(REPO, "ansible", name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class RequirementsTest(unittest.TestCase):
    def test_collections_are_declared(self):
        req = _load("requirements.yml")
        names = {c["name"] for c in req["collections"]}
        self.assertIn(
            "ansible.windows", names,
            "the Windows plays need this collection on the control node; "
            "without it they fail at parse time",
        )

    def test_every_collection_used_is_declared(self):
        declared = {c["name"] for c in _load("requirements.yml")["collections"]}
        declared.add("ansible.builtin")
        used = set()
        for path in check_ansible.playbooks():
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    for token in stripped.replace(":", " ").split():
                        if token.count(".") >= 2 and token[0].isalpha():
                            ns = ".".join(token.split(".")[:2])
                            if ns.startswith(("ansible.", "community.")):
                                used.add(ns)
        missing = used - declared
        self.assertEqual(missing, set(), f"undeclared collections: {missing}")


@unittest.skipUnless(ANSIBLE, "ansible-playbook not installed")
class SyntaxTest(unittest.TestCase):
    def test_every_playbook_parses(self):
        problems, skipped = [], []
        check_ansible.syntax_check(problems, skipped)
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertEqual(skipped, [])

    def test_no_playbook_references_a_nonexistent_module(self):
        """--syntax-check resolves module names; win_fetch failed exactly here."""

        problems, skipped = [], []
        check_ansible.syntax_check(problems, skipped)
        self.assertFalse(
            any("couldn't resolve module" in p for p in problems), problems
        )


@unittest.skipUnless(ANSIBLE, "ansible-playbook not installed")
class MutableRefGuardTest(unittest.TestCase):
    """SEC-035, exercised through Ansible rather than read."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.inv = os.path.join(self.tmp, "inv.ini")
        with open(self.inv, "w", encoding="utf-8") as fh:
            fh.write("[commatrix_hosts]\nlocalhost ansible_connection=local\n")

    def _run(self, *extra):
        return subprocess.run(
            [ANSIBLE, "-i", self.inv, "ansible/deploy.yml", "--check", *extra],
            capture_output=True, text=True, check=False, cwd=REPO,
            timeout=300,
        )

    def test_a_pinned_version_passes_the_guard(self):
        out = self._run().stdout + self._run().stderr
        self.assertNotIn("a mutable branch", out)

    def test_a_branch_name_is_refused(self):
        proc = self._run("-e", "commatrix_version=main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("a mutable branch", proc.stdout + proc.stderr)

    def test_the_escape_hatch_works(self):
        proc = self._run("-e", "commatrix_version=main",
                         "-e", "commatrix_allow_mutable_ref=true")
        self.assertNotIn("a mutable branch", proc.stdout + proc.stderr)


class PrivilegeDefaultsTest(unittest.TestCase):
    """SEC-034 / SEC-036 defaults, read from the files Ansible actually loads."""

    def setUp(self):
        self.allv = _load("group_vars/all.yml")

    def test_linux_deploy_does_not_default_to_root(self):
        self.assertFalse(self.allv["commatrix_run_as_root"])
        self.assertTrue(self.allv["commatrix_elevate"])

    def test_windows_deploy_drops_off_system_by_default(self):
        self.assertTrue(self.allv["commatrix_windows_elevate"])

    def test_sedebug_stays_opt_in(self):
        self.assertFalse(self.allv["commatrix_windows_allow_sedebug"])

    def test_changed_when_survives_a_missing_stdout(self):
        """A skipped or stdout-less task must not blow up the expression."""

        for name in ("deploy.yml", "deploy_windows.yml"):
            with open(os.path.join(REPO, "ansible", name), encoding="utf-8") as fh:
                text = fh.read()
            for line in text.splitlines():
                if ".stdout" in line and "search(" in line:
                    self.assertIn(
                        "default(", line,
                        f"ansible/{name}: {line.strip()} would raise on a "
                        "skipped task",
                    )


if __name__ == "__main__":
    unittest.main()
