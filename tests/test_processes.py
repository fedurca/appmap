"""CODE-012: PID / cgroup attribution had no test coverage at all.

Attribution is what turns "10.0.0.5:5432" into "postgres in container X of pod
Y", and it is a pile of regexes against a format that differs between cgroup
v1 and v2 and between every container runtime. Fixtures for Docker, CRI-O,
Podman and Kubernetes on both hierarchies live in tests/fixtures/cgroups/.
"""

import os
import tempfile
import unittest
from unittest import mock

from commatrix import processes

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "cgroups")


def _cgroup(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


class CgroupParsingTest(unittest.TestCase):
    def test_docker_v1(self):
        unit, cid, runtime, pod = processes._parse_cgroup(_cgroup("docker-v1.cgroup"))
        self.assertEqual(runtime, "docker")
        self.assertTrue(cid.startswith("9f4a2b1c3d5e"))
        self.assertIsNone(pod)

    def test_docker_v2(self):
        unit, cid, runtime, pod = processes._parse_cgroup(_cgroup("docker-v2.cgroup"))
        self.assertEqual(runtime, "docker")
        self.assertTrue(cid.startswith("9f4a2b1c3d5e"))

    def test_crio_v1_with_pod(self):
        unit, cid, runtime, pod = processes._parse_cgroup(_cgroup("crio-k8s-v1.cgroup"))
        self.assertEqual(runtime, "crio")
        self.assertTrue(cid.startswith("a1b2c3d4e5f6"))
        self.assertEqual(pod, "12345678-90ab-cdef-1234-567890abcdef")

    def test_crio_v2_normalises_underscore_pod_uid(self):
        unit, cid, runtime, pod = processes._parse_cgroup(_cgroup("crio-k8s-v2.cgroup"))
        self.assertEqual(runtime, "crio")
        self.assertEqual(
            pod, "12345678-90ab-cdef-1234-567890abcdef",
            "the systemd cgroup driver writes underscores; both must normalise "
            "to the same pod UID or the same pod appears twice in the catalog",
        )

    def test_podman_v2(self):
        unit, cid, runtime, pod = processes._parse_cgroup(_cgroup("podman-v2.cgroup"))
        self.assertEqual(runtime, "podman")
        self.assertTrue(cid.startswith("3c4d5e6f7081"))

    def test_k8s_pod_uid_without_dashes(self):
        unit, cid, runtime, pod = processes._parse_cgroup(
            _cgroup("k8s-pod-no-dashes.cgroup")
        )
        self.assertEqual(pod, "1234567890abcdef1234567890abcdef")

    def test_systemd_service_unit(self):
        unit, cid, runtime, pod = processes._parse_cgroup(_cgroup("systemd-service.cgroup"))
        self.assertEqual(unit, "nginx.service")
        self.assertIsNone(cid)

    def test_slices_are_not_reported_as_the_unit(self):
        unit, _cid, _rt, _pod = processes._parse_cgroup(
            _cgroup("systemd-user-scope.cgroup")
        )
        self.assertEqual(unit, "session-3.scope")

    def test_empty_and_malformed_input(self):
        self.assertEqual(processes._parse_cgroup(""), (None, None, None, None))
        self.assertEqual(
            processes._parse_cgroup("garbage without colons\n"),
            (None, None, None, None),
        )


class ProcRootAttributionTest(unittest.TestCase):
    """get_process_info / collect_processes against a synthetic /proc."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        processes.clear_package_cache()

    def _make_pid(self, pid, comm, cmdline, cgroup, uid=0):
        base = os.path.join(self.root, str(pid))
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, "comm"), "w") as fh:
            fh.write(comm + "\n")
        with open(os.path.join(base, "cmdline"), "wb") as fh:
            fh.write(b"\x00".join(p.encode() for p in cmdline) + b"\x00")
        with open(os.path.join(base, "cgroup"), "w") as fh:
            fh.write(cgroup)
        with open(os.path.join(base, "status"), "w") as fh:
            fh.write(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        return base

    def test_full_attribution_for_a_container_process(self):
        self._make_pid(4242, "postgres", ["postgres", "-D", "/data"],
                       _cgroup("docker-v1.cgroup"), uid=999)
        info = processes.get_process_info(4242, proc_root=self.root, resolve_package=False)
        self.assertEqual(info.comm, "postgres")
        self.assertEqual(info.cmdline, "postgres -D /data")
        self.assertEqual(info.container_runtime, "docker")
        self.assertEqual(info.uid, 999)

    def test_missing_pid_returns_none(self):
        self.assertIsNone(
            processes.get_process_info(99999, proc_root=self.root, resolve_package=False)
        )

    def test_pid_disappearing_mid_collection_is_skipped(self):
        self._make_pid(1, "init", ["/sbin/init"], _cgroup("systemd-service.cgroup"))
        got = processes.collect_processes([1, 2, 3], proc_root=self.root,
                                          resolve_package=False)
        self.assertEqual(list(got), [1])

    def test_unreadable_status_does_not_abort_attribution(self):
        base = self._make_pid(7, "svc", ["svc"], _cgroup("systemd-service.cgroup"))
        os.remove(os.path.join(base, "status"))
        info = processes.get_process_info(7, proc_root=self.root, resolve_package=False)
        self.assertIsNotNone(info)
        self.assertIsNone(info.uid)

    def test_deleted_binary_suffix_is_stripped_before_package_lookup(self):
        with mock.patch.object(
            processes, "_resolve_package_uncached", return_value="nginx"
        ) as resolver:
            processes._package_for_path(
                "/usr/sbin/nginx (deleted)", processes.PackageBudget()
            )
        resolver.assert_called_once_with("/usr/sbin/nginx")

    def test_relative_exe_is_never_shelled_out_for(self):
        with mock.patch.object(processes, "_resolve_package_uncached") as resolver:
            self.assertIsNone(
                processes._package_for_path("nginx", processes.PackageBudget())
            )
        resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
