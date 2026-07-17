import os
import tempfile
import unittest

from commatrix import netns


def _make_pid(root, pid, ns_inode, cgroup=""):
    base = os.path.join(root, str(pid))
    os.makedirs(os.path.join(base, "ns"), exist_ok=True)
    os.symlink(f"net:[{ns_inode}]", os.path.join(base, "ns", "net"))
    with open(os.path.join(base, "cgroup"), "w") as fh:
        fh.write(cgroup)


class EnumerateNetnsTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def test_host_and_container_netns(self):
        _make_pid(self.root, 1, 4026531840, "0::/init.scope\n")
        _make_pid(self.root, 100, 4026531840, "0::/user.slice\n")  # same (host) ns
        _make_pid(self.root, 200, 4026532000,
                  "0::/system.slice/docker-abcdef123456789.scope\n")
        nss = netns.enumerate_netns(proc_root=self.root)
        inodes = {n.inode for n in nss}
        self.assertEqual(len(inodes), 2)
        host = [n for n in nss if n.is_host]
        self.assertEqual(len(host), 1)
        cont = [n for n in nss if not n.is_host][0]
        self.assertEqual(cont.container_id, "abcdef123456789")
        self.assertEqual(cont.container_runtime, "docker")
        self.assertTrue(cont.label.startswith("docker:"))

    def test_include_host_false(self):
        _make_pid(self.root, 1, 4026531840)
        _make_pid(self.root, 200, 4026532000, "0::/system.slice/docker-deadbeef000000.scope\n")
        nss = netns.enumerate_netns(proc_root=self.root, include_host=False)
        self.assertTrue(all(not n.is_host for n in nss))
        self.assertEqual(len(nss), 1)

    def test_pod_uid_extracted(self):
        _make_pid(self.root, 1, 4026531840)
        cg = "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod12345678_1234_1234_1234_123456789abc.slice/docker-aaaabbbbcccc.scope\n"
        _make_pid(self.root, 300, 4026532111, cg)
        nss = netns.enumerate_netns(proc_root=self.root, include_host=False)
        self.assertEqual(nss[0].pod, "12345678-1234-1234-1234-123456789abc")


if __name__ == "__main__":
    unittest.main()
