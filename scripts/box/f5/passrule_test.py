"""Unit tests for the B-F5 pass rule (passrule.py) on synthetic inotify logs.

Run: python3 scripts/box/f5/passrule_test.py   (PASSRULE=<path> judges another copy of the rule)

F5-B6: the deferred-close cases are the box B4/B9 failures seen under strace. A child forked by another thread
copies the descriptor table and holds the open file description until its exec, so the kernel reports
IN_CLOSE_WRITE after the free (B4) or after the `re` marks (B9) although the parent closed inside its window.
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import f5lib  # noqa: E402
from f5lib import path_hash  # noqa: E402

RULE = os.environ.get("PASSRULE", os.path.join(HERE, "passrule.py"))
HOME = "/tmp/f5/home/.fuigo"
SID = "01a1b445-52cd-77c2-bbdb-5bf145b533e5"
DIR = HOME + "/sessions/%2Ftmp%2Ff5%2Fws%2Frepo/" + SID
MARKS = HOME + "/f5-marks/"


def mark(name):
    return [MARKS + name + "|CREATE", MARKS + name + "|CLOSE_WRITE,CLOSE"]


def window(gen, seq, path, *events):
    h = path_hash(path)
    return mark("b.%d.%d.%s" % (gen, seq, h)) + [path + "|" + e for e in events] + mark("e.%d.%d.%s" % (gen, seq, h))


def judge(lines, tree=None):
    with tempfile.TemporaryDirectory() as out:
        with open(os.path.join(out, "inotify.log"), "w") as f:
            f.write("\n".join(lines) + "\n")
        if tree is not None:
            with open(os.path.join(out, "home-tree.txt"), "w") as f:
                f.write("\n".join(tree) + "\n")
        p = subprocess.run([sys.executable, RULE, HOME, out], capture_output=True, text=True, cwd=HERE)
        return p.returncode, p.stdout


EVENTS = DIR + "/events.jsonl"
LOCK = DIR + "/summary.json.lock"
SUMMARY = DIR + "/summary.json"


def gen1_with_open_events():
    return mark("claim.%s.1" % SID) + window(1, 1, EVENTS, "CREATE", "MODIFY")


class DeferredClose(unittest.TestCase):
    def test_a_held_close_after_free_from_a_forked_child_passes(self):
        # B4: the session thread closed events.jsonl before free; the hook child's exec released it after the mark.
        rc, out = judge(gen1_with_open_events() + mark("free.%s.1" % SID) + [EVENTS + "|CLOSE_WRITE,CLOSE"])
        self.assertEqual(rc, 0, out)

    def test_a_summary_lock_close_after_its_section_passes(self):
        # B9: apply_patch_locked closed summary.json.lock inside rb/re; an MCP spawn's exec released it after re.
        h1, h2 = path_hash(LOCK), path_hash(SUMMARY)
        lines = (mark("claim.%s.1" % SID) + mark("rb.7.%s" % h1) + mark("rb.7.%s" % h2)
                 + [LOCK + "|CREATE", SUMMARY + "|MODIFY", SUMMARY + "|CLOSE_WRITE,CLOSE"]
                 + mark("re.7.%s" % h2) + mark("re.7.%s" % h1) + [LOCK + "|CLOSE_WRITE,CLOSE"])
        rc, out = judge(lines)
        self.assertEqual(rc, 0, out)


class StillCaught(unittest.TestCase):
    def test_an_old_handle_closed_in_the_next_generation_fails(self):
        lines = (gen1_with_open_events() + mark("free.%s.1" % SID) + mark("claim.%s.2" % SID)
                 + [EVENTS + "|CLOSE_WRITE,CLOSE"])
        rc, out = judge(lines)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("rule 2", out)

    def test_a_write_after_free_fails(self):
        rc, out = judge(gen1_with_open_events() + mark("free.%s.1" % SID) + [EVENTS + "|MODIFY"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("rule 1", out)

    def test_a_close_of_a_path_no_window_opened_fails(self):
        rc, out = judge(gen1_with_open_events() + [DIR + "/bypass.txt|CLOSE_WRITE,CLOSE"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("rule 1", out)

    def test_a_summary_write_after_its_section_fails(self):
        h1 = path_hash(LOCK)
        lines = mark("claim.%s.1" % SID) + mark("rb.7.%s" % h1) + mark("re.7.%s" % h1) + [SUMMARY + "|MODIFY"]
        rc, out = judge(lines)
        self.assertNotEqual(rc, 0, out)


class Coverage(unittest.TestCase):
    """A missed watch must never be a silent pass (the inotifywait -r new-subdirectory race)."""
    REL = "." + DIR[len(HOME):]

    def test_a_claimed_session_folder_with_no_event_inside_it_fails(self):
        rc, out = judge(mark("claim.%s.1" % SID) + mark("free.%s.1" % SID))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("coverage", out)

    def test_a_file_in_the_final_tree_with_no_recorded_event_fails(self):
        rc, out = judge(gen1_with_open_events() + mark("free.%s.1" % SID),
                        tree=[self.REL, self.REL + "/events.jsonl", self.REL + "/missed.jsonl"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("coverage", out)

    def test_a_fully_recorded_final_tree_passes(self):
        rc, out = judge(gen1_with_open_events() + mark("free.%s.1" % SID),
                        tree=[self.REL, self.REL + "/events.jsonl", "./f5-marks/x", "./sessions/session_search.sqlite"])
        self.assertEqual(rc, 0, out)


class CountLeaders(unittest.TestCase):
    """leader_proof's process count (f5lib.count_leaders) on a synthetic /proc."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = self.tmp.name
        self.bin = os.path.join(self.proc, "fuigo-pager")
        open(self.bin, "w").close()
        self.other = os.path.join(self.proc, "git")
        open(self.other, "w").close()

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, pid, ppid, exe, argv):
        d = os.path.join(self.proc, str(pid))
        os.mkdir(d)
        with open(d + "/cmdline", "wb") as f:
            f.write(b"\0".join(a.encode() for a in argv) + b"\0")
        with open(d + "/stat", "w") as f:
            f.write("%d (fuigo-pager) S %d 1 1 0 -1\n" % (pid, ppid))
        os.symlink(exe, d + "/exe")

    def leader_argv(self):
        return [self.bin, "agent", "leader", "--no-exit-on-disconnect"]

    def test_one_leader(self):
        self.add(10, 1, self.bin, self.leader_argv())
        self.assertEqual(f5lib.count_leaders(self.bin, self.proc), [10])

    def test_a_fork_child_before_exec_is_not_a_second_leader(self):
        self.add(10, 1, self.bin, self.leader_argv())
        self.add(11, 10, self.bin, self.leader_argv())  # forked for `git`, not yet exec'd: same argv and exe
        self.assertEqual(f5lib.count_leaders(self.bin, self.proc), [10])

    def test_a_pid_with_the_leader_argv_but_another_exe_is_not_counted(self):
        self.add(10, 1, self.bin, self.leader_argv())
        self.add(12, 1, self.other, self.leader_argv())
        self.assertEqual(f5lib.count_leaders(self.bin, self.proc), [10])

    def test_a_true_second_leader_is_caught(self):
        self.add(10, 1, self.bin, self.leader_argv())
        self.add(13, 1, self.bin, self.leader_argv())
        self.assertEqual(f5lib.count_leaders(self.bin, self.proc), [10, 13])


if __name__ == "__main__":
    unittest.main(verbosity=2)
