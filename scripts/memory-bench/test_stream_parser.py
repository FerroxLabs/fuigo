import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import deepseek_bench as bench
from smoke_requests import is_recall_request


class StreamParserTests(unittest.TestCase):
    def test_title_is_excluded_but_all_three_recall_stages_count(self):
        query = {"messages": [{"role": "user", "content": "What is CURRENT?"}]}
        title = dict(query, tools=[{"function": {"name": "session_title"}}],
                     tool_choice={"type": "function", "function": {"name": "session_title"}})
        calls = [title, dict(query, tools=[{"function": {"name": "memory_search"}}]),
                 dict(query, tools=[{"function": {"name": "memory_search"}}]), query]
        self.assertEqual(sum(is_recall_request(call) for call in calls), 3)
        self.assertTrue(is_recall_request(dict(query, tools=[{"function": {"name": "session_title"}}])))

    def run_fixture(self, rows, code):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def spawn(*args, **kwargs):
                for row in rows:
                    kwargs["stdout"].write(json.dumps(row) + "\n")
                kwargs["stdout"].flush()
                return Mock(wait=Mock(return_value=code))
            proxy = Mock(token="fake")
            with patch.object(bench.subprocess, "Popen", side_effect=spawn):
                return bench.run_turn(root / "binary", root, root, proxy, "fixture", root / "log")

    def test_non_object_diagnostics_do_not_mask_valid_events(self):
        result = self.run_fixture(["diagnostic", None, [], 7,
            {"type": "text", "data": "answer"},
            {"type": "end", "sessionId": "fixture", "stopReason": "end_turn"}], 0)
        self.assertTrue(result["completed"])
        self.assertEqual(result["non_event_json_lines"], 4)
        self.assertEqual(result["final_text"], "answer")

    def test_exit_and_terminal_requirements_remain_fail_closed(self):
        self.assertFalse(self.run_fixture(["error"], 0)["completed"])
        self.assertFalse(self.run_fixture([
            {"type": "end", "stopReason": "end_turn"}, "error"], 1)["completed"])


if __name__ == "__main__":
    unittest.main()
