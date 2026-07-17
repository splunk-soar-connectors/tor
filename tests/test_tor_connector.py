import sys
import types
import unittest
from unittest.mock import Mock, patch


phantom = types.ModuleType("phantom")
phantom_app = types.ModuleType("phantom.app")
phantom_app.APP_SUCCESS = "success"
phantom_app.APP_ERROR = "error"
phantom_app.is_fail = lambda value: value == phantom_app.APP_ERROR
phantom.action_result = types.ModuleType("phantom.action_result")
phantom.action_result.ActionResult = object
phantom.base_connector = types.ModuleType("phantom.base_connector")
phantom.base_connector.BaseConnector = object
sys.modules.setdefault("phantom", phantom)
sys.modules.setdefault("phantom.app", phantom_app)
sys.modules.setdefault("phantom.action_result", phantom.action_result)
sys.modules.setdefault("phantom.base_connector", phantom.base_connector)

if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")

from tor_connector import TordnselConnector


class ActionResult:
    def set_status(self, status, message):
        self.status = status
        self.message = message
        return status


class RecentExitTests(unittest.TestCase):
    def setUp(self):
        self.connector = TordnselConnector.__new__(TordnselConnector)
        self.connector._state = {}
        self.connector.save_progress = lambda message: None
        self.action_result = ActionResult()

    def test_cached_snapshot_excludes_action_specific_recent_exits(self):
        response = Mock(status_code=200, text="ExitAddress 192.0.2.1 2026-07-17 00:00:00\n")

        with patch("tor_connector.requests.get", return_value=response, create=True):
            result = self.connector._download_save_list(self.action_result, 123)

        self.assertEqual(result, "success")
        self.assertEqual(self.connector._state["ip_list"], ["192.0.2.1"])

    def test_recent_exits_are_queried_per_lookup(self):
        response = Mock(status_code=200, text="# comment\n198.51.100.2\n")

        with patch("tor_connector.requests.get", return_value=response, create=True) as request:
            result, recent_exits = self.connector._query_recent_exits(self.action_result, ["198.51.100.2"])

        self.assertEqual(result, "success")
        self.assertEqual(recent_exits, {"198.51.100.2"})
        request.assert_called_once_with(
            "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=198.51.100.2", timeout=30
        )

    def test_recent_exit_http_failure_fails_the_action(self):
        response = Mock(status_code=500)

        with patch("tor_connector.requests.get", return_value=response, create=True):
            result, recent_exits = self.connector._query_recent_exits(self.action_result, ["198.51.100.2"])

        self.assertEqual(result, "error")
        self.assertIsNone(recent_exits)
        self.assertEqual(self.action_result.message, "Error from recent exit node list server: HTTP 500")


if __name__ == "__main__":
    unittest.main()
