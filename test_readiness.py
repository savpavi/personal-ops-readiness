import unittest

from personal_ops_readiness import (
    capacity_guidance,
    classify_storage_percent,
    classify_systemd_service,
    merge_smart_evidence,
    overall_status,
    parse_backup_status,
    parse_git_porcelain,
    parse_smartctl,
    parse_systemd_show,
    parse_timer_definition,
    reconcile_backup_evidence,
    should_monitor_block_device,
)


class ReadinessParserTests(unittest.TestCase):
    def test_storage_thresholds(self):
        expected = {
            84: "GREEN",
            85: "YELLOW",
            89: "YELLOW",
            90: "ORANGE",
            94: "ORANGE",
            95: "RED",
        }
        for percent, status in expected.items():
            with self.subTest(percent=percent):
                self.assertEqual(classify_storage_percent(percent), status)

    def test_git_porcelain_counts_without_exposing_paths(self):
        raw = b" M tracked.md\0D  removed.md\0?? private-name.md\0R  old.md\0new.md\0"
        self.assertEqual(
            parse_git_porcelain(raw),
            {"modified": 2, "deleted": 1, "untracked": 1},
        )

    def test_smartctl_nvme_warning_and_temperature(self):
        payload = {
            "smart_status": {"passed": True},
            "temperature": {"current": 72},
            "nvme_smart_health_information_log": {
                "critical_warning": 0,
                "media_errors": 0,
            },
            "smartctl": {"exit_status": 0},
        }
        parsed = parse_smartctl(payload)
        self.assertEqual(parsed["health"], "PASSED")
        self.assertEqual(parsed["temperature_c"], 72)
        self.assertEqual(parsed["severity"], "WARNING")
        self.assertIn("temperature", parsed["warnings"][0].lower())

    def test_smartctl_collection_failure_is_unknown(self):
        payload = {
            "smartctl": {
                "exit_status": 2,
                "messages": [{"severity": "error", "string": "permission denied"}],
            }
        }
        parsed = parse_smartctl(payload)
        self.assertEqual(parsed["health"], "UNKNOWN")
        self.assertEqual(parsed["severity"], "UNKNOWN")
        self.assertNotIn("permission denied", str(parsed).lower())

    def test_ram_backed_block_devices_are_not_smart_targets(self):
        self.assertFalse(should_monitor_block_device({"name": "zram0", "type": "disk"}))
        self.assertTrue(should_monitor_block_device({"name": "nvme0n1", "type": "disk"}))
        self.assertTrue(should_monitor_block_device({"name": "sda", "type": "disk"}))

    def test_vault_git_status_distinguishes_failure_from_success(self):
        failed = parse_backup_status("FAILED exit=1 2026-08-07 19:26:52 +0300")
        self.assertEqual(failed["status"], "WARNING")
        self.assertEqual(failed["last_result"], "FAILED")
        self.assertIsNone(failed["last_success"])

        success = parse_backup_status("SUCCESS 2026-08-11 06:00:00 +0300")
        self.assertEqual(success["status"], "OK")
        self.assertEqual(success["last_result"], "SUCCESS")
        self.assertIsNotNone(success["last_success"])

    def test_vault_git_backup_script_status_lines_are_parsable(self):
        """vault-git-backup.sh'in urettigi satirlar parser sozlesmesine uymali."""
        pushed = parse_backup_status("SUCCESS stage=pushed 2026-08-23 12:32:48 +0300")
        self.assertEqual(pushed["last_result"], "SUCCESS")
        self.assertEqual(pushed["stage"], "pushed")
        self.assertIsNotNone(pushed["last_success"])

        # degisiklik yokken de basarili sayilir; freshness kanidi uretmeye devam eder
        nochange = parse_backup_status("SUCCESS stage=nochange 2026-08-23 12:30:14 +0300")
        self.assertEqual(nochange["status"], "OK")
        self.assertEqual(nochange["stage"], "nochange")
        self.assertIsNotNone(nochange["last_success"])

        failed = parse_backup_status("FAILED exit=1 stage=push 2026-08-23 12:35:00 +0300")
        self.assertEqual(failed["last_result"], "FAILED")
        self.assertEqual(failed["stage"], "push")
        self.assertEqual(failed["exit_code"], 1)
        self.assertIsNone(failed["last_success"])

    def test_archive_status_records_failure_stage(self):
        failed = parse_backup_status(
            "FAILED exit=10 stage=repository-preflight 2026-08-11 08:00:00 +0300"
        )
        self.assertEqual(failed["last_result"], "FAILED")
        self.assertEqual(failed["exit_code"], 10)
        self.assertEqual(failed["stage"], "repository-preflight")

    def test_timer_definition_extracts_cadence(self):
        definition = """
[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
Persistent=true
"""
        parsed = parse_timer_definition(definition)
        self.assertEqual(parsed["cadence"], "every 6h")
        self.assertTrue(parsed["persistent"])

    def test_overall_status_prioritizes_critical_then_warning_then_unknown(self):
        self.assertEqual(overall_status(["WARNING", "CRITICAL", "UNKNOWN"]), "RED")
        self.assertEqual(overall_status(["WARNING", "UNKNOWN"]), "YELLOW")
        self.assertEqual(overall_status(["UNKNOWN"]), "UNKNOWN")
        self.assertEqual(overall_status(["INFO"]), "GREEN")

    def test_successful_systemd_service_result(self):
        evidence = parse_systemd_show(
            """Id=vault-git-backup.service
ActiveState=inactive
SubState=dead
Result=success
ExecMainCode=exited
ExecMainStatus=0
ExecMainStartTimestamp=Tue 2026-08-11 06:55:50 +03
ExecMainExitTimestamp=Tue 2026-08-11 07:40:00 +03
InvocationID=abc123
"""
        )
        self.assertEqual(classify_systemd_service(evidence)["state"], "SUCCESS")

    def test_successful_systemd_service_accepts_numeric_exited_code(self):
        evidence = parse_systemd_show(
            """ActiveState=inactive
SubState=dead
Result=success
ExecMainCode=1
ExecMainStatus=0
ExecMainExitTimestamp=Tue 2026-08-11 10:07:42 +03
"""
        )
        self.assertEqual(classify_systemd_service(evidence)["state"], "SUCCESS")

    def test_failed_systemd_service_result(self):
        evidence = parse_systemd_show(
            """Id=archive-critical-backup.service
ActiveState=failed
SubState=failed
Result=exit-code
ExecMainCode=exited
ExecMainStatus=10
ExecMainExitTimestamp=Tue 2026-08-11 07:09:32 +03
"""
        )
        result = classify_systemd_service(evidence)
        self.assertEqual(result["state"], "FAILED")
        self.assertEqual(result["exit_status"], 10)

    def test_currently_running_systemd_service(self):
        evidence = parse_systemd_show(
            """Id=vault-git-backup.service
ActiveState=activating
SubState=start
Result=success
ExecMainCode=exited
ExecMainStatus=0
ExecMainStartTimestamp=Tue 2026-08-11 07:15:50 +03
ExecMainExitTimestamp=
"""
        )
        self.assertEqual(classify_systemd_service(evidence)["state"], "RUNNING")

    def test_timer_fired_but_service_result_unknown(self):
        result = classify_systemd_service({})
        self.assertEqual(result["state"], "UNKNOWN")

    def test_stale_status_file_disagreement(self):
        service = {"state": "SUCCESS", "completed": "2026-08-11T07:40:00+03:00"}
        stamp = parse_backup_status("FAILED exit=1 2026-08-07 19:26:52 +0300")
        result = reconcile_backup_evidence(service, stamp)
        self.assertEqual(result["status"], "WARNING")
        self.assertTrue(result["evidence_disagreement"])
        self.assertIn("stale", result["reason"].lower())

    def test_matching_success_evidence_has_no_disagreement_reason(self):
        service = {"state": "SUCCESS", "completed": "2026-08-11T10:07:42+03:00"}
        stamp = parse_backup_status("SUCCESS 2026-08-11 10:07:42 +0300")
        result = reconcile_backup_evidence(service, stamp)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertIsNone(result["reason"])

    def test_newer_incomplete_invocation_does_not_inherit_old_failed_stamp(self):
        service = {
            "state": "UNKNOWN",
            "started": "2026-08-11T06:55:50+03:00",
            "completed": None,
        }
        stamp = parse_backup_status("FAILED exit=1 2026-08-07 19:26:52 +0300")
        result = reconcile_backup_evidence(service, stamp)
        self.assertEqual(result["status"], "WARNING")
        self.assertIn("newer invocation", result["reason"].lower())
        self.assertNotIn("recorded only", result["reason"].lower())

    def test_smart_historical_alert_does_not_become_current_condition(self):
        current = {
            "health": "UNKNOWN",
            "temperature_c": None,
            "severity": "UNKNOWN",
            "warnings": ["SMART data could not be collected"],
        }
        merged = merge_smart_evidence(
            current,
            {"state": "live"},
            [{"timestamp": "2026-08-06", "temperature_c": "72"}],
        )
        self.assertEqual(merged["current_health"], "UNKNOWN")
        self.assertIsNone(merged["current_temperature_c"])
        self.assertEqual(merged["severity"], "UNKNOWN")
        self.assertEqual(merged["historical_alerts"][0]["temperature_c"], "72")

    def test_94_percent_capacity_requests_action_soon(self):
        guidance = capacity_guidance(94)
        self.assertEqual(guidance["status"], "ORANGE")
        self.assertEqual(guidance["headroom_to_red_points"], 1)
        self.assertEqual(guidance["recommendation"], "CAPACITY ACTION SOON")
        self.assertEqual(guidance["severity"], "WARNING")

    def test_95_percent_capacity_is_red(self):
        guidance = capacity_guidance(95)
        self.assertEqual(guidance["status"], "RED")
        self.assertEqual(guidance["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
