"""Tests for the :52500 API handlers — drive hack5250 programmatically."""
import json
import pytest
from hack5250.libhack5250 import Hack5250


@pytest.fixture
def h(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    h = Hack5250("127.0.0.1", 23, project_name="apitest")
    yield h
    h.shutdown()


def call(h, cmd, args=""):
    return h.api._handlers[cmd](args)


def test_all_handlers_registered(h):
    expected = {
        "ping", "get_screen_text", "send_aid", "get_captured_creds",
        "get_masked_keys", "ffw_unprotect", "ffw_reveal_hidden",
        "ffw_remove_numeric", "ffw_high_visibility", "ffw_status",
        "ibmrseed_downgrade", "devname_spoof", "nego_status",
        "send_attn", "mask_arm", "mask_status", "inject_word",
        "get_fields", "get_pf_mask", "log_count", "list_aids",
    }
    assert expected.issubset(set(h.api._handlers.keys()))


def test_ping(h):
    assert call(h, "ping") == "pong"


def test_ffw_unprotect_on_off(h):
    call(h, "ffw_unprotect", "on")
    assert h.daemon.mutate_opts.unprotect is True
    call(h, "ffw_unprotect", "off")
    assert h.daemon.mutate_opts.unprotect is False


def test_ffw_unprotect_truthy_values(h):
    for v in ("1", "true", "yes", "ON", "True"):
        call(h, "ffw_unprotect", v)
        assert h.daemon.mutate_opts.unprotect is True
        call(h, "ffw_unprotect", "0")


def test_ffw_status_returns_all_flags(h):
    h.set_ffw_unprotect(True)
    h.set_ffw_reveal_hidden(True)
    status = json.loads(call(h, "ffw_status"))
    assert status["unprotect"] is True
    assert status["reveal_hidden"] is True
    assert status["remove_numeric"] is False


def test_ibmrseed_downgrade(h):
    call(h, "ibmrseed_downgrade", "on")
    assert h.daemon.negotiate_opts.force_cleartext is True


def test_devname_spoof_set_and_clear(h):
    resp = call(h, "devname_spoof", "DSP01")
    assert "DSP01" in resp
    assert h.daemon.negotiate_opts.spoof_device_name == "DSP01"
    resp = call(h, "devname_spoof", "")
    assert "cleared" in resp
    assert h.daemon.negotiate_opts.spoof_device_name is None


def test_nego_status(h):
    h.set_ibmrseed_downgrade(True)
    h.set_devname_spoof("QPADEV0001")
    status = json.loads(call(h, "nego_status"))
    assert status["force_cleartext"] is True
    assert status["spoof_device_name"] == "QPADEV0001"
    assert status["stripped_seed"] is None


def test_mask_arm_and_status(h):
    assert json.loads(call(h, "mask_status"))["ready"] is False
    resp = call(h, "mask_arm")
    assert "armed" in resp
    assert h._capture_armed is True


def test_inject_word_without_mask_errors(h):
    resp = call(h, "inject_word", "WRKACTJOB")
    assert resp.startswith("ERROR")
    assert "mask not captured" in resp


def test_inject_word_no_args_errors(h):
    resp = call(h, "inject_word", "")
    assert resp.startswith("ERROR")


def test_get_fields_empty_when_no_screen(h):
    assert call(h, "get_fields") == "[]"


def test_get_fields_after_screen(h, pkt_one_input_field):
    """Simulate a screen via the observer."""
    h.last_screen = h.protocol.parse(pkt_one_input_field)
    fields = json.loads(call(h, "get_fields"))
    assert len(fields) == 1
    assert fields[0]["row"] == 5
    assert fields[0]["col"] == 10
    assert fields[0]["protected"] is False


def test_get_pf_mask(h, pkt_with_soh):
    h.last_screen = h.protocol.parse(pkt_with_soh)
    result = json.loads(call(h, "get_pf_mask"))
    assert result["mask"] == "0x201000"
    assert "F1" in result["masked_keys"]
    assert "F3" not in result["masked_keys"]  # F3 is enabled


def test_list_aids(h):
    aids = json.loads(call(h, "list_aids"))
    assert "ENTER" in aids
    assert "F1" in aids
    assert "F24" in aids
    assert "ROLLUP" in aids
    assert len(aids) >= 33


def test_log_count_starts_zero(h):
    assert call(h, "log_count") == "0"


def test_get_captured_creds_empty(h):
    assert json.loads(call(h, "get_captured_creds")) == []


def test_get_captured_creds_after_capture(h):
    h.protocol.captured_creds.append(("QSECOFR", "PASSWORD"))
    creds = json.loads(call(h, "get_captured_creds"))
    assert ["QSECOFR", "PASSWORD"] in creds


# === D3/D4/E2/E3: Phase 3 Quick stream wiring ===

def test_msg_findings_handler(h):
    """msg_findings returns the IBMiMessageDetector's findings dict."""
    h.message_detector.findings["decimal_data_error"] = ["MCH1202"]
    resp = json.loads(call(h, "msg_findings"))
    assert resp["decimal_data_error"] == ["MCH1202"]


def test_strpccmd_alerts_handler(h):
    h.strpccmd_canary.alerts.append({"warning": "test", "raw_hex": "deadbeef"})
    resp = json.loads(call(h, "strpccmd_alerts"))
    assert len(resp) == 1
    assert resp[0]["warning"] == "test"


def test_get_hidden_content_handler(h, pkt_hidden_field):
    """Wraps surface.get_hidden_content on last_screen."""
    h.last_screen = h.protocol.parse(pkt_hidden_field)
    resp = json.loads(call(h, "get_hidden_content"))
    assert len(resp) == 1
    assert resp[0]["row"] == 3  # pkt_hidden_field is at r3c5


def test_tamper_map_handler(h, pkt_signon_screen):
    """Wraps surface.tamper_map on last_screen."""
    h.last_screen = h.protocol.parse(pkt_signon_screen)
    resp = json.loads(call(h, "tamper_map"))
    assert isinstance(resp, list)
    # signon has 1 protected field: the "Sign On" label at r1c36
    # (password is hidden but UNprotected — tamper_map only ranks protected fields)
    assert len(resp) == 1
    assert resp[0]["row"] == 1
    assert "score" in resp[0] and "reasons" in resp[0]


def test_suppress_errors_handler(h):
    """Toggle the protocol's suppress_errors instance attr."""
    assert h.protocol.suppress_errors is False
    call(h, "suppress_errors", "on")
    assert h.protocol.suppress_errors is True
    call(h, "suppress_errors", "off")
    assert h.protocol.suppress_errors is False
