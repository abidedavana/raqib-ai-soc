"""Wazuh SIEM forwarder.

Ships each SecurityEvent to Wazuh so AI attacks show up alongside the rest of the
SOC's telemetry. Two transports:

  * file   (recommended) — append one JSON object per line to a log file that the
            Wazuh manager tails via a <localfile log_format="json"> entry. Robust,
            ordering-preserving, and the way real apps feed Wazuh.
  * syslog — JSON over UDP to the manager's remote-syslog port.

Disabled by default (WAZUH_ENABLED=false) and fully fail-safe: any forwarding
error is swallowed so the SIEM can never break Raqib's request path.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

from ..config import Settings, get_settings
from ..models import SecurityEvent


class WazuhForwarder:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return self.settings.wazuh_enabled

    def send(self, event: SecurityEvent) -> bool:
        if not self.enabled:
            return False
        if self.settings.wazuh_mode == "file":
            return self._send_file(event)
        return self._send_syslog(event)

    # ── transports ───────────────────────────────────────────────────────────
    def _payload(self, event: SecurityEvent) -> dict:
        # nest under "raqib" so Wazuh exposes fields as raqib.severity, raqib.owasp_llm, ...
        return {"raqib": event.model_dump(mode="json")}

    def _send_file(self, event: SecurityEvent) -> bool:
        try:
            path = Path(self.settings.wazuh_log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(self._payload(event), default=str) + "\n")
            return True
        except Exception:
            return False

    def _send_syslog(self, event: SecurityEvent) -> bool:
        line = "raqib-aisoc: " + json.dumps(self._payload(event), default=str)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(line.encode("utf-8"), (self.settings.wazuh_host, self.settings.wazuh_port))
            return True
        except Exception:
            return False
