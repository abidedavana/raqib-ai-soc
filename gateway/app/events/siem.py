"""Wazuh SIEM forwarder (Phase 6 integration point).

Ships each SecurityEvent to Wazuh as a single JSON line over UDP syslog. Wazuh's
custom Raqib decoders/rules (see ../../wazuh/) parse these into native alerts so
AI attacks show up alongside the rest of the SOC's telemetry.

Disabled by default (WAZUH_ENABLED=false). When disabled this is a safe no-op,
so the gateway runs fine before Wazuh exists.
"""
from __future__ import annotations

import json
import socket

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
        payload = {"raqib": event.model_dump(mode="json")}
        line = "raqib-aisoc: " + json.dumps(payload, default=str)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(line.encode("utf-8"), (self.settings.wazuh_host, self.settings.wazuh_port))
            return True
        except Exception:
            # never let SIEM forwarding break the request path
            return False
