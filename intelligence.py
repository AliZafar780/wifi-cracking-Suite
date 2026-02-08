#!/usr/bin/env python3
"""Intelligence and reporting helpers for WiFi Cracking Suite."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from typing import Any, Dict, Iterable, List


@dataclass
class RankedNetwork:
    """Represents a scored network target."""

    bssid: str
    essid: str
    score: int
    reason: str


class NetworkIntelligenceEngine:
    """Scores and ranks discovered networks using simple heuristics."""

    def score_network(self, network: Any) -> RankedNetwork:
        encryption = (getattr(network, "encryption", "") or "").upper()
        signal = self._parse_signal(getattr(network, "signal", ""))
        clients = int(getattr(network, "clients", 0) or 0)

        score = 0
        reasons: List[str] = []

        if "WEP" in encryption:
            score += 45
            reasons.append("legacy WEP")
        elif "WPA" in encryption and "WPA3" not in encryption:
            score += 25
            reasons.append("WPA/WPA2")
        elif "WPA3" in encryption:
            score += 10
            reasons.append("WPA3")
        else:
            score += 30
            reasons.append("unknown encryption")

        if signal >= -55:
            score += 25
            reasons.append("strong signal")
        elif signal >= -70:
            score += 15
            reasons.append("good signal")
        else:
            score += 5
            reasons.append("weak signal")

        if clients >= 10:
            score += 20
            reasons.append("high client activity")
        elif clients >= 3:
            score += 10
            reasons.append("moderate client activity")
        else:
            reasons.append("low client activity")

        wps_enabled = bool(getattr(network, "wps", False))
        wps_locked = bool(getattr(network, "wps_locked", False))
        if wps_enabled and not wps_locked:
            score += 20
            reasons.append("WPS enabled")

        essid = getattr(network, "essid", "") or "<hidden>"
        bssid = getattr(network, "bssid", "") or "unknown"
        return RankedNetwork(bssid=bssid, essid=essid, score=min(score, 100), reason=", ".join(reasons))

    def rank_networks(self, networks: Iterable[Any], top_n: int = 10) -> List[RankedNetwork]:
        ranked = [self.score_network(network) for network in networks]
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[:top_n]

    @staticmethod
    def _parse_signal(signal_value: Any) -> int:
        try:
            if isinstance(signal_value, (int, float)):
                return int(signal_value)
            value = str(signal_value).strip().replace("dBm", "").strip()
            return int(value)
        except Exception:
            return -100


class SessionReportBuilder:
    """Builds a portable session report with intelligence output."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.engine = NetworkIntelligenceEngine()

    def build_report(self, *, networks: Iterable[Any], system_info: Dict[str, Any], notes: str = "") -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"session_report_{timestamp}.json")

        network_list = list(networks)
        ranked = self.engine.rank_networks(network_list)

        payload = {
            "generated_at": datetime.now().isoformat(),
            "system": system_info,
            "notes": notes,
            "network_count": len(network_list),
            "ranked_targets": [
                {
                    "bssid": item.bssid,
                    "essid": item.essid,
                    "score": item.score,
                    "reason": item.reason,
                }
                for item in ranked
            ],
            "networks": [
                network.to_dict() if hasattr(network, "to_dict") else dict(network)
                for network in network_list
            ],
        }

        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

        return report_path
