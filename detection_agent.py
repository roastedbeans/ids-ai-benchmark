"""Detection Agent — LTE Specification-Based IDS (BR-1 to BR-43)

Implements all 43 behavior rules derived from behavior_rules_table.md and
formally verified in specification_verification.xml (UPPAAL, 2026).

Protocol scope : LTE only (TS 36.331, TS 36.304, TS 24.301, TS 33.401)
State labels   : s0–s25 map directly to the learned LTE protocol state machine

Part I  (BR-1  – BR-27) : Field-level and rate-based behavioral rules
Part II (BR-28 – BR-43) : State-machine sequence rules

Usage
-----
    python detection_agent.py                        # all csv_normal + csv_attack
    python detection_agent.py --detect trace.csv     # single file
    python detection_agent.py --json                 # JSON output
    python detection_agent.py --normal-dir D --attack-dir D
"""

from __future__ import annotations

import csv
import glob
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# State node IDs  (s0–s25, aligned with behavior_rules_table.md)
# ---------------------------------------------------------------------------
S0  = 0   # Ciphered NAS
S1  = 1   # TAU Accept
S2  = 2   # Service Request (standalone NAS)
S3  = 3   # TAU Request
S4  = 4   # DL Info Transfer + Ciphered NAS
S5  = 5   # RRC Setup Complete + Service Request
S6  = 6   # RRC Setup Complete + TAU Request
S7  = 7   # RRC Reconfiguration
S8  = 8   # RRC Reestablishment
S9  = 9   # Reestablishment Reject
S10 = 10  # RRC Release
S11 = 11  # RRC Setup
S12 = 12  # messageClassExtension
S13 = 13  # Security Mode Command
S14 = 14  # System Information (generic)
S15 = 15  # SIB1
S16 = 16  # UE Capability Enquiry
S17 = 17  # UE Information Request_r9
S18 = 18  # RRC Reconfiguration Complete
S19 = 19  # Reestablishment Complete
S20 = 20  # Reestablishment Request
S21 = 21  # RRC Request
S22 = 22  # Measurement Report
S23 = 23  # Security Mode Complete
S24 = 24  # UE Capability Information
S25 = 25  # UE Information Response_r9
MSG_NONE = -1

# Broadcast states — treated as transparent for sequence tracking (seq_prev
# is not updated when a broadcast arrives, preventing false positives from
# constant SIB1 / System Information messages in real traces).
BROADCAST: frozenset = frozenset({S14, S15})

# Uplink-NAS states used by BR-17
UL_NAS: frozenset = frozenset({S2, S3, S5, S6})

# CSV field sentinel
MISSING = "-1"
REQUIRED_FIELDS = {"packet_type", "direction", "info"}

# ---------------------------------------------------------------------------
# Rate-limit thresholds: (max_count, window_seconds)
# Calibrated from specification_verification.xml thresholds with
# empirically adjusted windows for real-capture analysis.
# ---------------------------------------------------------------------------
_RATE: Dict[str, tuple] = {
    "sys_info":  (10, 30.0),   # BR-2:  System Information flooding
    "rrc_req":   (5,  30.0),   # BR-4:  RRC Request flooding
    "reconfig":  (10, 30.0),   # BR-11: Reconfiguration flooding
    "meas":      (5,  30.0),   # BR-13: Measurement Report flooding
    "reest":     (5,  30.0),   # BR-15: Reestablishment Request flooding
    "release":   (5,  30.0),   # BR-18: RRC Release flooding
    "tau":       (5,  300.0),  # BR-21 TAU: mobility-driven (wider window)
    "service":   (5,  30.0),   # BR-21 SR:  data-session-driven
    "identity":  (3,  60.0),   # BR-26: Identity Request rate
    "auth_fail": (3,  60.0),   # BR-27: Authentication Failure rate
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int(val: str) -> Optional[int]:
    """Parse integer from raw CSV string; returns None for empty/missing."""
    v = (val or "").strip()
    if not v or v == MISSING:
        return None
    try:
        return int(v)
    except ValueError:
        try:
            return int(v, 16)
        except ValueError:
            return None


def _classify(info: str, ptype: str, row: dict) -> int:
    """Map a CSV row to a state-machine node ID (s0–s25).

    Classification is done by matching the ``info`` field against known
    message-name patterns from the LTE protocol state machine.  Returns
    ``MSG_NONE`` when the row does not match any known state.
    """
    il = info.lower().strip()

    # ── Reestablishment variants (check most specific first) ─────────────
    if "reestablishment reject" in il:
        return S9
    if "reestablishment complete" in il:
        return S19
    if "reestablishment request" in il:
        return S20
    if "reestablishment" in il:
        return S8

    # ── Reconfiguration variants ──────────────────────────────────────────
    if "reconfiguration complete" in il:
        return S18
    if "reconfiguration" in il:
        return S7

    # ── SIB1 before generic System Information ────────────────────────────
    if "system information block type1" in il or il == "sib1":
        return S15
    if il.startswith("system information"):
        return S14

    # ── RRC Setup Complete (combined NAS+RRC packets) ────────────────────
    if "setup complete" in il:
        if "tracking area update request" in il or "tau request" in il:
            return S6
        # Default: treat as service-request path (s5) even if NAS type
        # is ambiguous — downstream BR-31/BR-32 will catch flow violations.
        return S5

    # ── RRC Setup (not Complete) ─────────────────────────────────────────
    if "rrcconnection setup" in il and "complete" not in il:
        return S11

    # ── RRC Request ──────────────────────────────────────────────────────
    if "rrcconnection request" in il or "rrcsetuprequest" in il:
        return S21

    # ── RRC Release ──────────────────────────────────────────────────────
    if "rrcconnection release" in il or il == "rrcrelease":
        return S10

    # ── Security Mode ─────────────────────────────────────────────────────
    if "security mode complete" in il:
        return S23
    if "security mode command" in il:
        return S13

    # ── UE Capability ─────────────────────────────────────────────────────
    if "capability enquiry" in il or "uecapabilityenquiry" in il:
        return S16
    if "capability information" in il or "uecapabilityinformation" in il:
        return S24

    # ── UE Information ────────────────────────────────────────────────────
    if "information request_r9" in il or "ueinformationrequest" in il:
        return S17
    if "information response_r9" in il or "ueinformationresponse" in il:
        return S25

    # ── Measurement Report ────────────────────────────────────────────────
    if "measreport" in il or "measurement report" in il:
        return S22

    # ── messageClassExtension ─────────────────────────────────────────────
    if "messageclassextension" in il:
        return S12

    # ── NAS TAU messages ─────────────────────────────────────────────────
    if "tracking area update accept" in il:
        return S1
    if "tracking area update request" in il:
        return S3

    # ── Service Request (standalone NAS, not piggybacked) ─────────────────
    if il in ("service request", "service_request", "service request"):
        return S2
    if info.strip().upper() == "SERVICE REQUEST":
        return S2

    # ── DL Information Transfer carrying Ciphered NAS (s4) ───────────────
    if "dl information transfer" in il:
        return S4

    # ── Exclude auth messages from s0 (BR-25 false positive) ─────────────
    # Authentication Request/Response are plain NAS (sec_hdr 0), not ciphered.
    # Samsung diag may populate ciphered_msg for RES; avoid misclassifying as s0.
    if "authentication request" in il or "authentication response" in il:
        return MSG_NONE

    # ── Ciphered NAS (s0): pure NAS PDU with non-null security header ─────
    if ptype in ("nas",):
        sec_hdr = _int(row.get("nas-eps_security_header_type_value", MISSING))
        ciphered = row.get("nas-eps_ciphered_msg_value", MISSING).strip()
        if (sec_hdr is not None and sec_hdr in (2, 3, 4)) or \
           (ciphered not in (MISSING, "")):
            return S0

    return MSG_NONE


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------

@dataclass
class _State:
    """Per-trace session state mirroring the UPPAAL BRMonitor variables."""

    # ── Sequence tracking ────────────────────────────────────────────────
    # seq_prev: most recent non-broadcast state (transparent to S14/S15).
    # raw_prev: true immediate predecessor including broadcasts (for BR-16).
    # pre_s21:  predecessor of the last s21, determining Service/TAU flow.
    seq_prev: int = MSG_NONE
    raw_prev: int = MSG_NONE
    pre_s21:  int = MSG_NONE

    # ── Session ordering flags ────────────────────────────────────────────
    rrc_request_sent:  bool = False   # BR-6
    rrc_setup_rcvd:    bool = False   # BR-7
    smc_received:      bool = False   # BR-9 (Security Mode Command received)
    smc_complete:      bool = False   # BR-10 (Security Mode Complete done)
    security_ctx:      bool = False   # BR-24 (NAS security context exists)
    auth_completed:    bool = False   # BR-26
    ue_info_req_rcvd:  bool = False   # BR-14
    reconfig_counter:  int  = 0       # BR-12 pairing counter

    # ── SIB1 baseline (BR-1) ─────────────────────────────────────────────
    b_mcc:           Optional[str] = None
    b_mnc:           Optional[str] = None
    b_tac:           Optional[str] = None
    b_cell_id:       Optional[str] = None   # serving cell identity
    handover_active: bool           = False

    # ── Cell barring (BR-5) ───────────────────────────────────────────────
    cell_barred: bool = False

    # ── Current timestamp ─────────────────────────────────────────────────
    ts: float = 0.0

    # ── Rate-window timestamp lists ───────────────────────────────────────
    sys_info_ts:  List[float] = field(default_factory=list)
    rrc_req_ts:   List[float] = field(default_factory=list)
    reconfig_ts:  List[float] = field(default_factory=list)
    meas_ts:      List[float] = field(default_factory=list)
    reest_ts:     List[float] = field(default_factory=list)
    release_ts:   List[float] = field(default_factory=list)
    tau_ts:       List[float] = field(default_factory=list)
    service_ts:   List[float] = field(default_factory=list)
    identity_ts:  List[float] = field(default_factory=list)
    auth_fail_ts: List[float] = field(default_factory=list)

    # ── SPEC-ONLY NAS state (BR-26, BR-27) ───────────────────────────────
    identity_type:      Optional[str] = None  # '1'=IMSI, '3'=IMEI
    auth_reject_seen:   bool = False


# ---------------------------------------------------------------------------
# Behavior Rule Engine
# ---------------------------------------------------------------------------

class BehaviorRuleEngine:
    """Implements BR-1 to BR-43 on a packet trace (list of CSV rows).

    Call ``analyze(rows)`` to get a list of violation dicts.  State is reset
    at the start of every call so the engine is re-entrant across files.
    """

    def __init__(self) -> None:
        self._s = _State()

    def reset(self) -> None:
        self._s = _State()

    # ── Internal helpers ─────────────────────────────────────────────────

    def _ts(self, row: dict, idx: int) -> float:
        raw = row.get("timestamp", "")
        try:
            return float(raw) if raw else float(idx)
        except (ValueError, TypeError):
            return float(idx)

    def _rate_exceeded(self, ts_list: List[float], key: str) -> bool:
        """Prune stale entries and return True if rate limit is exceeded."""
        limit, window = _RATE[key]
        cutoff = self._s.ts - window
        ts_list[:] = [t for t in ts_list if t > cutoff]
        return len(ts_list) > limit

    # ── Part I — Behavioral Rules (BR-1 to BR-27) ───────────────────────

    def _br01(self, msg_id: int, row: dict, idx: int) -> Optional[dict]:
        """BR-1: SIB1 MCC/MNC/TAC of the SERVING cell must not change without handover.

        Only SIB1s from the serving cell are tracked (identified by cell
        identity).  SIB1s from neighbouring cells that the UE receives during
        measurement procedures are ignored, preventing false positives when
        the UE measures adjacent cells with different network parameters.
        """
        if msg_id != S15:
            return None
        mcc     = row.get("lte-rrc_mcc_value",            MISSING).strip()
        mnc     = row.get("lte-rrc_mnc_value",            MISSING).strip()
        tac     = row.get("lte-rrc_trackingareacode_value", MISSING).strip()
        cell_id = row.get("lte-rrc_cellidentity_value",   MISSING).strip()
        s = self._s

        # First SIB1: record baseline
        if s.b_mcc is None:
            if mcc != MISSING:
                s.b_mcc, s.b_mnc, s.b_tac, s.b_cell_id = mcc, mnc, tac, cell_id
            return None

        # Ignore SIB1s from a DIFFERENT cell (neighbouring-cell measurements)
        # A spoofing attack replaces the SERVING cell, so cell_id should match.
        if (cell_id not in (MISSING, "") and
                s.b_cell_id not in (MISSING, None) and
                cell_id != s.b_cell_id):
            return None

        # During handover / reestablishment, update the baseline silently
        if s.handover_active:
            s.b_mcc, s.b_mnc, s.b_tac, s.b_cell_id = mcc, mnc, tac, cell_id
            return None

        changed = (
            (mcc != MISSING and mcc != s.b_mcc) or
            (mnc != MISSING and mnc != s.b_mnc) or
            (tac != MISSING and tac != s.b_tac)
        )
        if changed:
            return {
                "row": idx, "rule": "BR-1", "severity": "CRITICAL",
                "msg": (f"SIB1 parameters changed without handover: "
                        f"MCC {s.b_mcc}→{mcc}, MNC {s.b_mnc}→{mnc}, "
                        f"TAC {s.b_tac}→{tac}"),
                "spec_ref": "TS 36.331 §5.2.1.2 / TS 36.304 §5.2.4",
            }
        return None

    def _br02(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-2: System Information message rate must not exceed threshold."""
        if msg_id != S14:
            return None
        self._s.sys_info_ts.append(self._s.ts)
        if self._rate_exceeded(self._s.sys_info_ts, "sys_info"):
            return {
                "row": idx, "rule": "BR-2", "severity": "HIGH",
                "msg": (f"System Information flooding: "
                        f"{len(self._s.sys_info_ts)} msgs in "
                        f"{_RATE['sys_info'][1]:.0f}s window"),
                "spec_ref": "TS 36.331 §5.2",
            }
        return None

    def _br03(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-3: messageClassExtension (s12) only after RRC Reestablishment (s8)."""
        if msg_id != S12:
            return None
        if self._s.seq_prev != S8:
            return {
                "row": idx, "rule": "BR-3", "severity": "HIGH",
                "msg": (f"messageClassExtension outside post-reestablishment "
                        f"context (seq_prev={self._s.seq_prev})"),
                "spec_ref": "TS 36.331 §5.3.7",
            }
        return None

    def _br04(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-4: RRC Request rate must not exceed threshold."""
        if msg_id != S21:
            return None
        self._s.rrc_req_ts.append(self._s.ts)
        if self._rate_exceeded(self._s.rrc_req_ts, "rrc_req"):
            return {
                "row": idx, "rule": "BR-4", "severity": "HIGH",
                "msg": (f"RRC Request flooding: "
                        f"{len(self._s.rrc_req_ts)} in "
                        f"{_RATE['rrc_req'][1]:.0f}s"),
                "spec_ref": "TS 36.331 §5.3.3",
            }
        return None

    def _br05(self, msg_id: int, row: dict, idx: int) -> Optional[dict]:
        """BR-5: UE must not connect to a cellBarred=barred cell."""
        if msg_id == S15:
            barred_val = _int(row.get("lte-rrc_cellbarred_value", MISSING))
            self._s.cell_barred = (barred_val == 0)
            return None
        if msg_id == S21 and self._s.cell_barred:
            return {
                "row": idx, "rule": "BR-5", "severity": "CRITICAL",
                "msg": "RRC Request to barred cell (cellBarred=barred in SIB1)",
                "spec_ref": "TS 36.304 §5.3.1",
            }
        return None

    def _br06(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-6: RRC Setup (s11) must follow a valid RRC Request (s21)."""
        if msg_id != S11:
            return None
        if not self._s.rrc_request_sent:
            return {
                "row": idx, "rule": "BR-6", "severity": "CRITICAL",
                "msg": "RRC Setup received without prior RRC Request",
                "spec_ref": "TS 36.331 §5.3.3.2",
            }
        return None

    def _br07(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-7: RRC Setup Complete (s5, s6) must follow RRC Setup (s11)."""
        if msg_id not in (S5, S6):
            return None
        if not self._s.rrc_setup_rcvd:
            return {
                "row": idx, "rule": "BR-7", "severity": "CRITICAL",
                "msg": "RRC Setup Complete received without prior RRC Setup",
                "spec_ref": "TS 36.331 §5.3.3.3",
            }
        return None

    def _br08(self, msg_id: int, row: dict, idx: int) -> Optional[dict]:
        """BR-8: Security Mode Command must use non-null ciphering and integrity."""
        if msg_id != S13:
            return None
        enc = _int(row.get("lte-rrc_cipheringalgorithm_value", MISSING))
        itg = _int(row.get("lte-rrc_integrityprotalgorithm_value", MISSING))
        null_enc = enc is not None and enc == 0
        null_itg = itg is not None and itg == 0
        if null_enc or null_itg:
            algs = []
            if null_enc:
                algs.append("EEA0 (null ciphering)")
            if null_itg:
                algs.append("EIA0 (null integrity)")
            return {
                "row": idx, "rule": "BR-8", "severity": "CRITICAL",
                "msg": f"Security Mode Command with null algorithm(s): {', '.join(algs)}",
                "spec_ref": "TS 33.401 §5.1.3.1",
            }
        return None

    def _br09(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-9: Security Mode Complete (s23) must follow Security Mode Command (s13)."""
        if msg_id != S23:
            return None
        if not self._s.smc_received:
            return {
                "row": idx, "rule": "BR-9", "severity": "CRITICAL",
                "msg": "Security Mode Complete without prior Security Mode Command",
                "spec_ref": "TS 36.331 §5.3.4",
            }
        return None

    def _br10(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-10: UE Capability Information (s24) must follow Enquiry (s16),
        which itself must only appear after Security Mode Complete (s23)."""
        if msg_id != S24:
            return None
        if not self._s.smc_complete:
            return {
                "row": idx, "rule": "BR-10", "severity": "HIGH",
                "msg": "UE Capability Information before Security Mode Complete",
                "spec_ref": "TS 36.331 §5.6.3.2",
            }
        return None

    def _br11(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-11: RRC Reconfiguration rate must not exceed threshold."""
        if msg_id != S7:
            return None
        self._s.reconfig_ts.append(self._s.ts)
        if self._rate_exceeded(self._s.reconfig_ts, "reconfig"):
            return {
                "row": idx, "rule": "BR-11", "severity": "HIGH",
                "msg": (f"RRC Reconfiguration flooding: "
                        f"{len(self._s.reconfig_ts)} in "
                        f"{_RATE['reconfig'][1]:.0f}s"),
                "spec_ref": "TS 36.331 §5.3.5",
            }
        return None

    def _br12(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-12: Each Reconfiguration Complete (s18) must match a prior s7."""
        if msg_id != S18:
            return None
        if self._s.reconfig_counter == 0:
            return {
                "row": idx, "rule": "BR-12", "severity": "HIGH",
                "msg": "RRC Reconfiguration Complete without a paired Reconfiguration",
                "spec_ref": "TS 36.331 §5.3.5.4",
            }
        return None

    def _br13(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-13: Measurement Report rate must not exceed threshold."""
        if msg_id != S22:
            return None
        self._s.meas_ts.append(self._s.ts)
        if self._rate_exceeded(self._s.meas_ts, "meas"):
            return {
                "row": idx, "rule": "BR-13", "severity": "HIGH",
                "msg": (f"Measurement Report flooding: "
                        f"{len(self._s.meas_ts)} in "
                        f"{_RATE['meas'][1]:.0f}s"),
                "spec_ref": "TS 36.331 §5.5.5",
            }
        return None

    def _br14(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-14: UE Information Response (s25) only after UE Info Request_r9 (s17)."""
        if msg_id != S25:
            return None
        if not self._s.ue_info_req_rcvd:
            return {
                "row": idx, "rule": "BR-14", "severity": "HIGH",
                "msg": "UE Information Response_r9 without prior UE Info Request_r9",
                "spec_ref": "TS 36.331 §5.6.8",
            }
        return None

    def _br15(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-15: Reestablishment Request rate must not exceed threshold."""
        if msg_id != S20:
            return None
        self._s.reest_ts.append(self._s.ts)
        if self._rate_exceeded(self._s.reest_ts, "reest"):
            return {
                "row": idx, "rule": "BR-15", "severity": "HIGH",
                "msg": (f"Reestablishment Request flooding: "
                        f"{len(self._s.reest_ts)} in "
                        f"{_RATE['reest'][1]:.0f}s"),
                "spec_ref": "TS 36.331 §5.3.7",
            }
        return None

    def _br16(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-16: RRC Reestablishment (s8) must follow s20, s15, or s19.

        Valid predecessors:
        - s20: normal path (Reestablishment Request → Reestablishment)
        - s15: idle-mode RLF (SIB1 → Reestablishment, count=2 in state machine)
        - s19: re-attempt after previous Reestablishment Complete (BR-42 allows
               s19→{s7,s8}, so back-to-back reestablishments are valid)

        raw_prev is used for the s15 exception because broadcasts do not update
        seq_prev; raw_prev captures the true immediate predecessor.
        """
        if msg_id != S8:
            return None
        if self._s.seq_prev in (S20, S19):
            return None
        if self._s.raw_prev == S15:
            return None  # idle-mode RLF: SIB1 immediately before Reestablishment
        return {
            "row": idx, "rule": "BR-16", "severity": "CRITICAL",
            "msg": (f"RRC Reestablishment without prior Reestablishment Request "
                    f"(seq_prev={self._s.seq_prev}, raw_prev={self._s.raw_prev})"),
            "spec_ref": "TS 36.331 §5.3.7.3",
        }

    def _br17(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-17: After Reestablishment Reject (s9), only TAU Request (s3)
        is a valid NAS follow-up."""
        if self._s.seq_prev != S9:
            return None
        if msg_id in UL_NAS and msg_id != S3:
            return {
                "row": idx, "rule": "BR-17", "severity": "HIGH",
                "msg": (f"Invalid NAS message (s{msg_id}) after "
                        f"Reestablishment Reject; only TAU Request (s3) is valid"),
                "spec_ref": "TS 36.331 §5.3.7.5",
            }
        return None

    def _br18(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-18: RRC Release rate must not exceed threshold."""
        if msg_id != S10:
            return None
        self._s.release_ts.append(self._s.ts)
        if self._rate_exceeded(self._s.release_ts, "release"):
            return {
                "row": idx, "rule": "BR-18", "severity": "HIGH",
                "msg": (f"RRC Release flooding: "
                        f"{len(self._s.release_ts)} in "
                        f"{_RATE['release'][1]:.0f}s"),
                "spec_ref": "TS 36.331 §5.3.8",
            }
        return None

    def _br19(self, info: str, row: dict, idx: int) -> Optional[dict]:
        """BR-19 (SPEC-ONLY): waitTime in RRC Connection Reject must be 1–16 s.

        Operates on the raw info string because RRC Connection Reject is not
        present in the s0–s25 state machine (not observed in training data).
        """
        il = info.lower()
        if "rrcconnection reject" not in il or "reestablishment" in il:
            return None
        wt = _int(row.get("lte-rrc_waittime_value", MISSING))
        if wt is not None and (wt < 1 or wt > 16):
            return {
                "row": idx, "rule": "BR-19", "severity": "HIGH",
                "msg": f"RRC Connection Reject waitTime={wt}s out of range [1,16]",
                "spec_ref": "TS 36.331 §5.3.3.6 Table 7.3-1",
            }
        return None

    def _br20(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-20: RRC Release (s10) must only be preceded by Ciphered NAS (s0)
        or TAU Accept (s1)."""
        if msg_id != S10:
            return None
        if self._s.seq_prev not in (S0, S1):
            return {
                "row": idx, "rule": "BR-20", "severity": "CRITICAL",
                "msg": (f"RRC Release from invalid predecessor s{self._s.seq_prev}; "
                        f"only s0 (Ciphered NAS) or s1 (TAU Accept) are valid"),
                "spec_ref": "TS 36.331 §5.3.8",
            }
        return None

    def _br21(self, msg_id: int, idx: int) -> List[dict]:
        """BR-21: TAU Request and Service Request rates — separate thresholds."""
        violations = []
        if msg_id == S3:
            self._s.tau_ts.append(self._s.ts)
            if self._rate_exceeded(self._s.tau_ts, "tau"):
                violations.append({
                    "row": idx, "rule": "BR-21", "severity": "HIGH",
                    "msg": (f"TAU Request flooding: "
                            f"{len(self._s.tau_ts)} in "
                            f"{_RATE['tau'][1]:.0f}s"),
                    "spec_ref": "TS 24.301 §5.5.3",
                })
        elif msg_id == S2:
            self._s.service_ts.append(self._s.ts)
            if self._rate_exceeded(self._s.service_ts, "service"):
                violations.append({
                    "row": idx, "rule": "BR-21", "severity": "HIGH",
                    "msg": (f"Service Request flooding: "
                            f"{len(self._s.service_ts)} in "
                            f"{_RATE['service'][1]:.0f}s"),
                    "spec_ref": "TS 24.301 §5.6.1",
                })
        return violations

    def _br22(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-22: TAU Accept (s1) must only follow Ciphered NAS (s0) or RRC Release (s10)."""
        if msg_id != S1:
            return None
        if self._s.seq_prev not in (S0, S10):
            return {
                "row": idx, "rule": "BR-22", "severity": "CRITICAL",
                "msg": (f"TAU Accept from invalid predecessor s{self._s.seq_prev}; "
                        f"only s0 (Ciphered NAS) or s10 (RRC Release) are valid"),
                "spec_ref": "TS 24.301 §5.5.3.2",
            }
        return None

    def _br23(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-23: Service Request (s2) must be followed by RRC Request (s21)."""
        if self._s.seq_prev != S2:
            return None
        if msg_id != S21:
            return {
                "row": idx, "rule": "BR-23", "severity": "HIGH",
                "msg": (f"Service Request not followed by RRC Request "
                        f"(got s{msg_id})"),
                "spec_ref": "TS 24.301 §5.6.1.2",
            }
        return None

    def _br24(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-24: DL Info Transfer with Ciphered NAS (s4) requires an existing
        NAS security context, or must directly follow Setup Complete+TAU (s6)."""
        if msg_id != S4:
            return None
        if not self._s.security_ctx and self._s.seq_prev != S6:
            return {
                "row": idx, "rule": "BR-24", "severity": "CRITICAL",
                "msg": "DL Info Transfer with Ciphered NAS when no NAS security context exists",
                "spec_ref": "TS 24.301 §5.5.3 / TS 33.401 §7.2",
            }
        return None

    def _br25(self, msg_id: int, row: dict, idx: int) -> Optional[dict]:
        """BR-25: Ciphered NAS (s0) must carry integrity-and-ciphered security header."""
        if msg_id != S0:
            return None
        sec_hdr = _int(row.get("nas-eps_security_header_type_value", MISSING))
        if sec_hdr is not None and sec_hdr not in (2, 3, 4):
            return {
                "row": idx, "rule": "BR-25", "severity": "CRITICAL",
                "msg": (f"Ciphered NAS message has invalid security header "
                        f"(type={sec_hdr}); integrity+ciphering required"),
                "spec_ref": "TS 24.301 §9.3.1 Table 9.3.1",
            }
        return None

    def _br26(self, info: str, row: dict, idx: int) -> List[dict]:
        """BR-26 (SPEC-ONLY): Identity Request for IMSI/IMEI only after auth."""
        violations = []
        il = info.lower()
        if "identity request" in il:
            self._s.identity_ts.append(self._s.ts)
            self._rate_exceeded(self._s.identity_ts, "identity")  # prune
            id_type = row.get("nas-eps_emm_type_of_id_value", MISSING).strip()
            self._s.identity_type = id_type
            if id_type in ("1", "3"):   # 1=IMSI, 3=IMEI
                if not self._s.auth_completed:
                    violations.append({
                        "row": idx, "rule": "BR-26", "severity": "HIGH",
                        "msg": (f"Identity Request for "
                                f"{'IMSI' if id_type == '1' else 'IMEI'} "
                                f"before authentication completed"),
                        "spec_ref": "TS 24.301 §5.4.4.2 / TS 33.501 §6.12",
                    })
            if len(self._s.identity_ts) > _RATE["identity"][0]:
                violations.append({
                    "row": idx, "rule": "BR-26", "severity": "HIGH",
                    "msg": (f"Identity Request flooding: "
                            f"{len(self._s.identity_ts)} in "
                            f"{_RATE['identity'][1]:.0f}s"),
                    "spec_ref": "TS 24.301 §5.4.4.2",
                })
        return violations

    def _br27(self, info: str, row: dict, idx: int) -> List[dict]:
        """BR-27 (SPEC-ONLY): Authentication must not be rejected or fail
        repeatedly."""
        violations = []
        il = info.lower()
        if "authentication reject" in il:
            self._s.auth_reject_seen = True
            violations.append({
                "row": idx, "rule": "BR-27", "severity": "CRITICAL",
                "msg": "Authentication Reject observed (TS 24.301 §5.4.2.7)",
                "spec_ref": "TS 24.301 §5.4.2.7",
            })
        if "authentication failure" in il:
            self._s.auth_fail_ts.append(self._s.ts)
            if self._rate_exceeded(self._s.auth_fail_ts, "auth_fail"):
                violations.append({
                    "row": idx, "rule": "BR-27", "severity": "HIGH",
                    "msg": (f"Authentication Failure flooding: "
                            f"{len(self._s.auth_fail_ts)} in "
                            f"{_RATE['auth_fail'][1]:.0f}s"),
                    "spec_ref": "TS 24.301 §5.4.2.5",
                })
        return violations

    # ── Part II — State Machine Sequence Rules (BR-28 to BR-43) ─────────
    #
    # Each rule checks: if seq_prev == TRIGGER, current msg must be in VALID_SET.
    # seq_prev is broadcast-transparent, so routine SIB1 / System Information
    # traffic does not break the sequence tracking.

    def _seq_violation(self, rule: str, prev: int, curr: int,
                       valid: set, idx: int, spec: str) -> Optional[dict]:
        if self._s.seq_prev != prev:
            return None
        # Broadcasts are transparent: they do not update seq_prev and must
        # not trigger a sequence violation for the broadcast message itself.
        if curr in BROADCAST:
            return None
        if curr in valid:
            return None
        return {
            "row": idx, "rule": rule, "severity": "HIGH",
            "msg": (f"Invalid sequence: s{prev} → s{curr}; "
                    f"valid next: {{{', '.join(f's{v}' for v in sorted(valid))}}}"),
            "spec_ref": spec,
        }

    def _br28(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-28: s21 → {s11, s2, s15}"""
        return self._seq_violation(
            "BR-28", S21, msg_id, {S11, S2, S15}, idx,
            "TS 36.331 §5.3.3.2",
        )

    def _br29_30(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-29 / BR-30: s11 successor — flow-aware.

        Service flow (pre_s21 == s2)  → valid: {s5, s2}
        TAU flow     (pre_s21 == s3)  → valid: {s6}
        Unknown flow (pre_s21 unknown) → combined whitelist: {s5, s2, s6}
        """
        if self._s.seq_prev != S11:
            return None
        pre = self._s.pre_s21
        if pre == S2:
            valid, rule = {S5, S2}, "BR-29"
        elif pre == S3:
            valid, rule = {S6}, "BR-30"
        else:
            valid, rule = {S5, S2, S6}, "BR-29"
        if msg_id in valid:
            return None
        return {
            "row": idx, "rule": rule, "severity": "HIGH",
            "msg": (f"Invalid s11 successor: s{msg_id}; "
                    f"expected {{{', '.join(f's{v}' for v in sorted(valid))}}} "
                    f"(flow context: pre_s21=s{pre})"),
            "spec_ref": "TS 36.331 §5.3.3.3",
        }

    def _br31(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-31: s5 → {s13}"""
        return self._seq_violation(
            "BR-31", S5, msg_id, {S13}, idx,
            "TS 36.331 §5.3.4 / TS 24.301 §5.4.3",
        )

    def _br32(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-32: s6 → {s4, s2}"""
        return self._seq_violation(
            "BR-32", S6, msg_id, {S4, S2}, idx,
            "TS 36.331 §5.3.4 / TS 24.301 §5.5.3",
        )

    def _br33(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-33: s4 → {s0}"""
        return self._seq_violation(
            "BR-33", S4, msg_id, {S0}, idx,
            "TS 24.301 §5.5.3.2",
        )

    def _br34(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-34: s0 → {s1, s10}"""
        return self._seq_violation(
            "BR-34", S0, msg_id, {S1, S10}, idx,
            "TS 24.301 §5.5.3.2",
        )

    def _br35(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-35: s13 → {s23}"""
        return self._seq_violation(
            "BR-35", S13, msg_id, {S23}, idx,
            "TS 36.331 §5.3.4.3",
        )

    def _br36(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-36: s23 → {s16}"""
        return self._seq_violation(
            "BR-36", S23, msg_id, {S16}, idx,
            "TS 36.331 §5.6.3.1",
        )

    def _br37(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-37: s16 → {s24}"""
        return self._seq_violation(
            "BR-37", S16, msg_id, {S24}, idx,
            "TS 36.331 §5.6.3.2",
        )

    def _br38(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-38: s24 → {s7}"""
        return self._seq_violation(
            "BR-38", S24, msg_id, {S7}, idx,
            "TS 36.331 §5.6.3.2",
        )

    def _br39(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-39: s7 → {s18}"""
        return self._seq_violation(
            "BR-39", S7, msg_id, {S18}, idx,
            "TS 36.331 §5.3.5.4",
        )

    def _br40(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-40: s20 → {s8, s9, s15}"""
        return self._seq_violation(
            "BR-40", S20, msg_id, {S8, S9, S15}, idx,
            "TS 36.331 §5.3.7.3",
        )

    def _br41(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-41: s8 → {s19, s12, s20}

        s20 (new Reestablishment Request) is added as a valid successor to
        accommodate re-attempt scenarios in poor RF coverage, where the UE
        receives the network's Reestablishment (s8) but must retry immediately.
        """
        return self._seq_violation(
            "BR-41", S8, msg_id, {S19, S12, S20}, idx,
            "TS 36.331 §5.3.7.4",
        )

    def _br42(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-42: s19 → {s7, s8}"""
        return self._seq_violation(
            "BR-42", S19, msg_id, {S7, S8}, idx,
            "TS 36.331 §5.3.7.4 / §5.3.5",
        )

    def _br43(self, msg_id: int, idx: int) -> Optional[dict]:
        """BR-43: s17 → {s25}"""
        return self._seq_violation(
            "BR-43", S17, msg_id, {S25}, idx,
            "TS 36.331 §5.6.8.2",
        )

    # ── State update (runs AFTER all rule checks) ────────────────────────

    def _update(self, msg_id: int) -> None:
        """Update session state after running all checks for the current message.

        Mirrors the UPPAAL update_session_state() function, including:
        - pre_s21 capture when s21 is processed
        - broadcast-transparent seq_prev update
        - flag and pairing-counter management
        """
        s = self._s

        # Always update raw_prev (for BR-16 s15 exception)
        s.raw_prev = msg_id

        # Broadcast-transparent seq_prev: only update for non-broadcasts
        if msg_id not in BROADCAST:
            s.seq_prev = msg_id

        # Ordering flags
        if msg_id == S21:
            s.rrc_request_sent = True
            s.pre_s21 = s.seq_prev  # capture flow context before advancing seq_prev

        if msg_id == S11:
            s.rrc_setup_rcvd = True
        if msg_id == S13:
            s.smc_received = True
        if msg_id == S23:
            s.smc_complete   = True
            s.security_ctx   = True
        if msg_id == S17:
            s.ue_info_req_rcvd = True

        # Reconfiguration pairing counter (BR-12)
        # checkBR12 runs before _update, so counter reflects pre-message state.
        if msg_id == S7:
            s.reconfig_counter += 1
        if msg_id == S18 and s.reconfig_counter > 0:
            s.reconfig_counter -= 1

        # Handover / cell-change detection.
        # RRC Reconfiguration (s7) = handover; clear on Reconfiguration Complete (s18).
        # RRC Reestablishment sequence (s20→s8→s19) also implies a cell change:
        # mark handover active during the reestablishment and clear on s19.
        if msg_id in (S7, S20):
            s.handover_active = True
        elif msg_id in (S18, S19):
            s.handover_active = False

    # ── Main entry point ─────────────────────────────────────────────────

    def analyze(self, rows: List[dict]) -> List[dict]:
        """Run all BR-1 to BR-43 checks on a packet trace.

        Checks run in the order: Part I field/rate rules → Part II sequence
        rules, for every row.  State is reset at the start of each call.

        Returns a list of violation dicts, one per triggered rule instance.
        """
        self.reset()
        violations: List[dict] = []
        s = self._s

        def _add(v):
            if v is not None:
                violations.append(v)

        def _addall(vs):
            violations.extend(vs)

        for idx, row in enumerate(rows, start=1):
            s.ts = self._ts(row, idx)
            info  = " ".join(row.get("info", "").split())
            ptype = row.get("packet_type", "").strip().lower()

            msg_id = _classify(info, ptype, row)
            if msg_id == MSG_NONE:
                continue  # unknown message type — skip all checks

            # ── Part I: Field-level and rate-based rules ──────────────────

            # Phase 1: Cell Broadcast (s14, s15, s12)
            _add(self._br01(msg_id, row, idx))
            _add(self._br02(msg_id, idx))
            _add(self._br03(msg_id, idx))

            # Phase 2: RRC Connection Establishment (s21, s11, s5, s6)
            _add(self._br04(msg_id, idx))
            _add(self._br05(msg_id, row, idx))
            _add(self._br06(msg_id, idx))
            _add(self._br07(msg_id, idx))

            # Phase 3: NAS Security Activation (s13, s23, s16, s24)
            _add(self._br08(msg_id, row, idx))
            _add(self._br09(msg_id, idx))
            _add(self._br10(msg_id, idx))

            # Phase 4: RRC Reconfiguration / Handover (s7, s18, s22)
            _add(self._br11(msg_id, idx))
            _add(self._br12(msg_id, idx))
            _add(self._br13(msg_id, idx))

            # Phase 5: UE Information (s17, s25)
            _add(self._br14(msg_id, idx))

            # Phase 6: RRC Reestablishment (s20, s8, s9, s19)
            _add(self._br15(msg_id, idx))
            _add(self._br16(msg_id, idx))
            _add(self._br17(msg_id, idx))

            # Phase 7: RRC Release (s10) + SPEC-ONLY waitTime
            _add(self._br18(msg_id, idx))
            _add(self._br19(info, row, idx))
            _add(self._br20(msg_id, idx))

            # Phase 8: NAS TAU and Service Request (s3, s2)
            _addall(self._br21(msg_id, idx))
            _add(self._br22(msg_id, idx))
            _add(self._br23(msg_id, idx))

            # Phase 9: NAS DL Info Transfer and Ciphered NAS (s4, s0)
            _add(self._br24(msg_id, idx))
            _add(self._br25(msg_id, row, idx))

            # Phase 10: NAS Identity and Authentication (SPEC-ONLY)
            _addall(self._br26(info, row, idx))
            _addall(self._br27(info, row, idx))

            # ── Part II: State Machine Sequence Rules ─────────────────────
            _add(self._br28(msg_id, idx))
            _add(self._br29_30(msg_id, idx))
            _add(self._br31(msg_id, idx))
            _add(self._br32(msg_id, idx))
            _add(self._br33(msg_id, idx))
            _add(self._br34(msg_id, idx))
            _add(self._br35(msg_id, idx))
            _add(self._br36(msg_id, idx))
            _add(self._br37(msg_id, idx))
            _add(self._br38(msg_id, idx))
            _add(self._br39(msg_id, idx))
            _add(self._br40(msg_id, idx))
            _add(self._br41(msg_id, idx))
            _add(self._br42(msg_id, idx))
            _add(self._br43(msg_id, idx))

            # ── State update (AFTER all checks) ───────────────────────────
            self._update(msg_id)

        return violations


# ---------------------------------------------------------------------------
# Detection Agent  (CSV I/O layer)
# ---------------------------------------------------------------------------

class DetectionAgent:
    """Reads CSV packet traces and runs the BehaviorRuleEngine."""

    NORMAL_DIR = "csv_normal"
    ATTACK_DIR = "csv_attack"

    def __init__(self) -> None:
        self._engine = BehaviorRuleEngine()

    def _read(self, path: str) -> List[dict]:
        rows: List[dict] = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i == 0 and not REQUIRED_FIELDS.issubset(row.keys()):
                    raise ValueError(
                        f"CSV missing required fields: "
                        f"{REQUIRED_FIELDS - row.keys()}"
                    )
                rows.append(row)
        return rows

    def analyze_rows(self, rows: List[dict]) -> dict:
        """Analyze pre-loaded rows (inference only, no I/O). For benchmarking."""
        violations = self._engine.analyze(rows)
        verdict    = "ANOMALOUS" if violations else "NORMAL"

        by_rule: Dict[str, int] = {}
        for v in violations:
            by_rule[v["rule"]] = by_rule.get(v["rule"], 0) + 1

        return {
            "verdict":        verdict,
            "violations":     len(violations),
            "rules_triggered": by_rule,
            "detail":         violations[:10],
        }

    def detect(self, path: str) -> dict:
        """Analyze a single CSV trace file."""
        rows    = self._read(path)
        result  = self.analyze_rows(rows)
        result["file"] = os.path.basename(path)
        return result

    def detect_all(self, directory: str) -> List[dict]:
        """Analyze all CSV files in a directory."""
        results = []
        for p in sorted(glob.glob(os.path.join(directory, "*.csv"))):
            try:
                results.append(self.detect(p))
            except Exception as exc:
                results.append({
                    "file":    os.path.basename(p),
                    "verdict": "ERROR",
                    "error":   str(exc),
                })
        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Detection Agent — LTE Specification-Based IDS (BR-1 to BR-43)"
    )
    parser.add_argument(
        "--detect", metavar="FILE",
        help="Analyze a single CSV trace and print JSON result",
    )
    parser.add_argument(
        "--normal-dir", default="csv_normal",
        help="Directory of normal-traffic CSV files  (default: csv_normal)",
    )
    parser.add_argument(
        "--attack-dir", default="csv_attack",
        help="Directory of attack CSV files  (default: csv_attack)",
    )
    parser.add_argument(
        "--dir", metavar="FOLDER",
        help="Analyze all CSV files in a custom folder (single-folder mode)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit full JSON result instead of summary table",
    )
    args = parser.parse_args()

    agent = DetectionAgent()

    if args.detect:
        print(json.dumps(agent.detect(args.detect), indent=2, default=str))
        return

    if args.dir:
        results = agent.detect_all(args.dir)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
            return
        banner = "Detection Agent — Custom Folder Analysis"
        print("=" * len(banner))
        print(f"  {banner}")
        print("=" * len(banner))
        print(f"\n[Folder: {args.dir}]")
        for r in results:
            v = r.get("verdict", "")
            status = "  OK  " if v == "NORMAL" else ("!! ERR" if v == "ERROR" else "!! ANOM")
            vcount = r.get("violations", "err")
            rules = ", ".join(r.get("rules_triggered", {}).keys()) if r.get("rules_triggered") else "—"
            err = f"  error={r['error']}" if v == "ERROR" and r.get("error") else ""
            print(f"  {status}  {r['file']:<50}  violations={vcount}  rules=[{rules}]{err}")
        return

    banner = "Detection Agent — Behavior Rules BR-1 to BR-43 (LTE)"
    print("=" * len(banner))
    print(f"  {banner}")
    print("=" * len(banner))

    normal_results = agent.detect_all(args.normal_dir)
    attack_results = agent.detect_all(args.attack_dir)

    if args.json:
        print(json.dumps(
            {"normal": normal_results, "attack": attack_results},
            indent=2, default=str,
        ))
        return

    # ── Normal files ──────────────────────────────────────────────────────
    print(f"\n[Normal: {args.normal_dir}]")
    for r in normal_results:
        status = "  OK  " if r.get("verdict") == "NORMAL" else "!! FP"
        vcount = r.get("violations", "err")
        print(f"  {status}  {r['file']:<50}  violations={vcount}")

    # ── Attack files ──────────────────────────────────────────────────────
    print(f"\n[Attack: {args.attack_dir}]")
    for r in attack_results:
        status = "  OK  " if r.get("verdict") == "ANOMALOUS" else "!! FN"
        vcount = r.get("violations", "err")
        rules  = (", ".join(r.get("rules_triggered", {}).keys())
                  if r.get("rules_triggered") else "—")
        print(f"  {status}  {r['file']:<50}  violations={vcount}  "
              f"rules=[{rules}]")

    # ── Accuracy summary ──────────────────────────────────────────────────
    tp = sum(1 for r in attack_results if r.get("verdict") == "ANOMALOUS")
    tn = sum(1 for r in normal_results if r.get("verdict") == "NORMAL")
    fp = sum(1 for r in normal_results if r.get("verdict") == "ANOMALOUS")
    fn = sum(1 for r in attack_results if r.get("verdict") == "NORMAL")
    total = tp + tn + fp + fn

    acc  = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp)    if (tp + fp) else 0.0
    rec  = tp / (tp + fn)    if (tp + fn) else 0.0
    f1   = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

    sep = "=" * len(banner)
    print(f"\n{sep}")
    print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}  (total={total})")
    print(f"  Accuracy : {acc:.1%}  ({tp + tn}/{total})")
    print(f"  Precision: {prec:.1%}   Recall: {rec:.1%}   F1: {f1:.1%}")
    print(sep)


if __name__ == "__main__":
    main()
