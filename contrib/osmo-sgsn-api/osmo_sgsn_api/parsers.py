import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PdpContext:
    imsi: str
    sapi: int
    nsapi: int
    ti: int
    apn: Optional[str] = None
    pdp_address: Optional[str] = None
    gtp_local_control: Optional[str] = None
    gtp_local_teic: Optional[str] = None
    gtp_remote_control: Optional[str] = None
    gtp_remote_teic: Optional[str] = None


@dataclass
class MmContext:
    imsi: str
    imei: str
    p_tmsi: str
    msisdn: Optional[str] = None
    tlli: Optional[str] = None
    hlr: Optional[str] = None
    gmm_state: Optional[str] = None
    routing_area: Optional[str] = None
    cell_id: Optional[int] = None
    mm_state: Optional[str] = None
    ran_type: Optional[str] = None
    pdp_contexts: List[PdpContext] = field(default_factory=list)


_RE_MM = re.compile(
    r"^MM Context for IMSI ([^,]+), IMEI ([^,]+), P-TMSI ([0-9a-fA-Fx]+)"
)
_RE_MM_LINE2 = re.compile(r"^  MSISDN: ([^,]+), TLLI: ([0-9a-fA-Fx]+) HLR: (.*)$")
_RE_MM_LINE3 = re.compile(
    r"^  GMM State: ([^,]+), Routeing Area: ([^,]+), Cell ID: (\d+)"
)
_RE_MM_LINE4 = re.compile(r"^  MM State: ([^,]+), RAN Type: (.+)$")
_RE_PDP = re.compile(
    r"^  PDP Context IMSI: ([^,]+), SAPI: (\d+), NSAPI: (\d+), TI: (\d+)"
)
_RE_APN = re.compile(r"^    APN: (.+)$")
_RE_PDP_ADDR = re.compile(r"^    PDP Address: (.+)$")
_RE_GTP_LOCAL = re.compile(
    r"^  GTPv\d Local Control\(([^)]+) / TEIC: (0x[0-9a-fA-F]+)"
)
_RE_GTP_REMOTE = re.compile(
    r"^  GTPv\d Remote Control\(([^)]+) / TEIC: (0x[0-9a-fA-F]+)"
)


def parse_mm_contexts(text: str, include_pdp: bool = True) -> List[MmContext]:
    contexts: List[MmContext] = []
    current: Optional[MmContext] = None
    current_pdp: Optional[PdpContext] = None

    for line in text.splitlines():
        m = _RE_MM.match(line)
        if m:
            current = MmContext(
                imsi=m.group(1).strip(),
                imei=m.group(2).strip(),
                p_tmsi=m.group(3).strip(),
            )
            contexts.append(current)
            current_pdp = None
            continue

        if not current:
            continue

        m = _RE_MM_LINE2.match(line)
        if m:
            current.msisdn = m.group(1).strip()
            current.tlli = m.group(2).strip()
            current.hlr = m.group(3).strip()
            continue

        m = _RE_MM_LINE3.match(line)
        if m:
            current.gmm_state = m.group(1).strip()
            current.routing_area = m.group(2).strip()
            current.cell_id = int(m.group(3))
            continue

        m = _RE_MM_LINE4.match(line)
        if m:
            current.mm_state = m.group(1).strip()
            current.ran_type = m.group(2).strip()
            continue

        if not include_pdp:
            continue

        m = _RE_PDP.match(line)
        if m:
            current_pdp = PdpContext(
                imsi=m.group(1).strip(),
                sapi=int(m.group(2)),
                nsapi=int(m.group(3)),
                ti=int(m.group(4)),
            )
            current.pdp_contexts.append(current_pdp)
            continue

        if not current_pdp:
            continue

        m = _RE_APN.match(line)
        if m:
            current_pdp.apn = m.group(1).strip()
            continue

        m = _RE_PDP_ADDR.match(line)
        if m and current_pdp.pdp_address is None:
            current_pdp.pdp_address = m.group(1).strip()
            continue

        m = _RE_GTP_LOCAL.match(line)
        if m:
            current_pdp.gtp_local_control = m.group(1).strip()
            current_pdp.gtp_local_teic = m.group(2).strip()
            continue

        m = _RE_GTP_REMOTE.match(line)
        if m:
            current_pdp.gtp_remote_control = m.group(1).strip()
            current_pdp.gtp_remote_teic = m.group(2).strip()
            continue

    return contexts


def parse_pdp_contexts(text: str) -> List[PdpContext]:
    contexts: List[PdpContext] = []
    current: Optional[PdpContext] = None

    for line in text.splitlines():
        m = re.match(
            r"^PDP Context IMSI: ([^,]+), SAPI: (\d+), NSAPI: (\d+), TI: (\d+)",
            line,
        )
        if m:
            current = PdpContext(
                imsi=m.group(1).strip(),
                sapi=int(m.group(2)),
                nsapi=int(m.group(3)),
                ti=int(m.group(4)),
            )
            contexts.append(current)
            continue

        if not current:
            continue

        if line.startswith("  APN:"):
            current.apn = line.split(":", 1)[1].strip()
            continue

        if line.startswith("  PDP Address:"):
            if current.pdp_address is None:
                current.pdp_address = line.split(":", 1)[1].strip()
            continue

        m = _RE_GTP_LOCAL.match(line)
        if m:
            current.gtp_local_control = m.group(1).strip()
            current.gtp_local_teic = m.group(2).strip()
            continue

        m = _RE_GTP_REMOTE.match(line)
        if m:
            current.gtp_remote_control = m.group(1).strip()
            current.gtp_remote_teic = m.group(2).strip()
            continue

    return contexts
