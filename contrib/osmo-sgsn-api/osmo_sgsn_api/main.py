from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .config import settings
from .parsers import MmContext, PdpContext, parse_mm_contexts, parse_pdp_contexts
from .vty_client import VtyClient, VtyError

bearer = HTTPBearer(auto_error=False)

app = FastAPI(
    title="OsmoSGSN REST API",
    description="Token-authenticated HTTP API over OsmoSGSN VTY",
    version="1.0.0",
)


def require_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer),
) -> None:
    if not credentials or credentials.credentials != settings.osmo_sgsn_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _mm_to_dict(mm: MmContext, include_pdp: bool) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "imsi": mm.imsi,
        "imei": mm.imei,
        "p_tmsi": mm.p_tmsi,
        "msisdn": mm.msisdn,
        "tlli": mm.tlli,
        "hlr": mm.hlr,
        "gmm_state": mm.gmm_state,
        "routing_area": mm.routing_area,
        "cell_id": mm.cell_id,
        "mm_state": mm.mm_state,
        "ran_type": mm.ran_type,
        "pdp_count": len(mm.pdp_contexts),
    }
    if include_pdp:
        data["pdp_contexts"] = [_pdp_to_dict(p) for p in mm.pdp_contexts]
    return data


def _pdp_to_dict(pdp: PdpContext) -> Dict[str, Any]:
    return {
        "imsi": pdp.imsi,
        "sapi": pdp.sapi,
        "nsapi": pdp.nsapi,
        "ti": pdp.ti,
        "apn": pdp.apn,
        "pdp_address": pdp.pdp_address,
        "gtp_local_control": pdp.gtp_local_control,
        "gtp_local_teic": pdp.gtp_local_teic,
        "gtp_remote_control": pdp.gtp_remote_control,
        "gtp_remote_teic": pdp.gtp_remote_teic,
    }


def _run_vty(cmd: str, require_enable: bool = False) -> str:
    try:
        with VtyClient() as vty:
            return vty.command(cmd, require_enable=require_enable)
    except (VtyError, OSError, TimeoutError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"VTY connection failed: {exc}",
        )


class CountsResponse(BaseModel):
    mm_context_count: int
    pdp_context_count: int
    active_pdp_count: int = Field(
        description="PDP contexts attached to MM contexts (from show mm-context all pdp)"
    )


class ActionResponse(BaseModel):
    ok: bool
    imsi: str
    action: str
    detail: Optional[str] = None


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/contexts/counts", response_model=CountsResponse, dependencies=[Depends(require_token)])
def get_counts() -> CountsResponse:
    mm_text = _run_vty("show mm-context all pdp")
    pdp_text = _run_vty("show pdp-context all")
    mm_contexts = parse_mm_contexts(mm_text, include_pdp=True)
    pdp_contexts = parse_pdp_contexts(pdp_text)
    active_pdp = sum(len(mm.pdp_contexts) for mm in mm_contexts)
    return CountsResponse(
        mm_context_count=len(mm_contexts),
        pdp_context_count=len(pdp_contexts),
        active_pdp_count=active_pdp,
    )


@app.get("/v1/contexts/mm", dependencies=[Depends(require_token)])
def list_mm_contexts(include_pdp: bool = True) -> Dict[str, Any]:
    cmd = "show mm-context all pdp" if include_pdp else "show mm-context all"
    text = _run_vty(cmd)
    contexts = parse_mm_contexts(text, include_pdp=include_pdp)
    return {
        "count": len(contexts),
        "mm_contexts": [_mm_to_dict(mm, include_pdp) for mm in contexts],
    }


@app.get("/v1/contexts/mm/{imsi}", dependencies=[Depends(require_token)])
def get_mm_context(imsi: str, include_pdp: bool = True) -> Dict[str, Any]:
    cmd = f"show mm-context imsi {imsi}" + (" pdp" if include_pdp else "")
    text = _run_vty(cmd)
    if "No MM context" in text:
        raise HTTPException(status_code=404, detail=f"No MM context for IMSI {imsi}")
    contexts = parse_mm_contexts(text, include_pdp=include_pdp)
    if not contexts:
        raise HTTPException(status_code=404, detail=f"No MM context for IMSI {imsi}")
    return _mm_to_dict(contexts[0], include_pdp)


@app.get("/v1/contexts/pdp", dependencies=[Depends(require_token)])
def list_pdp_contexts() -> Dict[str, Any]:
    text = _run_vty("show pdp-context all")
    contexts = parse_pdp_contexts(text)
    return {
        "count": len(contexts),
        "pdp_contexts": [_pdp_to_dict(p) for p in contexts],
    }


@app.get("/v1/subscribers/cache", dependencies=[Depends(require_token)])
def subscriber_cache() -> Dict[str, Any]:
    text = _run_vty("show subscriber cache")
    return {"raw": text}


@app.post("/v1/subscribers/{imsi}/disconnect", response_model=ActionResponse, dependencies=[Depends(require_token)])
def disconnect_subscriber(imsi: str) -> ActionResponse:
    """Remove MM context locally without sending GMM Detach to the MS."""
    text = _run_vty(f"subscriber imsi {imsi} disconnect", require_enable=True)
    if "No MM context" in text:
        raise HTTPException(status_code=404, detail=f"No MM context for IMSI {imsi}")
    if text.startswith("%"):
        raise HTTPException(status_code=400, detail=text)
    return ActionResponse(ok=True, imsi=imsi, action="disconnect", detail=text or None)


@app.post("/v1/subscribers/{imsi}/detach", response_model=ActionResponse, dependencies=[Depends(require_token)])
def detach_subscriber(imsi: str) -> ActionResponse:
    """Network-initiated detach: send GMM Detach Request to the MS."""
    text = _run_vty(f"subscriber imsi {imsi} detach", require_enable=True)
    if "No MM context" in text:
        raise HTTPException(status_code=404, detail=f"No MM context for IMSI {imsi}")
    if text.startswith("%"):
        raise HTTPException(status_code=400, detail=text)
    return ActionResponse(ok=True, imsi=imsi, action="detach", detail=text or None)


@app.post("/v1/subscribers/{imsi}/page", response_model=ActionResponse, dependencies=[Depends(require_token)])
def page_subscriber(imsi: str) -> ActionResponse:
    text = _run_vty(f"page imsi {imsi}", require_enable=True)
    if "No MM context" in text:
        raise HTTPException(status_code=404, detail=f"No MM context for IMSI {imsi}")
    return ActionResponse(ok=True, imsi=imsi, action="page", detail=text or None)
