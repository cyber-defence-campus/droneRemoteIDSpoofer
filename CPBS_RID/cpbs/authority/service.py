"""Authority REST API (FastAPI). Binary values travel as base64.

Run:  python -m cpbs.authority.service --port 8471
"""
import argparse
import base64
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from cpbs.authority.hsm import Authority, AuthorityError
from cpbs.metrics import Metrics


def b64(b: Optional[bytes]) -> Optional[str]:
    return base64.b64encode(b).decode() if b is not None else None


def unb64(s: Optional[str]) -> Optional[bytes]:
    return base64.b64decode(s) if s is not None else None


class JoinReq(BaseModel):
    member_id: str
    epoch: int
    step: int
    msg: Optional[str] = None


class OpenReq(BaseModel):
    core: str
    requester: str
    ticket: str


class DecryptReq(BaseModel):
    c_enc: str
    requester: str
    ticket: str
    session: str = ""


def create_app(authority: Authority) -> FastAPI:
    app = FastAPI(title="CPBS Authority")

    def guard(fn, *args):
        try:
            return fn(*args)
        except AuthorityError as e:
            raise HTTPException(status_code=403, detail=str(e))

    @app.get("/epoch")
    def epoch():
        e, gpk = authority.group_key()
        return {"epoch": e, "scheme": authority.scheme.name, "grpkey": b64(gpk)}

    @app.get("/gpk/{epoch}")
    def gpk(epoch: int):
        e, key = guard(authority.group_key, epoch)
        return {"epoch": e, "grpkey": b64(key)}

    @app.get("/responder_pk")
    def responder_pk():
        return {"pk": b64(authority.responder_pk)}

    @app.post("/enroll")
    def enroll(r: JoinReq):
        return {"msg": b64(guard(authority.join_step, r.member_id, r.epoch, r.step, unb64(r.msg)))}

    @app.post("/revoke/{member_id}")
    def revoke(member_id: str):
        authority.revoke(member_id)
        return {"revoked": member_id}

    @app.post("/rollover")
    def rollover():
        return {"epoch": authority.rollover()}

    @app.post("/open")
    def open_(r: OpenReq):
        return guard(authority.open, unb64(r.core), r.requester, r.ticket)

    @app.post("/responder/decrypt")
    def decrypt(r: DecryptReq):
        res = guard(authority.decrypt_fields, unb64(r.c_enc), r.requester, r.ticket, r.session)
        return {"fields": {str(k): v.hex() for k, v in res["fields"].items()},
                "audit_index": res["audit_index"]}

    @app.get("/audit")
    def audit():
        return {"valid": authority.audit.verify(), "head": authority.audit.head,
                "entries": authority.audit.entries}

    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scheme", default="bbs04")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8471)
    ap.add_argument("--metrics")
    a = ap.parse_args()
    authority = Authority(a.scheme, Metrics(a.metrics, "authority"))
    uvicorn.run(create_app(authority), host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
