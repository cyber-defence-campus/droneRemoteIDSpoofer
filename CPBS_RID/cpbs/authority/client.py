"""HTTP client for the authority API (used by senders and receivers)."""
import base64
from typing import Optional, Tuple

import httpx

from cpbs.crypto.groupsig import GroupScheme


def _b(s: Optional[str]) -> Optional[bytes]:
    return base64.b64decode(s) if s is not None else None


class AuthorityClient:
    def __init__(self, url: str, client: Optional[httpx.Client] = None):
        self.http = client or httpx.Client(base_url=url, timeout=30)

    def _get(self, path: str) -> dict:
        r = self.http.get(path)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, body: Optional[dict] = None) -> dict:
        r = self.http.post(path, json=body or {})
        if r.status_code == 403:
            raise PermissionError(r.json()["detail"])
        r.raise_for_status()
        return r.json()

    def current(self) -> Tuple[int, str, bytes]:
        d = self._get("/epoch")
        return d["epoch"], d["scheme"], _b(d["grpkey"])

    def group_key(self, epoch: int) -> bytes:
        return _b(self._get(f"/gpk/{epoch}")["grpkey"])

    def responder_pk(self) -> bytes:
        return _b(self._get("/responder_pk")["pk"])

    def enroll(self, scheme: GroupScheme, member_id: str, epoch: int, grpkey: bytes) -> bytes:
        """Run the join protocol (member side local, manager steps over HTTP); returns the member key."""
        first, last = scheme.join_steps()
        msg, memkey = None, None
        for step in range(first, last + 1):
            if scheme.is_manager_step(step):
                body = {"member_id": member_id, "epoch": epoch, "step": step,
                        "msg": base64.b64encode(msg).decode() if msg is not None else None}
                msg = _b(self._post("/enroll", body)["msg"])
            else:
                msg, memkey = scheme.join_mem(grpkey, step, msg, memkey)
        return memkey

    def revoke(self, member_id: str) -> None:
        self._post(f"/revoke/{member_id}")

    def rollover(self) -> int:
        return self._post("/rollover")["epoch"]

    def open(self, core: bytes, requester: str, ticket: str) -> dict:
        return self._post("/open", {"core": base64.b64encode(core).decode(), "requester": requester, "ticket": ticket})

    def decrypt(self, c_enc: bytes, requester: str, ticket: str, session: str = "") -> dict:
        d = self._post("/responder/decrypt", {"c_enc": base64.b64encode(c_enc).decode(),
                                              "requester": requester, "ticket": ticket, "session": session})
        return {int(k): bytes.fromhex(v) for k, v in d["fields"].items()}

    def audit(self) -> dict:
        return self._get("/audit")
