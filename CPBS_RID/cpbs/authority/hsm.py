"""Authority logic: issuer + opener + revocation, with simulated HSM key storage.

Single root of trust: one authority issues member keys, opens signatures and
publishes the per-epoch group public key. The manager keys, member lists and
responder decryption key never leave this object (the "HSM"); the API only
exposes operations, each opening/decryption being written to the audit log.

Revocation = one group per epoch: on rollover a fresh group is created and
only non-revoked members may enrol in it.
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from cpbs.authority.audit import AuditLog
from cpbs.console import RED, say, short
from cpbs.crypto import seal
from cpbs.crypto.groupsig import GroupScheme, GroupState
from cpbs.metrics import NULL, Metrics
from cpbs.protocol.core import Core, decode_fields, verify_core


class AuthorityError(Exception):
    pass


@dataclass
class _Epoch:
    group: GroupState
    members: Dict[int, str] = field(default_factory=dict)  # GML index -> member id
    created: float = field(default_factory=time.time)


class Authority:
    def __init__(self, scheme: str, metrics: Metrics = NULL):
        self.scheme = GroupScheme(scheme)
        self.metrics = metrics
        self.epochs: Dict[int, _Epoch] = {}
        self.epoch = -1
        self.revoked: Set[str] = set()
        self.audit = AuditLog()
        self._responder_sk, self.responder_pk = seal.generate_keypair()
        self._lock = threading.Lock()  # libgroupsig native state is not thread-safe
        first, last = self.scheme.join_steps()
        self._final_mgr_step = max(s for s in range(first, last + 1) if self.scheme.is_manager_step(s))
        self.rollover()

    # -- epochs / revocation ---------------------------------------------------

    def rollover(self) -> int:
        with self._lock:
            with self.metrics.timer("group_setup", scheme=self.scheme.name):
                group = self.scheme.setup()
            self.epoch += 1
            self.epochs[self.epoch] = _Epoch(group)
            self.metrics.event("epoch", epoch=self.epoch, revoked=len(self.revoked))
            say("authority", f"epoch {self.epoch} started: new {self.scheme.name} group"
                             + (f", {len(self.revoked)} revoked member(s) excluded" if self.revoked else ""))
            return self.epoch

    def revoke(self, member_id: str) -> None:
        """Effective from the next epoch: the member cannot enrol any more."""
        with self._lock:
            self.revoked.add(member_id)
        say("authority", f"revoked '{member_id}' (effective at the next epoch)", RED)

    def group_key(self, epoch: Optional[int] = None) -> Tuple[int, bytes]:
        epoch = self.epoch if epoch is None else epoch
        if epoch not in self.epochs:
            raise AuthorityError(f"unknown epoch {epoch}")
        return epoch, self.epochs[epoch].group.grpkey

    # -- enrolment (join protocol, manager side) ------------------------------

    def join_step(self, member_id: str, epoch: int, step: int, msg_in: Optional[bytes]) -> bytes:
        with self._lock:
            if member_id in self.revoked:
                say("authority", f"refused enrolment of revoked '{member_id}' in epoch {epoch}", RED)
                raise AuthorityError("member revoked")
            if epoch != self.epoch:
                raise AuthorityError("enrolment only for the current epoch")
            if not self.scheme.is_manager_step(step):
                raise AuthorityError("not a manager step")
            ep = self.epochs[epoch]
            with self.metrics.timer("join_mgr", step=step):
                out = self.scheme.join_mgr(ep.group, step, msg_in)
            if step == self._final_mgr_step:  # this step appends the GML entry
                ep.members[len(ep.members)] = member_id
                self.metrics.event("enrolled", member=member_id, epoch=epoch)
                say("authority", f"enrolled '{member_id}' in epoch {epoch} (member #{len(ep.members) - 1})")
            return out

    # -- opening (authority tier) and decryption (responder tier) ------------

    def open(self, core_bytes: bytes, requester: str, ticket: str) -> dict:
        core = Core.decode(core_bytes)
        if core is None:
            raise AuthorityError("malformed Core")
        with self._lock:
            ep = self.epochs.get(core.epoch)
            if ep is None:
                raise AuthorityError("unknown epoch")
            if not verify_core(self.scheme, self.scheme.verifying_key(ep.group.grpkey), core):
                raise AuthorityError("invalid group signature")
            with self.metrics.timer("open", scheme=self.scheme.name, members=len(ep.members)):
                index = self.scheme.open(core.group_sig, ep.group)
            member = ep.members.get(index)
            entry = self.audit.append(action="open", requester=requester, ticket=ticket,
                                      session=core.session_id.hex(), epoch=core.epoch)
        say("authority", f"OPEN by {requester} (ticket {ticket}): session {short(core.session_id)} -> "
                         f"'{member}' (audit #{entry['index']})")
        return {"member_id": member, "epoch": core.epoch, "gml_index": index,
                "audit_index": entry["index"]}

    def decrypt_fields(self, c_enc: bytes, requester: str, ticket: str, session: str = "") -> dict:
        plain = seal.unseal(self._responder_sk, c_enc)
        if plain is None:
            raise AuthorityError("cannot decrypt")
        with self._lock:
            entry = self.audit.append(action="decrypt", requester=requester, ticket=ticket, session=session)
        say("authority", f"DECRYPT C_enc for {requester} (session {short(session)}, audit #{entry['index']})")
        return {"fields": decode_fields(plain), "audit_index": entry["index"]}
