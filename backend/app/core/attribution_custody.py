"""共享代理日志保全与租户归属核验域。

背景：共享代理的日志过去只按客户端地址写入，无法区分"这条日志属于哪个
租户"。本域在原始日志入库时按来源（租户）建立归属批次，保全不可篡改的
归属证据与历史，并在调查采样、租户转让等环节强制执行归属核验：

- ``store_events`` 按来源归属保存：有归属证明的原行入租户库存，未取得
  归属证明的原行进隔离区，任何租户都不得领用（采样）。
- ``sample`` 先按调查权限过滤（租户只能读到自己实际有权读取的事件），
  再从候选集合里选代表；越权记录一律不会被领用。
- 调查一旦领取即冻结当时的采样范围快照，已完成调查可凭归属历史复算
  当时的采样范围。
- 租户转让必须交回尚未结案的调查：已结案结果保留旧依据，未结案原行
  只能由原租户继续完成或明确交回，受让方不得重复结案，最终只保留
  一份处理结果。
- 在途归属与转让生效范围冲突时：有证据的原行仍可向来源租户交付，
  未取得归属证明的原行不能给任何租户。
- 并发提交同一归属只入库一次（按 来源租户+原行指纹 幂等）。
- 已证明的行可单独放行，也可随整组进入共同调查（组内未证原行在证明
  补齐前不能被任一租户采样）。

全部实现只依赖标准库，数据保存在内存中，便于随项目直接运行与测试。
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable


# ---------- 枚举与常量 ----------

class CustodyState(str, Enum):
    """原行保全状态。"""

    PROVEN = "已证明"
    """归属证明核验通过，已入来源租户库存，可被该租户采样。"""

    QUARANTINED = "待证隔离"
    """未取得有效归属证明，不能给任何租户，任何采样都不得领用。"""

    JOINT_HOLD = "共同调查留存"
    """有证明但随整组等待共同调查，期间不进入任何租户的单独库存。"""

    REVOKED = "归属撤销"
    """归属证明被证伪或撤销（审计留痕，不允许采样）。"""


class ProofStatus(str, Enum):
    """归属证明核验结论。"""

    VALID = "证明有效"
    MISSING = "无证明"
    TAMPERED = "证明被篡改"
    TENANT_MISMATCH = "证明租户与来源不符"


class TransferState(str, Enum):
    """租户转让单状态。"""

    PENDING = "待生效"
    EFFECTIVE = "已生效"
    ROLLED_BACK = "已撤回"


class InvestigationState(str, Enum):
    """调查生命周期状态。"""

    OPEN = "待领取"
    CLAIMED = "已领取"
    HANDED_BACK = "已交回"
    CLOSED = "已结案"


# store_events 的放行模式
RELEASE_INDIVIDUAL = "单独放行"
RELEASE_JOINT = "共同调查"

# 归属历史事件类型
EVT_RECEIVED = "接收"
EVT_CLAIM = "调查领取"
EVT_PROVEN = "证明核验通过"
EVT_QUARANTINE = "待证隔离"
EVT_JOINT_HOLD = "整组留存"
EVT_JOINT_RELEASE = "共同调查结束放行"
EVT_TRANSFER_OUT = "转让转出"
EVT_TRANSFER_IN = "转让转入"
EVT_HANDBACK = "调查交回"
EVT_CLOSE = "调查结案"
EVT_REVOKE = "归属撤销"


# ---------- 纯函数工具 ----------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def raw_line_fingerprint(client_addr: str, raw_line: str, source_id: str) -> str:
    """原行内容指纹：同一客户端地址下不同原始日志仍是不同原行。"""
    return _sha256(f"{source_id}|{client_addr}|{raw_line}")


def make_proof_signature(tenant_id: str, client_addr: str, raw_line: str,
                         source_id: str, tenant_secret: str) -> str:
    """租户用自己的密钥对"来源+地址+原行"生成归属签名。

    接收方在入库时可独立复算签名进行核验，签名材料不包含任何可变状态，
    因此同一条原行的核验结论是确定、可复算的。
    """
    material = "|".join([tenant_id, source_id, client_addr, raw_line])
    return hashlib.sha256((material + "||" + tenant_secret).encode("utf-8")).hexdigest()


def default_clock() -> datetime:
    return datetime.now()


# ---------- 领域数据模型 ----------

@dataclass
class AttributionProof:
    """接收时可核对的归属证明。"""

    tenant_id: str
    signature: str
    algorithm: str = "sha256-hmac-material"
    issued_at: datetime | None = None
    verified: bool = False
    verify_status: ProofStatus = ProofStatus.MISSING
    verified_at: datetime | None = None

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "verified": self.verified,
            "verify_status": self.verify_status.value,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }


@dataclass
class AttributionEvent:
    """归属历史中的一笔不可变事件（保全留痕）。"""

    seq: int
    at: datetime
    event_type: str
    from_tenant: str | None
    to_tenant: str | None
    detail: str = ""
    transfer_id: str | None = None
    investigation_id: str | None = None

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at.isoformat(),
            "event_type": self.event_type,
            "from_tenant": self.from_tenant,
            "to_tenant": self.to_tenant,
            "detail": self.detail,
            "transfer_id": self.transfer_id,
            "investigation_id": self.investigation_id,
        }


@dataclass
class RawProxyLog:
    """一条按来源租户归属保全的代理原始日志（库存原行）。"""

    row_id: str
    source_tenant: str
    client_addr: str
    raw_line: str
    source_id: str
    received_at: datetime
    fingerprint: str
    intake_batch_id: str
    proof: AttributionProof | None = None
    custody_state: CustodyState = CustodyState.QUARANTINED
    owner_tenant: str | None = None
    group_id: str | None = None
    history: list[AttributionEvent] = field(default_factory=list)
    content_hash: str = ""

    def state_at(self, point: datetime) -> tuple[CustodyState, str | None]:
        """根据归属历史复算某一时刻该原行的（状态, 责任租户）。

        历史事件只追加、不可改，因此任意历史时刻的归属都可复算。
        """
        state = CustodyState.QUARANTINED
        owner: str | None = None
        for evt in self.history:
            if evt.at > point:
                break
            if evt.event_type == EVT_PROVEN:
                state, owner = CustodyState.PROVEN, evt.to_tenant
            elif evt.event_type == EVT_QUARANTINE:
                state, owner = CustodyState.QUARANTINED, None
            elif evt.event_type == EVT_JOINT_HOLD:
                state = CustodyState.JOINT_HOLD
                owner = evt.to_tenant
            elif evt.event_type == EVT_JOINT_RELEASE:
                state, owner = CustodyState.PROVEN, evt.to_tenant
            elif evt.event_type == EVT_TRANSFER_OUT:
                owner = None
            elif evt.event_type == EVT_TRANSFER_IN:
                state, owner = CustodyState.PROVEN, evt.to_tenant
            elif evt.event_type == EVT_REVOKE:
                state, owner = CustodyState.REVOKED, None
        return state, owner

    def readable_by(self, tenant_id: str) -> bool:
        """租户当前是否实际有权读取该原行。"""
        if self.custody_state in (CustodyState.QUARANTINED, CustodyState.REVOKED):
            return False
        if self.custody_state == CustodyState.JOINT_HOLD:
            # 共同调查留存期间不进入任一租户的单独可读库存，
            # 只能通过共同调查组的调查上下文领用。
            return False
        return self.owner_tenant == tenant_id

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "source_tenant": self.source_tenant,
            "client_addr": self.client_addr,
            "raw_line": self.raw_line,
            "source_id": self.source_id,
            "received_at": self.received_at.isoformat(),
            "fingerprint": self.fingerprint,
            "content_hash": self.content_hash,
            "intake_batch_id": self.intake_batch_id,
            "custody_state": self.custody_state.value,
            "owner_tenant": self.owner_tenant,
            "group_id": self.group_id,
            "proof": self.proof.to_snapshot() if self.proof else None,
            "history": [evt.to_snapshot() for evt in self.history],
        }


@dataclass
class ScopeSnapshot:
    """调查领取时冻结的采样范围（已完成调查可据此复算）。"""

    tenant_id: str
    eligible_row_ids: list[str]
    row_states: dict[str, dict[str, Any]]
    transfer_id: str | None
    group_id: str | None
    frozen_at: datetime
    scope_hash: str

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "eligible_row_ids": list(self.eligible_row_ids),
            "row_states": dict(self.row_states),
            "transfer_id": self.transfer_id,
            "group_id": self.group_id,
            "frozen_at": self.frozen_at.isoformat(),
            "scope_hash": self.scope_hash,
        }


@dataclass
class Investigation:
    """调查单：一条原行在同一时刻最多只能被一个租户领取处理。"""

    investigation_id: str
    tenant_id: str
    subject: str
    group_id: str | None
    created_at: datetime
    state: InvestigationState = InvestigationState.OPEN
    claimed_by: str | None = None
    claimed_at: datetime | None = None
    scope: ScopeSnapshot | None = None
    representative_ids: list[str] = field(default_factory=list)
    closed_at: datetime | None = None
    close_result: dict[str, Any] | None = None
    bound_row_id: str | None = None
    handback_history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state in (InvestigationState.OPEN,
                              InvestigationState.CLAIMED,
                              InvestigationState.HANDED_BACK)

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "tenant_id": self.tenant_id,
            "subject": self.subject,
            "group_id": self.group_id,
            "bound_row_id": self.bound_row_id,
            "state": self.state.value,
            "claimed_by": self.claimed_by,
            "claimed_at": self.claimed_at.isoformat() if self.claimed_at else None,
            "scope": self.scope.to_snapshot() if self.scope else None,
            "representative_ids": list(self.representative_ids),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "close_result": dict(self.close_result) if self.close_result else None,
            "handback_history": [dict(item) for item in self.handback_history],
        }


@dataclass
class TransferOrder:
    """租户归属转让单（甲 → 乙）。"""

    transfer_id: str
    from_tenant: str
    to_tenant: str
    opened_at: datetime
    state: TransferState = TransferState.PENDING
    effective_at: datetime | None = None
    transferred_row_ids: list[str] = field(default_factory=list)
    blocked_row_ids: list[str] = field(default_factory=list)
    unproven_row_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "from_tenant": self.from_tenant,
            "to_tenant": self.to_tenant,
            "opened_at": self.opened_at.isoformat(),
            "state": self.state.value,
            "effective_at": self.effective_at.isoformat() if self.effective_at else None,
            "transferred_row_ids": list(self.transferred_row_ids),
            "blocked_row_ids": list(self.blocked_row_ids),
            "unproven_row_ids": list(self.unproven_row_ids),
            "notes": list(self.notes),
        }


@dataclass
class JointGroup:
    """共同调查组：整组等待共同调查，组内未证原行证明补齐前不得采样。"""

    group_id: str
    created_at: datetime
    row_ids: list[str] = field(default_factory=list)
    released: bool = False
    released_at: datetime | None = None

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "created_at": self.created_at.isoformat(),
            "row_ids": list(self.row_ids),
            "released": self.released,
            "released_at": self.released_at.isoformat() if self.released_at else None,
        }


@dataclass
class StoredItem:
    """store_events 单条入库结果。"""

    row: RawProxyLog | None
    duplicated: bool
    proof_status: ProofStatus
    detail: str


# ---------- 主领域服务 ----------

class AttributionCustodyService:
    """代理日志保全、归属核验、调查采样与租户转让的统一服务。

    所有写操作都在同一把锁内串行化，保证并发提交同一归属只入库一次。
    """

    def __init__(self, tenant_secrets: dict[str, str] | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.tenant_secrets: dict[str, str] = dict(tenant_secrets or {})
        self.clock = clock or default_clock
        self._lock = threading.RLock()
        self._rows: dict[str, RawProxyLog] = {}
        self._idempotency: set[tuple[str, str]] = set()
        self._transfers: dict[str, TransferOrder] = {}
        self._investigations: dict[str, Investigation] = {}
        self._groups: dict[str, JointGroup] = {}
        self._row_seq = 0
        self._transfer_seq = 0
        self._invest_seq = 0
        self._group_seq = 0
        self._event_seq = 0

    # ===== 基础工具 =====

    def _next_event_seq(self) -> int:
        self._event_seq += 1
        return self._event_seq

    def _append_history(self, row: RawProxyLog, event_type: str,
                        from_tenant: str | None, to_tenant: str | None,
                        detail: str = "", transfer_id: str | None = None,
                        investigation_id: str | None = None) -> AttributionEvent:
        evt = AttributionEvent(
            seq=self._next_event_seq(), at=self.clock(), event_type=event_type,
            from_tenant=from_tenant, to_tenant=to_tenant, detail=detail,
            transfer_id=transfer_id, investigation_id=investigation_id,
        )
        row.history.append(evt)
        return evt

    def register_tenant(self, tenant_id: str, secret: str) -> None:
        """登记租户密钥（归属签名的核验依据）。"""
        with self._lock:
            self.tenant_secrets[tenant_id] = secret

    def _verify_proof(self, tenant_id: str, client_addr: str, raw_line: str,
                      source_id: str, proof: AttributionProof | None) -> None:
        """就地核验归属证明，写入核验结论。"""
        now = self.clock()
        if proof is None:
            return
        proof.verified_at = now
        if proof.tenant_id != tenant_id:
            proof.verified = False
            proof.verify_status = ProofStatus.TENANT_MISMATCH
            return
        secret = self.tenant_secrets.get(tenant_id)
        if secret is None:
            proof.verified = False
            proof.verify_status = ProofStatus.MISSING
            return
        expected = make_proof_signature(tenant_id, client_addr, raw_line,
                                        source_id, secret)
        if expected != proof.signature:
            proof.verified = False
            proof.verify_status = ProofStatus.TAMPERED
            return
        proof.verified = True
        proof.verify_status = ProofStatus.VALID

    # ===== 1. store_events：按来源归属保存（含并发幂等） =====

    def store_events(self, tenant_id: str, client_addr: str,
                     raw_lines: list[str], *, source_id: str = "proxy-shared-01",
                     intake_batch_id: str | None = None,
                     proofs: dict[int, AttributionProof] | None = None,
                     release_mode: str = RELEASE_INDIVIDUAL,
                     group_id: str | None = None,
                     client_addrs: list[str] | None = None) -> list[StoredItem]:
        """按来源租户把代理原始日志写入归属库存。

        - ``client_addr`` 为批次默认客户端地址；同一批次含多个地址时，可通过
          ``client_addrs`` 逐行指定（归属签名与原行指纹都按该行实际地址计算）。
        - 有有效归属证明：单独放行时直接入租户库存；共同调查模式下整组
          留存，等待共同调查。
        - 无证明/证明失效：进待证隔离区，不归属任何租户，不得被采样。
        - 同一来源租户重复提交同一原行（同指纹）只入库一次，后续提交
          作为重复项返回，保证并发幂等。
        """
        if release_mode not in (RELEASE_INDIVIDUAL, RELEASE_JOINT):
            raise ValueError(f"未知放行模式：{release_mode}")
        if client_addrs is not None and len(client_addrs) != len(raw_lines):
            raise ValueError("client_addrs 与 raw_lines 数量必须一致")
        proofs = proofs or {}
        results: list[StoredItem] = []
        with self._lock:
            batch_id = intake_batch_id or f"BATCH-{tenant_id}-{self.clock().strftime('%Y%m%d%H%M%S%f')}"
            joint_group: JointGroup | None = None
            if release_mode == RELEASE_JOINT:
                joint_group = self._groups.get(group_id or "")
                if joint_group is None:
                    self._group_seq += 1
                    gid = group_id or f"GROUP-{self._group_seq:04d}"
                    joint_group = JointGroup(group_id=gid, created_at=self.clock())
                    self._groups[gid] = joint_group

            for index, line in enumerate(raw_lines):
                line = line.strip()
                line_addr = client_addrs[index] if client_addrs is not None else client_addr
                fp = raw_line_fingerprint(line_addr, line, source_id)
                idem_key = (tenant_id, fp)
                if idem_key in self._idempotency:
                    existing = next(
                        (row for row in self._rows.values()
                         if row.source_tenant == tenant_id and row.fingerprint == fp),
                        None,
                    )
                    results.append(StoredItem(
                        row=existing, duplicated=True,
                        proof_status=existing.proof.verify_status if existing and existing.proof
                        else ProofStatus.MISSING,
                        detail="同一来源租户已提交过该原行，幂等跳过、未重复入库",
                    ))
                    continue

                proof = proofs.get(index)
                self._verify_proof(tenant_id, line_addr, line, source_id, proof)
                self._row_seq += 1
                row_id = f"ROW-{self._row_seq:05d}"
                now = self.clock()
                row = RawProxyLog(
                    row_id=row_id, source_tenant=tenant_id, client_addr=line_addr,
                    raw_line=line, source_id=source_id, received_at=now, fingerprint=fp,
                    intake_batch_id=batch_id, proof=proof,
                    content_hash=_sha256(f"{fp}|{line}"),
                )
                self._append_history(
                    row, EVT_RECEIVED, None, tenant_id,
                    detail=f"按来源 {tenant_id} 接收入库，批次 {batch_id}")

                proof_ok = bool(proof and proof.verified)
                if not proof_ok:
                    reason = proof.verify_status.value if proof else ProofStatus.MISSING.value
                    row.custody_state = CustodyState.QUARANTINED
                    row.owner_tenant = None
                    # 共同调查批次内的缺证原行也标记组号，便于核对报告追踪，
                    # 但不加入组的可放行清单，证明补齐前任何租户都采不到。
                    if release_mode == RELEASE_JOINT:
                        row.group_id = joint_group.group_id
                    self._append_history(
                        row, EVT_QUARANTINE, tenant_id, None,
                        detail=f"归属证明核验结论：{reason}，原行隔离、不向任何租户交付")
                    results.append(StoredItem(row=row, duplicated=False,
                                              proof_status=proof.verify_status if proof
                                              else ProofStatus.MISSING,
                                              detail="待证隔离：未取得有效归属证明"))
                elif release_mode == RELEASE_JOINT:
                    row.custody_state = CustodyState.JOINT_HOLD
                    row.owner_tenant = tenant_id
                    row.group_id = joint_group.group_id
                    joint_group.row_ids.append(row_id)
                    self._append_history(
                        row, EVT_JOINT_HOLD, None, tenant_id,
                        detail=f"证明有效，随组 {joint_group.group_id} 等待共同调查")
                    results.append(StoredItem(row=row, duplicated=False,
                                              proof_status=ProofStatus.VALID,
                                              detail="共同调查留存：已证明但整组等待"))
                else:
                    row.custody_state = CustodyState.PROVEN
                    row.owner_tenant = tenant_id
                    self._append_history(
                        row, EVT_PROVEN, None, tenant_id,
                        detail="归属证明核验通过，原行交付来源租户库存")
                    results.append(StoredItem(row=row, duplicated=False,
                                              proof_status=ProofStatus.VALID,
                                              detail="已证明：单独放行入租户库存"))

                self._rows[row_id] = row
                self._idempotency.add(idem_key)
            return results

    def release_joint_group(self, group_id: str) -> list[RawProxyLog]:
        """共同调查结束：组内已证明原行放行回租户库存；未证原行继续隔离。"""
        with self._lock:
            group = self._groups.get(group_id)
            if group is None:
                raise KeyError(f"共同调查组不存在：{group_id}")
            if group.released:
                return [self._rows[rid] for rid in group.row_ids if rid in self._rows]
            released: list[RawProxyLog] = []
            for rid in group.row_ids:
                row = self._rows[rid]
                if row.custody_state == CustodyState.JOINT_HOLD and row.proof and row.proof.verified:
                    row.custody_state = CustodyState.PROVEN
                    self._append_history(
                        row, EVT_JOINT_RELEASE, None, row.owner_tenant,
                        detail=f"组 {group_id} 共同调查结束，已证明原行放行")
                    released.append(row)
                # 组内未证原行不在 group.row_ids 的放行范围：它们入库时即隔离，
                # 仅在证明补齐后才能交付（见 attach_proof）。
            group.released = True
            group.released_at = self.clock()
            return released

    def attach_proof(self, row_id: str, proof: AttributionProof) -> RawProxyLog:
        """为隔离原行补交汇归属证明；核验通过才允许交付给来源租户。"""
        with self._lock:
            row = self._rows.get(row_id)
            if row is None:
                raise KeyError(f"原行不存在：{row_id}")
            self._verify_proof(row.source_tenant, row.client_addr, row.raw_line,
                               row.source_id, proof)
            row.proof = proof
            if not proof.verified:
                self._append_history(
                    row, EVT_QUARANTINE, row.source_tenant, None,
                    detail=f"补交证明仍未通过：{proof.verify_status.value}，继续隔离")
                return row
            if row.group_id and not self._groups[row.group_id].released:
                row.custody_state = CustodyState.JOINT_HOLD
                row.owner_tenant = row.source_tenant
                self._groups[row.group_id].row_ids.append(row_id)
                self._append_history(
                    row, EVT_JOINT_HOLD, None, row.source_tenant,
                    detail=f"补交证明通过，随组 {row.group_id} 共同调查留存")
            else:
                row.custody_state = CustodyState.PROVEN
                row.owner_tenant = row.source_tenant
                self._append_history(
                    row, EVT_PROVEN, None, row.source_tenant,
                    detail="补交归属证明核验通过，原行交付来源租户库存")
            return row

    # ===== 2. 库存与权限过滤 =====

    def inventory(self, tenant_id: str) -> list[RawProxyLog]:
        """租户库存：仅包含该租户实际有权读取的原行。"""
        with self._lock:
            return [row for row in self._rows.values() if row.readable_by(tenant_id)]

    def quarantined_rows(self) -> list[RawProxyLog]:
        """待证隔离区：未取得归属证明、任何租户都不可领用的原行。"""
        with self._lock:
            return [row for row in self._rows.values()
                    if row.custody_state == CustodyState.QUARANTINED]

    def permitted_rows(self, tenant_id: str, *, group_id: str | None = None) -> list[RawProxyLog]:
        """调查权限过滤：返回租户在该调查上下文里实际有权读取的原行。

        越权记录（其他租户库存、待证隔离、归属撤销、非本组共同留存）
        一律被过滤掉，后续采样只能在本函数的返回集合内进行。
        """
        with self._lock:
            eligible: list[RawProxyLog] = []
            for row in self._rows.values():
                if group_id is not None:
                    if row.group_id != group_id:
                        continue
                    group = self._groups[group_id]
                    if group.released:
                        # 组已放行后回到普通库存权限判断
                        if row.readable_by(tenant_id):
                            eligible.append(row)
                        continue
                    # 组未放行：仅组内已证明原行可在共同调查上下文领用，
                    # 且领用方必须是该原行的来源/责任租户；未证原行（隔离态）
                    # 与其他租户的原行一律不可领用。
                    if (row.custody_state == CustodyState.JOINT_HOLD
                            and row.proof and row.proof.verified
                            and tenant_id in (row.owner_tenant, row.source_tenant)):
                        eligible.append(row)
                    continue
                if row.readable_by(tenant_id):
                    eligible.append(row)
            return eligible

    # ===== 3. sample：权限过滤后选代表 =====

    def sample(self, tenant_id: str, *, max_representatives: int = 5,
               group_id: str | None = None) -> list[RawProxyLog]:
        """按调查权限过滤后，从租户实际有权读取的事件中选代表。

        选样规则确定性、可复算：先按 row_id 排序，再按客户端地址归并，
        每个地址取该地址最早的一条原行作为代表。
        """
        with self._lock:
            eligible = self.permitted_rows(tenant_id, group_id=group_id)
            eligible.sort(key=lambda row: row.row_id)
            chosen: list[RawProxyLog] = []
            seen_addr: set[str] = set()
            for row in eligible:
                if row.client_addr in seen_addr:
                    continue
                seen_addr.add(row.client_addr)
                chosen.append(row)
                if len(chosen) >= max_representatives:
                    break
            return chosen

    def _freeze_scope(self, tenant_id: str, group_id: str | None,
                      transfer_id: str | None) -> ScopeSnapshot:
        eligible = self.permitted_rows(tenant_id, group_id=group_id)
        eligible.sort(key=lambda row: row.row_id)
        row_states = {
            row.row_id: {
                "custody_state": row.custody_state.value,
                "owner_tenant": row.owner_tenant,
                "content_hash": row.content_hash,
                "history_tail": row.history[-1].to_snapshot() if row.history else None,
            }
            for row in eligible
        }
        frozen_at = self.clock()
        scope_hash = _sha256(
            tenant_id + "|" + (group_id or "") + "|" + (transfer_id or "")
            + "|" + ",".join(row.row_id for row in eligible)
            + "|" + ",".join(row.content_hash for row in eligible)
        )
        return ScopeSnapshot(
            tenant_id=tenant_id,
            eligible_row_ids=[row.row_id for row in eligible],
            row_states=row_states, transfer_id=transfer_id, group_id=group_id,
            frozen_at=frozen_at, scope_hash=scope_hash,
        )

    def recompute_sampling_scope(self, snapshot: ScopeSnapshot) -> dict[str, Any]:
        """复算某历史时刻的调查采样范围，与冻结快照逐行核对。

        依据各原行只追加的归属历史还原 ``frozen_at`` 时刻的状态与责任
        租户，再套用同一套调查权限过滤规则。
        """
        point = snapshot.frozen_at
        recomputed_ids: list[str] = []
        mismatches: list[dict[str, Any]] = []
        with self._lock:
            for row in self._rows.values():
                state, owner = row.state_at(point)
                permitted = False
                if snapshot.group_id is not None:
                    if row.group_id == snapshot.group_id:
                        group = self._groups.get(snapshot.group_id)
                        group_open = bool(group and not group.released
                                          and group.created_at <= point)
                        if group_open:
                            permitted = (state == CustodyState.JOINT_HOLD
                                         and bool(row.proof and row.proof.verified)
                                         and snapshot.tenant_id in (
                                             row.owner_tenant, row.source_tenant))
                        else:
                            permitted = (state == CustodyState.PROVEN
                                         and owner == snapshot.tenant_id)
                else:
                    permitted = (state == CustodyState.PROVEN
                                 and owner == snapshot.tenant_id)
                if permitted:
                    recomputed_ids.append(row.row_id)
            recomputed_ids.sort()
            frozen_ids = sorted(snapshot.eligible_row_ids)
            if recomputed_ids != frozen_ids:
                mismatches.append({
                    "type": "eligible_set_diff",
                    "missing_in_recompute": sorted(set(frozen_ids) - set(recomputed_ids)),
                    "extra_in_recompute": sorted(set(recomputed_ids) - set(frozen_ids)),
                })
            for rid in frozen_ids:
                row = self._rows.get(rid)
                if row is None:
                    mismatches.append({"type": "row_missing", "row_id": rid})
                    continue
                state, owner = row.state_at(point)
                frozen_state = snapshot.row_states.get(rid, {})
                if frozen_state.get("custody_state") != state.value:
                    mismatches.append({
                        "type": "state_diff", "row_id": rid,
                        "frozen": frozen_state.get("custody_state"),
                        "recomputed": state.value,
                    })
                if frozen_state.get("owner_tenant") != owner:
                    mismatches.append({
                        "type": "owner_diff", "row_id": rid,
                        "frozen": frozen_state.get("owner_tenant"),
                        "recomputed": owner,
                    })
            return {
                "tenant_id": snapshot.tenant_id,
                "frozen_at": point.isoformat(),
                "frozen_row_ids": frozen_ids,
                "recomputed_row_ids": recomputed_ids,
                "scope_hash": snapshot.scope_hash,
                "consistent": not mismatches,
                "mismatches": mismatches,
            }

    # ===== 4. 调查生命周期与交回 =====

    def create_investigation(self, tenant_id: str, subject: str, *,
                             group_id: str | None = None,
                             bound_row_id: str | None = None) -> Investigation:
        """创建调查单（待领取）。可绑定一条具体原行用于转让交回场景。"""
        with self._lock:
            if bound_row_id is not None and bound_row_id not in self._rows:
                raise KeyError(f"绑定原行不存在：{bound_row_id}")
            self._invest_seq += 1
            inv = Investigation(
                investigation_id=f"INV-{self._invest_seq:05d}",
                tenant_id=tenant_id, subject=subject, group_id=group_id,
                created_at=self.clock(), bound_row_id=bound_row_id,
            )
            self._investigations[inv.investigation_id] = inv
            return inv

    def _claimed_investigation_for_row(self, row_id: str) -> Investigation | None:
        """该原行当前是否被某租户持有（已领取未结案）——这才是可执行清单。"""
        for inv in self._investigations.values():
            if (inv.bound_row_id == row_id
                    and inv.state == InvestigationState.CLAIMED):
                return inv
        return None

    def _open_investigation_for_row(self, row_id: str) -> Investigation | None:
        """该原行是否存在尚未结案的调查（含待领取/已交回，排除已结案）。"""
        for inv in self._investigations.values():
            if inv.bound_row_id == row_id and inv.is_open:
                return inv
        return None

    def claim_investigation(self, investigation_id: str, tenant_id: str, *,
                            max_representatives: int = 5) -> Investigation:
        """领取调查：核对调查权限后冻结采样范围并选出实际代表。

        转让冲突核验：若绑定原行仍处于"甲已领取、乙未满足接收条件"的
        状态，乙的领取会被拒绝，保证一条原行不会两边都能结案。
        """
        with self._lock:
            inv = self._investigations.get(investigation_id)
            if inv is None:
                raise KeyError(f"调查不存在：{investigation_id}")
            if inv.state == InvestigationState.CLOSED:
                raise PermissionError(f"调查 {investigation_id} 已结案，不得重复处理")
            if inv.state == InvestigationState.CLAIMED and inv.claimed_by != tenant_id:
                raise PermissionError(
                    f"调查已被 {inv.claimed_by} 领取且未交回，{tenant_id} 不得重复领取")

            if inv.bound_row_id:
                row = self._rows[inv.bound_row_id]
                active = self._claimed_investigation_for_row(row.row_id)
                if active is not None and active.investigation_id != inv.investigation_id:
                    raise PermissionError(
                        f"原行 {row.row_id} 存在已领取未结案调查 {active.investigation_id}，"
                        "须由当前责任租户完成或明确交回后才能再次领取")
                # 接收前核对：受让租户只能在原行已转入自己名下后领取。
                if not row.readable_by(tenant_id) and not (
                        inv.group_id and row.group_id == inv.group_id):
                    raise PermissionError(
                        f"{tenant_id} 对原行 {row.row_id} 尚无读取权限："
                        "在途转让未生效或原行仍由原租户负责，拒绝领用")

            # 权限过滤 → 冻结采样范围 → 选代表；越权记录不会进入候选集。
            scope = self._freeze_scope(tenant_id, inv.group_id,
                                       transfer_id=self._active_transfer_id(tenant_id))
            representatives = self.sample(
                tenant_id, max_representatives=max_representatives,
                group_id=inv.group_id)
            inv.state = InvestigationState.CLAIMED
            inv.claimed_by = tenant_id
            inv.claimed_at = self.clock()
            inv.scope = scope
            inv.representative_ids = [row.row_id for row in representatives]
            if inv.bound_row_id:
                self._append_history(
                    self._rows[inv.bound_row_id], EVT_CLAIM, None, tenant_id,
                    detail=f"调查 {investigation_id} 由 {tenant_id} 领取，采样范围已冻结",
                    investigation_id=investigation_id)
            return inv

    def _active_transfer_id(self, tenant_id: str) -> str | None:
        for order in self._transfers.values():
            if order.state == TransferState.PENDING and tenant_id in (
                    order.from_tenant, order.to_tenant):
                return order.transfer_id
        return None

    def handback_investigation(self, investigation_id: str, tenant_id: str,
                               note: str = "") -> Investigation:
        """明确交回未结案调查：交回后其他租户才可领取同一原行。"""
        with self._lock:
            inv = self._investigations.get(investigation_id)
            if inv is None:
                raise KeyError(f"调查不存在：{investigation_id}")
            if inv.state != InvestigationState.CLAIMED:
                raise PermissionError("只有已领取且未结案的调查可以交回")
            if inv.claimed_by != tenant_id:
                raise PermissionError("只有当前领取人可以交回调查")
            inv.state = InvestigationState.HANDED_BACK
            inv.handback_history.append({
                "at": self.clock().isoformat(), "by": tenant_id, "note": note,
            })
            if inv.bound_row_id:
                self._append_history(
                    self._rows[inv.bound_row_id], EVT_HANDBACK, tenant_id, None,
                    detail=f"调查 {investigation_id} 由 {tenant_id} 明确交回：{note}",
                    investigation_id=investigation_id)
            return inv

    def close_investigation(self, investigation_id: str, tenant_id: str,
                            conclusion: str) -> Investigation:
        """结案：保留结案时的旧依据（冻结快照+代表+结论），只产生一份结果。"""
        with self._lock:
            inv = self._investigations.get(investigation_id)
            if inv is None:
                raise KeyError(f"调查不存在：{investigation_id}")
            if inv.state == InvestigationState.CLOSED:
                raise PermissionError("调查已结案，不得两边重复结案")
            if inv.state != InvestigationState.CLAIMED or inv.claimed_by != tenant_id:
                raise PermissionError("只有当前领取人可以结案")
            inv.state = InvestigationState.CLOSED
            inv.closed_at = self.clock()
            inv.close_result = {
                "by": tenant_id,
                "at": inv.closed_at.isoformat(),
                "conclusion": conclusion,
                "basis_scope_hash": inv.scope.scope_hash if inv.scope else None,
                "basis_row_ids": list(inv.representative_ids),
            }
            if inv.bound_row_id:
                self._append_history(
                    self._rows[inv.bound_row_id], EVT_CLOSE, tenant_id, tenant_id,
                    detail=f"调查结案，结论：{conclusion}；旧依据快照保留",
                    investigation_id=investigation_id)
            return inv

    # ===== 5. 租户转让：未结案调查必须交回 =====

    def open_transfer(self, from_tenant: str, to_tenant: str) -> TransferOrder:
        """发起租户转让（在途）。生效前双方职责报告均标记"转移中"。"""
        with self._lock:
            self._transfer_seq += 1
            order = TransferOrder(
                transfer_id=f"TRF-{self._transfer_seq:05d}",
                from_tenant=from_tenant, to_tenant=to_tenant,
                opened_at=self.clock(),
            )
            blockers = [
                row.row_id for row in self._rows.values()
                if row.owner_tenant == from_tenant
                and self._claimed_investigation_for_row(row.row_id) is not None
            ]
            if blockers:
                order.notes.append(
                    f"发起时发现 {len(blockers)} 条原行存在未结案调查，"
                    "生效前须由原租户结案或明确交回")
            self._transfers[order.transfer_id] = order
            return order

    def _executable_list(self, tenant_id: str) -> list[str]:
        """租户当前仍可执行（已领取、未结案调查绑定）的原行清单。

        已交回（HANDED_BACK）和待领取（OPEN）的调查不再由当前租户持有，
        不阻断转让生效；只有自己实际领取且未结案的原行才算可执行清单。
        """
        return [
            row.row_id for row in self._rows.values()
            if row.owner_tenant == tenant_id
            and self._claimed_investigation_for_row(row.row_id) is not None
        ]

    def effect_transfer(self, transfer_id: str) -> TransferOrder:
        """转让生效：再次核对甲是否仍有可执行清单，并处理在途冲突。

        - 甲仍持有未结案调查的原行：阻断，留在甲名下，乙不能领取。
        - 已证明且无未结案调查的原行：转给乙，双方各写一笔归属历史。
        - 待证隔离原行：不向任何租户交付，仅记录在案。
        """
        with self._lock:
            order = self._transfers.get(transfer_id)
            if order is None:
                raise KeyError(f"转让单不存在：{transfer_id}")
            if order.state != TransferState.PENDING:
                raise PermissionError(f"转让单 {transfer_id} 状态为 {order.state.value}，不可生效")

            blocked = self._executable_list(order.from_tenant)
            order.blocked_row_ids = sorted(blocked)
            if blocked:
                order.notes.append(
                    f"生效核对：{order.from_tenant} 仍有可执行清单 {blocked}，"
                    "相关原行阻断转让，须先结案或交回")
                # 阻断不改变任何归属，调用方处理完未结案调查后可再次调用。
                return order

            for row in self._rows.values():
                if row.source_tenant != order.from_tenant and row.owner_tenant != order.from_tenant:
                    continue
                if row.owner_tenant != order.from_tenant:
                    # 隔离/撤销等无责任租户的原行不能借转让交付给任何人。
                    if row.custody_state == CustodyState.QUARANTINED:
                        order.unproven_row_ids.append(row.row_id)
                        order.notes.append(
                            f"原行 {row.row_id} 未取得归属证明，转让生效范围不覆盖，继续隔离")
                    continue
                if row.custody_state == CustodyState.JOINT_HOLD:
                    order.blocked_row_ids.append(row.row_id)
                    order.notes.append(f"原行 {row.row_id} 处于共同调查留存，暂不转让")
                    continue
                # 有证据的原行：即使是转让在途期间接收的，也随生效范围转给乙。
                self._append_history(
                    row, EVT_TRANSFER_OUT, order.from_tenant, None,
                    detail=f"转让 {transfer_id} 生效，转出责任", transfer_id=transfer_id)
                row.owner_tenant = order.to_tenant
                self._append_history(
                    row, EVT_TRANSFER_IN, None, order.to_tenant,
                    detail=f"转让 {transfer_id} 生效，转入 {order.to_tenant} 库存",
                    transfer_id=transfer_id)
                order.transferred_row_ids.append(row.row_id)

            order.state = TransferState.EFFECTIVE
            order.effective_at = self.clock()
            return order

    # ===== 6. 核对报告（保全与归属核验） =====

    def reconciliation_report(self, tenants: list[str]) -> dict[str, Any]:
        """输出分类入库与实际选样核对报告。

        内容：租户库存实际日志、每侧实际代表、共同调查未证原行、
        历史归属、转让单、调查单、隔离区。
        """
        with self._lock:
            per_tenant: dict[str, dict[str, Any]] = {}
            for tenant_id in tenants:
                inventory_rows = self.inventory(tenant_id)
                representatives = self.sample(tenant_id)
                per_tenant[tenant_id] = {
                    "inventory_row_ids": [row.row_id for row in inventory_rows],
                    "inventory_count": len(inventory_rows),
                    "representative_row_ids": [row.row_id for row in representatives],
                    "representative_count": len(representatives),
                    "open_investigation_rows": self._executable_list(tenant_id),
                }
            joint_unproven: list[dict[str, Any]] = []
            for group in self._groups.values():
                unproven = [
                    row.row_id for rid in group.row_ids
                    if (row := self._rows.get(rid)) is not None
                    and row.custody_state == CustodyState.QUARANTINED
                ]
                # 组内未证原行不在 group.row_ids 中（入库即隔离），
                # 这里额外按 group_id 标记兜底扫描。
                for row in self._rows.values():
                    if (row.group_id == group.group_id
                            and row.custody_state == CustodyState.QUARANTINED
                            and row.row_id not in unproven):
                        unproven.append(row.row_id)
                joint_unproven.append({
                    "group_id": group.group_id,
                    "released": group.released,
                    "unproven_row_ids": sorted(unproven),
                })
            return {
                "generated_at": self.clock().isoformat(),
                "tenants": per_tenant,
                "quarantine_row_ids": [row.row_id for row in self.quarantined_rows()],
                "joint_groups": [group.to_snapshot() for group in self._groups.values()],
                "joint_unproven": joint_unproven,
                "transfers": [order.to_snapshot() for order in self._transfers.values()],
                "investigations": [inv.to_snapshot() for inv in self._investigations.values()],
                "all_rows": [row.to_snapshot() for row in self._rows.values()],
            }

    # ===== 查询辅助 =====

    def get_row(self, row_id: str) -> RawProxyLog:
        with self._lock:
            row = self._rows.get(row_id)
            if row is None:
                raise KeyError(f"原行不存在：{row_id}")
            return row

    def get_investigation(self, investigation_id: str) -> Investigation:
        with self._lock:
            inv = self._investigations.get(investigation_id)
            if inv is None:
                raise KeyError(f"调查不存在：{investigation_id}")
            return inv

    def get_transfer(self, transfer_id: str) -> TransferOrder:
        with self._lock:
            order = self._transfers.get(transfer_id)
            if order is None:
                raise KeyError(f"转让单不存在：{transfer_id}")
            return order

    def all_rows(self) -> list[RawProxyLog]:
        with self._lock:
            return list(self._rows.values())
