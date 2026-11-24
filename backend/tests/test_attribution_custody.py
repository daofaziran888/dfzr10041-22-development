"""测试：共享代理日志保全与租户归属核验。

覆盖题面规则：
1. store_events 按来源归属保存：有证入库存、无证进隔离、任何租户不得领用；
2. 并发提交同一归属（同来源+同原行指纹）只入库一次；
3. sample 先按调查权限过滤再选代表，越权记录一律不被领用；
4. 调查领取冻结采样范围，已完成调查可复算当时采样范围；
5. 租户转让须交回未结案调查：已结案保留旧依据，未结案只能由甲完成
   或明确交回后乙才能处理，不得两边都能结案，最终只保留一份处理结果；
6. 在途归属与转让生效范围冲突：有证行仍可向甲交付，未证行不给任何租户；
7. 已证明行可单独放行，也可随整组共同调查；缺证原行不能被任一租户采样；
8. 甲乙各送相同地址原始日志的完整场景核对（库存、代表、共同调查、历史）。
"""
from __future__ import annotations

import os
import sys
import threading
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.attribution_custody import (
    RELEASE_INDIVIDUAL, RELEASE_JOINT,
    AttributionCustodyService, AttributionProof,
    CustodyState, InvestigationState, ProofStatus, TransferState,
    make_proof_signature, raw_line_fingerprint,
)


# ---------- 测试夹具 ----------

TENANT_A = "tenant-jia"
TENANT_B = "tenant-yi"
SECRET_A = "secret-jia-2026"
SECRET_B = "secret-yi-2026"
SHARED_ADDR = "10.20.30.40"
SOURCE = "proxy-shared-01"


class StepClock:
    """确定性时钟：每取一次时间前进一秒，保证快照/历史可复算。"""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 24, 9, 0, 0)

    def __call__(self) -> datetime:
        current = self.now
        self.now += timedelta(seconds=1)
        return current


def make_service() -> AttributionCustodyService:
    svc = AttributionCustodyService(clock=StepClock())
    svc.register_tenant(TENANT_A, SECRET_A)
    svc.register_tenant(TENANT_B, SECRET_B)
    return svc


def proof_for(svc: AttributionCustodyService, tenant: str, addr: str,
              line: str) -> AttributionProof:
    secret = svc.tenant_secrets[tenant]
    return AttributionProof(
        tenant_id=tenant,
        signature=make_proof_signature(tenant, addr, line, SOURCE, secret),
        issued_at=svc.clock(),
    )


def tampered_proof(tenant: str) -> AttributionProof:
    return AttributionProof(tenant_id=tenant, signature="0" * 64)


# ---------- 1. 按来源归属保存与证明核验 ----------

class TestStoreByAttribution:
    """store_events 按来源归属保存。"""

    def test_proven_row_enters_source_tenant_inventory(self):
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:10:00:01] "GET /a HTTP/1.1" 200 12'
        items = svc.store_events(
            TENANT_A, SHARED_ADDR, [line], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line)})
        assert len(items) == 1
        row = items[0].row
        assert items[0].proof_status == ProofStatus.VALID
        assert row.custody_state == CustodyState.PROVEN
        assert row.owner_tenant == TENANT_A
        # 保全：内容哈希与归属历史均已落地
        assert row.content_hash
        assert [evt.event_type for evt in row.history] == ["接收", "证明核验通过"]
        assert [r.row_id for r in svc.inventory(TENANT_A)] == [row.row_id]

    def test_unproven_row_quarantined_and_unreadable(self):
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:10:00:02] "GET /b HTTP/1.1" 200 34'
        items = svc.store_events(TENANT_A, SHARED_ADDR, [line], source_id=SOURCE)
        row = items[0].row
        assert items[0].proof_status == ProofStatus.MISSING
        assert row.custody_state == CustodyState.QUARANTINED
        assert row.owner_tenant is None
        # 任何租户都读不到、采不到
        assert svc.inventory(TENANT_A) == []
        assert svc.inventory(TENANT_B) == []
        assert svc.sample(TENANT_A) == []
        assert svc.sample(TENANT_B) == []
        assert [r.row_id for r in svc.quarantined_rows()] == [row.row_id]

    def test_tampered_and_mismatched_proof_rejected(self):
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:10:00:03] "GET /c HTTP/1.1" 200 56'
        # 篡改签名
        items = svc.store_events(
            TENANT_A, SHARED_ADDR, [line], source_id=SOURCE,
            proofs={0: tampered_proof(TENANT_A)})
        assert items[0].proof_status == ProofStatus.TAMPERED
        assert items[0].row.custody_state == CustodyState.QUARANTINED
        # 证明租户与来源不符
        wrong = AttributionProof(
            tenant_id=TENANT_B,
            signature=make_proof_signature(TENANT_B, SHARED_ADDR, line, SOURCE, SECRET_B))
        items2 = svc.store_events(
            TENANT_A, SHARED_ADDR, [line + " x"], source_id=SOURCE, proofs={0: wrong})
        assert items2[0].proof_status == ProofStatus.TENANT_MISMATCH
        assert items2[0].row.custody_state == CustodyState.QUARANTINED

    def test_same_address_different_tenants_are_separate_rows(self):
        """甲乙各送一条相同地址的原始日志，按来源分成两条独立归属原行。"""
        svc = make_service()
        line_a = f'{SHARED_ADDR} - - [24/Nov/2026:10:01:00] "GET /jia HTTP/1.1" 200 1'
        line_b = f'{SHARED_ADDR} - - [24/Nov/2026:10:01:00] "GET /yi HTTP/1.1" 200 2'
        res_a = svc.store_events(
            TENANT_A, SHARED_ADDR, [line_a], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line_a)})
        res_b = svc.store_events(
            TENANT_B, SHARED_ADDR, [line_b], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_B, SHARED_ADDR, line_b)})
        row_a, row_b = res_a[0].row, res_b[0].row
        assert row_a.row_id != row_b.row_id
        assert row_a.owner_tenant == TENANT_A and row_b.owner_tenant == TENANT_B
        assert svc.get_row(row_a.row_id).readable_by(TENANT_B) is False
        assert svc.get_row(row_b.row_id).readable_by(TENANT_A) is False

    def test_concurrent_same_attribution_stored_once(self):
        """并发提交同一归属（同来源+同原行指纹）只入库一次。"""
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:10:02:00] "GET /once HTTP/1.1" 200 7'
        outcomes: list = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            items = svc.store_events(
                TENANT_A, SHARED_ADDR, [line], source_id=SOURCE,
                proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line)})
            outcomes.append(items[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stored = [item for item in outcomes if not item.duplicated]
        duplicates = [item for item in outcomes if item.duplicated]
        assert len(stored) == 1
        assert len(duplicates) == 7
        assert len(svc.all_rows()) == 1
        # 重复提交拿到的是同一条原行
        assert all(item.row.row_id == stored[0].row.row_id for item in duplicates)

    def test_sequential_duplicate_submission_is_idempotent(self):
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:10:03:00] "GET /dup HTTP/1.1" 200 9'
        proof = proof_for(svc, TENANT_A, SHARED_ADDR, line)
        first = svc.store_events(TENANT_A, SHARED_ADDR, [line],
                                 source_id=SOURCE, proofs={0: proof})
        second = svc.store_events(TENANT_A, SHARED_ADDR, [line],
                                  source_id=SOURCE, proofs={0: proof})
        assert first[0].duplicated is False
        assert second[0].duplicated is True
        assert second[0].row.row_id == first[0].row.row_id
        assert len(svc.all_rows()) == 1


# ---------- 2. 调查权限过滤与采样代表 ----------

class TestPermissionFilteredSampling:
    """sample 按调查权限过滤后选代表，越权记录一律不被领用。"""

    def _seed_two_tenants(self) -> tuple[AttributionCustodyService, str, str]:
        svc = make_service()
        line_a1 = f'{SHARED_ADDR} - - [24/Nov/2026:11:00:01] "GET /a1 HTTP/1.1" 200 1'
        line_a2 = '10.20.30.41 - - [24/Nov/2026:11:00:02] "GET /a2 HTTP/1.1" 200 2'
        line_b1 = f'{SHARED_ADDR} - - [24/Nov/2026:11:00:03] "GET /b1 HTTP/1.1" 200 3'
        ra = svc.store_events(
            TENANT_A, SHARED_ADDR, [line_a1], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line_a1)})
        svc.store_events(
            TENANT_A, "10.20.30.41", [line_a2], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, "10.20.30.41", line_a2)})
        rb = svc.store_events(
            TENANT_B, SHARED_ADDR, [line_b1], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_B, SHARED_ADDR, line_b1)})
        return svc, ra[0].row.row_id, rb[0].row.row_id

    def test_each_tenant_samples_only_own_rows(self):
        svc, row_a, row_b = self._seed_two_tenants()
        reps_a = svc.sample(TENANT_A)
        reps_b = svc.sample(TENANT_B)
        ids_a = [r.row_id for r in reps_a]
        ids_b = [r.row_id for r in reps_b]
        assert row_a in ids_a and row_b not in ids_a
        assert row_b in ids_b and row_a not in ids_b
        # 甲有两个地址，应各出一个代表
        assert len(reps_a) == 2

    def test_quarantined_row_never_sampled_by_any_tenant(self):
        svc = make_service()
        line_ok = f'{SHARED_ADDR} - - [24/Nov/2026:11:10:01] "GET /ok HTTP/1.1" 200 1'
        line_no = '10.20.30.99 - - [24/Nov/2026:11:10:02] "GET /no-proof HTTP/1.1" 200 2'
        svc.store_events(TENANT_A, SHARED_ADDR, [line_ok], source_id=SOURCE,
                         proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line_ok)})
        svc.store_events(TENANT_A, "10.20.30.99", [line_no], source_id=SOURCE)
        reps = svc.sample(TENANT_A)
        assert all(r.custody_state == CustodyState.PROVEN for r in reps)
        assert all(r.client_addr != "10.20.30.99" for r in reps)
        assert svc.sample(TENANT_B) == []

    def test_claim_freezes_scope_and_picks_representatives(self):
        svc, row_a, _ = self._seed_two_tenants()
        inv = svc.create_investigation(TENANT_A, "甲侧异常调查")
        claimed = svc.claim_investigation(inv.investigation_id, TENANT_A)
        assert claimed.state == InvestigationState.CLAIMED
        assert claimed.scope is not None
        # 冻结范围只含甲有权读取的原行，乙的原行被权限过滤剔除
        assert row_a in claimed.scope.eligible_row_ids
        assert len(claimed.scope.eligible_row_ids) == 2
        assert claimed.representative_ids and all(
            rid in claimed.scope.eligible_row_ids for rid in claimed.representative_ids)

    def test_recompute_scope_matches_frozen_snapshot(self):
        """已完成调查可复算当时的采样范围，且与冻结快照逐行一致。"""
        svc, _, _ = self._seed_two_tenants()
        inv = svc.create_investigation(TENANT_A, "甲侧异常调查")
        claimed = svc.claim_investigation(inv.investigation_id, TENANT_A)
        frozen = claimed.scope
        # 之后库存再变化（新原行入库、转让），复算仍应回到冻结时刻
        later_line = '10.20.30.77 - - [24/Nov/2026:12:00:00] "GET /later HTTP/1.1" 200 1'
        svc.store_events(TENANT_A, "10.20.30.77", [later_line], source_id=SOURCE,
                         proofs={0: proof_for(svc, TENANT_A, "10.20.30.77", later_line)})
        report = svc.recompute_sampling_scope(frozen)
        assert report["consistent"] is True
        assert report["recomputed_row_ids"] == sorted(frozen.eligible_row_ids)
        assert report["mismatches"] == []

    def test_close_keeps_old_basis_and_blocks_double_close(self):
        svc, _, _ = self._seed_two_tenants()
        inv = svc.create_investigation(TENANT_A, "甲侧异常调查")
        svc.claim_investigation(inv.investigation_id, TENANT_A)
        closed = svc.close_investigation(inv.investigation_id, TENANT_A, "确认误报")
        assert closed.state == InvestigationState.CLOSED
        assert closed.close_result["conclusion"] == "确认误报"
        assert closed.close_result["basis_scope_hash"] == inv.scope.scope_hash
        # 已结案不得重复处理
        try:
            svc.claim_investigation(inv.investigation_id, TENANT_B)
        except PermissionError:
            pass
        else:
            raise AssertionError("已结案调查不应允许再次领取")
        try:
            svc.close_investigation(inv.investigation_id, TENANT_A, "再次结案")
        except PermissionError:
            pass
        else:
            raise AssertionError("同一调查不得两边/两次结案")


# ---------- 3. 租户转让与未结案调查交回 ----------

class TestTransferAndHandback:
    """有证转让原行：甲领取、交接、乙领取全链路，最终只有一份处理结果。"""

    def _seed_proven_transfer_row(self) -> tuple[AttributionCustodyService, str]:
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:13:00:00] "GET /transfer HTTP/1.1" 200 88'
        items = svc.store_events(
            TENANT_A, SHARED_ADDR, [line], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line)})
        return svc, items[0].row.row_id

    def test_full_handover_single_result(self):
        svc, row_id = self._seed_proven_transfer_row()
        # 1) 甲领取并产生处理动作（未结案）
        inv_a = svc.create_investigation(TENANT_A, "转让原行调查", bound_row_id=row_id)
        svc.claim_investigation(inv_a.investigation_id, TENANT_A)
        # 2) 发起转让；生效核对发现甲仍有可执行清单 → 阻断
        order = svc.open_transfer(TENANT_A, TENANT_B)
        order = svc.effect_transfer(order.transfer_id)
        assert order.state == TransferState.PENDING
        assert row_id in order.blocked_row_ids
        # 乙此时领取同一原行必须被拒绝
        inv_b = svc.create_investigation(TENANT_B, "乙试图接收", bound_row_id=row_id)
        try:
            svc.claim_investigation(inv_b.investigation_id, TENANT_B)
        except PermissionError:
            pass
        else:
            raise AssertionError("甲仍有可执行清单时，乙不得领取该原行")
        # 3) 甲明确交回
        svc.handback_investigation(inv_a.investigation_id, TENANT_A,
                                   note="随租户转让交回未结案调查")
        assert svc.get_investigation(inv_a.investigation_id).state == InvestigationState.HANDED_BACK
        # 4) 再次生效：无阻断，原行转给乙（双方各留一笔归属历史）
        order = svc.effect_transfer(order.transfer_id)
        assert order.state == TransferState.EFFECTIVE
        assert order.transferred_row_ids == [row_id]
        assert svc.get_row(row_id).owner_tenant == TENANT_B
        event_types = [evt.event_type for evt in svc.get_row(row_id).history]
        assert "转让转出" in event_types and "转让转入" in event_types
        # 5) 乙领取并结案；甲的旧调查不能再结案
        svc.claim_investigation(inv_b.investigation_id, TENANT_B)
        closed_b = svc.close_investigation(inv_b.investigation_id, TENANT_B, "乙确认处置")
        assert closed_b.close_result["by"] == TENANT_B
        try:
            svc.close_investigation(inv_a.investigation_id, TENANT_A, "甲重复结案")
        except PermissionError:
            pass
        else:
            raise AssertionError("已交回的甲调查不得再结案，两边不能各出一份结果")
        # 最终只有一份处理结果
        results = [
            inv for inv in (svc.get_investigation(inv_a.investigation_id),
                            svc.get_investigation(inv_b.investigation_id))
            if inv.state == InvestigationState.CLOSED
        ]
        assert len(results) == 1
        assert results[0].close_result["by"] == TENANT_B

    def test_closed_investigation_keeps_old_basis_after_transfer(self):
        """甲已结案的结果保留旧依据，转让后仍可复算甲当时的采样范围。"""
        svc, row_id = self._seed_proven_transfer_row()
        inv = svc.create_investigation(TENANT_A, "结案后转让", bound_row_id=row_id)
        svc.claim_investigation(inv.investigation_id, TENANT_A)
        svc.close_investigation(inv.investigation_id, TENANT_A, "甲已结案：风险排除")
        frozen = inv.scope
        order = svc.open_transfer(TENANT_A, TENANT_B)
        order = svc.effect_transfer(order.transfer_id)
        assert order.state == TransferState.EFFECTIVE
        assert row_id in order.transferred_row_ids
        # 旧结案结果与旧依据不变
        again = svc.get_investigation(inv.investigation_id)
        assert again.state == InvestigationState.CLOSED
        assert again.close_result["conclusion"] == "甲已结案：风险排除"
        report = svc.recompute_sampling_scope(frozen)
        assert report["consistent"] is True

    def test_unproven_row_not_delivered_in_transfer(self):
        """在途归属冲突：未取得归属证明的原行不能给任何租户。"""
        svc = make_service()
        line_proven = f'{SHARED_ADDR} - - [24/Nov/2026:13:30:01] "GET /p HTTP/1.1" 200 1'
        line_unknown = '10.20.30.66 - - [24/Nov/2026:13:30:02] "GET /u HTTP/1.1" 200 2'
        proven = svc.store_events(
            TENANT_A, SHARED_ADDR, [line_proven], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line_proven)})
        unknown = svc.store_events(TENANT_A, "10.20.30.66", [line_unknown],
                                   source_id=SOURCE)
        order = svc.open_transfer(TENANT_A, TENANT_B)
        order = svc.effect_transfer(order.transfer_id)
        assert order.state == TransferState.EFFECTIVE
        # 有证行转给乙；无证行继续隔离，转让生效范围不覆盖
        assert proven[0].row.owner_tenant == TENANT_B
        assert unknown[0].row.custody_state == CustodyState.QUARANTINED
        assert unknown[0].row.owner_tenant is None
        assert unknown[0].row.row_id in order.unproven_row_ids
        assert svc.inventory(TENANT_A) == [] and svc.inventory(TENANT_B) == [proven[0].row]

    def test_inflight_proven_row_still_deliverable_to_old_tenant(self):
        """转让在途期间，有证据的新原行仍可向甲（来源租户）交付。"""
        svc, row_id = self._seed_proven_transfer_row()
        order = svc.open_transfer(TENANT_A, TENANT_B)  # 仅发起、未生效
        inflight_line = '10.20.30.77 - - [24/Nov/2026:13:45:00] "GET /inflight HTTP/1.1" 200 5'
        items = svc.store_events(
            TENANT_A, "10.20.30.77", [inflight_line], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, "10.20.30.77", inflight_line)})
        inflight_row = items[0].row
        assert inflight_row.custody_state == CustodyState.PROVEN
        # 在途先入甲库存，转让生效后随整组转给乙
        assert inflight_row.owner_tenant == TENANT_A
        order = svc.effect_transfer(order.transfer_id)
        assert order.state == TransferState.EFFECTIVE
        assert {row_id, inflight_row.row_id} == set(order.transferred_row_ids)
        assert inflight_row.owner_tenant == TENANT_B

    def test_cannot_claim_other_tenant_row_without_transfer(self):
        svc, row_id = self._seed_proven_transfer_row()
        inv = svc.create_investigation(TENANT_B, "乙越权领取", bound_row_id=row_id)
        try:
            svc.claim_investigation(inv.investigation_id, TENANT_B)
        except PermissionError:
            pass
        else:
            raise AssertionError("乙未取得归属，不得领取甲库存中的原行")


# ---------- 4. 共同调查与整组留存 ----------

class TestJointInvestigation:
    """已证明行可单独放行，也可随整组共同调查；缺证行不得被采样。"""

    def test_joint_hold_and_release(self):
        svc = make_service()
        line1 = f'{SHARED_ADDR} - - [24/Nov/2026:14:00:01] "GET /g1 HTTP/1.1" 200 1'
        line2 = '10.20.30.45 - - [24/Nov/2026:14:00:02] "GET /g2 HTTP/1.1" 200 2'
        items = svc.store_events(
            TENANT_A, SHARED_ADDR, [line1, line2], source_id=SOURCE,
            client_addrs=[SHARED_ADDR, "10.20.30.45"],
            proofs={
                0: proof_for(svc, TENANT_A, SHARED_ADDR, line1),
                1: proof_for(svc, TENANT_A, "10.20.30.45", line2),
            },
            release_mode=RELEASE_JOINT, group_id="GROUP-J1")
        assert all(item.row.custody_state == CustodyState.JOINT_HOLD for item in items)
        # 留存期间不进入任一租户的单独库存
        assert svc.inventory(TENANT_A) == []
        # 但共同调查上下文中，已证明原行可被领用
        reps = svc.sample(TENANT_A, group_id="GROUP-J1")
        assert {r.row_id for r in reps} == {item.row.row_id for item in items}
        # 放行后回到甲库存
        released = svc.release_joint_group("GROUP-J1")
        assert len(released) == 2
        assert all(r.custody_state == CustodyState.PROVEN for r in released)
        assert len(svc.inventory(TENANT_A)) == 2

    def test_joint_group_unproven_row_excluded(self):
        """共同调查组里的缺证原行不能被任一租户采样，补证后才可交付。"""
        svc = make_service()
        line_ok = f'{SHARED_ADDR} - - [24/Nov/2026:14:10:01] "GET /j-ok HTTP/1.1" 200 1'
        line_no = '10.20.30.46 - - [24/Nov/2026:14:10:02] "GET /j-no HTTP/1.1" 200 2'
        items = svc.store_events(
            TENANT_A, SHARED_ADDR, [line_ok, line_no], source_id=SOURCE,
            client_addrs=[SHARED_ADDR, "10.20.30.46"],
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line_ok)},
            release_mode=RELEASE_JOINT, group_id="GROUP-J2")
        proven_row, unproven_row = items[0].row, items[1].row
        assert proven_row.custody_state == CustodyState.JOINT_HOLD
        assert unproven_row.custody_state == CustodyState.QUARANTINED
        # 组内采样只拿到已证行，缺证行两个租户都采不到
        reps = svc.sample(TENANT_A, group_id="GROUP-J2")
        assert [r.row_id for r in reps] == [proven_row.row_id]
        assert svc.sample(TENANT_B, group_id="GROUP-J2") == []
        assert svc.sample(TENANT_A) == []  # 普通库存视角同样采不到
        # 补证通过后随组留存、可在共同调查上下文领用
        svc.attach_proof(unproven_row.row_id,
                         proof_for(svc, TENANT_A, "10.20.30.46", line_no))
        refreshed = svc.get_row(unproven_row.row_id)
        assert refreshed.custody_state == CustodyState.JOINT_HOLD
        reps2 = svc.sample(TENANT_A, group_id="GROUP-J2")
        assert {r.row_id for r in reps2} == {proven_row.row_id, unproven_row.row_id}

    def test_individual_release_mode_is_default(self):
        svc = make_service()
        line = f'{SHARED_ADDR} - - [24/Nov/2026:14:20:00] "GET /solo HTTP/1.1" 200 1'
        items = svc.store_events(
            TENANT_A, SHARED_ADDR, [line], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line)},
            release_mode=RELEASE_INDIVIDUAL)
        assert items[0].row.custody_state == CustodyState.PROVEN
        assert len(svc.inventory(TENANT_A)) == 1


# ---------- 5. 题面完整场景：甲乙同地址 + 在途冲突 + 核对报告 ----------

class TestEndToEndScenario:
    """完整串联：库存归属落地 → 核对调查权限 → 转让 → 分类入库与选样核对。"""

    def test_full_scenario_reconciliation(self):
        svc = make_service()
        # 甲两条待处理：一条带接收时可核对的归属证明，一条只知道来源在途转让
        line_a_proven = f'{SHARED_ADDR} - - [24/Nov/2026:15:00:01] "GET /a-proven HTTP/1.1" 200 11'
        line_a_unknown = '10.20.30.50 - - [24/Nov/2026:15:00:02] "GET /a-unknown HTTP/1.1" 200 22'
        line_b_proven = f'{SHARED_ADDR} - - [24/Nov/2026:15:00:03] "GET /b-proven HTTP/1.1" 200 33'

        a_proven = svc.store_events(
            TENANT_A, SHARED_ADDR, [line_a_proven], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_A, SHARED_ADDR, line_a_proven)})[0].row
        a_unknown = svc.store_events(
            TENANT_A, "10.20.30.50", [line_a_unknown], source_id=SOURCE)[0].row
        b_proven = svc.store_events(
            TENANT_B, SHARED_ADDR, [line_b_proven], source_id=SOURCE,
            proofs={0: proof_for(svc, TENANT_B, SHARED_ADDR, line_b_proven)})[0].row

        # 串联入口：库存归属落地后再核对调查权限
        inv_a = svc.create_investigation(TENANT_A, "甲两条待处理调查",
                                         bound_row_id=a_proven.row_id)
        svc.claim_investigation(inv_a.investigation_id, TENANT_A)
        # 甲的代表只来自甲实际有权读取的已证原行；未证原行被过滤
        reps_a = svc.sample(TENANT_A)
        assert [r.row_id for r in reps_a] == [a_proven.row_id]
        assert a_unknown.row_id in [r.row_id for r in svc.quarantined_rows()]

        # 发起甲→乙转让：甲有未结案调查，先阻断
        order = svc.open_transfer(TENANT_A, TENANT_B)
        first_effect = svc.effect_transfer(order.transfer_id)
        assert first_effect.state == TransferState.PENDING
        assert a_proven.row_id in first_effect.blocked_row_ids

        # 甲结案（保留旧依据）后转让生效；未证原行不交付任何租户
        svc.close_investigation(inv_a.investigation_id, TENANT_A, "甲侧处置完成")
        order = svc.effect_transfer(order.transfer_id)
        assert order.state == TransferState.EFFECTIVE
        assert order.transferred_row_ids == [a_proven.row_id]
        assert order.unproven_row_ids == [a_unknown.row_id]
        assert svc.get_row(a_proven.row_id).owner_tenant == TENANT_B
        assert svc.get_row(a_unknown.row_id).custody_state == CustodyState.QUARANTINED

        # 乙库存含乙自己的 + 转入的甲已证行；甲库存清空
        inv_b_ids = {r.row_id for r in svc.inventory(TENANT_B)}
        assert inv_b_ids == {a_proven.row_id, b_proven.row_id}
        assert svc.inventory(TENANT_A) == []
        # 乙采样：同地址归并只出一个代表，乙自己的同地址原行优先
        reps_b = svc.sample(TENANT_B)
        assert len(reps_b) == 1
        assert reps_b[0].client_addr == SHARED_ADDR

        # 已完成的甲调查仍可复算当时采样范围
        report = svc.recompute_sampling_scope(inv_a.scope)
        assert report["consistent"] is True

        # 核对报告：实际日志、每侧代表、未证原行、历史归属齐备
        recon = svc.reconciliation_report([TENANT_A, TENANT_B])
        assert recon["tenants"][TENANT_A]["inventory_count"] == 0
        assert recon["tenants"][TENANT_B]["inventory_count"] == 2
        assert recon["tenants"][TENANT_B]["representative_count"] == 1
        assert recon["quarantine_row_ids"] == [a_unknown.row_id]
        transferred_history = [
            evt for evt in svc.get_row(a_proven.row_id).history
            if evt.event_type in ("转让转出", "转让转入")
        ]
        assert len(transferred_history) == 2
        assert all(evt.transfer_id == order.transfer_id for evt in transferred_history)
        # 甲旧结案结果保留
        assert svc.get_investigation(inv_a.investigation_id).close_result["by"] == TENANT_A

    def test_fingerprint_distinguishes_lines_under_same_addr(self):
        fp1 = raw_line_fingerprint(SHARED_ADDR, "line-one", SOURCE)
        fp2 = raw_line_fingerprint(SHARED_ADDR, "line-two", SOURCE)
        assert fp1 != fp2


# ---------- 运行入口 ----------

if __name__ == "__main__":
    import traceback

    test_classes = [
        TestStoreByAttribution,
        TestPermissionFilteredSampling,
        TestTransferAndHandback,
        TestJointInvestigation,
        TestEndToEndScenario,
    ]
    passed = 0
    failed = 0
    total = 0
    for cls in test_classes:
        instance = cls()
        for name in sorted(dir(instance)):
            if not name.startswith("test_"):
                continue
            total += 1
            try:
                getattr(instance, name)()
                passed += 1
                print(f"  PASS  test_attribution_custody: {cls.__name__}.{name}")
            except Exception:
                failed += 1
                print(f"  FAIL  test_attribution_custody: {cls.__name__}.{name}")
                traceback.print_exc()

    print(f"\ntest_attribution_custody: {passed} passed, {failed} failed, {total} total")
    sys.exit(1 if failed else 0)
