"""Exhaustive tests for ai_brain.active.work_queue."""

import pytest

from ai_brain.active.work_queue import (
    AdaptiveWorkQueue,
    WorkItem,
    _TECHNIQUE_IMPACT,
    _SIDE_EFFECT_RISK,
)


# ── WorkItem ───────────────────────────────────────────────────────────


class TestWorkItem:
    def test_defaults(self):
        item = WorkItem()
        assert item.category == "exploit"
        assert item.status == "pending"
        assert item.novelty == 1.0
        assert item.policy_allowance == 1.0
        assert len(item.id) > 0

    def test_unique_ids(self):
        ids = {WorkItem().id for _ in range(100)}
        assert len(ids) == 100

    def test_compute_priority_basic(self):
        item = WorkItem(expected_impact=3.0, novelty=1.0, verifier_uncertainty=1.0,
                        program_value=0.5, policy_allowance=1.0,
                        estimated_cost=0.01, side_effect_risk=0.1)
        p = item.compute_priority()
        assert p > 0
        assert item.priority_score == p

    def test_compute_priority_zero_policy(self):
        item = WorkItem(expected_impact=3.0, policy_allowance=0.0)
        p = item.compute_priority()
        assert p == 0.0

    def test_compute_priority_high_risk_reduces(self):
        item_low = WorkItem(expected_impact=3.0, side_effect_risk=0.1)
        item_high = WorkItem(expected_impact=3.0, side_effect_risk=0.9)
        item_low.compute_priority()
        item_high.compute_priority()
        assert item_low.priority_score > item_high.priority_score

    def test_compute_priority_division_by_zero_safe(self):
        item = WorkItem(estimated_cost=0.0, side_effect_risk=0.0)
        p = item.compute_priority()
        assert p > 0  # Uses max(0.001) and max(0.01)

    def test_to_dict(self):
        item = WorkItem(category="scan", endpoint="http://x.com", technique="sqli")
        d = item.to_dict()
        assert d["category"] == "scan"
        assert d["endpoint"] == "http://x.com"
        assert d["technique"] == "sqli"
        assert "id" in d

    def test_from_dict_roundtrip(self):
        item = WorkItem(category="exploit", endpoint="http://test.com/api",
                        technique="xss", test_count=3, status="done")
        d = item.to_dict()
        restored = WorkItem.from_dict(d)
        assert restored.category == "exploit"
        assert restored.endpoint == "http://test.com/api"
        assert restored.technique == "xss"
        assert restored.test_count == 3
        assert restored.status == "done"

    def test_from_dict_defaults(self):
        restored = WorkItem.from_dict({})
        assert restored.category == "exploit"
        assert restored.status == "pending"


# ── Impact & Risk Tables ──────────────────────────────────────────────


class TestImpactTables:
    def test_rce_highest_impact(self):
        assert _TECHNIQUE_IMPACT["rce"] >= _TECHNIQUE_IMPACT["xss"]
        assert _TECHNIQUE_IMPACT["rce"] >= _TECHNIQUE_IMPACT["sqli"]

    def test_all_impacts_positive(self):
        for technique, impact in _TECHNIQUE_IMPACT.items():
            assert impact > 0, f"{technique} impact must be positive"

    def test_side_effect_risk_range(self):
        for technique, risk in _SIDE_EFFECT_RISK.items():
            assert 0.0 <= risk <= 1.0, f"{technique} risk out of range"

    def test_rce_high_side_effect(self):
        assert _SIDE_EFFECT_RISK["rce"] >= 0.5


# ── AdaptiveWorkQueue ─────────────────────────────────────────────────


class TestAdaptiveWorkQueue:
    def test_empty_queue(self):
        q = AdaptiveWorkQueue()
        assert q.get_top_n(5) == []
        assert q.get_effective_phase() == "reporting"
        assert not q.should_block_exploitation()

    def test_seed_from_endpoints(self):
        q = AdaptiveWorkQueue()
        endpoints = {
            "http://example.com/api": {"auth_required": False},
            "http://example.com/admin": {"auth_required": True},
        }
        q.seed_from_endpoints(endpoints, {})
        stats = q.get_stats()
        assert stats["total"] > 0
        assert stats["pending"] > 0

    def test_seed_tech_stack_extras(self):
        q = AdaptiveWorkQueue()
        endpoints = {"http://example.com/api": {}}
        q.seed_from_endpoints(endpoints, {}, tech_stack=["GraphQL", "Java Spring"])
        # Should have graphql and deserialization items
        techniques = {item.technique for item in q._items.values()}
        assert "graphql" in techniques
        assert "deserialization" in techniques

    def test_seed_skips_tested(self):
        q = AdaptiveWorkQueue()
        endpoints = {"http://example.com/api": {}}
        tested = {"http://example.com/api::sqli": True}
        q.seed_from_endpoints(endpoints, tested)
        techniques = {item.technique for item in q._items.values()}
        assert "sqli" not in techniques

    def test_seed_no_duplicates(self):
        q = AdaptiveWorkQueue()
        endpoints = {"http://example.com/api": {}}
        q.seed_from_endpoints(endpoints, {})
        count1 = len(q._items)
        q.seed_from_endpoints(endpoints, {})
        count2 = len(q._items)
        assert count1 == count2

    def test_auth_required_boost(self):
        q = AdaptiveWorkQueue()
        endpoints = {
            "http://example.com/public": {"auth_required": False},
            "http://example.com/admin": {"auth_required": True},
        }
        q.seed_from_endpoints(endpoints, {})
        # Admin items should have higher impact
        admin_items = [it for it in q._items.values() if "admin" in it.endpoint]
        public_items = [it for it in q._items.values() if "public" in it.endpoint]
        if admin_items and public_items:
            # Same technique
            for ai in admin_items:
                for pi in public_items:
                    if ai.technique == pi.technique:
                        assert ai.expected_impact > pi.expected_impact

    def test_add_work_item(self):
        q = AdaptiveWorkQueue()
        item = WorkItem(technique="custom", endpoint="http://x.com")
        q.add_work_item(item)
        assert item.priority_score > 0
        assert item.id in q._items

    def test_inject_discovery_items(self):
        q = AdaptiveWorkQueue()
        q.inject_discovery_items(["http://new1.com", "http://new2.com"])
        techniques = {item.technique for item in q._items.values()}
        assert "crawl" in techniques
        assert "js_analysis" in techniques

    def test_inject_discovery_no_duplicate(self):
        q = AdaptiveWorkQueue()
        q.inject_discovery_items(["http://new.com"])
        count1 = len(q._items)
        q._discovery_done["http://new.com"] = True
        q.inject_discovery_items(["http://new.com"])
        assert len(q._items) == count1

    def test_get_top_n(self):
        q = AdaptiveWorkQueue()
        endpoints = {"http://example.com/api": {}}
        q.seed_from_endpoints(endpoints, {})
        top = q.get_top_n(3)
        assert len(top) <= 3
        # Sorted by priority descending
        for i in range(len(top) - 1):
            assert top[i].priority_score >= top[i + 1].priority_score

    def test_get_top_n_skips_done(self):
        q = AdaptiveWorkQueue()
        item = WorkItem(technique="sqli", endpoint="http://x.com")
        q.add_work_item(item)
        q.mark_done(item.id)
        assert q.get_top_n(5) == []

    def test_get_top_n_skips_zero_policy(self):
        q = AdaptiveWorkQueue()
        item = WorkItem(technique="sqli", policy_allowance=0.0)
        q.add_work_item(item)
        assert q.get_top_n(5) == []

    def test_get_top_n_respects_dependencies(self):
        q = AdaptiveWorkQueue()
        dep = WorkItem(id="dep1", technique="crawl", category="discovery")
        blocked = WorkItem(technique="sqli", depends_on=["dep1"])
        q.add_work_item(dep)
        q.add_work_item(blocked)
        top = q.get_top_n(10)
        ids = [it.id for it in top]
        assert blocked.id not in ids or dep.id in ids

    def test_get_top_n_unblocks_after_dep_done(self):
        q = AdaptiveWorkQueue()
        dep = WorkItem(id="dep1", technique="crawl", category="discovery")
        blocked = WorkItem(technique="sqli", depends_on=["dep1"])
        q.add_work_item(dep)
        q.add_work_item(blocked)
        q.mark_done("dep1")
        top = q.get_top_n(10)
        ids = [it.id for it in top]
        assert blocked.id in ids

    def test_mark_done(self):
        q = AdaptiveWorkQueue()
        item = WorkItem(technique="xss", endpoint="http://x.com")
        q.add_work_item(item)
        q.mark_done(item.id, found_something=True)
        assert item.status == "done"
        assert item.test_count == 1
        assert "xss" in q._found_techniques

    def test_mark_done_nonexistent(self):
        q = AdaptiveWorkQueue()
        q.mark_done("nonexistent")  # Should not crash

    def test_mark_done_anti_fixation(self):
        q = AdaptiveWorkQueue()
        item1 = WorkItem(technique="xss", endpoint="http://x.com/a")
        item2 = WorkItem(technique="xss", endpoint="http://x.com/a")  # Same ep+technique
        q.add_work_item(item1)
        q.add_work_item(item2)
        original_priority = item2.priority_score
        q.mark_done(item1.id)
        # item2 should have reduced novelty
        assert item2.novelty < 1.0

    def test_mark_done_by_key(self):
        q = AdaptiveWorkQueue()
        item = WorkItem(technique="sqli", endpoint="http://x.com/api")
        q.add_work_item(item)
        q.mark_done_by_key("http://x.com/api", "sqli", found=True)
        assert item.status == "done"

    def test_should_block_exploitation_low_coverage(self):
        q = AdaptiveWorkQueue()
        # Add 10 items, no scans done
        for i in range(10):
            q.add_work_item(WorkItem(
                endpoint=f"http://x.com/{i}",
                technique="sqli",
                category="exploit",
            ))
        assert q.should_block_exploitation()

    def test_should_block_exploitation_high_coverage(self):
        q = AdaptiveWorkQueue()
        for i in range(5):
            scan = WorkItem(
                endpoint=f"http://x.com/{i}",
                technique="crawl",
                category="discovery",
                status="done",
            )
            q._items[scan.id] = scan
            exploit = WorkItem(
                endpoint=f"http://x.com/{i}",
                technique="sqli",
                category="exploit",
            )
            q._items[exploit.id] = exploit
        assert not q.should_block_exploitation()

    def test_build_prompt_section_empty(self):
        q = AdaptiveWorkQueue()
        s = q.build_prompt_section()
        assert "empty" in s

    def test_build_prompt_section_with_items(self):
        q = AdaptiveWorkQueue()
        q.add_work_item(WorkItem(technique="sqli", endpoint="http://x.com/api"))
        s = q.build_prompt_section()
        assert "sqli" in s
        assert "priority=" in s

    def test_get_effective_phase_exploit(self):
        q = AdaptiveWorkQueue()
        for t in ("sqli", "xss", "cmdi"):
            q.add_work_item(WorkItem(technique=t, endpoint="http://x.com", category="exploit"))
        assert q.get_effective_phase() == "exploitation"

    def test_get_effective_phase_discovery(self):
        q = AdaptiveWorkQueue()
        for t in ("crawl", "js_analysis", "content_discovery"):
            q.add_work_item(WorkItem(technique=t, endpoint="http://x.com", category="discovery"))
        assert q.get_effective_phase() == "recon"

    def test_get_stats(self):
        q = AdaptiveWorkQueue()
        q.add_work_item(WorkItem(technique="sqli", category="exploit"))
        q.add_work_item(WorkItem(technique="crawl", category="discovery"))
        stats = q.get_stats()
        assert stats["total"] == 2
        assert stats["pending"] == 2
        assert stats["done"] == 0
        assert "exploit" in stats["by_category"]

    def test_to_state_dict_roundtrip(self):
        q = AdaptiveWorkQueue()
        q.add_work_item(WorkItem(technique="sqli", endpoint="http://x.com/api"))
        q.add_work_item(WorkItem(technique="xss", endpoint="http://x.com/form"))
        state = q.to_state_dict()

        q2 = AdaptiveWorkQueue()
        q2.from_state_dict(state)
        assert len(q2._items) == 2
        techniques = {item.technique for item in q2._items.values()}
        assert "sqli" in techniques
        assert "xss" in techniques

    def test_priority_ordering_ssti_over_xss(self):
        q = AdaptiveWorkQueue()
        endpoints = {"http://x.com": {}}
        q.seed_from_endpoints(endpoints, {})
        top = q.get_top_n(20)
        techniques = [it.technique for it in top]
        if "ssti" in techniques and "xss" in techniques:
            ssti_idx = techniques.index("ssti")
            xss_idx = techniques.index("xss")
            assert ssti_idx < xss_idx  # SSTI should be higher priority

    def test_policy_manifest_integration(self):
        from ai_brain.active.policy import PolicyManifest, AssetRule
        manifest = PolicyManifest(
            allowed_assets=[AssetRule(pattern="example.com", criticality=0.9)],
            prohibited_tests=frozenset({"dos"}),
        )
        q = AdaptiveWorkQueue(manifest=manifest)
        endpoints = {"http://example.com/api": {}}
        q.seed_from_endpoints(endpoints, {})
        # Items should have program_value from manifest
        for item in q._items.values():
            if item.technique not in ("dos",):
                assert item.program_value > 0

    def test_uncertainty_drops_after_finding(self):
        q = AdaptiveWorkQueue()
        item1 = WorkItem(technique="xss", endpoint="http://x.com/a")
        item2 = WorkItem(technique="xss", endpoint="http://x.com/b")
        q.add_work_item(item1)
        q.add_work_item(item2)
        original_uncertainty = item2.verifier_uncertainty
        q.mark_done(item1.id, found_something=True)
        assert item2.verifier_uncertainty < original_uncertainty
