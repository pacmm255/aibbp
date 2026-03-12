"""Exhaustive tests for benchmarks.metrics, benchmarks.benchmark_harness, benchmarks.ci_runner."""

import pytest

from benchmarks.metrics import BenchmarkMetrics
from benchmarks.benchmark_harness import (
    BenchmarkResult,
    SuiteResult,
    XBOWBenchmark,
    JuiceShopBenchmark,
    CrAPIBenchmark,
)
from benchmarks.ci_runner import DEFAULT_BASELINES, load_baselines


# ── BenchmarkMetrics ───────────────────────────────────────────────────


class TestBenchmarkMetrics:
    def test_defaults(self):
        m = BenchmarkMetrics()
        assert m.validated_finding_precision == 0.0
        assert m.false_positive_rate == 0.0
        assert m.scope_violations == 0
        assert m.total_cost == 0.0

    def test_compute_precision(self):
        m = BenchmarkMetrics(total_reported=10, confirmed_true=8)
        m.compute()
        assert m.validated_finding_precision == 0.8

    def test_compute_fp_rate(self):
        m = BenchmarkMetrics(total_reported=10, false_positives=2)
        m.compute()
        assert m.false_positive_rate == 0.2

    def test_compute_replay(self):
        m = BenchmarkMetrics(total_replays=5, successful_replays=4)
        m.compute()
        assert m.replay_success_rate == 0.8

    def test_compute_cost_per_finding(self):
        m = BenchmarkMetrics(total_cost=10.0, confirmed_true=5)
        m.compute()
        assert m.cost_per_validated_finding == 2.0

    def test_compute_dedup(self):
        m = BenchmarkMetrics(total_raw=100, duplicates=20)
        m.compute()
        assert m.duplicate_reduction_rate == 0.8

    def test_compute_coverage(self):
        m = BenchmarkMetrics(total_endpoints=50, tested_endpoints=25)
        m.compute()
        assert m.coverage_ratio == 0.5

    def test_compute_zero_division_safe(self):
        m = BenchmarkMetrics()
        m.compute()  # Should not crash
        assert m.validated_finding_precision == 0.0

    def test_to_dict(self):
        m = BenchmarkMetrics(total_reported=10, confirmed_true=7, total_cost=5.0)
        m.compute()
        d = m.to_dict()
        assert d["validated_finding_precision"] == 0.7
        assert d["total_reported"] == 10
        assert isinstance(d["total_cost"], float)

    def test_to_dict_rounding(self):
        m = BenchmarkMetrics(total_reported=3, confirmed_true=1)
        m.compute()
        d = m.to_dict()
        assert d["validated_finding_precision"] == round(1 / 3, 4)

    def test_passes_baseline_ok(self):
        m = BenchmarkMetrics(total_reported=10, confirmed_true=9)
        m.compute()
        passes, failures = m.passes_baseline({"validated_finding_precision": 0.8})
        assert passes
        assert failures == []

    def test_passes_baseline_fail(self):
        m = BenchmarkMetrics(total_reported=10, confirmed_true=5)
        m.compute()
        passes, failures = m.passes_baseline({"validated_finding_precision": 0.8})
        assert not passes
        assert len(failures) == 1

    def test_passes_baseline_scope_violations(self):
        m = BenchmarkMetrics(scope_violations=1)
        passes, failures = m.passes_baseline({})
        assert not passes
        assert "scope_violations" in failures[0]

    def test_passes_baseline_zero_violations_ok(self):
        m = BenchmarkMetrics(scope_violations=0, total_reported=5, confirmed_true=5)
        m.compute()
        passes, _ = m.passes_baseline({"validated_finding_precision": 0.5})
        assert passes

    def test_passes_baseline_unknown_metric(self):
        m = BenchmarkMetrics()
        passes, failures = m.passes_baseline({"nonexistent_metric": 0.5})
        assert passes  # Unknown metrics are skipped

    def test_from_results(self):
        results = [
            {"findings_count": 5, "confirmed_count": 4, "fp_count": 1, "cost": 2.0, "time_to_first_high": 30.0},
            {"findings_count": 3, "confirmed_count": 2, "fp_count": 1, "cost": 1.5, "time_to_first_high": 45.0},
        ]
        m = BenchmarkMetrics.from_results(results)
        assert m.total_reported == 8
        assert m.confirmed_true == 6
        assert m.false_positives == 2
        assert m.total_cost == 3.5
        assert m.time_to_first_high == 30.0  # Minimum

    def test_from_results_empty(self):
        m = BenchmarkMetrics.from_results([])
        assert m.total_reported == 0
        assert m.validated_finding_precision == 0.0


# ── BenchmarkResult ────────────────────────────────────────────────────


class TestBenchmarkResult:
    def test_defaults(self):
        r = BenchmarkResult()
        assert r.challenge_id == ""
        assert r.passed is False
        assert r.findings == []
        assert r.cost == 0.0

    def test_custom(self):
        r = BenchmarkResult(
            challenge_id="XBEN-001",
            challenge_name="Basic XSS",
            passed=True,
            cost=1.50,
            turns=20,
        )
        assert r.challenge_id == "XBEN-001"
        assert r.passed is True
        assert r.cost == 1.50


# ── SuiteResult ────────────────────────────────────────────────────────


class TestSuiteResult:
    def test_empty(self):
        sr = SuiteResult()
        assert sr.pass_rate == 0.0
        assert sr.total_cost == 0.0

    def test_pass_rate(self):
        sr = SuiteResult(results=[
            BenchmarkResult(passed=True, cost=1.0),
            BenchmarkResult(passed=True, cost=1.5),
            BenchmarkResult(passed=False, cost=2.0),
        ])
        assert sr.pass_rate == pytest.approx(2 / 3)

    def test_total_cost(self):
        sr = SuiteResult(results=[
            BenchmarkResult(cost=1.0),
            BenchmarkResult(cost=2.5),
        ])
        assert sr.total_cost == 3.5

    def test_summary(self):
        sr = SuiteResult(
            suite_name="Test",
            results=[
                BenchmarkResult(passed=True, cost=1.0),
                BenchmarkResult(passed=False, cost=2.0),
            ],
            total_duration=60.0,
        )
        s = sr.summary()
        assert "1/2" in s
        assert "50.0%" in s
        assert "$3.00" in s


# ── XBOWBenchmark ──────────────────────────────────────────────────────


class TestXBOWBenchmark:
    def test_init(self):
        xbow = XBOWBenchmark()
        assert xbow._challenges == []

    def test_get_challenges_empty(self):
        xbow = XBOWBenchmark(xbow_dir="/nonexistent")
        assert xbow.get_challenges() == []

    @pytest.mark.asyncio
    async def test_verify_correct_flag(self):
        xbow = XBOWBenchmark()
        challenge = {"flag": "CTF{test_flag_123}"}
        output = {"findings": {"f1": {"evidence": "Found: CTF{test_flag_123}"}}}
        assert await xbow.verify(challenge, output)

    @pytest.mark.asyncio
    async def test_verify_flag_in_poc(self):
        xbow = XBOWBenchmark()
        challenge = {"flag": "FLAG{abc}"}
        output = {"findings": {"f1": {"poc_code": "print('FLAG{abc}')"}}}
        assert await xbow.verify(challenge, output)

    @pytest.mark.asyncio
    async def test_verify_wrong_flag(self):
        xbow = XBOWBenchmark()
        challenge = {"flag": "CTF{correct}"}
        output = {"findings": {"f1": {"evidence": "No flag here"}}}
        assert not await xbow.verify(challenge, output)

    @pytest.mark.asyncio
    async def test_verify_no_flag(self):
        xbow = XBOWBenchmark()
        challenge = {}
        output = {"findings": {}}
        assert not await xbow.verify(challenge, output)

    @pytest.mark.asyncio
    async def test_verify_no_findings(self):
        xbow = XBOWBenchmark()
        challenge = {"flag": "CTF{x}"}
        output = {}
        assert not await xbow.verify(challenge, output)


# ── CrAPIBenchmark ────────────────────────────────────────────────────


class TestCrAPIBenchmark:
    def test_challenges_count(self):
        crapi = CrAPIBenchmark()
        assert len(crapi.get_challenges()) == 10

    def test_challenge_ids(self):
        crapi = CrAPIBenchmark()
        ids = [c["id"] for c in crapi.get_challenges()]
        assert "crapi-01" in ids
        assert "crapi-10" in ids

    @pytest.mark.asyncio
    async def test_verify_match(self):
        crapi = CrAPIBenchmark()
        challenge = {"vuln_type": "bola"}
        output = {"findings": {"f1": {"vuln_type": "bola"}}}
        assert await crapi.verify(challenge, output)

    @pytest.mark.asyncio
    async def test_verify_partial_match(self):
        crapi = CrAPIBenchmark()
        challenge = {"vuln_type": "broken_auth"}
        output = {"findings": {"f1": {"vuln_type": "broken_auth_bypass"}}}
        assert await crapi.verify(challenge, output)

    @pytest.mark.asyncio
    async def test_verify_no_match(self):
        crapi = CrAPIBenchmark()
        challenge = {"vuln_type": "bola"}
        output = {"findings": {"f1": {"vuln_type": "xss"}}}
        assert not await crapi.verify(challenge, output)


# ── JuiceShopBenchmark ────────────────────────────────────────────────


class TestJuiceShopBenchmark:
    def test_init(self):
        js = JuiceShopBenchmark()
        assert js._port == 3000
        assert js._challenges == []

    def test_custom_port(self):
        js = JuiceShopBenchmark(port=9000)
        assert js._port == 9000


# ── CI Runner ──────────────────────────────────────────────────────────


class TestCIRunner:
    def test_default_baselines(self):
        assert "xbow" in DEFAULT_BASELINES
        assert "juiceshop" in DEFAULT_BASELINES
        assert "crapi" in DEFAULT_BASELINES
        assert DEFAULT_BASELINES["xbow"]["validated_finding_precision"] >= 0.5

    def test_load_baselines_default(self):
        baselines = load_baselines("")
        assert baselines == DEFAULT_BASELINES

    def test_load_baselines_nonexistent(self):
        baselines = load_baselines("/nonexistent/path.yaml")
        assert baselines == DEFAULT_BASELINES

    def test_load_baselines_yaml(self, tmp_path):
        import yaml
        data = {"custom": {"precision": 0.9}}
        f = tmp_path / "baselines.yaml"
        f.write_text(yaml.dump(data))
        baselines = load_baselines(str(f))
        assert baselines == data
