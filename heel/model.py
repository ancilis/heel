"""
HEEL — pluggable model / LLM control loop (spec §3, §11).

The adversarial agent's reasoning (currently: discovery of un-anticipated abuse affordances) is
driven by a swappable `Model`. The default `StubModel` is DETERMINISTIC and needs no API key, so
the synthetic demo runs offline (spec §11). An `AnthropicModel` swaps in behind
`HEEL_MODEL=anthropic` (+ `ANTHROPIC_API_KEY`) for a real LLM control loop, called via stdlib
`urllib` (no SDK dependency, keeping the pure-stdlib core).

SAFETY: the model only ever sees OBSERVABLE affordance properties (never planted ground truth),
and it only PROPOSES declarative scenario specs — HEEL builds the contained PoC itself. The model
is instructed to stay in HEEL's lane (product/business consequence; no weaponization, no prohibited
content, no jailbreak technique). On any error or missing key it falls back to the heuristic.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .agents import heuristic_discover

SYSTEM_PROMPT = (
    "You are HEEL's discovery reasoner. HEEL rehearses product/business-logic ABUSE against a "
    "product the operator owns, to harden it before launch. You see only OBSERVABLE affordance "
    "properties. For affordances that show a likely abuse CONSEQUENCE (unauthorized action, data "
    "over-extraction, cost amplification, license/quota/economy gaming) propose a DECLARATIVE "
    "scenario spec. NEVER produce exploit code, prohibited content, or jailbreak techniques; those "
    "are out of lane. Output ONLY JSON: {\"scenarios\":[{\"affordance_id\",\"category\",\"criterion\","
    "\"control\",\"likelihood\",\"impact\"}]}."
)


class Model:
    name = "base"
    def discover(self, target, fired, run_id, log):
        raise NotImplementedError


class StubModel(Model):
    """Deterministic, offline. Discovery = the missing-control heuristic (agents.heuristic_discover)."""
    name = "stub"
    def discover(self, target, fired, run_id, log):
        return heuristic_discover(target, fired, run_id, log)


class AnthropicModel(Model):
    name = "anthropic"
    def __init__(self, model_id: str | None = None, api_key: str | None = None):
        self.model_id = model_id or os.environ.get("HEEL_MODEL_ID", "claude-sonnet-4-6")
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    def discover(self, target, fired, run_id, log):
        if not self.api_key:
            log("model_fallback", {"reason": "no ANTHROPIC_API_KEY", "to": "stub"})
            return heuristic_discover(target, fired, run_id, log)
        candidates = [{"affordance_id": a.id, "kind": a.kind, "category": a.category.value,
                       "properties": a.properties} for a in target.affordances
                      if a.id not in fired and not a.decoy]
        try:
            specs = self._call(candidates)
        except Exception as e:  # network/parse/timeout → safe fallback
            log("model_error", {"error": str(e)[:120], "fallback": "stub"})
            return heuristic_discover(target, fired, run_id, log)
        return self._materialize(target, specs, run_id, log)

    def _call(self, candidates):
        body = json.dumps({
            "model": self.model_id, "max_tokens": 1024, "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": "Un-fired affordances (observable):\n"
                          + json.dumps(candidates) + "\nPropose discovered abuse scenarios as JSON."}],
        }).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST",
                                     headers={"content-type": "application/json", "x-api-key": self.api_key,
                                              "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        start, end = text.find("{"), text.rfind("}")
        return json.loads(text[start:end + 1]).get("scenarios", []) if start >= 0 else []

    def _materialize(self, target, specs, run_id, log):
        from .agents import _vector
        from .contracts import AbuseScenario, Category, ScenarioSource
        aff_by_id = {a.id: a for a in target.affordances}
        discovered, extra = [], []
        vid = 2000
        for s in specs:
            aff = aff_by_id.get(s.get("affordance_id"))
            if not aff:
                continue
            try:
                cat = Category(s.get("category", aff.category.value))
            except ValueError:
                cat = aff.category
            sc = AbuseScenario(
                id=f"sc.discovered.llm.{aff.id}", category=cat,
                objective=f"LLM-discovered abuse on {aff.kind}", target_affordance_pattern={"kind": aff.kind},
                probe_strategy="discovered_llm", success_criterion=s.get("criterion", {}),
                severity_model={"likelihood": float(s.get("likelihood", 0.5)), "impact": float(s.get("impact", 0.5))},
                source=ScenarioSource.DISCOVERED, recommended_control=s.get("control", "add the missing control"),
                exploitability_reduction=0.7)
            discovered.append(sc)
            vid += 1
            extra.append(_vector(target, aff, sc, f"av:{run_id}:{vid}", {"obs": "llm-discovered"}))
            log("discovered_scenario_llm", {"affordance": aff.id})
        return discovered, extra


def get_model() -> Model:
    if os.environ.get("HEEL_MODEL", "stub").lower() == "anthropic":
        return AnthropicModel()
    return StubModel()
