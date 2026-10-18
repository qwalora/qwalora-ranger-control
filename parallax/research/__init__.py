"""PARALLAX Phase 2A - controlled AI-security research harness (LLM/RAG prompt-injection).

A provider-independent framework for conducting REAL, reproducible prompt-injection experiments against
an authorized, locally-executable language model behind a bounded RAG application. Every component is
genuine (deterministic retrieval, real trust-boundary prompt construction, rule-based objective
evaluation, machine-readable signed evidence). The ONE externally-dependent component is the model
backend: when an authorized real model endpoint is configured it runs genuine experiments
(`backend_provenance == "infrastructure_backed"`); otherwise a transparent deterministic stub exercises
the harness plumbing ONLY (`backend_provenance == "simulated"`) and its outputs are NEVER empirical
findings.

Honest status in the current environment: no real model can be executed (model-weight sources are
blocked by the egress allowlist, there is no GPU, and paid inference APIs are prohibited), so the real
experimental campaign is OPEN and Phase 2A is PARTIAL. See docs/PARALLAX_PHASE_2A_ENGINEERING_REPORT.md.
"""

HARNESS_VERSION = "2A.1"
