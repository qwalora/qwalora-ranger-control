"""Ranger Phase 2 SOC / OpenSearch SIEM integration.

The broker (this package) is the only component that holds the OpenSearch admin
credential. It normalizes per-candidate telemetry, seeds it into per-candidate
indices, mints candidate-scoped roles and short-lived credentials, and enforces
that a candidate is active, approved, and on the correct board before any access.

Nothing here has been validated against a live OpenSearch cluster yet; the tests
run against an in-process security-enforcing fake. Live validation awaits the
approved node (see ARCHITECTURE.md).
"""
__version__ = "0.1.0"
SCHEMA_VERSION = "ranger-ecs-1"
GENERATOR_VERSION = "siem-telemetry-0.1.0"
