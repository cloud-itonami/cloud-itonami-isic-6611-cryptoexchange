# Governance

Maintained by the cloud-itonami org (gftdcojp). Decisions land as ADRs in the
superproject ledger (design ADR: ADR-2607141200). The actor pattern
(advisor-LLM sealed behind an independent governor, append-only audit ledger)
is non-negotiable per ADR-2607011000: the governor gates every action, HARD
invariant violations cannot be overridden by human approval, and withdrawal
actuation above thresholds requires human sign-off. INV-14 (no real funds /
real customers without jurisdiction licensing plus an explicit owner decision)
is a permanent operational gate, not a milestone.
