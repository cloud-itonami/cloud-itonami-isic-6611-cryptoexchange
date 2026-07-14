# Security Policy

This repository currently contains a business blueprint only (no running
actor, no credentials, no customer funds, no personal data). If a future
implementation introduces vulnerabilities, report privately to
root@junkawasaki.com. Do not open public issues for security reports.

Design-level security invariants (custody quorum, WYSIWYS signing,
withdrawal guards, solvency auto-halt) are specified in ADR-2607141200 and
in `blueprint.edn` — critiques of those invariants are welcome as issues,
since they are design, not exploitable surface.
