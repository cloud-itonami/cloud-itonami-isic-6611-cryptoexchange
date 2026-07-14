# cloud-itonami-isic-6611-cryptoexchange

Open Business Blueprint for an **incident-proof crypto-asset
exchange** — a role-suffix satellite of ISIC 6611 (administration of
financial markets), designed in ADR-2607141200 of the superproject
ledger.

**Maturity: `:blueprint`** — this repository publishes the business
blueprint only. There is **no actor implementation yet**, and none is
claimed. Division 66 sits in **rollout Wave 0
(settlement-information root)** of the reverse-toposort plan
(ADR-2607121000), so implementation is *not* robotics-gated — it is
gated on the M1+ milestones of the design ADR and, permanently, on
INV-14: **no real funds and no real customers until jurisdiction
licensing (e.g. the Japanese Payment Services Act crypto-asset
exchange registration) plus an explicit owner decision.**

## Design premise: incidents first

The design is driven by a register of ten incident classes and maps
each to a verifiable invariant (INV-1..14, full traceability table in
ADR-2607141200):

| Incident class | Representative failures | Killed by |
|---|---|---|
| Customer-asset misuse / commingling | FTX 2022, Celsius | INV-1 full-reserve, INV-2 no-rehypothecation, INV-3 self-token excluded |
| Ledger backdoors / privileged accounts | FTX `allow_negative`, Alameda exemptions | INV-4 zero-privilege, INV-5 append-only balances |
| Concealed insolvency | Mt. Gox 2014 | INV-1 auto-halt, INV-6 conservation, INV-7 PoR **+ PoL** |
| Hot-wallet compromise | Coincheck 2018, Zaif, BitPoint | INV-8 distributed custody (cold ≥ 95%, M-of-N) |
| Signing-operation compromise | DMM Bitcoin 2024, WazirX, Bybit 2025 | INV-9 withdrawal guards, INV-10 WYSIWYS signing |
| Single-person key risk | QuadrigaCX 2019 | INV-8 quorum custody, INV-7 public attestation |
| Exit scam | Thodex, Africrypt | INV-7 public PoR/PoL, open source, public audit log |
| AML/KYC failure | Binance 2023, BitMEX | INV-12 jurisdiction gate + intake screening |
| Market abuse / conflicts | wash trading, insider listing, front-running | INV-11 deterministic matching + public order log, INV-4 |
| Leverage amplification | FTX derivatives, liquidation cascades | INV-13 spot-only full-reserve scope fence |

All fourteen invariants are HARD: enforced by integer-coded,
fail-closed safety kernels (`solvency` / `custody` / `conservation` /
`conflict`, per the Wave-0 kernel discipline of ADR-2607121200) or by
construction (the balance-mutation API simply does not exist), and a
HARD violation cannot be overridden by human approval
(ADR-2607011000-shaped governor contract).

## What the implemented actor will be

**ExchangeOps-LLM ⊣ Crypto-Exchange Governor** — the fleet-standard
pattern: the advisor LLM drafts listings, compliance assessments and
operational runbooks; the independent `:cryptoexchange-governor` (a
keyword unique fleet-wide) gates every action. State lives solely in
an append-only event-sourced ledger (kotoba-datomic); balances and
the order book are pure folds. Withdrawal broadcast happens only
inside the actor's StateGraph after the custody kernel passes, with
`interrupt-before` human sign-off on large amounts — the LLM is never
wired to an actuator (ADR-2607011000).

Deliberately forgone revenue: full-reserve + zero proprietary trading
+ spot-only means fee income only. Structurally renouncing the
FTX-style revenue (customer-asset reuse, leverage) is the point of
this design, not a bug.

Operating states: `intake → quote → match → settle → custody → attest → audit`.

## Why open

AGPL-3.0-or-later, forkable by any qualified operator, so exchange
users never have to trust a closed custodian's word about reserves —
solvency is a published, verifiable artifact. Part of the
[cloud-itonami](https://itonami.cloud) open business fleet.
