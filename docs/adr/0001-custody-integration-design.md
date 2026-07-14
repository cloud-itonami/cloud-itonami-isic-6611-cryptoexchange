# ADR-0001: Custody integration — detailed design (M3, no real funds)

**Status**: accepted (design-only — INV-14 keeps real funds/keys out of scope
until jurisdiction licensing plus an explicit owner decision)
**Date**: 2026-07-14
**Parent**: superproject ADR-2607141200 (design), ADR-2607121200 (kernel discipline)

## Scope

This document fixes HOW the custody invariants (INV-8/9/10) become an
operable key-management design: scheme selection, key ceremony,
recovery governance, the WYSIWYS signing runbook, and the mapping from
operational reality onto the `cryptoexchange.kernels.custody` wire
codes. It deliberately handles **no real funds and no real keys** —
every procedure below is exercisable end-to-end on testnets with
throwaway keys before INV-14 ever opens.

## 1. Scheme selection

Decision: **on-chain verifiable multisig for cold storage; minimal
per-chain multisig for the small hot tier; MPC-TSS deferred.**

| Tier | Scheme | Quorum | Why |
|---|---|---|---|
| Cold (≥95%, INV-8) | BTC: descriptor multisig P2WSH/P2TR (miniscript). ETH: Safe v1.4+ contracts | 3-of-5 | **Publicly verifiable**: the quorum policy itself is on-chain, so PoR reserve addresses (M2c `:reserve-refs`) prove not just balances but *that no single person can move them* — QuadrigaCX (A6) is refuted by the address format, not by our word |
| Hot (≤5% hard cap) | per-chain native 2-of-3 multisig, hardware-backed | 2-of-3 | Small enough (hot-cap + velocity caps) that losing it is survivable; simplicity beats MPC operational complexity at this size |
| MPC-TSS | deferred | — | Open-source candidates evaluated (ZF FROST for Schnorr chains, dfns cggmp21 / Binance tss-lib for ECDSA). Adopt only when a chain offers no native multisig or hot-tier ops demonstrably need it. **No closed-SaaS custody (Fireblocks-class) as a design premise** — AGPL fleet, data sovereignty, and the PoR verifiability argument all prefer schemes the public can check |

Bybit 2025 (A5) is the governing counterexample for "contracts are
enough": the Safe *contracts* held; the **signing procedure** failed
(UI-rendered payloads, blind signing). Scheme choice therefore matters
less than §4 — the WYSIWYS runbook applies identically to every tier
and every scheme.

## 2. Key ceremony (cold tier)

- **Participants**: 5 keyholders, organizationally and geographically
  distinct; no two shares in the same building, no two keyholders in
  the same reporting line. m=3 (kernel `min-quorum-m` ≥ 2 is the HARD
  floor; 3-of-5 is the operating policy).
- **Generation**: each key generated ON the keyholder's own air-gapped
  signer (Coldcard/SeedSigner class, stock open-source firmware,
  supply-chain-verified). Only xpubs/descriptors leave the device —
  **no key material is ever assembled in one place, at any time,
  including during the ceremony** (the anti-QuadrigaCX property is
  established at birth, not by later policy).
- **Backup**: per-keyholder SLIP-39 (or steel-plate) shards in
  separate jurisdictions; a shard alone reconstructs nothing.
- **Record**: the ceremony is minuted (who, device serials, firmware
  hashes, resulting descriptor) and the descriptor + attestation are
  committed to the audit ledger — the ceremony record is itself an
  event, third-party checkable against the on-chain addresses.

## 3. Recovery governance (dead-man path)

- BTC: miniscript timelocked alternate spend path — after ~6 months of
  on-chain inactivity (`older(26280)` blocks), an alternate 4-of-7
  recovery quorum (superset: original holders + escrow trustees)
  becomes valid. **The dead-man switch is enforced by the chain, not
  by a promise.**
- ETH: Safe recovery module with an equivalent timelock + alternate
  quorum, plus a cancel path for the primary quorum (a live quorum can
  always pre-empt recovery).
- Any recovery activation is, by definition, an incident: it halts
  intake (operationally wired to the same halt as INV-1) and is
  publicly visible on-chain.

## 4. WYSIWYS signing runbook (INV-10 — the Bybit/DMM/WazirX countermeasure)

The kernel's `verifier-match-flag` is set to 1 **only** by this
procedure; nothing else may set it:

1. A withdrawal proposal exists only as an approved effect from the
   propose→approve queue (parent ADR §6) — signers never originate
   transfers.
2. **Two independent verifier implementations** (separate codebases,
   separate maintainers; V-A: CLJS decoder, V-B: kernel-subset/other-
   language decoder) each reconstruct the signing payload **from the
   raw unsigned transaction bytes** — never from a wallet UI, web
   page, or PSBT metadata field — and each independently derive:
   destination, asset, amount, fee, change address, and (ETH) the full
   EIP-712 domain + struct hash.
   > **Implemented (BTC), 2026-07-14**: `cryptoexchange.wysiwys-btc`
   > parses a real raw unsigned Bitcoin tx back to its
   > `(destination address, value)` outputs (P2WPKH/P2WSH/P2TR/P2PKH/
   > P2SH), reusing `kotoba-lang/btc-crypto`'s bech32/base58 encoders
   > for the script→address step it must invert; an unrecognized
   > script fails closed. JVM-only (btc-crypto is `byte-array`-based),
   > which suits the JVM actuation boundary. **ETH (2026-07-14)**:
   > `cryptoexchange.wysiwys-eth` parses a raw unsigned ETH tx
   > (legacy / EIP-2930 / EIP-1559) back to its `(to, value)`, adding
   > the RLP DECODE direction on top of `kotoba-lang/eth-crypto`'s
   > rlp-encode + EIP-55; a Safe-multisig `execTransaction` SafeTx
   > struct-hash path (the real destination inside calldata) is the
   > remaining follow-up and fails closed until then. The
   > two-independent-toolchain requirement above is the
   > production goal; the shipped decoder is one real verifier plus the
   > portable `cryptoexchange.wysiwys` stand-in for the byte-compare
   > discipline.
3. Both derivations are byte-compared (digest equality). Any mismatch
   → `verifier-match-flag` stays 0 → kernel code 6, no signature is
   produced, incident review opens. A compromised wallet UI (Bybit)
   or a compromised signing workstation (DMM) must now compromise two
   independent toolchains *and* the air-gapped display to win.
4. Each signer confirms the derived (not rendered) destination/amount
   on their own device screen before signing. Devices sign the raw
   payload; signatures reunite only at broadcast.
5. Broadcast happens only after the custody kernel returns 0 over the
   full wire-code row (§5) — quorum, allowlist, timelock, velocity and
   hot-cap included — inside the actor's StateGraph with
   interrupt-before human sign-off above tier thresholds.

## 5. Kernel wire-code mapping (design → code, drift-pinned by tests)

| Kernel input | Operational source |
|---|---|
| `hot-bp` | hot-tier reserves ÷ total reserves, basis points, from the daily M2c attestation inputs; operating target ≤300, HARD cap 500 (= cold ≥95%, JP PSA level) |
| `quorum-sigs` / `quorum-m` | signatures collected ÷ policy quorum (cold 3-of-5, hot 2-of-3); `min-quorum-m` 2 is the kernel floor — a 1-of-N policy is a violation even if "met" |
| `allowlist-flag` | destination ∈ allowlist registry; additions land only via propose→approve effects with a 48h cooling period (no same-day allowlist-then-drain) |
| `timelock-ok` | broadcast time ≥ proposal time + tier delay (large withdrawals: 24h; recovery paths: chain-enforced) |
| `verifier-match-flag` | §4 byte-equality, set by the dual-verifier procedure only |
| `window-outflow` / `velocity-cap` | 24h rolling outflow per asset, folded from the M2a ledger vs per-asset absolute caps (DMM lesson: a bulk drain trips code 7 regardless of signatures) |

## 6. Non-goals (permanent unless a new ADR says otherwise)

- No real funds, keys, or mainnet custody until INV-14 opens (license
  + owner decision). Testnet rehearsal of §2–§4 is the M3 exit
  criterion when implementation begins.
- No browser-extension or hot-workstation signing, ever.
- No closed-SaaS custody dependency as a premise.
- No reuse of exchange operator keys for any other fleet system.
