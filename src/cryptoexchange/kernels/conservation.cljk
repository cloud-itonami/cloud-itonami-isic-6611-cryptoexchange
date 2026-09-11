(ns cryptoexchange.kernels.conservation
  "Safety kernel for INV-5/INV-6 (append-only balances + conservation)
  of ADR-2607141200 — the decision core behind
  `cryptoexchange.governor/conservation-check`, written in the
  safe-kotoba subset (ADR-2607121200): `defn`, nested `if`, `=`, `<`,
  integer arithmetic only.

  All sums are per-asset aggregates in integer minor units, computed by
  the caller as pure folds of the append-only event log (INV-5 — the
  ledger has no mutation API, so these inputs are reproducible by any
  third party from the same log).

  Wire codes:
    verdict  0 conserved
             1 broken          (balances != deposits - withdrawals - fees)
             2 invalid-amount  (any negative aggregate)

  A negative aggregate balance is classified as INVALID rather than
  merely broken: the only way a total balance goes negative is an
  FTX-style `allow_negative` backdoor or a corrupted fold — both demand
  a halt + investigation, not arithmetic tolerance (A2).

  Fail-closed direction: every nonzero verdict halts intake/trading
  (same wiring as the solvency kernel; withdrawals continue per INV-1)."
  )

(defn neg-flag [a] (if (< a 0) 1 0))
(defn or2 [a b] (if (= a 1) 1 (if (= b 1) 1 0)))

(defn invalid-input-flag
  [sum-balances sum-deposits sum-withdrawals sum-fees]
  (or2 (or2 (neg-flag sum-balances) (neg-flag sum-deposits))
       (or2 (neg-flag sum-withdrawals) (neg-flag sum-fees))))

(defn conservation-verdict
  "0 conserved / 1 broken / 2 invalid-amount."
  [sum-balances sum-deposits sum-withdrawals sum-fees]
  (if (= 1 (invalid-input-flag sum-balances sum-deposits sum-withdrawals sum-fees))
    2
    (if (= sum-balances (- sum-deposits sum-withdrawals sum-fees))
      0
      1)))

(defn broken-flag
  "1 on any nonzero verdict."
  [verdict]
  (if (= verdict 0) 0 1))

;; ----------------------------- battery -----------------------------

(defn check-verdict [b d w f expected]
  (if (= (conservation-verdict b d w f) expected) 1 0))

(defn check-broken [verdict expected]
  (if (= (broken-flag verdict) expected) 1 0))

(def battery-case-count 12)

(defn battery-pass-count []
  (+
   ;; -- conserved books
   (check-verdict 1000 1500 400 100 0)
   (check-verdict 0 0 0 0 0)
   (check-verdict 0 500 400 100 0)
   ;; -- broken by one minor unit, both directions
   (check-verdict 1001 1500 400 100 1)
   (check-verdict 999 1500 400 100 1)
   ;; -- negative aggregates are INVALID (allow_negative backdoor, A2)
   (check-verdict -1 0 0 0 2)
   (check-verdict 0 -1 0 0 2)
   (check-verdict 0 0 -1 0 2)
   (check-verdict 0 0 0 -1 2)
   ;; -- halt mapping
   (check-broken 0 0)
   (check-broken 1 1)
   (check-broken 2 1)))
