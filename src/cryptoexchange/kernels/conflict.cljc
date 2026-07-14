(ns cryptoexchange.kernels.conflict
  "Safety kernel for INV-2 (no rehypothecation) and INV-4 (zero
  privilege / zero proprietary trading) of ADR-2607141200 — the
  decision core behind `cryptoexchange.governor/conflict-check`,
  written in the safe-kotoba subset (ADR-2607121200): `defn`, nested
  `if`, `=`, integer arithmetic only.

  Inputs are ATTESTATION flags: the operator attests, per audit
  window, that each forbidden structure does not exist. Only exact 0
  attests 'does not exist'; anything else — including unknown — is a
  violation (fail-closed: you cannot be silently unsure about whether
  you trade against your own customers).

  Wire codes (verdict is a bit-sum; 0 = clean):
    +1 prop-trading           (exchange trades its own book, A9 / FTX-Alameda A1)
    +2 self-token-collateral  (self-issued token pledged as collateral, A1)
    +4 privileged-bypass      (an account tier bypasses risk checks, A2)
    +8 lending                (customer assets lent/invested/pledged, A1)

  Any nonzero verdict is a HARD violation: human approval cannot
  override it (ADR-2607011000-shaped governor contract), because each
  bit names a structure the blueprint forbids permanently — there is
  no legitimate operational state in which one of these flags is set."
  )

(defn norm-flag
  "Fail-closed attestation: only exact 0 counts as 'structure absent'."
  [a]
  (if (= a 0) 0 1))

(defn conflict-code
  "Bit-sum of the violated invariants; 0 = clean."
  [prop-trading self-token-collateral privileged-bypass lending]
  (+ (* 1 (norm-flag prop-trading))
     (+ (* 2 (norm-flag self-token-collateral))
        (+ (* 4 (norm-flag privileged-bypass))
           (* 8 (norm-flag lending))))))

(defn hard-violation-flag
  "1 on any nonzero code."
  [code]
  (if (= code 0) 0 1))

;; ----------------------------- battery -----------------------------

(defn check-code [p s b l expected]
  (if (= (conflict-code p s b l) expected) 1 0))

(defn check-hard [code expected]
  (if (= (hard-violation-flag code) expected) 1 0))

(def battery-case-count 13)

(defn battery-pass-count []
  (+
   ;; -- clean book
   (check-code 0 0 0 0 0)
   ;; -- each forbidden structure alone
   (check-code 1 0 0 0 1)
   (check-code 0 1 0 0 2)
   (check-code 0 0 1 0 4)
   (check-code 0 0 0 1 8)
   ;; -- combinations compose as bit-sums
   (check-code 1 1 0 0 3)
   (check-code 0 1 0 1 10)
   (check-code 1 1 1 1 15)
   ;; -- fail-closed attestation: garbage/unknown counts as violation
   (check-code 7 0 0 0 1)
   (check-code 0 0 0 9 8)
   ;; -- hard mapping
   (check-hard 0 0)
   (check-hard 1 1)
   (check-hard 15 1)))
