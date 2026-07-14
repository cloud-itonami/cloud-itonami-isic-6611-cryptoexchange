(ns cryptoexchange.kernels.solvency
  "Safety kernel for INV-1 (full-reserve solvency) and INV-3 (self-issued
  tokens count as ZERO reserve) of ADR-2607141200 — the decision core
  behind `cryptoexchange.governor/solvency-check`, written in the
  safe-kotoba subset (cloud-itonami kernels discipline, ADR-2607121200):
  `defn`, `def` constants, nested `if`, `=`, `<`, integer arithmetic
  only. No keywords, strings, maps, atoms, host interop or I/O — the
  façade reduces evidence maps to integer wire codes at the boundary
  and maps result codes back to keywords.

  All amounts are integer minor units (never floats).

  Wire codes:
    self-token-flag  0 = the attested reserve asset is NOT self-issued;
                     anything else (including unknown) counts as
                     self-issued (fail-closed, INV-3)
    verdict          0 solvent-ok
                     1 insolvent (effective reserves < liabilities)
                     2 invalid-amount (negative reserve or liability)
    halt-intake      0 continue  1 halt new deposits/trading

  Fail-closed direction: every invalid or unknown input degrades toward
  HALT, never toward continued intake. The kernel gates INTAKE/TRADING
  only — INV-1 keeps customer withdrawals running on breach; the façade
  and (later) the actor wire the verdict accordingly. A HARD verdict
  here can never be overridden by human approval (ADR-2607011000-shaped
  governor contract).

  Incident traceability: Mt. Gox operated insolvent for years (A3);
  FTX counted its self-issued token as backing (A1). Both map to a
  nonzero verdict here."
  )

;; --------------------------- combinators ---------------------------

(defn norm-flag
  "Fail-closed flag normalization: only exact 0 counts as 'no'."
  [a]
  (if (= a 0) 0 1))

;; ----------------------------- core --------------------------------

(defn effective-reserve
  "Reserves that may count against customer liabilities. A self-issued
  token (flag != 0, INV-3) contributes ZERO regardless of its market
  quote — the FTT lesson."
  [reserve-minor self-token-flag]
  (if (= 0 (norm-flag self-token-flag)) reserve-minor 0))

(defn solvency-verdict
  "0 solvent-ok / 1 insolvent / 2 invalid-amount. Insolvency is decided
  on EFFECTIVE reserves (self-issued tokens excluded)."
  [reserve-minor liability-minor self-token-flag]
  (if (< reserve-minor 0)
    2
    (if (< liability-minor 0)
      2
      (if (< (effective-reserve reserve-minor self-token-flag) liability-minor)
        1
        0))))

(defn halt-intake-flag
  "1 when intake/trading must halt: any nonzero verdict. Withdrawals
  are NOT gated by this flag (INV-1)."
  [verdict]
  (if (= verdict 0) 0 1))

;; ----------------------------- battery -----------------------------
;; Executable spec, kernels-style: each check returns 1 on pass, the
;; battery sums them, and the test suite locks the sum against
;; `battery-case-count` so a silently-skipped case can't pass review.

(defn check-verdict [reserve liability flag expected]
  (if (= (solvency-verdict reserve liability flag) expected) 1 0))

(defn check-halt [verdict expected]
  (if (= (halt-intake-flag verdict) expected) 1 0))

(def battery-case-count 14)

(defn battery-pass-count []
  (+
   ;; -- exact full-reserve boundary: reserves == liabilities is solvent
   (check-verdict 100 100 0 0)
   (check-verdict 99 100 0 1)
   (check-verdict 100 99 0 0)
   ;; -- zero book
   (check-verdict 0 0 0 0)
   (check-verdict 0 1 0 1)
   ;; -- INV-3: self-issued reserves count as zero (FTT lesson)
   (check-verdict 1000 1 1 1)
   (check-verdict 1000 0 1 0)
   ;; -- fail-closed flag normalization: any nonzero flag = self-issued
   (check-verdict 1000 1 7 1)
   ;; -- invalid amounts fail closed
   (check-verdict -1 0 0 2)
   (check-verdict 0 -1 0 2)
   (check-verdict -1 -1 0 2)
   ;; -- halt mapping: only verdict 0 continues intake
   (check-halt 0 0)
   (check-halt 1 1)
   (check-halt 2 1)))
