(ns cryptoexchange.kernels.custody
  "Safety kernel for INV-8 (distributed custody), INV-9 (withdrawal
  guards) and INV-10 (WYSIWYS signing) of ADR-2607141200 — the decision
  core behind `cryptoexchange.governor/withdrawal-check`, written in
  the safe-kotoba subset (ADR-2607121200): `defn`, `def` constants,
  nested `if`, `=`, `<`, integer arithmetic only.

  All amounts are integer minor units; ratios are integer basis points.

  Wire codes:
    permission flags (allowlist / timelock / verifier-match):
      only EXACT 1 grants; 0, unknown or garbage denies (fail-closed)
    verdict  0 allow
             1 invalid-input   (negative amounts/counts, hot-bp out of
                                the 0..10000 basis-point range)
             2 hot-ratio-exceeded        (hot wallet > hot-cap-bp)
             3 quorum-not-met            (m < min-quorum-m, or sigs < m)
             4 destination-not-allowlisted
             5 timelock-not-met
             6 verifier-mismatch         (WYSIWYS two-path byte compare)
             7 velocity-exceeded         (window outflow + amount > cap)

  Deny codes are resolved in that fixed order; the first failing gate
  names the verdict. Every gate is fail-closed: unknown degrades to
  deny, never to allow.

  Constants (drift-pinned by the test suite):
    hot-cap-bp 500    — cold storage >= 95% (JP PSA-level requirement)
    min-quorum-m 2    — no single human can move funds (QuadrigaCX A6);
                        an M-of-N policy with m < 2 is itself a violation

  Incident traceability: Coincheck/Zaif/BitPoint hot-wallet drains (A4)
  map to codes 1/2; DMM Bitcoin and WazirX/Bybit signing compromises
  (A5) map to codes 4/5/6/7 — an attacker who owns the wallet UI still
  fails the independent payload reconstruction (code 6), and a bulk
  drain trips the absolute velocity cap (code 7)."
  )

;; --------------------------- constants -----------------------------

(def hot-cap-bp 500)
(def min-quorum-m 2)
(def bp-scale 10000)

;; --------------------------- combinators ---------------------------

(defn norm-ok
  "Permission flag: only exact 1 grants (fail-closed)."
  [a]
  (if (= a 1) 1 0))

(defn neg-flag [a] (if (< a 0) 1 0))
(defn or2 [a b] (if (= a 1) 1 (if (= b 1) 1 0)))
(defn or3 [a b c] (or2 a (or2 b c)))

;; ------------------------------ gates -------------------------------

(defn invalid-input-flag
  "1 when any amount/count is negative or hot-bp is outside 0..10000."
  [hot-bp quorum-sigs quorum-m amount-minor window-outflow-minor velocity-cap-minor]
  (or2 (or3 (neg-flag amount-minor)
            (neg-flag window-outflow-minor)
            (neg-flag velocity-cap-minor))
       (or3 (or2 (neg-flag hot-bp) (if (< bp-scale hot-bp) 1 0))
            (neg-flag quorum-sigs)
            (neg-flag quorum-m))))

(defn quorum-ok-flag
  "1 when the M-of-N policy itself is lawful (m >= min-quorum-m) AND
  enough independent signatures were collected (sigs >= m)."
  [quorum-sigs quorum-m]
  (if (< quorum-m min-quorum-m)
    0
    (if (< quorum-sigs quorum-m) 0 1)))

(defn velocity-ok-flag
  "1 when window outflow + this amount stays within the absolute cap."
  [amount-minor window-outflow-minor velocity-cap-minor]
  (if (< velocity-cap-minor (+ window-outflow-minor amount-minor)) 0 1))

(defn withdrawal-verdict
  "Resolve the verdict code, first failing gate wins (order documented
  in the ns docstring)."
  [hot-bp quorum-sigs quorum-m allowlist-flag timelock-flag verifier-flag
   amount-minor window-outflow-minor velocity-cap-minor]
  (if (= 1 (invalid-input-flag hot-bp quorum-sigs quorum-m
                               amount-minor window-outflow-minor velocity-cap-minor))
    1
    (if (< hot-cap-bp hot-bp)
      2
      (if (= 0 (quorum-ok-flag quorum-sigs quorum-m))
        3
        (if (= 0 (norm-ok allowlist-flag))
          4
          (if (= 0 (norm-ok timelock-flag))
            5
            (if (= 0 (norm-ok verifier-flag))
              6
              (if (= 0 (velocity-ok-flag amount-minor window-outflow-minor velocity-cap-minor))
                7
                0))))))))

(defn allow-flag
  "1 only on verdict 0."
  [verdict]
  (if (= verdict 0) 1 0))

;; ----------------------------- battery -----------------------------

(defn check-verdict [hot sigs m allow tl ver amount window cap expected]
  (if (= (withdrawal-verdict hot sigs m allow tl ver amount window cap) expected) 1 0))

(def battery-case-count 22)

(defn battery-pass-count []
  (+
   ;; -- clean allow, hot-cap boundary inclusive
   (check-verdict 500 2 2 1 1 1 100 0 1000 0)
   (check-verdict 0 3 2 1 1 1 100 0 1000 0)
   ;; -- hot ratio: 501 denies, out-of-range bp is invalid input
   (check-verdict 501 2 2 1 1 1 100 0 1000 2)
   (check-verdict 10001 2 2 1 1 1 100 0 1000 1)
   (check-verdict -1 2 2 1 1 1 100 0 1000 1)
   ;; -- quorum: single-human policies are violations even when 'met'
   (check-verdict 500 1 1 1 1 1 100 0 1000 3)
   (check-verdict 500 2 1 1 1 1 100 0 1000 3)
   (check-verdict 500 0 0 1 1 1 100 0 1000 3)
   (check-verdict 500 1 2 1 1 1 100 0 1000 3)
   (check-verdict 500 3 3 1 1 1 100 0 1000 0)
   ;; -- permission flags: only exact 1 grants (fail-closed)
   (check-verdict 500 2 2 0 1 1 100 0 1000 4)
   (check-verdict 500 2 2 7 1 1 100 0 1000 4)
   (check-verdict 500 2 2 1 0 1 100 0 1000 5)
   (check-verdict 500 2 2 1 1 0 100 0 1000 6)
   (check-verdict 500 2 2 1 1 7 100 0 1000 6)
   ;; -- velocity: cap boundary inclusive, +1 denies
   (check-verdict 500 2 2 1 1 1 100 900 1000 0)
   (check-verdict 500 2 2 1 1 1 101 900 1000 7)
   ;; -- invalid amounts fail closed
   (check-verdict 500 2 2 1 1 1 -1 0 1000 1)
   (check-verdict 500 2 2 1 1 1 100 -1 1000 1)
   (check-verdict 500 2 2 1 1 1 100 0 -1 1)
   ;; -- precedence: hot ratio outranks a quorum failure
   (check-verdict 501 0 0 0 0 0 100 0 1000 2)
   ;; -- precedence: invalid input outranks everything
   (check-verdict 10001 0 0 0 0 0 -1 -1 -1 1)))
