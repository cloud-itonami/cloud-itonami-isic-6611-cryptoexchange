(ns cryptoexchange.governor
  "Keyword/map façade over the four safety kernels of ADR-2607141200.
  The kernels DECIDE; this ns only reduces evidence maps to integer
  wire codes at the boundary and maps result codes back to keywords
  (ADR-2607121200 façade discipline — no decision logic may live
  here; the parity tests hold this ns to that contract).

  Fail-closed boolean conversion at the boundary:
    - permission facts (:allowlisted? :timelock-ok? :verifier-match?)
      grant only on explicit `true`; nil/unknown denies.
    - attestation facts (:prop-trading? :self-token-collateral?
      :privileged-bypass? :lending? :self-token?) are clean only on
      explicit `false`; nil/unknown is a violation. You must attest
      the absence of a forbidden structure, not merely omit the key.

  Every :hard? result is human-un-overridable (ADR-2607011000-shaped
  governor contract): the (future) actor may narrow what it does on
  top of these verdicts, never widen."
  (:require [cryptoexchange.kernels.conflict :as conflict]
            [cryptoexchange.kernels.conservation :as conservation]
            [cryptoexchange.kernels.custody :as custody]
            [cryptoexchange.kernels.solvency :as solvency]))

;; ------------------------ boundary conversion -----------------------

(defn- permission-flag
  "Only explicit true grants (fail-closed)."
  [x]
  (if (true? x) 1 0))

(defn- attestation-flag
  "Only explicit false attests absence (fail-closed)."
  [x]
  (if (false? x) 0 1))

;; ------------------------------ solvency ----------------------------

(def solvency-reasons
  {0 :ok 1 :insolvent 2 :invalid-amount})

(defn solvency-check
  "INV-1/INV-3. `:self-token?` is an attestation fact: nil counts as
  self-issued. On any non-:ok reason, intake and trading halt while
  withdrawals continue (INV-1) — :hard? is true and cannot be
  approved away."
  [{:keys [reserve-minor liability-minor self-token?]}]
  (let [code (solvency/solvency-verdict reserve-minor liability-minor
                                        (attestation-flag self-token?))]
    {:code code
     :reason (get solvency-reasons code)
     :ok? (= code 0)
     :halt-intake? (= 1 (solvency/halt-intake-flag code))
     :hard? (not= code 0)}))

;; ------------------------------ custody -----------------------------

(def withdrawal-reasons
  {0 :allow
   1 :invalid-amount
   2 :hot-ratio-exceeded
   3 :quorum-not-met
   4 :destination-not-allowlisted
   5 :timelock-not-met
   6 :verifier-mismatch
   7 :velocity-exceeded})

(defn withdrawal-check
  "INV-8/INV-9/INV-10. Permission facts grant only on explicit true.
  A denial is HARD at this layer: collecting the missing fact (another
  signature, the elapsed timelock) and re-proposing is the only way
  through — approving over a mismatch is not."
  [{:keys [hot-bp quorum-sigs quorum-m allowlisted? timelock-ok?
           verifier-match? amount-minor window-outflow-minor
           velocity-cap-minor]}]
  (let [code (custody/withdrawal-verdict
              hot-bp quorum-sigs quorum-m
              (permission-flag allowlisted?)
              (permission-flag timelock-ok?)
              (permission-flag verifier-match?)
              amount-minor window-outflow-minor velocity-cap-minor)]
    {:code code
     :reason (get withdrawal-reasons code)
     :allow? (= 1 (custody/allow-flag code))
     :hard? (not= code 0)}))

;; ---------------------------- conservation --------------------------

(def conservation-reasons
  {0 :conserved 1 :broken 2 :invalid-amount})

(defn conservation-check
  "INV-5/INV-6. Inputs are per-asset pure folds of the append-only
  event log; any third party can recompute them from the same log."
  [{:keys [sum-balances-minor sum-deposits-minor sum-withdrawals-minor
           sum-fees-minor]}]
  (let [code (conservation/conservation-verdict
              sum-balances-minor sum-deposits-minor
              sum-withdrawals-minor sum-fees-minor)]
    {:code code
     :reason (get conservation-reasons code)
     :conserved? (= code 0)
     :halt-intake? (= 1 (conservation/broken-flag code))
     :hard? (not= code 0)}))

;; ------------------------------ conflict ----------------------------

(defn conflict-check
  "INV-2/INV-4. Attestation facts are clean only on explicit false;
  every violation bit is permanent-structure-forbidden, so :hard? on
  any nonzero code."
  [{:keys [prop-trading? self-token-collateral? privileged-bypass?
           lending?]}]
  (let [p (attestation-flag prop-trading?)
        s (attestation-flag self-token-collateral?)
        b (attestation-flag privileged-bypass?)
        l (attestation-flag lending?)
        code (conflict/conflict-code p s b l)]
    {:code code
     :violations (into []
                       (concat (if (= 1 p) [:prop-trading] [])
                               (if (= 1 s) [:self-token-collateral] [])
                               (if (= 1 b) [:privileged-bypass] [])
                               (if (= 1 l) [:lending] [])))
     :clean? (= code 0)
     :hard? (= 1 (conflict/hard-violation-flag code))}))
