(ns cryptoexchange.censor-test
  "Executable spec for the ExchangeGovernor (M4). The censor is a pure
  composition of the four safety kernels; these tests pin the routing
  (which kernel gates which op) and the HARD-over-escalate-over-commit
  precedence. Portable — runs under the CLJS primary gate."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.censor :as censor]))

(def ^:private clean-attest
  {:prop-trading? false :self-token-collateral? false
   :privileged-bypass? false :lending? false})

(def ^:private solvent {:reserve-minor 1000 :liability-minor 1000 :self-token? false})
(def ^:private conserved {:sum-balances-minor 100 :sum-deposits-minor 100
                          :sum-withdrawals-minor 0 :sum-fees-minor 0})
(def ^:private good-custody {:hot-bp 100 :quorum-sigs 3 :quorum-m 3
                             :allowlisted? true :timelock-ok? true
                             :verifier-match? true :amount-minor 10
                             :window-outflow-minor 0 :velocity-cap-minor 1000})

(deftest reads-are-clean
  (doseq [op [:balance/report :attestation/report]]
    (let [v (censor/check {:op op} {})]
      (is (:ok? v))
      (is (not (:hard? v)))
      (is (not (:escalate? v))))))

(deftest self-dealing-is-hard-on-every-op
  (testing "conflict attestations gate every op, reads included in spirit —
            a lending operator cannot record deposits or place orders"
    (doseq [op [:deposit/record :order/place :withdrawal/broadcast :adjustment/apply]]
      (let [v (censor/check {:op op}
                            {:attestations (assoc clean-attest :lending? true)
                             :solvency solvent :conservation conserved
                             :custody good-custody})]
        (is (:hard? v) (str op " must HARD-hold on a lending attestation"))
        (is (= [:self-dealing] (mapv :rule (:violations v))))))))

(deftest intake-requires-solvent-conserved-book
  (testing "an insolvent book halts deposit intake (INV-1) — HARD"
    (let [v (censor/check {:op :deposit/record}
                          {:attestations clean-attest
                           :solvency {:reserve-minor 999 :liability-minor 1000 :self-token? false}
                           :conservation conserved})]
      (is (:hard? v))
      (is (some #{:insolvent} (mapv :rule (:violations v))))))
  (testing "a self-issued reserve counts as zero -> insolvent (INV-3)"
    (let [v (censor/check {:op :order/place}
                          {:attestations clean-attest
                           :solvency {:reserve-minor 100000 :liability-minor 1 :self-token? true}
                           :conservation conserved})]
      (is (:hard? v))))
  (testing "a broken conservation book halts intake (INV-6) — HARD"
    (let [v (censor/check {:op :deposit/record}
                          {:attestations clean-attest :solvency solvent
                           :conservation (assoc conserved :sum-balances-minor 999)})]
      (is (:hard? v))
      (is (some #{:conservation-broken} (mapv :rule (:violations v))))))
  (testing "solvency/conservation do NOT gate a withdrawal (that's custody's job)"
    (let [v (censor/check {:op :withdrawal/broadcast}
                          {:attestations clean-attest :custody good-custody})]
      (is (not (:hard? v)))
      (is (:escalate? v) "withdrawal is actuation -> escalate"))))

(deftest withdrawal-custody-denial-is-hard
  (testing "a verifier mismatch (WYSIWYS) cannot be approved past — HARD"
    (let [v (censor/check {:op :withdrawal/broadcast}
                          {:attestations clean-attest
                           :custody (assoc good-custody :verifier-match? false)})]
      (is (:hard? v))
      (is (= [:custody-denied] (mapv :rule (:violations v))))))
  (testing "a single-human quorum policy is denied — HARD (INV-8)"
    (let [v (censor/check {:op :withdrawal/broadcast}
                          {:attestations clean-attest
                           :custody (assoc good-custody :quorum-m 1 :quorum-sigs 1)})]
      (is (:hard? v)))))

(deftest actuation-always-escalates-when-clean
  (testing "a fully-clean withdrawal/adjustment still escalates to a human
            (structural, INV-10 / dual control) — never :ok?"
    (doseq [op [:withdrawal/broadcast :adjustment/apply]]
      (let [v (censor/check {:op op}
                            {:attestations clean-attest :custody good-custody})]
        (is (not (:ok? v)))
        (is (:escalate? v))
        (is (:high-stakes? v)))))
  (testing "HARD dominates the actuation escalation"
    (let [v (censor/check {:op :withdrawal/broadcast}
                          {:attestations (assoc clean-attest :prop-trading? true)
                           :custody good-custody})]
      (is (:hard? v))
      (is (not (:escalate? v))))))

(deftest clean-intake-is-committable
  (testing "clean attestations + solvent + conserved -> :ok? (auto-commit
            eligible, subject to the phase gate)"
    (let [v (censor/check {:op :deposit/record}
                          {:attestations clean-attest :solvency solvent
                           :conservation conserved})]
      (is (:ok? v))
      (is (not (:hard? v)))
      (is (not (:escalate? v))))))
