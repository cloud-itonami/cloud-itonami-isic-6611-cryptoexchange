(ns cryptoexchange.phase-test
  "Executable spec for the rollout phase gate (M4). Pins the structural
  invariant — the actuation ops are never auto-eligible at ANY phase —
  and the phase-widening ladder. Portable (CLJS primary gate)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.phase :as phase]))

(deftest actuation-never-auto-at-any-phase
  (testing "withdrawal broadcast and adjustment never auto-commit, phase 3
            included — the WYSIWYS/dual-control invariant lives here AND in
            the censor (two independent layers)"
    (doseq [p [0 1 2 3]
            op [:withdrawal/broadcast :adjustment/apply]]
      (is (not (contains? (:auto (get phase/phases p)) op))
          (str op " must not be auto-eligible at phase " p)))
    (testing "a governor-clean withdrawal escalates at phase 3 (not commit)"
      (is (= {:disposition :escalate :reason :phase-approval}
             (phase/gate 3 {:op :withdrawal/broadcast} :commit))))))

(deftest reads-pass-through-every-phase
  (doseq [p [0 1 2 3]]
    (is (= :commit (:disposition (phase/gate p {:op :balance/report} :commit))))))

(deftest hold-stays-hold
  (testing "a base HOLD is never widened by the phase gate"
    (doseq [p [0 1 2 3]
            op [:deposit/record :withdrawal/broadcast]]
      (is (= :hold (:disposition (phase/gate p {:op op} :hold)))))))

(deftest phase-widening-ladder
  (testing "phase 0 = read-only: even a clean deposit is phase-disabled"
    (is (= {:disposition :hold :reason :phase-disabled}
           (phase/gate 0 {:op :deposit/record} :commit))))
  (testing "phase 1 enables deposit writes but only via approval"
    (is (= {:disposition :escalate :reason :phase-approval}
           (phase/gate 1 {:op :deposit/record} :commit)))
    (is (= {:disposition :hold :reason :phase-disabled}
           (phase/gate 1 {:op :order/place} :commit))))
  (testing "phase 2 adds trading (still approval)"
    (is (= {:disposition :escalate :reason :phase-approval}
           (phase/gate 2 {:op :order/place} :commit))))
  (testing "phase 3 auto-commits governor-clean deposit/order writes"
    (is (= {:disposition :commit :reason nil}
           (phase/gate 3 {:op :deposit/record} :commit)))
    (is (= {:disposition :commit :reason nil}
           (phase/gate 3 {:op :order/place} :commit)))))

(deftest unknown-phase-falls-back-to-default
  (testing "an out-of-range phase uses default-phase, not more autonomy"
    (is (= (phase/gate phase/default-phase {:op :deposit/record} :commit)
           (phase/gate 99 {:op :deposit/record} :commit)))))

(deftest verdict-to-base-disposition
  (is (= :hold (phase/verdict->disposition {:hard? true})))
  (is (= :escalate (phase/verdict->disposition {:escalate? true})))
  (is (= :commit (phase/verdict->disposition {:ok? true}))))
