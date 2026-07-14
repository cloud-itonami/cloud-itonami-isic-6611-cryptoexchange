(ns cryptoexchange.kernels.conflict-test
  "Executable spec for the conflict kernel: battery lock + parity
  matrix against an independent bit-composition restatement of
  INV-2/INV-4 (kernels discipline, ADR-2607121200)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.kernels.conflict :as conflict]))

(deftest battery-lock
  (is (= conflict/battery-case-count (conflict/battery-pass-count))
      "every battery case must pass; update battery-case-count only when adding cases"))

(defn- ref-code [p s b l]
  (+ (if (zero? p) 0 1)
     (if (zero? s) 0 2)
     (if (zero? b) 0 4)
     (if (zero? l) 0 8)))

(deftest parity-matrix
  (testing "kernel == reference over the full input space (81 combos)"
    (doseq [p [0 1 7]
            s [0 1 7]
            b [0 1 7]
            l [0 1 7]]
      (is (= (ref-code p s b l)
             (conflict/conflict-code p s b l))
          (str "mismatch at prop=" p " self-collateral=" s
               " bypass=" b " lending=" l)))))

(deftest every-bit-is-hard
  (testing "any single forbidden structure is a HARD violation"
    (doseq [code [1 2 4 8 3 15]]
      (is (= 1 (conflict/hard-violation-flag code))))
    (is (= 0 (conflict/hard-violation-flag 0)))))
