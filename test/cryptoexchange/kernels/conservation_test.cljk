(ns cryptoexchange.kernels.conservation-test
  "Executable spec for the conservation kernel: battery lock + parity
  matrix against an independent restatement of INV-5/INV-6 (kernels
  discipline, ADR-2607121200)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.kernels.conservation :as conservation]))

(deftest battery-lock
  (is (= conservation/battery-case-count (conservation/battery-pass-count))
      "every battery case must pass; update battery-case-count only when adding cases"))

(defn- ref-verdict [b d w f]
  (cond
    (or (neg? b) (neg? d) (neg? w) (neg? f)) 2
    (= b (- d w f)) 0
    :else 1))

(deftest parity-matrix
  (testing "kernel == reference over the full input space (256 combos)"
    (doseq [b [-1 0 1000 999]
            d [-1 0 1500 1000]
            w [-1 0 400 500]
            f [-1 0 100 500]]
      (is (= (ref-verdict b d w f)
             (conservation/conservation-verdict b d w f))
          (str "mismatch at balances=" b " deposits=" d
               " withdrawals=" w " fees=" f)))))

(deftest negative-balance-is-invalid-not-broken
  (testing "an aggregate negative balance is the allow_negative backdoor
            signature (FTX A2): verdict 2, never tolerated arithmetic"
    (is (= 2 (conservation/conservation-verdict -1 0 1 0)))))

(deftest off-by-one-minor-unit-breaks
  (is (= 1 (conservation/conservation-verdict 1001 1500 400 100)))
  (is (= 1 (conservation/conservation-verdict 999 1500 400 100)))
  (is (= 0 (conservation/conservation-verdict 1000 1500 400 100))))
