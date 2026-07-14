(ns cryptoexchange.kernels.solvency-test
  "Executable spec for the solvency kernel: battery lock + parity
  matrix against an independent restatement of INV-1/INV-3 in ordinary
  set/cond Clojure (kernels discipline, ADR-2607121200)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.kernels.solvency :as solvency]))

(deftest battery-lock
  (is (= solvency/battery-case-count (solvency/battery-pass-count))
      "every battery case must pass; update battery-case-count only when adding cases"))

;; Independent oracle: INV-1/INV-3 restated without the kernel's
;; integer combinators.
(defn- ref-verdict [reserve liability self-token]
  (cond
    (or (neg? reserve) (neg? liability)) 2
    (< (if (zero? self-token) reserve 0) liability) 1
    :else 0))

(deftest parity-matrix
  (testing "kernel == reference over the full input space (90 combos)"
    (doseq [reserve   [-5 -1 0 1 99 100 1000]
            liability [-1 0 1 100 101]
            flag      [0 1 7]]
      (is (= (ref-verdict reserve liability flag)
             (solvency/solvency-verdict reserve liability flag))
          (str "mismatch at reserve=" reserve " liability=" liability
               " self-token-flag=" flag)))))

(deftest exact-full-reserve-is-solvent
  (testing "reserves == liabilities clears; one minor unit short halts"
    (is (= 0 (solvency/solvency-verdict 100 100 0)))
    (is (= 1 (solvency/solvency-verdict 99 100 0)))))

(deftest self-token-reserves-count-as-zero
  (testing "INV-3: a self-issued token cannot back liabilities (FTT lesson)"
    (is (= 1 (solvency/solvency-verdict 1000000 1 1)))
    (is (= 0 (solvency/effective-reserve 1000000 1)))
    (is (= 0 (solvency/effective-reserve 1000000 7))
        "unknown flag values fail closed to self-issued")))

(deftest withdrawals-not-gated-here
  (testing "halt-intake-flag names INTAKE only (INV-1 keeps withdrawals running)"
    (is (= 0 (solvency/halt-intake-flag 0)))
    (is (= 1 (solvency/halt-intake-flag 1)))
    (is (= 1 (solvency/halt-intake-flag 2)))))
