(ns cryptoexchange.kernels.custody-test
  "Executable spec for the custody kernel: battery lock, constant
  drift pins, and a parity matrix against an independent cond/set
  restatement of INV-8/INV-9/INV-10 over the full sampled input space
  (kernels discipline, ADR-2607121200)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.kernels.custody :as custody]))

(deftest battery-lock
  (is (= custody/battery-case-count (custody/battery-pass-count))
      "every battery case must pass; update battery-case-count only when adding cases"))

(deftest constants-pinned
  (testing "hot-cap 500bp == the documented cold >= 95% (JP PSA level)"
    (is (= 500 custody/hot-cap-bp))
    (is (= 9500 (- custody/bp-scale custody/hot-cap-bp))))
  (testing "min quorum 2 == the no-single-human invariant (QuadrigaCX A6)"
    (is (= 2 custody/min-quorum-m))))

;; Independent oracle: the deny ladder restated as ordinary cond over
;; the same wire codes.
(defn- ref-verdict [hot sigs m allow tl ver amount window cap]
  (cond
    (or (neg? amount) (neg? window) (neg? cap)
        (neg? hot) (> hot 10000) (neg? sigs) (neg? m)) 1
    (> hot 500) 2
    (or (< m 2) (< sigs m)) 3
    (not= allow 1) 4
    (not= tl 1) 5
    (not= ver 1) 6
    (> (+ window amount) cap) 7
    :else 0))

(deftest parity-matrix
  (testing "kernel == reference over the sampled input space (15120 combos)"
    (doseq [hot   [-1 0 499 500 501 10000 10001]
            sigs  [0 1 2 3]
            m     [0 1 2 3]
            allow [0 1 7]
            tl    [0 1 7]
            ver   [0 1 7]
            [amount window cap] [[0 0 0]
                                 [100 900 1000]
                                 [101 900 1000]
                                 [-1 0 1000]
                                 [1 0 0]]]
      (is (= (ref-verdict hot sigs m allow tl ver amount window cap)
             (custody/withdrawal-verdict hot sigs m allow tl ver amount window cap))
          (str "mismatch at hot=" hot " sigs=" sigs " m=" m
               " allow=" allow " tl=" tl " ver=" ver
               " amount=" amount " window=" window " cap=" cap)))))

(deftest single-human-custody-is-a-violation-everywhere
  (testing "an m<2 policy denies even with sigs collected (INV-8)"
    (doseq [sigs [1 2 3 100]]
      (is (= 3 (custody/withdrawal-verdict 0 sigs 1 1 1 1 0 0 0))))))

(deftest wysiwys-cannot-be-satisfied-by-garbage
  (testing "verifier-match grants only on exact 1 — a compromised UI
            reporting a nonzero-but-wrong flag still denies (Bybit A5)"
    (is (= 6 (custody/withdrawal-verdict 0 2 2 1 1 7 0 0 0)))
    (is (= 6 (custody/withdrawal-verdict 0 2 2 1 1 0 0 0 0)))))
