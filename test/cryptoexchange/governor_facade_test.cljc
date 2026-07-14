(ns cryptoexchange.governor-facade-test
  "Holds the façade to its contract: no decision logic outside the
  kernels. Every façade result is recomputed through the raw kernel
  wire codes (full-matrix parity), and the fail-closed boolean
  conversion at the boundary is pinned in both directions."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.governor :as governor]
            [cryptoexchange.kernels.conservation :as conservation]
            [cryptoexchange.kernels.custody :as custody]
            [cryptoexchange.kernels.solvency :as solvency]))

;; ---------------------------- solvency ------------------------------

(deftest solvency-facade-parity
  (testing "façade == kernel over booleans x amounts (attestation: only
            explicit false is 'not self-issued')"
    (doseq [reserve   [-1 0 99 100 1000]
            liability [-1 0 100]
            attested  [true false nil]]
      (let [flag (if (false? attested) 0 1)
            code (solvency/solvency-verdict reserve liability flag)
            r (governor/solvency-check {:reserve-minor reserve
                                        :liability-minor liability
                                        :self-token? attested})]
        (is (= code (:code r)))
        (is (= (= code 0) (:ok? r)))
        (is (= (not= code 0) (:hard? r)))
        (is (= (= 1 (solvency/halt-intake-flag code)) (:halt-intake? r)))))))

(deftest solvency-nil-attestation-fails-closed
  (testing "omitting :self-token? counts the reserve as self-issued"
    (is (false? (:ok? (governor/solvency-check
                       {:reserve-minor 1000 :liability-minor 1}))))
    (is (true? (:ok? (governor/solvency-check
                      {:reserve-minor 1000 :liability-minor 1
                       :self-token? false}))))))

;; ---------------------------- custody -------------------------------

(deftest withdrawal-facade-parity
  (testing "façade == kernel over booleans x sampled amounts"
    (doseq [allow [true false nil]
            tl    [true false nil]
            ver   [true false nil]
            [hot sigs m] [[0 2 2] [501 2 2] [0 1 1]]
            [amount window cap] [[100 900 1000] [101 900 1000]]]
      (let [code (custody/withdrawal-verdict
                  hot sigs m
                  (if (true? allow) 1 0)
                  (if (true? tl) 1 0)
                  (if (true? ver) 1 0)
                  amount window cap)
            r (governor/withdrawal-check {:hot-bp hot
                                          :quorum-sigs sigs
                                          :quorum-m m
                                          :allowlisted? allow
                                          :timelock-ok? tl
                                          :verifier-match? ver
                                          :amount-minor amount
                                          :window-outflow-minor window
                                          :velocity-cap-minor cap})]
        (is (= code (:code r)))
        (is (= (= code 0) (:allow? r)))
        (is (= (get governor/withdrawal-reasons code) (:reason r)))))))

(deftest withdrawal-nil-permission-denies
  (testing "an unknown permission fact never grants"
    (is (= :destination-not-allowlisted
           (:reason (governor/withdrawal-check
                     {:hot-bp 0 :quorum-sigs 2 :quorum-m 2
                      :timelock-ok? true :verifier-match? true
                      :amount-minor 1 :window-outflow-minor 0
                      :velocity-cap-minor 10}))))))

;; -------------------------- conservation ----------------------------

(deftest conservation-facade-parity
  (doseq [b [-1 0 1000 1001]
          d [0 1500]
          w [0 400]
          f [0 100]]
    (let [code (conservation/conservation-verdict b d w f)
          r (governor/conservation-check {:sum-balances-minor b
                                          :sum-deposits-minor d
                                          :sum-withdrawals-minor w
                                          :sum-fees-minor f})]
      (is (= code (:code r)))
      (is (= (= code 0) (:conserved? r)))
      (is (= (not= code 0) (:hard? r))))))

;; ---------------------------- conflict ------------------------------

(deftest conflict-facade-parity-and-violation-names
  (testing "code recomposes from the named violations (bit weights
            prop=1 self-collateral=2 bypass=4 lending=8)"
    (doseq [p [true false nil]
            s [true false nil]
            b [true false nil]
            l [true false nil]]
      (let [r (governor/conflict-check {:prop-trading? p
                                        :self-token-collateral? s
                                        :privileged-bypass? b
                                        :lending? l})
            weights {:prop-trading 1 :self-token-collateral 2
                     :privileged-bypass 4 :lending 8}]
        (is (= (:code r) (reduce + 0 (map weights (:violations r)))))
        (is (= (:clean? r) (zero? (:code r))))
        (is (= (:hard? r) (pos? (:code r))))))))

(deftest conflict-requires-explicit-attestation
  (testing "a fully-attested clean book is clean; omitting one
            attestation is a violation (fail-closed)"
    (is (true? (:clean? (governor/conflict-check
                         {:prop-trading? false :self-token-collateral? false
                          :privileged-bypass? false :lending? false}))))
    (let [r (governor/conflict-check
             {:prop-trading? false :self-token-collateral? false
              :privileged-bypass? false})]
      (is (false? (:clean? r)))
      (is (= [:lending] (:violations r))))))
