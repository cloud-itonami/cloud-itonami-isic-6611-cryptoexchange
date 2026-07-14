(ns cryptoexchange.attest-test
  "Executable spec for the M2c PoR/PoL attestation (INV-7 of
  ADR-2607141200): Merkle-sum liability tree, per-user inclusion
  proofs, sum-shrinking rejection, cross-runtime root determinism
  (pinned fixture hash), and the solvency-kernel judgment on the
  public artifact."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.attest :as attest]
            [cryptoexchange.ledger :as ledger]))

(defn- funded-ledger [amounts]
  (:ledger (ledger/replay
            (map-indexed (fn [i [account amount]]
                           {:kind :deposit :seq (inc i) :account account
                            :asset :btc :amount-minor amount})
                         amounts))))

(def ^:private fixture
  (funded-ledger [[:alice 300] [:bob 200] [:carol 100] [:dave 70] [:erin 30]]))

(def ^:private fixture-root-hash
  "Pinned on 2026-07-14 (JVM). The CLJS primary gate must reproduce it
  byte-for-byte — this constant is the cross-runtime determinism lock.
  Re-pinned when the leaf preimage switched to colon-free account/asset
  names (`attest/pname`) so the published JSON is independently
  verifiable — see docs/verify-inclusion.md."
  "8f34cecdd7527c650c312b27c4df2167a68077e219c0cfcec5a5b99a4321f4ca")

(deftest root-sum-is-total-customer-liability
  (let [tree (attest/build-tree fixture :btc)]
    (is (= 700 (get-in tree [:root :sum])))
    (is (= 5 (count (:leaves tree))))
    (is (= [5 3 2 1] (mapv count (:levels tree)))
        "odd node carries up (never duplicated — duplication would double-count sums)")
    (testing "root hash is runtime-independent (pinned)"
      (is (= fixture-root-hash (get-in tree [:root :hash]))))
    (testing "operator balances are NOT customer liabilities"
      (let [l (:ledger (ledger/append fixture {:kind :fee :seq 6 :account :alice
                                               :asset :btc :amount-minor 10}))
            t2 (attest/build-tree l :btc)]
        (is (= 690 (get-in t2 [:root :sum])))))))

(deftest every-account-gets-a-verifying-inclusion-proof
  (doseq [n [1 2 3 4 5]]
    (let [accounts (mapv #(vector (keyword (str "acct" %)) (* 10 (inc %))) (range n))
          l (funded-ledger accounts)
          tree (attest/build-tree l :btc)]
      (doseq [[account amount] accounts]
        (is (true? (attest/verify-inclusion account :btc amount
                                            (attest/inclusion-proof tree account)
                                            (:root tree)))
            (str "proof must verify for " account " in a " n "-leaf tree"))))))

(deftest proofs-reject-lies
  (let [tree (attest/build-tree fixture :btc)
        proof (attest/inclusion-proof tree :alice)
        root (:root tree)]
    (testing "wrong amount, wrong account, negative amount"
      (is (false? (attest/verify-inclusion :alice :btc 299 proof root)))
      (is (false? (attest/verify-inclusion :bob :btc 300 proof root)))
      (is (false? (attest/verify-inclusion :alice :btc -300 proof root))))
    (testing "tampered proof step and shrunken root sum"
      (is (false? (attest/verify-inclusion :alice :btc 300
                                           (assoc-in (vec proof) [0 :sum] 0) root)))
      (is (false? (attest/verify-inclusion :alice :btc 300 proof
                                           (assoc root :sum 500)))))
    (testing "negative sibling sums are rejected outright (sum-shrinking attack)"
      (is (false? (attest/verify-inclusion :alice :btc 300
                                           (assoc-in (vec proof) [0 :sum] -100) root))))
    (testing "an account with no leaf has no proof"
      (is (nil? (attest/inclusion-proof tree :mallory))))))

(deftest attestation-is-judged-by-the-solvency-kernel
  (testing "full reserves, explicitly attested non-self-issued: ok, no halt"
    (let [a (attest/attestation fixture :btc {:reserve-minor 700 :self-token? false
                                              :reserve-refs ["addr:bc1qfixture"]})]
      (is (= :ok (get-in a [:solvency :reason])))
      (is (false? (:halt-intake? a)))
      (is (= 700 (get-in a [:liability-root :sum])))
      (is (= fixture-root-hash (get-in a [:liability-root :hash])))))
  (testing "one minor unit short: insolvent, intake halts (Mt.Gox A3)"
    (let [a (attest/attestation fixture :btc {:reserve-minor 699 :self-token? false})]
      (is (= :insolvent (get-in a [:solvency :reason])))
      (is (true? (:halt-intake? a)))))
  (testing "a huge self-issued reserve counts as zero (FTT lesson, INV-3);
            omitting the attestation fails closed the same way"
    (is (= :insolvent (get-in (attest/attestation fixture :btc
                                                  {:reserve-minor 1000000 :self-token? true})
                              [:solvency :reason])))
    (is (= :insolvent (get-in (attest/attestation fixture :btc
                                                  {:reserve-minor 1000000})
                              [:solvency :reason]))))
  (testing "empty book attests cleanly with the defined empty root"
    (let [a (attest/attestation ledger/empty-ledger :btc
                                {:reserve-minor 0 :self-token? false})]
      (is (= :ok (get-in a [:solvency :reason])))
      (is (= 0 (get-in a [:liability-root :sum]))))))
