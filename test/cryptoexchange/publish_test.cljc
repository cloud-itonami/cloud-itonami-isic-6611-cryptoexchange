(ns cryptoexchange.publish-test
  "Executable spec for the PoR/PoL artifact builder (INV-7). Pins that
  the artifact carries BOTH sides (liability root + reserves) and every
  user's inclusion proof, that solvency is judged per asset by the
  kernel, and that the published proofs actually verify against the
  published roots."
  (:require [clojure.test :refer [deftest is testing]]
            #?(:clj [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [cryptoexchange.attest :as attest]
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.publish :as publish]))

(def ^:private led
  (:ledger (ledger/replay
            [{:kind :deposit :seq 1 :account :alice :asset :btc :amount-minor 300}
             {:kind :deposit :seq 2 :account :bob :asset :btc :amount-minor 200}
             {:kind :deposit :seq 3 :account :alice :asset :jpy :amount-minor 5000}])))

(def ^:private reserves
  {:btc {:reserve-minor 500 :self-token? false :reserve-refs ["addr:bc1qcold"]}
   :jpy {:reserve-minor 5000 :self-token? false :reserve-refs ["bank:trust-account"]}})

(deftest artifact-carries-both-sides-and-proofs
  (let [a (publish/build-artifact led reserves "2026-07-14T00:00:00Z")
        btc (first (filter #(= :btc (:asset %)) (:assets a)))]
    (is (= :cryptoexchange/attestation (:kind a)))
    (is (true? (:overall-solvent? a)))
    (is (= 500 (get-in btc [:liability-root :sum])) "PoL root sum == total BTC liabilities")
    (is (= 500 (:reserve-minor btc)) "PoR reserve figure present")
    (is (true? (:solvent? btc)))
    (is (= 2 (:leaf-count btc)))
    (is (contains? (:inclusion-proofs btc) :alice))
    (is (contains? (:inclusion-proofs btc) :bob))))

(deftest published-proofs-verify-against-published-roots
  (testing "any user can recompute their leaf to the published root using
            only the artifact — the whole point of PoL"
    (let [a (publish/build-artifact led reserves "t")]
      (doseq [{:keys [asset liability-root inclusion-proofs]} (:assets a)]
        (doseq [[account {:keys [amount proof]}] inclusion-proofs]
          (is (true? (attest/verify-inclusion account asset amount proof liability-root))
              (str account "/" asset " proof must verify against the published root")))))))

(deftest insolvency-shows-up-per-asset
  (testing "a short BTC reserve flips that asset's solvency and the overall flag"
    (let [a (publish/build-artifact led (assoc-in reserves [:btc :reserve-minor] 499) "t")
          btc (first (filter #(= :btc (:asset %)) (:assets a)))]
      (is (false? (:solvent? btc)))
      (is (true? (:halt-intake? btc)))
      (is (false? (:overall-solvent? a)))))
  (testing "a self-issued BTC reserve counts as zero (INV-3)"
    (let [a (publish/build-artifact led (assoc-in reserves [:btc :self-token?] true) "t")
          btc (first (filter #(= :btc (:asset %)) (:assets a)))]
      (is (false? (:solvent? btc))))))

(deftest edn-round-trips
  (let [a (publish/build-artifact led reserves "t")
        s (publish/render-edn a)]
    (is (string? s))
    (is (= a (edn/read-string s)) "canonical EDN artifact round-trips")))

(deftest markdown-summary-shows-both-sides
  (let [md (publish/render-summary-md (publish/build-artifact led reserves "2026-07-14"))]
    (is (re-find #"Proof of Reserves \+ Liabilities" md))
    (is (re-find #"Liability \(PoL root sum\)" md))
    (is (re-find #"Reserves \(PoR\)" md))
    (is (re-find #"liability-root" md))
    (is (re-find #"not a conforming" md))
    (is (re-find #"INV-7" md))))
