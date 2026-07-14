(ns cryptoexchange.store-contract-test
  "The Store contract, run against BOTH backends (M2d of
  ADR-2607141200). Proving MemStore and the Datomic-backed
  (langchain.db) store satisfy the same contract — and produce
  IDENTICAL folds, fills and attestation roots from the same script —
  is what makes 'swap the SSoT for Datomic / kotoba-server' a
  configuration change, not a rewrite. Same pattern as
  `underwriting.store-contract-test` and its siblings."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.attest :as attest]
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.matching :as matching]
            [cryptoexchange.store :as store]))

(defn- backends []
  [["MemStore" (store/mem-store)] ["DatomicStore" (store/datomic-store)]])

(def ^:private ledger-script
  [{:kind :deposit :seq 1 :account :alice :asset :btc :amount-minor 1000}
   {:kind :deposit :seq 2 :account :bob :asset :jpy :amount-minor 500000}
   {:kind :trade :seq 3 :buyer :bob :seller :alice :base :btc :quote :jpy
    :base-amount-minor 400 :quote-amount-minor 200000}
   {:kind :fee :seq 4 :account :bob :asset :btc :amount-minor 4}])

(def ^:private order-script
  [{:kind :order :seq 1 :id :a1 :account :bob :side :sell :price-minor 105 :qty-minor 10}
   {:kind :order :seq 2 :id :a2 :account :carol :side :sell :price-minor 100 :qty-minor 10}
   {:kind :cancel :seq 3 :id :a1 :account :bob}
   {:kind :order :seq 4 :id :b1 :account :alice :side :buy :price-minor 105 :qty-minor 15}])

(deftest empty-store-is-usable
  (doseq [[label s] (backends)]
    (testing label
      (is (= [] (store/ledger-events s)))
      (is (= [] (store/order-events s)))
      (is (= {} (ledger/balances (store/ledger-of s))))
      (is (= matching/empty-book (:book (store/book-of s)))))))

(deftest appends-validate-through-the-domain-folds
  (doseq [[label s] (backends)]
    (testing label
      (testing "valid ledger events persist in total order"
        (doseq [e ledger-script]
          (is (true? (:ok? (store/append-ledger-event! s e)))))
        (is (= ledger-script (store/ledger-events s)))
        (is (= 600 (ledger/balance (store/ledger-of s) :alice :btc))))
      (testing "an event a fresh replay would reject is NEVER persisted"
        (let [r (store/append-ledger-event!
                 s {:kind :withdrawal :seq 5 :account :alice :asset :btc
                    :amount-minor 601})]
          (is (false? (:ok? r)))
          (is (= :insufficient-balance (:reason r))))
        (let [r (store/append-ledger-event!
                 s {:kind :deposit :seq 99 :account :x :asset :btc :amount-minor 1})]
          (is (= :out-of-order (:reason r))))
        (is (= 4 (count (store/ledger-events s))) "rejected events left no trace"))
      (testing "the stored log stays fully third-party-replayable"
        (is (true? (:ok? (ledger/replay (store/ledger-events s))))))
      (testing "conservation holds over the stored log"
        (doseq [asset [:btc :jpy]]
          (is (true? (:conserved? (ledger/conservation-check
                                   (store/ledger-of s) asset)))))))))

(deftest order-log-contract
  (doseq [[label s] (backends)]
    (testing label
      (doseq [e order-script]
        (is (true? (:ok? (store/append-order-event! s e)))
            (str "order event must apply: " e)))
      (testing "self-trade prevention holds at the store boundary too"
        (let [r1 (store/append-order-event!
                  s {:kind :order :seq 5 :id :a3 :account :dave :side :sell
                     :price-minor 200 :qty-minor 1})
              r2 (store/append-order-event!
                  s {:kind :order :seq 6 :id :b2 :account :dave :side :buy
                     :price-minor 200 :qty-minor 1})]
          (is (true? (:ok? r1)))
          (is (= :self-trade-prevented (:reason r2)))
          (is (= 5 (count (store/order-events s))) "rejected order not persisted")))
      (testing "the folded book matches a direct replay of the stored log"
        (let [{:keys [book fills]} (store/book-of s)
              direct (matching/replay-book (store/order-events s))]
          (is (= (:book direct) book))
          (is (= (:fills direct) fills))
          (is (= [:a2] (mapv :maker-id fills)))
          (is (= [100] (mapv :price-minor fills))))))))

(deftest backends-are-fold-identical
  (testing "the same script yields identical events, balances, books,
            fills and attestation roots on both backends"
    (let [[[_ m] [_ d]] (backends)]
      (doseq [s [m d] e ledger-script] (store/append-ledger-event! s e))
      (doseq [s [m d] e order-script] (store/append-order-event! s e))
      (is (= (store/ledger-events m) (store/ledger-events d)))
      (is (= (store/order-events m) (store/order-events d)))
      (is (= (ledger/balances (store/ledger-of m))
             (ledger/balances (store/ledger-of d))))
      (is (= (store/book-of m) (store/book-of d)))
      (let [am (attest/attestation (store/ledger-of m) :btc
                                   {:reserve-minor 996 :self-token? false})
            ad (attest/attestation (store/ledger-of d) :btc
                                   {:reserve-minor 996 :self-token? false})]
        (is (= (:liability-root am) (:liability-root ad)))
        (is (= :ok (get-in am [:solvency :reason])))))))
