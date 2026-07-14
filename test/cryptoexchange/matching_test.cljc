(ns cryptoexchange.matching-test
  "Executable spec for the M2b deterministic matching engine:
  price-time priority, maker price rule, strictest self-trade
  prevention, total order, third-party replay, and the ledger seam
  (INV-11/INV-4 of ADR-2607141200)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.matching :as matching]))

(defn- submit-all [events]
  (let [r (matching/replay-book events)]
    (is (true? (:ok? r)) (str "unexpected reject " (:reason r) " at " (:at r)))
    r))

(def ^:private ask (fn [seq id account price qty]
                     {:kind :order :seq seq :id id :account account
                      :side :sell :price-minor price :qty-minor qty}))
(def ^:private bid (fn [seq id account price qty]
                     {:kind :order :seq seq :id id :account account
                      :side :buy :price-minor price :qty-minor qty}))

(deftest price-time-priority-and-maker-price
  (testing "better price fills first; equal price fills oldest first;
            every fill executes at the RESTING order's price"
    (let [{:keys [fills]} (submit-all
                           [(ask 1 :a1 :alice 105 10)
                            (ask 2 :a2 :bob 100 10)
                            (ask 3 :a3 :carol 100 10)
                            (bid 4 :b1 :dave 105 25)])]
      (is (= [:a2 :a3 :a1] (mapv :maker-id fills))
          "100 (bob, older) -> 100 (carol) -> 105 (alice)")
      (is (= [100 100 105] (mapv :price-minor fills))
          "maker price rule: taker paying up to 105 still fills the 100s at 100")
      (is (= [10 10 5] (mapv :qty-minor fills))))))

(deftest partial-fills-rest-and-keep-time-priority
  (let [{:keys [book fills]} (submit-all
                              [(bid 1 :b1 :alice 100 10)
                               (ask 2 :a1 :bob 100 4)])]
    (is (= [{:maker-id :b1 :qty 4}]
           (mapv #(hash-map :maker-id (:maker-id %) :qty (:qty-minor %)) fills)))
    (testing "the partially-filled resting bid keeps its original :seq
              (time priority is not reset by a partial fill)"
      (is (= [{:id :b1 :qty-minor 6 :seq 1}]
             (mapv #(select-keys % [:id :qty-minor :seq]) (:bids book))))))
  (testing "an unfilled remainder of a taker rests on its own side"
    (let [{:keys [book]} (submit-all
                          [(ask 1 :a1 :bob 100 4)
                           (bid 2 :b1 :alice 100 10)])]
      (is (= [{:id :b1 :qty-minor 6}]
             (mapv #(select-keys % [:id :qty-minor]) (:bids book))))
      (is (empty? (:asks book))))))

(deftest no-cross-no-fill
  (let [{:keys [book fills]} (submit-all
                              [(ask 1 :a1 :bob 101 10)
                               (bid 2 :b1 :alice 100 10)])]
    (is (empty? fills))
    (is (= 1 (count (:asks book))))
    (is (= 1 (count (:bids book))))))

(deftest self-trade-prevention-rejects-the-taker
  (testing "an incoming order whose crossing region contains ANY own
            resting order is rejected before a single fill (A9)"
    (let [r (matching/replay-book
             [(ask 1 :a1 :bob 100 10)
              (ask 2 :a2 :alice 101 10)
              (bid 3 :b1 :alice 101 25)])]
      (is (false? (:ok? r)))
      (is (= :self-trade-prevented (:reason r)))
      (is (= 3 (:at r)))
      (testing "the book is left exactly as it was (bob was NOT filled first)"
        (is (= [:a1 :a2] (mapv :id (:asks (:book r)))))
        (is (= [10 10] (mapv :qty-minor (:asks (:book r)))))
        (is (empty? (:fills r)))))))

(deftest total-order-and-validation
  (let [{:keys [book]} (submit-all [(ask 1 :a1 :bob 100 10)])]
    (is (= :out-of-order (:reason (matching/submit book (ask 3 :x :alice 100 1)))))
    (is (= :duplicate-id (:reason (matching/submit book (ask 2 :a1 :alice 100 1)))))
    (is (= :malformed (:reason (matching/submit book (ask 2 :a2 :alice 0 1)))))
    (is (= :malformed (:reason (matching/submit book (ask 2 :a3 :alice 100 0)))))
    (is (= :malformed (:reason (matching/submit book {:kind :order :seq 2 :id :a4
                                                      :account :alice :side :short
                                                      :price-minor 1 :qty-minor 1}))))))

(deftest cancel-is-owner-only
  (let [{:keys [book]} (submit-all [(ask 1 :a1 :bob 100 10)])]
    (is (= :not-owner (:reason (matching/cancel-order book {:kind :cancel :seq 2 :id :a1 :account :alice}))))
    (is (= :unknown-order (:reason (matching/cancel-order book {:kind :cancel :seq 2 :id :zzz :account :bob}))))
    (let [r (matching/cancel-order book {:kind :cancel :seq 2 :id :a1 :account :bob})]
      (is (true? (:ok? r)))
      (is (empty? (:asks (:book r))))
      (is (= 2 (:last-seq (:book r)))))))

(deftest replay-is-deterministic
  (let [log [(ask 1 :a1 :bob 105 10)
             (bid 2 :b1 :alice 90 5)
             (ask 3 :a2 :carol 100 7)
             {:kind :cancel :seq 4 :id :b1 :account :alice}
             (bid 5 :b2 :dave 105 12)]
        r1 (submit-all log)
        r2 (submit-all log)]
    (testing "same log -> byte-identical book and fills, twice"
      (is (= (:book r1) (:book r2)))
      (is (= (:fills r1) (:fills r2))))
    (testing "the walk crossed two price levels in priority order"
      (is (= [:a2 :a1] (mapv :maker-id (:fills r1))))
      (is (= [100 105] (mapv :price-minor (:fills r1)))))))

(deftest fills-settle-on-the-ledger-and-conserve
  (testing "engine fills map to ledger :trade events; the funded book
            settles and every asset conserves (M2a seam)"
    (let [{:keys [fills]} (submit-all [(ask 1 :a1 :bob 3 100)
                                       (bid 2 :b1 :alice 3 100)])
          market {:base :btc :quote :jpy}
          funded (reduce (fn [l e] (:ledger (ledger/append l e)))
                         ledger/empty-ledger
                         [{:kind :deposit :seq 1 :account :bob :asset :btc :amount-minor 100}
                          {:kind :deposit :seq 2 :account :alice :asset :jpy :amount-minor 300}])
          settled (reduce (fn [l [i fill]]
                            (let [r (ledger/append l (matching/fill->trade-event
                                                      fill market (+ 3 i)))]
                              (is (:ok? r) (str "settlement rejected: " (:reason r)))
                              (:ledger r)))
                          funded
                          (map-indexed vector fills))]
      (is (= 100 (ledger/balance settled :alice :btc)))
      (is (= 300 (ledger/balance settled :bob :jpy)))
      (doseq [asset [:btc :jpy]]
        (is (true? (:conserved? (ledger/conservation-check settled asset))))))))
