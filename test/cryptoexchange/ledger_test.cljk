(ns cryptoexchange.ledger-test
  "Executable spec for the M2a event-sourced ledger: append-only
  construction, balances as pure folds, no negative balances by
  construction, dual-control adjustments, and the conservation-kernel
  seam (INV-5/INV-6 of ADR-2607141200)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.governor :as governor]
            [cryptoexchange.ledger :as ledger]))

(defn- append-all
  "Append events, asserting each one is accepted."
  [events]
  (reduce (fn [l e]
            (let [r (ledger/append l e)]
              (is (:ok? r) (str "unexpected reject " (:reason r) " at " e))
              (:ledger r)))
          ledger/empty-ledger
          events))

(def ^:private happy-path
  [{:kind :deposit :seq 1 :account :alice :asset :btc :amount-minor 1000}
   {:kind :deposit :seq 2 :account :bob :asset :jpy :amount-minor 500000}
   {:kind :trade :seq 3 :buyer :bob :seller :alice :base :btc :quote :jpy
    :base-amount-minor 400 :quote-amount-minor 200000}
   {:kind :fee :seq 4 :account :bob :asset :btc :amount-minor 4}
   {:kind :withdrawal :seq 5 :account :alice :asset :jpy :amount-minor 150000}])

(deftest balances-are-pure-folds
  (let [l (append-all happy-path)]
    (testing "post-trade, post-fee, post-withdrawal book"
      (is (= 600 (ledger/balance l :alice :btc)))
      (is (= 50000 (ledger/balance l :alice :jpy)))
      (is (= 396 (ledger/balance l :bob :btc)))
      (is (= 300000 (ledger/balance l :bob :jpy)))
      (is (= 4 (ledger/balance l ledger/operator-account :btc))))
    (testing "folding twice gives the same book (no hidden state)"
      (is (= (ledger/balances l) (ledger/balances l))))))

(deftest conservation-holds-on-every-asset
  (let [l (append-all happy-path)]
    (doseq [asset [:btc :jpy]]
      (let [r (ledger/conservation-check l asset)]
        (is (true? (:conserved? r)) (str asset " must conserve: " r))))
    (testing "trade legs are zero-sum per asset (customer sums move only
              via deposit/withdrawal/fee)"
      (is (= 996 (:sum-balances-minor (ledger/conservation-sums l :btc))))
      (is (= 350000 (:sum-balances-minor (ledger/conservation-sums l :jpy)))))))

(deftest total-order-is-enforced
  (let [l (append-all [{:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 10}])]
    (is (= :out-of-order (:reason (ledger/append l {:kind :deposit :seq 3 :account :a :asset :btc :amount-minor 1}))))
    (is (= :out-of-order (:reason (ledger/append l {:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 1}))))
    (is (:ok? (ledger/append l {:kind :deposit :seq 2 :account :a :asset :btc :amount-minor 1})))))

(deftest no-negative-balances-by-construction
  (let [l (append-all [{:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 100}])]
    (testing "overdrawing withdrawal / fee / trade legs are rejected"
      (is (= :insufficient-balance
             (:reason (ledger/append l {:kind :withdrawal :seq 2 :account :a :asset :btc :amount-minor 101}))))
      (is (= :insufficient-balance
             (:reason (ledger/append l {:kind :fee :seq 2 :account :a :asset :btc :amount-minor 101}))))
      (is (= :insufficient-balance
             (:reason (ledger/append l {:kind :trade :seq 2 :buyer :b :seller :a :base :btc :quote :jpy
                                        :base-amount-minor 101 :quote-amount-minor 1}))))
      (is (= :insufficient-balance
             (:reason (ledger/append l {:kind :trade :seq 2 :buyer :b :seller :a :base :btc :quote :jpy
                                        :base-amount-minor 10 :quote-amount-minor 1})))
          "buyer must hold the quote leg too"))
    (testing "exact balance clears"
      (is (:ok? (ledger/append l {:kind :withdrawal :seq 2 :account :a :asset :btc :amount-minor 100}))))))

(deftest malformed-events-are-rejected
  (let [l ledger/empty-ledger]
    (is (= :malformed (:reason (ledger/append l {:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 0}))))
    (is (= :malformed (:reason (ledger/append l {:kind :deposit :seq 1 :account :a :asset :btc :amount-minor -5}))))
    (is (= :malformed (:reason (ledger/append l {:kind :deposit :seq 1 :asset :btc :amount-minor 5}))))
    (is (= :unknown-kind (:reason (ledger/append l {:kind :mint :seq 1 :account :a :asset :btc :amount-minor 5}))))
    (testing "self-trade and same-asset trades are malformed"
      (let [l2 (append-all [{:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 10}
                            {:kind :deposit :seq 2 :account :b :asset :jpy :amount-minor 10}])]
        (is (= :malformed (:reason (ledger/append l2 {:kind :trade :seq 3 :buyer :a :seller :a :base :btc :quote :jpy
                                                      :base-amount-minor 1 :quote-amount-minor 1}))))
        (is (= :malformed (:reason (ledger/append l2 {:kind :trade :seq 3 :buyer :b :seller :a :base :btc :quote :btc
                                                      :base-amount-minor 1 :quote-amount-minor 1}))))))))

(deftest adjustments-require-dual-control
  (let [l (append-all [{:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 100}])]
    (testing "no / single / duplicated approvers are rejected (INV-5)"
      (is (= :dual-control-required
             (:reason (ledger/append l {:kind :adjustment :seq 2 :account :a :asset :btc :delta-minor -10}))))
      (is (= :dual-control-required
             (:reason (ledger/append l {:kind :adjustment :seq 2 :account :a :asset :btc :delta-minor -10
                                        :approvers [:ops1]}))))
      (is (= :dual-control-required
             (:reason (ledger/append l {:kind :adjustment :seq 2 :account :a :asset :btc :delta-minor -10
                                        :approvers [:ops1 :ops1]})))))
    (testing "dual-controlled corrections land on the public log and conserve"
      (let [r (ledger/append l {:kind :adjustment :seq 2 :account :a :asset :btc :delta-minor -10
                                :approvers [:ops1 :ops2] :evidence "chain reorg refund"})]
        (is (:ok? r))
        (is (= 90 (ledger/balance (:ledger r) :a :btc)))
        (is (true? (:conserved? (ledger/conservation-check (:ledger r) :btc))))))
    (testing "an adjustment may not overdraw either"
      (is (= :insufficient-balance
             (:reason (ledger/append l {:kind :adjustment :seq 2 :account :a :asset :btc :delta-minor -101
                                        :approvers [:ops1 :ops2]})))))))

(deftest replay-is-the-third-party-recomputation-path
  (testing "a valid log replays to the identical book"
    (let [direct (append-all happy-path)
          replayed (ledger/replay happy-path)]
      (is (true? (:ok? replayed)))
      (is (= (ledger/balances direct) (ledger/balances (:ledger replayed))))))
  (testing "a tampered log (event vector edited behind append's back)
            is caught at the first invalid event"
    (let [tampered (assoc-in (vec happy-path) [0 :amount-minor] 10)
          r (ledger/replay tampered)]
      ;; alice now 'deposited' only 10 but still sells 400 in the trade
      (is (false? (:ok? r)))
      (is (= :insufficient-balance (:reason r)))
      (is (= 3 (:at r)))))
  (testing "a forged balance that skipped the log entirely is caught by
            the conservation kernel (defense in depth: recomputed sums
            vs claimed balances)"
    (let [l (append-all happy-path)
          honest (ledger/conservation-sums l :btc)
          cooked (update honest :sum-balances-minor + 500)]
      (is (= :broken (:reason (governor/conservation-check cooked)))))))

(deftest conservation-holds-step-by-step-across-a-mixed-multi-asset-log
  (testing "a long mix of deposits / trades / fees / withdrawals / dual-control
            adjustments across THREE accounts and TWO assets must conserve BOTH
            assets after EVERY single event (the invariant is not just an
            end-state property)"
    (let [events [{:kind :deposit :seq 1 :account :a :asset :btc :amount-minor 1000}
                  {:kind :deposit :seq 2 :account :b :asset :jpy :amount-minor 500000}
                  {:kind :trade :seq 3 :buyer :b :seller :a :base :btc :quote :jpy
                   :base-amount-minor 400 :quote-amount-minor 200000}
                  {:kind :fee :seq 4 :account :b :asset :btc :amount-minor 4}
                  {:kind :withdrawal :seq 5 :account :a :asset :jpy :amount-minor 150000}
                  {:kind :adjustment :seq 6 :account :a :asset :btc :delta-minor -10
                   :approvers [:o1 :o2] :evidence "reorg refund"}
                  {:kind :deposit :seq 7 :account :c :asset :btc :amount-minor 50}
                  {:kind :fee :seq 8 :account :c :asset :btc :amount-minor 5}
                  ;; c (holds 45 btc after the fee) sells 40 btc to b (holds
                  ;; 300000 jpy after seq 3); both legs are covered.
                  {:kind :trade :seq 9 :buyer :b :seller :c :base :btc :quote :jpy
                   :base-amount-minor 40 :quote-amount-minor 30000}]]
      (loop [l ledger/empty-ledger es events]
        (when (seq es)
          (let [e (first es)
                r (ledger/append l e)]
            (is (:ok? r) (str "event must append: " (:reason r) " at " e))
            (doseq [asset [:btc :jpy]]
              (is (true? (:conserved? (ledger/conservation-check (:ledger r) asset)))
                  (str "conservation on " asset " after seq " (:seq e))))
            (recur (:ledger r) (rest es))))))))
