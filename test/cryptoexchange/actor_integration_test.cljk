(ns cryptoexchange.actor-integration-test
  "End-to-end drive of the OperationActor StateGraph (M4): the advisor
  proposes, the ExchangeGovernor + phase gate decide, human sign-off
  gates the actuation ops, and only the commit node writes the store.
  This exercises the whole langgraph seam (interrupt-before / resume),
  so it lives OUTSIDE the CLJS primary runner — the fleet convention is
  to CLJS-test the decision cores (censor/phase/kernels/store) and drive
  the graph on the JVM (mirrors cloud-itonami-isic-6511, whose graph is
  likewise not in its cljs runner)."
  (:require [clojure.test :refer [deftest is testing]]
            [langgraph.graph :as g]
            [cryptoexchange.actor :as actor]
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.store :as store]))

(def ^:private operator {:actor-id "ex-1" :phase 3
                         :attestations {:prop-trading? false :self-token-collateral? false
                                        :privileged-bypass? false :lending? false}
                         :reserve {:reserve-minor 1000000 :self-token? false}})

(defn- exec! [act tid request context]
  (g/run* act {:request request :context context} {:thread-id tid}))

(defn- signoff! [act tid by]
  (g/run* act {:approval {:status :approved :by by}} {:thread-id tid :resume? true}))

(defn- reject! [act tid]
  (g/run* act {:approval {:status :rejected}} {:thread-id tid :resume? true}))

(defn- audit-kinds [result]
  (mapv :t (get-in result [:state :audit])))

(deftest deposit-auto-commits-at-phase-3
  (let [s (store/mem-store)
        act (actor/build s)
        r (exec! act "t1" {:op :deposit/record :account :alice :asset :btc
                           :amount-minor 500 :seq 1} operator)]
    (is (= :done (:status r)))
    (is (some #{:committed} (audit-kinds r)))
    (is (= 500 (ledger/balance (store/ledger-of s) :alice :btc))
        "the deposit event reached the store")))

(deftest withdrawal-always-pauses-for-signoff-then-broadcasts
  (let [s (store/mem-store)
        act (actor/build s)]
    ;; fund alice so the withdrawal is covered when it settles
    (store/append-ledger-event! s {:kind :deposit :seq 1 :account :alice
                                   :asset :btc :amount-minor 1000})
    (let [good-custody {:hot-bp 100 :quorum-sigs 3 :quorum-m 3
                        :allowlisted? true :timelock-ok? true :verifier-match? true
                        :amount-minor 400 :window-outflow-minor 0 :velocity-cap-minor 10000}
          paused (exec! act "w1" {:op :withdrawal/broadcast :account :alice :asset :btc
                                  :amount-minor 400 :seq 2}
                        (assoc operator :custody good-custody))]
      (testing "the actor interrupts before sign-off — no broadcast yet"
        (is (= :interrupted (:status paused)))
        (is (some #{:signoff-requested} (audit-kinds paused)))
        (is (= 1000 (ledger/balance (store/ledger-of s) :alice :btc))
            "nothing settled while paused"))
      (testing "a human signer resumes -> the settlement event is appended"
        (let [done (signoff! act "w1" "signer-A")]
          (is (= :done (:status done)))
          (is (some #{:signoff-granted} (audit-kinds done)))
          (is (some #{:committed} (audit-kinds done)))
          (is (= 600 (ledger/balance (store/ledger-of s) :alice :btc))))))))

(deftest a-rejected-signoff-broadcasts-nothing
  (let [s (store/mem-store)
        act (actor/build s)]
    (store/append-ledger-event! s {:kind :deposit :seq 1 :account :bob
                                   :asset :btc :amount-minor 1000})
    (let [good-custody {:hot-bp 100 :quorum-sigs 3 :quorum-m 3
                        :allowlisted? true :timelock-ok? true :verifier-match? true
                        :amount-minor 100 :window-outflow-minor 0 :velocity-cap-minor 10000}
          _ (exec! act "w2" {:op :withdrawal/broadcast :account :bob :asset :btc
                             :amount-minor 100 :seq 2}
                   (assoc operator :custody good-custody))
          done (reject! act "w2")]
      (is (= :done (:status done)))
      (is (some #{:signoff-rejected} (audit-kinds done)))
      (is (not (some #{:committed} (audit-kinds done))))
      (is (= 1000 (ledger/balance (store/ledger-of s) :bob :btc))
          "the book is untouched by a rejected withdrawal"))))

(deftest a-hard-custody-denial-never-reaches-a-human
  (testing "a WYSIWYS verifier mismatch HARD-holds — the actor never even
            pauses for sign-off (you cannot approve past it)"
    (let [s (store/mem-store)
          act (actor/build s)
          bad-custody {:hot-bp 100 :quorum-sigs 3 :quorum-m 3
                       :allowlisted? true :timelock-ok? true :verifier-match? false
                       :amount-minor 100 :window-outflow-minor 0 :velocity-cap-minor 10000}
          r (exec! act "w3" {:op :withdrawal/broadcast :account :x :asset :btc
                             :amount-minor 100 :seq 1}
                   (assoc operator :custody bad-custody))]
      (is (= :done (:status r)))
      (is (some #{:governor-hold} (audit-kinds r)))
      (is (not (some #{:signoff-requested} (audit-kinds r))))
      (is (not (some #{:committed} (audit-kinds r)))))))

(deftest an-insolvent-book-halts-intake
  (testing "a deposit is HARD-held when the operator's reserves don't cover
            liabilities (INV-1) — the advisor's proposal never commits"
    (let [s (store/mem-store)
          act (actor/build s)]
      (store/append-ledger-event! s {:kind :deposit :seq 1 :account :whale
                                     :asset :btc :amount-minor 1000})
      (let [thin-reserve (assoc operator :reserve {:reserve-minor 10 :self-token? false})
            r (exec! act "d2" {:op :deposit/record :account :minnow :asset :btc
                               :amount-minor 5 :seq 2} thin-reserve)]
        (is (some #{:governor-hold} (audit-kinds r)))
        (is (not (some #{:committed} (audit-kinds r))))
        (is (zero? (ledger/balance (store/ledger-of s) :minnow :btc)))
        (is (= 1 (count (store/ledger-events s))) "only the whale's deposit is on the log")))))

(deftest order-placement-flows-to-the-order-log
  (let [s (store/mem-store)
        act (actor/build s)
        r (exec! act "o1" {:op :order/place
                           :order {:seq 1 :id :o1 :account :alice :side :buy
                                   :price-minor 100 :qty-minor 10}}
                 operator)]
    (is (some #{:committed} (audit-kinds r)))
    (is (= 1 (count (store/order-events s))))))
