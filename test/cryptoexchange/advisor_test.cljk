(ns cryptoexchange.advisor-test
  "Direct spec for the contained Exchange-LLM advisor. Its proposal
  shapes are load-bearing: the actor commits the `:event` a proposal
  carries, and the censor gates on `:stake` (the actuation ops must be
  structurally `:actuation` so they always escalate). These tests pin
  that contract independently of the actor graph."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.advisor :as advisor]))

(deftest reads-are-noop-proposals
  (doseq [op [:balance/report :attestation/report]]
    (let [p (advisor/infer {:op op})]
      (is (= :noop (:effect p)))
      (is (nil? (:event p)) "a read commits no event")
      (is (nil? (:stake p)))
      (is (= 1.0 (:confidence p))))))

(deftest deposit-builds-a-deposit-event
  (let [p (advisor/infer {:op :deposit/record :account :alice :asset :btc
                          :amount-minor 500 :seq 7})]
    (is (= :ledger/deposit (:effect p)))
    (is (nil? (:stake p)) "recording a deposit is not actuation")
    (is (= {:kind :deposit :seq 7 :account :alice :asset :btc :amount-minor 500}
           (:event p)))))

(deftest order-carries-the-order-tagged-as-an-event
  (let [order {:seq 3 :id :o1 :account :bob :side :buy :price-minor 100 :qty-minor 10}
        p (advisor/infer {:op :order/place :order order})]
    (is (= :order/place (:effect p)))
    (is (nil? (:stake p)))
    (is (= (assoc order :kind :order) (:event p)))))

(deftest actuation-ops-are-structurally-staked-actuation
  (testing "withdrawal broadcast — the real-world act — carries :stake :actuation
            so the censor always escalates it (never auto)"
    (let [p (advisor/infer {:op :withdrawal/broadcast :account :alice :asset :btc
                            :amount-minor 400 :seq 9})]
      (is (= :ledger/withdrawal (:effect p)))
      (is (= :actuation (:stake p)))
      (is (= {:kind :withdrawal :seq 9 :account :alice :asset :btc :amount-minor 400}
             (:event p)))))
  (testing "a dual-control adjustment is also :actuation"
    (let [p (advisor/infer {:op :adjustment/apply :account :bob :asset :btc
                            :delta-minor -10 :seq 4 :evidence "reorg refund"})]
      (is (= :ledger/adjustment (:effect p)))
      (is (= :actuation (:stake p)))
      (is (= {:kind :adjustment :seq 4 :account :bob :asset :btc
              :delta-minor -10 :evidence "reorg refund"}
             (:event p))))))

(deftest unknown-op-fails-to-a-safe-noop
  (testing "an unrecognized op yields a zero-confidence noop so the censor
            never auto-commits an advisor hiccup"
    (let [p (advisor/infer {:op :mint/coins})]
      (is (= :noop (:effect p)))
      (is (nil? (:event p)))
      (is (nil? (:stake p)))
      (is (= 0.0 (:confidence p))))))

(deftest mock-advisor-delegates-to-infer
  (let [a (advisor/mock-advisor)
        req {:op :deposit/record :account :x :asset :btc :amount-minor 1 :seq 1}]
    (is (= (advisor/infer req) (advisor/-advise a req)))))

(deftest trace-is-a-decision-grounded-record
  (let [req {:op :withdrawal/broadcast :account :alice :asset :btc :amount-minor 5 :seq 2}
        p (advisor/infer req)
        t (advisor/trace req p)]
    (is (= :advisor-proposal (:t t)))
    (is (= :withdrawal/broadcast (:op t)))
    (is (= :ledger/withdrawal (:effect t)))
    (is (= (:confidence p) (:confidence t)))
    (is (= (:summary p) (:summary t)))))
