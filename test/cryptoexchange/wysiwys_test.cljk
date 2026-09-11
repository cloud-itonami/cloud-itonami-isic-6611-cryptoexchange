(ns cryptoexchange.wysiwys-test
  "Executable spec for the WYSIWYS dual-verifier harness (custody ADR §4,
  INV-10). The flag is 1 only when two independent decoders agree AND
  match intent; every tamper axis drops it to 0 and the custody kernel
  then returns code 6 (verifier-mismatch)."
  (:require [clojure.test :refer [deftest is testing]]
            [cryptoexchange.kernels.custody :as custody]
            [cryptoexchange.wysiwys :as wysiwys]))

(def ^:private intent
  {:destination "bc1qexamplecoldsink" :asset "BTC"
   :amount-minor 250000 :fee-minor 300 :chain-id 0})

(deftest honest-tx-verifies
  (let [raw (wysiwys/encode-tx intent)
        r (wysiwys/verify raw intent)]
    (is (= 1 (:verifier-match-flag r)))
    (is (= :match (:reason r)))
    (is (= (select-keys intent [:destination :asset :amount-minor :fee-minor :chain-id])
           (:decoded r)))))

(deftest both-decoders-agree-on-honest-bytes
  (let [raw (wysiwys/encode-tx intent)]
    (is (= (wysiwys/decode-a raw) (wysiwys/decode-b raw)))
    (is (:ok? (wysiwys/decode-a raw)))))

(deftest a-ui-that-shows-intent-but-signs-a-different-destination-fails
  (testing "the classic Bybit attack: intent record says one address,
            the raw bytes handed to the signer say another. Independent
            reconstruction from the bytes catches it — flag 0."
    (let [attacker-tx (assoc intent :destination "bc1qATTACKERdrainwallet")
          raw (wysiwys/encode-tx attacker-tx)
          r (wysiwys/verify raw intent)]
      (is (= 0 (:verifier-match-flag r)))
      (is (= :intent-mismatch (:reason r)))
      (testing "and the custody kernel then denies with code 6"
        (is (= 6 (custody/withdrawal-verdict 100 3 3 1 1
                                             (:verifier-match-flag r)
                                             250000 0 1000000)))))))

(deftest tampered-amount-or-fee-fails
  (doseq [[k bad] [[:amount-minor 999999] [:fee-minor 999] [:chain-id 1] [:asset "ETH"]]]
    (let [raw (wysiwys/encode-tx (assoc intent k bad))
          r (wysiwys/verify raw intent)]
      (is (= 0 (:verifier-match-flag r)) (str "tampered " k " must fail"))
      (is (= :intent-mismatch (:reason r))))))

(deftest malformed-bytes-fail-closed
  (testing "truncated / corrupt raw bytes never yield a 1"
    (let [raw (wysiwys/encode-tx intent)]
      (is (= 0 (:verifier-match-flag (wysiwys/verify (subvec raw 0 (dec (count raw))) intent))))
      (is (= 0 (:verifier-match-flag (wysiwys/verify (conj raw 9 9 9) intent))))
      (is (= 0 (:verifier-match-flag (wysiwys/verify [] intent)))))))

(deftest decoders-are-genuinely-independent
  (testing "a byte edit inside a field is caught: both decoders read the
            corrupted field identically (so they agree) but it no longer
            matches intent -> intent-mismatch, still flag 0"
    (let [raw (wysiwys/encode-tx intent)
          ;; flip a byte in the destination field value (index 2 = first
          ;; char of destination, after tag+len; 88 = ASCII 'X', which
          ;; differs from the original 'b'=98)
          corrupted (assoc raw 2 88)
          r (wysiwys/verify corrupted intent)]
      (is (= 0 (:verifier-match-flag r)))
      (is (= :intent-mismatch (:reason r))))))

(deftest round-trips-across-sizes
  (testing "amounts of varying byte-length round-trip through both decoders"
    (doseq [amt [0 1 255 256 65535 250000 4200000000]]
      (let [i (assoc intent :amount-minor amt)
            raw (wysiwys/encode-tx i)]
        (is (= 1 (:verifier-match-flag (wysiwys/verify raw i))))))))
