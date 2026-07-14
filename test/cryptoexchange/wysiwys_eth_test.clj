(ns cryptoexchange.wysiwys-eth-test
  "Spec for the REAL Ethereum WYSIWYS decoder (JVM-only; not in the CLJS
  primary runner). Raw txs are built with eth-crypto's own `rlp-encode`
  and decoded back, so the RLP decode direction is verified against the
  encode direction it must invert; destination addresses are checked
  against eth-crypto's `eip55-checksum`."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [eth-crypto.core :as eth]
            [cryptoexchange.kernels.custody :as custody]
            [cryptoexchange.wysiwys-eth :as we]))

;; ------------------------------ builders -----------------------------

(defn- minimal-be [n]
  (if (zero? n) [] (loop [n n acc ()] (if (zero? n) (vec acc) (recur (quot n 256) (cons (mod n 256) acc))))))

(defn- ba [ints] (byte-array (map unchecked-byte ints)))

(defn- ->ints [^bytes b] (mapv #(bit-and % 0xff) (seq b)))

(def ^:private to20 (vec (range 1 21)))          ; 0x0102..14
(def ^:private expected-addr
  (eth/eip55-checksum (apply str (map #(format "%02x" %) to20))))

(defn- legacy-tx [to-ints value-wei]
  (->ints (eth/rlp-encode [(ba (minimal-be 0))            ; nonce
                           (ba (minimal-be 20000000000))  ; gasPrice
                           (ba (minimal-be 21000))        ; gas
                           (ba to-ints)                   ; to
                           (ba (minimal-be value-wei))    ; value
                           (ba [])                        ; data
                           (ba (minimal-be 1))            ; chainId (EIP-155)
                           (ba []) (ba [])])))            ; r, s

(defn- eip1559-tx [to-ints value-wei]
  (vec (concat [0x02]
               (->ints (eth/rlp-encode [(ba (minimal-be 1))           ; chainId
                                        (ba (minimal-be 0))           ; nonce
                                        (ba (minimal-be 1000000000))  ; maxPriority
                                        (ba (minimal-be 30000000000)) ; maxFee
                                        (ba (minimal-be 21000))       ; gas
                                        (ba to-ints)                  ; to
                                        (ba (minimal-be value-wei))   ; value
                                        (ba [])                       ; data
                                        []])))))                      ; accessList (empty list)

(deftest decodes-legacy-and-1559
  (testing "legacy (EIP-155) transfer"
    (let [r (we/decode-transfer (legacy-tx to20 1000000000000000000))]  ; 1 ETH
      (is (true? (:ok? r)))
      (is (= :legacy (:tx-type r)))
      (is (= expected-addr (:to r)))
      (is (= 1000000000000000000 (:value-wei r)))))
  (testing "EIP-1559 typed transfer"
    (let [r (we/decode-transfer (eip1559-tx to20 250000))]
      (is (true? (:ok? r)))
      (is (= 0x02 (:tx-type r)))
      (is (= expected-addr (:to r)))
      (is (= 250000 (:value-wei r))))))

(deftest address-is-eip55-checksummed
  (testing "the decoded destination matches eth-crypto's own EIP-55 output"
    (is (= expected-addr (:to (we/decode-transfer (legacy-tx to20 1)))))
    (is (re-find #"^0x[0-9a-fA-F]{40}$" expected-addr))))

(deftest verify-matches-intent-and-feeds-the-custody-kernel
  (let [raw (legacy-tx to20 1000000000000000000)]
    (testing "honest tx paying the intended to+value → flag 1"
      (let [v (we/verify raw {:to expected-addr :value-wei 1000000000000000000})]
        (is (= 1 (:verifier-match-flag v)))
        (is (= :match (:reason v)))))
    (testing "the Bybit attack: bytes send to a DIFFERENT address → flag 0 → kernel code 6"
      (let [attacker (eth/eip55-checksum (apply str (repeat 40 "9")))
            v (we/verify raw {:to attacker :value-wei 1000000000000000000})]
        (is (= 0 (:verifier-match-flag v)))
        (is (= :intent-mismatch (:reason v)))
        (is (= 6 (custody/withdrawal-verdict 100 3 3 1 1 (:verifier-match-flag v)
                                             250000 0 1000000)))))
    (testing "tampered value → flag 0"
      (is (= 0 (:verifier-match-flag (we/verify raw {:to expected-addr :value-wei 999})))))
    (testing "checksum casing is display-only — a lowercase intent still matches"
      (is (= 1 (:verifier-match-flag
                (we/verify raw {:to (str/lower-case expected-addr)
                                :value-wei 1000000000000000000})))))))

(deftest contract-creation-and-malformed-fail-closed
  (testing "an empty `to` (contract creation) has no destination to confirm → flag 0"
    (let [raw (legacy-tx [] 0)
          r (we/decode-transfer raw)]
      (is (false? (:ok? r)))
      (is (= :no-destination (:reason r)))
      (is (= 0 (:verifier-match-flag (we/verify raw {:to expected-addr :value-wei 0}))))))
  (testing "garbage bytes fail closed"
    (is (false? (:ok? (we/decode-transfer [0x02 0xff]))))
    (is (= 0 (:verifier-match-flag (we/verify [0x00] {:to expected-addr :value-wei 1}))))))
