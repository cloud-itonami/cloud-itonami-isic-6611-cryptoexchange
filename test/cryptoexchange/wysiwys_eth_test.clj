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

;; --------------------- Gnosis Safe execTransaction -------------------

(defn- pad32-left [ints] (into (vec (repeat (- 32 (count ints)) 0)) ints))
(defn- uint256 [n] (pad32-left (minimal-be n)))
(defn- addr-word [addr20] (pad32-left (vec addr20)))

(def ^:private exec-sel [0x6a 0x76 0x12 0x02])
(def ^:private transfer-sel [0xa9 0x05 0x9c 0xbb])
(def ^:private recipient20 (vec (range 21 41)))       ; 0x15..28
(def ^:private token20 (vec (range 41 61)))
(defn- eip55 [ints] (eth/eip55-checksum (apply str (map #(format "%02x" %) ints))))

(defn- safe-exec-native [to20 value]
  (vec (concat exec-sel (addr-word to20) (uint256 value) (uint256 320) (uint256 0)
               (uint256 0) (uint256 0) (uint256 0)
               (addr-word (repeat 20 0)) (addr-word (repeat 20 0))
               (uint256 352) (uint256 0) (uint256 0))))   ; data-len 0, sig-len 0

(defn- safe-exec-token [token20 recip20 amount]
  (let [inner (vec (concat transfer-sel (addr-word recip20) (uint256 amount)))]  ; 68 bytes
    (vec (concat exec-sel (addr-word token20) (uint256 0) (uint256 320) (uint256 0)
                 (uint256 0) (uint256 0) (uint256 0)
                 (addr-word (repeat 20 0)) (addr-word (repeat 20 0))
                 (uint256 999) (uint256 (count inner)) inner))))

(defn- safe-exec-delegatecall [to20 value]
  (vec (concat exec-sel (addr-word to20) (uint256 value) (uint256 320) (uint256 1)  ; operation 1
               (uint256 0) (uint256 0) (uint256 0)
               (addr-word (repeat 20 0)) (addr-word (repeat 20 0))
               (uint256 352) (uint256 0) (uint256 0))))

(defn- legacy-tx-with-data [to-ints value-wei data-ints]
  (->ints (eth/rlp-encode [(ba (minimal-be 0)) (ba (minimal-be 20000000000))
                           (ba (minimal-be 100000)) (ba to-ints) (ba (minimal-be value-wei))
                           (ba data-ints)                        ; DATA = the execTransaction calldata
                           (ba (minimal-be 1)) (ba []) (ba [])])))

(def ^:private safe20 (vec (range 61 81)))              ; the Safe contract address

(deftest safe-native-withdrawal-recovers-the-real-recipient
  (let [raw (legacy-tx-with-data safe20 0 (safe-exec-native recipient20 1000000000000000000))
        r (we/decode-safe raw)]
    (is (true? (:ok? r)))
    (is (= :native (:kind r)))
    (is (= (eip55 recipient20) (:to r)))
    (is (= 1000000000000000000 (:value-wei r)))
    (testing "verify-safe: matching native intent -> flag 1"
      (is (= 1 (:verifier-match-flag
                (we/verify-safe raw {:kind :native :to (eip55 recipient20)
                                     :value-wei 1000000000000000000})))))
    (testing "Bybit: the outer tx pays the Safe, but the REAL recipient differs
              from intent -> flag 0 -> kernel code 6"
      (let [attacker (eip55 (vec (range 91 111)))
            v (we/verify-safe raw {:kind :native :to attacker :value-wei 1000000000000000000})]
        (is (= 0 (:verifier-match-flag v)))
        (is (= 6 (custody/withdrawal-verdict 100 3 3 1 1 (:verifier-match-flag v)
                                             250000 0 1000000)))))))

(deftest safe-erc20-withdrawal-recovers-token-recipient-amount
  (let [raw (legacy-tx-with-data safe20 0 (safe-exec-token token20 recipient20 250000))
        r (we/decode-safe raw)]
    (is (= :token (:kind r)))
    (is (= (eip55 token20) (:token r)))
    (is (= (eip55 recipient20) (:to r)))
    (is (= 250000 (:amount r)))
    (testing "matching token intent -> flag 1; tampered amount / recipient -> flag 0"
      (is (= 1 (:verifier-match-flag
                (we/verify-safe raw {:kind :token :token (eip55 token20)
                                     :to (eip55 recipient20) :amount 250000}))))
      (is (= 0 (:verifier-match-flag
                (we/verify-safe raw {:kind :token :token (eip55 token20)
                                     :to (eip55 recipient20) :amount 999}))))
      (is (= 0 (:verifier-match-flag
                (we/verify-safe raw {:kind :token :token (eip55 token20)
                                     :to (eip55 (vec (range 91 111))) :amount 250000})))))))

(deftest safe-delegatecall-and-unknown-inner-fail-closed
  (testing "operation 1 (DELEGATECALL) is refused"
    (let [raw (legacy-tx-with-data safe20 0 (safe-exec-delegatecall recipient20 1))]
      (is (= :delegatecall (:reason (we/decode-safe raw))))
      (is (= 0 (:verifier-match-flag (we/verify-safe raw {:kind :native :to (eip55 recipient20) :value-wei 1}))))))
  (testing "a non-Safe tx (data not an execTransaction) is :not-safe-exec"
    (let [raw (legacy-tx-with-data safe20 0 [0xde 0xad 0xbe 0xef])]
      (is (= :not-safe-exec (:reason (we/decode-safe raw)))))))

(deftest safe-kind-mismatch-fails-closed
  (testing "a native decode against a token intent (or vice versa) fails closed"
    (let [raw (legacy-tx-with-data safe20 0 (safe-exec-native recipient20 5))]
      (is (= 0 (:verifier-match-flag
                (we/verify-safe raw {:kind :token :token (eip55 token20)
                                     :to (eip55 recipient20) :amount 5})))))))

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
