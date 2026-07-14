(ns cryptoexchange.wysiwys-btc-test
  "Spec for the REAL Bitcoin WYSIWYS decoder (JVM-only; not in the CLJS
  primary runner). Raw txs are assembled from their wire bytes and
  decoded back; the destination addresses are cross-checked against
  btc-crypto's own encoders (round-trip) and one is grounded in a real
  private key, so the decode direction is verified against the encode
  direction it must invert."
  (:require [clojure.test :refer [deftest is testing]]
            [btc-crypto.bech32 :as bech32]
            [btc-crypto.core :as btc]
            [cryptoexchange.kernels.custody :as custody]
            [cryptoexchange.wysiwys-btc :as wb]))

;; ------------------------------ builders -----------------------------

(defn- le64 [n]
  (mapv #(bit-and (bit-shift-right n (* 8 %)) 0xff) (range 8)))

(defn- varint [n]
  (cond (< n 0xfd) [n]
        (<= n 0xffff) [0xfd (bit-and n 0xff) (bit-and (bit-shift-right n 8) 0xff)]
        :else [0xfe (bit-and n 0xff) (bit-and (bit-shift-right n 8) 0xff)
               (bit-and (bit-shift-right n 16) 0xff) (bit-and (bit-shift-right n 24) 0xff)]))

(defn- output [value-sat script]
  (vec (concat (le64 value-sat) (varint (count script)) script)))

(defn- p2wpkh-script [program] (vec (concat [0x00 0x14] program)))
(defn- p2wsh-script [program] (vec (concat [0x00 0x20] program)))
(defn- p2tr-script [program] (vec (concat [0x51 0x20] program)))
(defn- p2pkh-script [h160] (vec (concat [0x76 0xa9 0x14] h160 [0x88 0xac])))

(defn- tx-with-outputs
  "A minimal (non-witness) tx: version, 1 dummy input, the given outputs,
  locktime. This is the pre-signing shape a signer is asked to sign."
  [outputs]
  (let [version [0x02 0x00 0x00 0x00]
        vin (varint 1)
        input (vec (concat (repeat 32 0x00) [0x00 0x00 0x00 0x00]  ; outpoint 36
                           (varint 0)                              ; empty scriptSig
                           [0xff 0xff 0xff 0xff]))                 ; sequence
        vout (varint (count outputs))
        locktime [0x00 0x00 0x00 0x00]]
    (vec (concat version vin input vout (apply concat outputs) locktime))))

(def ^:private prog20 (vec (repeat 20 0x11)))
(def ^:private prog32 (vec (repeat 32 0x22)))

(deftest decodes-every-standard-output-type
  (let [outs [(output 250000 (p2wpkh-script prog20))
              (output 5 (p2wsh-script prog32))
              (output 7 (p2tr-script prog32))
              (output 9 (p2pkh-script prog20))]
        r (wb/decode-outputs (tx-with-outputs outs))]
    (is (true? (:ok? r)))
    (is (= [:p2wpkh :p2wsh :p2tr :p2pkh] (mapv :type (:outputs r))))
    (is (= [250000 5 7 9] (mapv :value-sat (:outputs r))))
    (testing "decoded address == btc-crypto's own encoder (round-trip)"
      (is (= (bech32/encode-segwit-address "bc" 0 prog20)
             (:address (first (:outputs r)))))
      (is (= (bech32/encode-segwit-address "bc" 0 prog32)
             (:address (second (:outputs r)))))
      (is (= (bech32/encode-segwit-address "bc" 1 prog32)
             (:address (nth (:outputs r) 2)))))))

(deftest grounded-in-a-real-private-key
  (testing "a p2wpkh output paying a real key's address decodes back to
            exactly that address (encode ∘ decode round-trip on btc-crypto)"
    (let [privkey (byte-array (concat (repeat 31 0x00) [0x2a]))  ; = 42
          addr (:p2wpkh (btc/address-of-privkey privkey :mainnet))
          program (:program (bech32/decode-segwit-address addr))
          raw (tx-with-outputs [(output 100000 (p2wpkh-script program))])
          r (wb/decode-outputs raw)]
      (is (= addr (:address (first (:outputs r)))))
      (is (= 100000 (:value-sat (first (:outputs r))))))))

(deftest segwit-marked-tx-parses
  (testing "a tx carrying the 0x00 0x01 segwit marker still yields outputs"
    (let [version [0x02 0x00 0x00 0x00]
          marker [0x00 0x01]
          vin (varint 1)
          input (vec (concat (repeat 32 0x00) [0x00 0x00 0x00 0x00] (varint 0) [0xff 0xff 0xff 0xff]))
          out (output 250000 (p2wpkh-script prog20))
          ;; (witness bytes would follow; the decoder ignores them)
          raw (vec (concat version marker vin input (varint 1) out [0x00 0x00 0x00 0x00]))
          r (wb/decode-outputs raw)]
      (is (true? (:ok? r)))
      (is (= 250000 (:value-sat (first (:outputs r))))))))

(deftest verify-matches-intent-and-feeds-the-custody-kernel
  (let [addr (bech32/encode-segwit-address "bc" 0 prog20)
        raw (tx-with-outputs [(output 250000 (p2wpkh-script prog20))])]
    (testing "an honest tx paying the intended address+amount → flag 1"
      (let [v (wb/verify raw {:address addr :value-sat 250000} {})]
        (is (= 1 (:verifier-match-flag v)))
        (is (= :match (:reason v)))))
    (testing "the Bybit attack: bytes pay a DIFFERENT address → flag 0 → kernel code 6"
      (let [attacker (bech32/encode-segwit-address "bc" 0 (vec (repeat 20 0x99)))
            v (wb/verify raw {:address attacker :value-sat 250000} {})]
        (is (= 0 (:verifier-match-flag v)))
        (is (= :intent-not-in-outputs (:reason v)))
        (is (= 6 (custody/withdrawal-verdict 100 3 3 1 1 (:verifier-match-flag v)
                                             250000 0 1000000)))))
    (testing "tampered amount → flag 0"
      (is (= 0 (:verifier-match-flag (wb/verify raw {:address addr :value-sat 249999} {})))))))

(deftest unrecognized-script-fails-closed
  (testing "an output whose script the verifier cannot classify never
            passes WYSIWYS (you don't sign what you can't read)"
    (let [weird (output 5 [0x6a 0x04 0xde 0xad 0xbe 0xef])   ; OP_RETURN data
          raw (tx-with-outputs [weird])
          r (wb/decode-outputs raw)]
      (is (= :unknown (:type (first (:outputs r)))))
      (is (= 0 (:verifier-match-flag
                (wb/verify raw {:address "bc1qanything" :value-sat 5} {})))))))

(deftest malformed-bytes-fail-closed
  (is (= 0 (:verifier-match-flag (wb/verify [0x02 0x00] {:address "x" :value-sat 1} {}))))
  (is (false? (:ok? (wb/decode-outputs [0x02 0x00 0x00])))))

(deftest truncation-never-throws
  (testing "the decoder parses ATTACKER-controlled bytes — EVERY prefix of a
            valid tx must return a map, never throw (a crash on malformed input
            is itself a fail-open). The complete tx verifies. NOTE: a prefix
            that cuts only trailing bytes (witness/locktime) still contains all
            outputs, so it legitimately reports the same destination — that is
            correct (truncating past the outputs cannot redirect funds), which
            is why the property here is 'never throws', not 'never verifies'."
    (let [addr (bech32/encode-segwit-address "bc" 0 prog20)
          raw (tx-with-outputs [(output 250000 (p2wpkh-script prog20))
                                (output 5 (p2wsh-script prog32))])]
      (doseq [n (range 0 (count raw))]
        (is (map? (wb/decode-outputs (subvec (vec raw) 0 n)))
            (str "prefix len " n " must not throw")))
      (is (= 1 (:verifier-match-flag (wb/verify raw {:address addr :value-sat 250000} {})))
          "the complete tx verifies"))))

(deftest truncation-within-an-output-fails-closed
  (testing "cutting inside the value or scriptPubKey of the intended output
            (so it is NOT fully present) must fail closed — never a partial
            false-positive"
    (let [addr (bech32/encode-segwit-address "bc" 0 prog20)
          version [0x02 0x00 0x00 0x00]
          input (vec (concat (repeat 32 0x00) [0x00 0x00 0x00 0x00] (varint 0) [0xff 0xff 0xff 0xff]))
          ;; header through vout=1 and the value, then a scriptPubKey LENGTH of
          ;; 0x16 (22, a p2wpkh script) but only a few bytes actually follow —
          ;; the script is cut short, so the output is not fully present
          head (vec (concat version (varint 1) input (varint 1) (le64 250000) [0x16 0x00 0x14 0x11 0x11]))]
      (is (false? (:ok? (wb/decode-outputs head))))
      (is (= 0 (:verifier-match-flag (wb/verify head {:address addr :value-sat 250000} {})))))))

(deftest oversized-length-claims-fail-closed
  (testing "a scriptPubKey length claiming more bytes than remain, and an
            output count far exceeding the data, both fail closed (no throw,
            no partial false-positive)"
    ;; version + 1 dummy input + vout=1 + value(8) + script-len=0xfc (252) but
    ;; only a few bytes follow
    (let [version [0x02 0x00 0x00 0x00]
          input (vec (concat (repeat 32 0x00) [0x00 0x00 0x00 0x00] (varint 0) [0xff 0xff 0xff 0xff]))
          bad-script-len (vec (concat version (varint 1) input (varint 1) (le64 5) [0xfc 0x00 0x11]))
          bad-vout-count (vec (concat version (varint 1) input [0xff] (le64 5)))]  ; 0xff varint header, truncated
      (is (map? (wb/decode-outputs bad-script-len)))
      (is (false? (:ok? (wb/decode-outputs bad-script-len))))
      (is (map? (wb/decode-outputs bad-vout-count)))
      (is (false? (:ok? (wb/decode-outputs bad-vout-count)))))))
