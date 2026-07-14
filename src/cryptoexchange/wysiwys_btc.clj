(ns cryptoexchange.wysiwys-btc
  "REAL WYSIWYS decoder for Bitcoin — the production backend behind
  `cryptoexchange.wysiwys`'s dual-verifier discipline (custody ADR §4,
  INV-10). Where `cryptoexchange.wysiwys` is a portable semantic
  stand-in, this parses an ACTUAL raw unsigned Bitcoin transaction back
  to its `(destination address, value)` outputs, so a signer verifies
  what they are really about to sign from the bytes — never from a
  wallet UI (the Bybit/DMM attack).

  Reuses `kotoba-lang/btc-crypto`'s address encoders (bech32 for segwit,
  base58check for legacy) rather than re-deriving them; this ns only
  adds the DECODE direction (byte parser + scriptPubKey classification),
  which btc-crypto does not provide.

  **JVM-only** — btc-crypto is `byte-array`/`System`-based (no CLJS
  branch), so this is a deliberate compat layer at the JVM actuation
  boundary (the actor's withdrawal-broadcast path is JVM-driven), NOT on
  the portable CLJS kernel/attest path. It is therefore run by the JVM
  test gate, not the CLJS primary runner.

  Raw tx is a vector of ints 0..255 (same representation as
  `cryptoexchange.wysiwys`). Handles pre-signing (non-witness) and
  segwit-marked serializations; reads only what WYSIWYS needs — the
  outputs — and ignores witness/locktime."
  (:require [btc-crypto.bech32 :as bech32]
            [btc-crypto.base58 :as base58]))

;; ------------------------------ cursor -------------------------------
;; A tiny explicit-index reader over the int-vector, so the parse is a
;; straight-line audit rather than clever slicing.

(defn- u8 [bs i] (nth bs i))

(defn- read-le
  "[value next-index] — little-endian unsigned int of `n` bytes."
  [bs i n]
  [(loop [k 0 acc 0] (if (= k n) acc (recur (inc k) (+ acc (bit-shift-left (u8 bs (+ i k)) (* 8 k))))))
   (+ i n)])

(defn- read-varint
  "Bitcoin CompactSize varint. [value next-index]."
  [bs i]
  (let [b0 (u8 bs i)]
    (cond
      (< b0 0xfd) [b0 (inc i)]
      (= b0 0xfd) (read-le bs (inc i) 2)
      (= b0 0xfe) (read-le bs (inc i) 4)
      :else (read-le bs (inc i) 8))))

;; ------------------------ scriptPubKey → address ---------------------

(defn- take-bytes [bs i n] (subvec (vec bs) i (+ i n)))

(defn script->address
  "Classify a scriptPubKey (int vector) and encode its address under
  `hrp`/`network`. Returns {:address .. :type ..} or {:type :unknown
  :script-hex ..} — an unrecognized script is surfaced, never guessed
  (an address the verifier can't reconstruct must fail WYSIWYS, not
  pass silently)."
  [script {:keys [hrp network] :or {hrp "bc" network :mainnet}}]
  (let [n (count script)
        b (fn [k] (nth script k))]
    (cond
      ;; P2WPKH: OP_0 0x14 <20>
      (and (= n 22) (= (b 0) 0x00) (= (b 1) 0x14))
      {:type :p2wpkh :address (bech32/encode-segwit-address hrp 0 (take-bytes script 2 20))}
      ;; P2WSH: OP_0 0x20 <32>
      (and (= n 34) (= (b 0) 0x00) (= (b 1) 0x20))
      {:type :p2wsh :address (bech32/encode-segwit-address hrp 0 (take-bytes script 2 32))}
      ;; P2TR (taproot): OP_1 0x20 <32>
      (and (= n 34) (= (b 0) 0x51) (= (b 1) 0x20))
      {:type :p2tr :address (bech32/encode-segwit-address hrp 1 (take-bytes script 2 32))}
      ;; P2PKH: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
      (and (= n 25) (= (b 0) 0x76) (= (b 1) 0xa9) (= (b 2) 0x14)
           (= (b 23) 0x88) (= (b 24) 0xac))
      {:type :p2pkh :address (base58/encode-check
                              (byte-array (cons (if (= network :mainnet) 0x00 0x6f)
                                                (take-bytes script 3 20))))}
      ;; P2SH: OP_HASH160 0x14 <20> OP_EQUAL
      (and (= n 23) (= (b 0) 0xa9) (= (b 1) 0x14) (= (b 22) 0x87))
      {:type :p2sh :address (base58/encode-check
                             (byte-array (cons (if (= network :mainnet) 0x05 0xc4)
                                               (take-bytes script 2 20))))}
      :else
      {:type :unknown})))

;; ------------------------------ tx parse -----------------------------

(defn decode-outputs
  "Parse a raw unsigned Bitcoin tx (int vector) and return
  `{:ok? true :outputs [{:value-sat n :address .. :type ..} ...]}` or
  `{:ok? false :reason kw}`. Reads version, (optional) segwit marker,
  inputs (skipped), then every output; witness/locktime are ignored."
  ([raw] (decode-outputs raw {}))
  ([raw opts]
   (try
     (let [n (count raw)
           ;; version (4) then optional segwit marker 0x00 0x01
           segwit? (and (> n 5) (= (nth raw 4) 0x00) (= (nth raw 5) 0x01))
           i0 (if segwit? 6 4)
           [vin i1] (read-varint raw i0)
           ;; skip vin inputs: 36-byte outpoint + scriptSig(varint+bytes) + 4-byte seq
           i-after-in (loop [k 0 i i1]
                        (if (= k vin)
                          i
                          (let [i (+ i 36)
                                [slen i] (read-varint raw i)
                                i (+ i slen 4)]
                            (recur (inc k) i))))
           [vout i2] (read-varint raw i-after-in)]
       (loop [k 0 i i2 outs []]
         (if (= k vout)
           {:ok? true :outputs outs}
           (let [[value i] (read-le raw i 8)
                 [slen i] (read-varint raw i)
                 script (take-bytes raw i slen)
                 addr (script->address script opts)
                 i (+ i slen)]
             (recur (inc k) i
                    (conj outs (merge {:value-sat value} addr)))))))
     (catch Exception e
       {:ok? false :reason :parse-error :ex (str e)}))))

;; ------------------------------ verify -------------------------------

(defn verify
  "WYSIWYS check for a BTC withdrawal: decode the raw tx and confirm it
  pays exactly `intent` `{:address .. :value-sat ..}` on some output.
  Returns `{:verifier-match-flag 0|1 :reason kw :outputs ..}` — the flag
  drops straight into `cryptoexchange.kernels.custody`'s wire row.

  An unrecognized destination script, a decode failure, or the absence
  of an output paying the intended (address, value) all yield flag 0:
  the signer never signs a tx whose real destination they can't confirm
  from the bytes."
  [raw {:keys [address value-sat] :as _intent} opts]
  (let [{:keys [ok? outputs reason]} (decode-outputs raw opts)]
    (cond
      (not ok?) {:verifier-match-flag 0 :reason (or reason :decode-failed)}
      (some #(= (:type %) :unknown) outputs)
      {:verifier-match-flag 0 :reason :unrecognized-script :outputs outputs}
      (some #(and (= (:address %) address) (= (:value-sat %) value-sat)) outputs)
      {:verifier-match-flag 1 :reason :match :outputs outputs}
      :else
      {:verifier-match-flag 0 :reason :intent-not-in-outputs :outputs outputs})))
