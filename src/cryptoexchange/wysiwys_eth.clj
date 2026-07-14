(ns cryptoexchange.wysiwys-eth
  "REAL WYSIWYS decoder for Ethereum — the ETH counterpart of
  `cryptoexchange.wysiwys-btc` (custody ADR §4, INV-10). Parses an
  ACTUAL raw unsigned Ethereum transaction (legacy / EIP-2930 /
  EIP-1559) back to its `(to address, value)` so a signer verifies what
  they are really about to sign from the bytes, not from a wallet UI
  (the Bybit/DMM attack).

  Adds the RLP DECODE direction that `kotoba-lang/eth-crypto` lacks
  (it has `rlp-encode`), and reuses eth-crypto's `eip55-checksum` for
  the address formatting rather than re-deriving keccak/EIP-55.

  **JVM-only** — eth-crypto's keccak/rlp are `byte-array`-based (no CLJS
  branch), so like wysiwys-btc this is a deliberate compat layer at the
  JVM actuation boundary (the actor's broadcast path is JVM-driven),
  NOT on the portable CLJS kernel path.

  Raw tx is a vector of ints 0..255 (same representation as
  `cryptoexchange.wysiwys` / `wysiwys-btc`). Scope: a DIRECT ETH
  transfer's `to`/`value`. A Safe-multisig `execTransaction` wraps the
  real destination inside calldata / an EIP-712 SafeTx struct — decoding
  THAT is a documented follow-up (the SafeTx struct-hash path); an
  unrecognized shape fails closed rather than reporting a wrong
  destination."
  (:require [clojure.string :as str]
            [eth-crypto.core :as eth]))

;; ------------------------------ RLP decode ---------------------------

(defn- big-endian [bs] (reduce (fn [acc b] (+' (*' acc 256) b)) 0 bs))

(defn- read-len [bs i n] [(big-endian (subvec bs i (+ i n))) (+ i n)])

(declare rlp-item)

(defn- rlp-list [bs start end]
  (loop [i start items []]
    (if (>= i end)
      items
      (let [[it j] (rlp-item bs i)] (recur j (conj items it))))))

(defn- rlp-item
  "Decode one RLP item at `i`. Returns [item next-i] where item is
  {:str [bytes]} or {:list [items]}."
  [bs i]
  (let [b (nth bs i)]
    (cond
      (< b 0x80) [{:str [b]} (inc i)]
      (<= b 0xb7) (let [len (- b 0x80) s (inc i)] [{:str (subvec bs s (+ s len))} (+ s len)])
      (<= b 0xbf) (let [ll (- b 0xb7) [len j] (read-len bs (inc i) ll)]
                    [{:str (subvec bs j (+ j len))} (+ j len)])
      (<= b 0xf7) (let [len (- b 0xc0) s (inc i) e (+ s len)] [{:list (rlp-list bs s e)} e])
      :else (let [ll (- b 0xf7) [len j] (read-len bs (inc i) ll) e (+ j len)]
              [{:list (rlp-list bs j e)} e]))))

;; ------------------------ field → human meaning ----------------------

(defn- addr-of
  "20-byte address field → EIP-55 checksummed 0x address, or nil for the
  empty field (contract creation — no destination)."
  [{s :str}]
  (when (= 20 (count s))
    (eth/eip55-checksum (apply str (map #(format "%02x" %) s)))))

(defn- wei-of [{s :str}] (big-endian (or s [])))

;; ------------------------------ tx parse -----------------------------
;; Field layout per type; nil `type` = legacy (starts directly with the
;; RLP list, first byte >= 0xc0).
(def ^:private layout
  {:legacy {:to 3 :value 4}   ; [nonce gasPrice gas TO VALUE data v r s]
   0x01    {:to 4 :value 5}   ; EIP-2930 [chainId nonce gasPrice gas TO VALUE data accessList]
   0x02    {:to 5 :value 6}}) ; EIP-1559 [chainId nonce maxPrio maxFee gas TO VALUE data accessList]

(defn decode-transfer
  "Parse a raw unsigned ETH tx (int vector) → {:ok? true :to <0x addr>
  :value-wei <n> :tx-type kw|int} or {:ok? false :reason kw}."
  [raw]
  (try
    (let [b0 (nth raw 0)
          [tx-type body-start] (if (>= b0 0xc0) [:legacy 0] [b0 1])
          [item _] (rlp-item (vec raw) body-start)
          fields (:list item)
          {:keys [to value]} (get layout tx-type)]
      (if (or (nil? fields) (nil? to) (<= (count fields) value))
        {:ok? false :reason :unrecognized-tx-shape}
        (let [addr (addr-of (nth fields to))]
          (if (nil? addr)
            {:ok? false :reason :no-destination}   ; contract creation / malformed to
            {:ok? true :to addr :value-wei (wei-of (nth fields value)) :tx-type tx-type}))))
    (catch Exception e
      {:ok? false :reason :parse-error :ex (str e)})))

;; ------------------------------ verify -------------------------------

(defn verify
  "WYSIWYS check for an ETH withdrawal: decode the raw tx and confirm it
  sends exactly `intent` `{:to <0x addr> :value-wei n}`. Returns
  `{:verifier-match-flag 0|1 :reason kw ...}` for the custody kernel's
  wire row. Address comparison is case-insensitive on the hex (EIP-55
  checksum casing is display-only), but the 20 address bytes must match
  exactly. A decode failure or destination mismatch fails closed."
  [raw {:keys [to value-wei] :as _intent}]
  (let [r (decode-transfer raw)]
    (cond
      (not (:ok? r)) {:verifier-match-flag 0 :reason (:reason r)}
      (and (= (clojure.string/lower-case (str (:to r)))
              (clojure.string/lower-case (str to)))
           (= (:value-wei r) value-wei))
      {:verifier-match-flag 1 :reason :match :to (:to r) :value-wei (:value-wei r)}
      :else
      {:verifier-match-flag 0 :reason :intent-mismatch :to (:to r) :value-wei (:value-wei r)})))
