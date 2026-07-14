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
  {:legacy {:to 3 :value 4 :data 5}   ; [nonce gasPrice gas TO VALUE DATA v r s]
   0x01    {:to 4 :value 5 :data 6}   ; EIP-2930 [chainId nonce gasPrice gas TO VALUE DATA accessList]
   0x02    {:to 5 :value 6 :data 7}}) ; EIP-1559 [chainId nonce maxPrio maxFee gas TO VALUE DATA accessList]

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

;; --------------------- Gnosis Safe execTransaction -------------------
;; A withdrawal from a Safe multisig (custody ADR §1, ETH cold) is NOT a
;; direct transfer: the outer tx's `to` is the Safe contract and its
;; DATA carries an ABI-encoded execTransaction(...) whose inner `to` /
;; `value` (or, for an ERC-20, a nested transfer(address,uint256)) is
;; the REAL destination. Recovering that from the calldata is the WYSIWYS
;; job for Safe — a signer must confirm the true recipient, not the Safe
;; address. Selectors verified against eth-crypto's keccak256:
;;   execTransaction(...) = 0x6a761202   transfer(address,uint256) = 0xa9059cbb
(def ^:private exec-selector [0x6a 0x76 0x12 0x02])
(def ^:private transfer-selector [0xa9 0x05 0x9c 0xbb])

(defn- selector? [calldata sel]
  (and (>= (count calldata) 4) (= (subvec (vec calldata) 0 4) sel)))

(defn- word
  "The i-th 32-byte ABI word (0-based) after the 4-byte selector, as an
  int vector."
  [calldata i]
  (let [s (+ 4 (* i 32))]
    (subvec (vec calldata) s (+ s 32))))

(defn- word-uint [calldata i] (big-endian (word calldata i)))

(defn- word-addr
  "ABI address word -> EIP-55 0x address (last 20 bytes of the word)."
  [calldata i]
  (let [w (word calldata i)]
    (eth/eip55-checksum (apply str (map #(format "%02x" %) (subvec w 12 32))))))

(defn- dyn-bytes
  "Dynamic `bytes` at ABI `byte-offset` (relative to the arg block, i.e.
  after the selector): a 32-byte length then that many bytes."
  [calldata byte-offset]
  (let [len-at (+ 4 byte-offset)
        len (big-endian (subvec (vec calldata) len-at (+ len-at 32)))
        start (+ len-at 32)]
    (subvec (vec calldata) start (+ start len))))

(defn decode-safe-exec
  "Decode a Safe `execTransaction` calldata (int vector) to the REAL
  intent. Returns {:ok? true :kind :native :to <0x> :value-wei n} for a
  native ETH move, {:ok? true :kind :token :token <0x> :to <0x> :amount
  n} for a nested ERC-20 transfer, or {:ok? false :reason kw}. Only
  operation 0 (CALL) is accepted; a DELEGATECALL or any unrecognized
  inner call fails closed (you don't sign what you can't reduce to a
  destination)."
  [calldata]
  (if-not (selector? calldata exec-selector)
    {:ok? false :reason :not-safe-exec}
    (let [to (word-addr calldata 0)
          value (word-uint calldata 1)
          data-off (word-uint calldata 2)
          operation (word-uint calldata 3)
          inner (dyn-bytes calldata data-off)]
      (cond
        (not= operation 0) {:ok? false :reason :delegatecall}
        (empty? inner) {:ok? true :kind :native :to to :value-wei value}
        (selector? inner transfer-selector)
        {:ok? true :kind :token :token to
         :to (word-addr inner 0) :amount (word-uint inner 1)}
        :else {:ok? false :reason :unrecognized-inner-call}))))

(defn decode-safe
  "Parse a raw unsigned ETH tx whose DATA is a Safe execTransaction, and
  recover the real inner intent (see `decode-safe-exec`)."
  [raw]
  (try
    (let [b0 (nth raw 0)
          [tx-type body-start] (if (>= b0 0xc0) [:legacy 0] [b0 1])
          [item _] (rlp-item (vec raw) body-start)
          fields (:list item)
          {:keys [data]} (get layout tx-type)]
      (if (or (nil? fields) (nil? data) (<= (count fields) data))
        {:ok? false :reason :unrecognized-tx-shape}
        (decode-safe-exec (vec (:str (nth fields data))))))
    (catch Exception e
      {:ok? false :reason :parse-error :ex (str e)})))

(defn- addr= [a b]
  (= (str/lower-case (str a)) (str/lower-case (str b))))

(defn verify-safe
  "WYSIWYS check for a Safe-multisig ETH withdrawal: decode the inner
  execTransaction and confirm it matches `intent`. Native intent:
  `{:kind :native :to <0x> :value-wei n}`. Token intent:
  `{:kind :token :token <0x> :to <0x> :amount n}`. Any decode failure,
  kind mismatch, or field mismatch fails closed -> flag 0."
  [raw {:keys [kind] :as intent}]
  (let [r (decode-safe raw)]
    (cond
      (not (:ok? r)) {:verifier-match-flag 0 :reason (:reason r)}
      (not= (:kind r) kind) {:verifier-match-flag 0 :reason :kind-mismatch :decoded r}
      (and (= kind :native)
           (addr= (:to r) (:to intent)) (= (:value-wei r) (:value-wei intent)))
      {:verifier-match-flag 1 :reason :match :decoded r}
      (and (= kind :token)
           (addr= (:token r) (:token intent)) (addr= (:to r) (:to intent))
           (= (:amount r) (:amount intent)))
      {:verifier-match-flag 1 :reason :match :decoded r}
      :else {:verifier-match-flag 0 :reason :intent-mismatch :decoded r})))
