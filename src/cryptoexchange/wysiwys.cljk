(ns cryptoexchange.wysiwys
  "WYSIWYS (What You See Is What You Sign) dual-verifier harness — the
  automatable core of the custody ADR §4 (docs/adr/0001), the
  Bybit/DMM/WazirX countermeasure (INV-10 of ADR-2607141200).

  The physical parts of §4 — air-gapped signers, per-device screen
  confirmation, the key ceremony — cannot be unit-tested. What CAN be
  made mechanical, and is here, is the load-bearing rule:

    `cryptoexchange.kernels.custody`'s verifier-match-flag may be set to
    1 ONLY when two INDEPENDENT decoders reconstruct the intended
    payload from the RAW unsigned transaction bytes and byte-compare
    equal — never from a wallet UI, a web page, or a PSBT metadata
    field an attacker can forge.

  This ns provides:
    - a tiny canonical wire format (a stand-in for a raw unsigned tx:
      length-prefixed fields over bytes) so the two decoders have
      something concrete and adversarial to parse;
    - TWO independent decoders (`decode-a`, `decode-b`) written to
      DIFFERENT strategies, so a bug or a tampered field in one is
      unlikely to be mirrored in the other;
    - `verify`, which decodes both, byte-compares, and cross-checks the
      result against the operator's INTENDED withdrawal — a mismatch on
      ANY axis (the two decoders disagree, OR they agree but differ
      from intent) yields verifier-match 0.

  `verify` returns {:verifier-match-flag 0|1 :reason kw :decoded ..}
  ready to drop into the custody kernel's wire row. A compromised
  wallet UI (Bybit) or signing workstation (DMM) must now defeat two
  independent toolchains AND the intent record to get a 1.

  Bytes are integers 0..255 in vectors — portable .cljc, no host
  crypto, deterministic on JVM and ClojureScript. This is a semantic
  harness for the equality discipline, not a real transaction codec;
  the real decoders parse actual BTC/ETH unsigned tx bytes to the same
  contract."
  )

;; --------------------------- wire format -----------------------------
;; A raw \"unsigned tx\": [tag len byte... ] records, concatenated.
;; tags: 1 destination, 2 asset, 3 amount (big-endian minor units),
;;       4 fee, 5 chain-id. A field is (tag, len, len bytes).

(def ^:private tag->field
  {1 :destination 2 :asset 3 :amount-minor 4 :fee-minor 5 :chain-id})

(defn- bytes->int [bs] (reduce (fn [acc b] (+ (* acc 256) b)) 0 bs))

(defn- ascii->str [bs]
  #?(:clj (apply str (map char bs))
     :cljs (apply str (map #(js/String.fromCharCode %) bs))))

(defn str->bytes [s]
  #?(:clj (mapv int s)
     :cljs (mapv #(.charCodeAt s %) (range (count s)))))

(defn int->bytes
  "Big-endian minimal byte vector (at least one byte)."
  [n]
  (if (zero? n)
    [0]
    (loop [n n acc ()]
      (if (zero? n) (vec acc) (recur (quot n 256) (cons (mod n 256) acc))))))

(defn encode-field [tag bs]
  (into [tag (count bs)] bs))

(defn encode-tx
  "Build the canonical raw bytes for an intended withdrawal — the thing
  a real signer would be handed. Field order is fixed."
  [{:keys [destination asset amount-minor fee-minor chain-id]}]
  (vec (concat (encode-field 1 (str->bytes destination))
               (encode-field 2 (str->bytes asset))
               (encode-field 3 (int->bytes amount-minor))
               (encode-field 4 (int->bytes fee-minor))
               (encode-field 5 (int->bytes chain-id)))))

;; --------------------------- decoder A -------------------------------
;; Strategy A: linear scan, explicit index arithmetic.

(defn decode-a
  "Returns {:ok? true :fields {...}} or {:ok? false :reason kw}."
  [bytes]
  (loop [i 0 acc {}]
    (cond
      (= i (count bytes))
      (if (= 5 (count acc)) {:ok? true :fields acc} {:ok? false :reason :missing-fields})

      (> (+ i 2) (count bytes)) {:ok? false :reason :truncated-header}

      :else
      (let [tag (nth bytes i)
            len (nth bytes (inc i))
            start (+ i 2)
            end (+ start len)]
        (cond
          (> end (count bytes)) {:ok? false :reason :truncated-value}
          (not (contains? tag->field tag)) {:ok? false :reason :unknown-tag}
          :else
          (let [raw (subvec (vec bytes) start end)
                field (tag->field tag)
                v (case field
                    (:destination :asset) (ascii->str raw)
                    (bytes->int raw))]
            (recur end (assoc acc field v))))))))

;; --------------------------- decoder B -------------------------------
;; Strategy B: recursive consume via partition-by-header, independent
;; of A's index math. Deliberately a different shape.

(defn- take-field [bytes]
  (when (>= (count bytes) 2)
    (let [tag (first bytes)
          len (second bytes)
          rest' (drop 2 bytes)]
      (when (and (contains? tag->field tag) (>= (count rest') len))
        {:tag tag :len len
         :raw (vec (take len rest'))
         :remaining (drop len rest')}))))

(defn decode-b
  [bytes]
  (loop [remaining (seq bytes) acc {}]
    (if (nil? remaining)
      (if (= 5 (count acc)) {:ok? true :fields acc} {:ok? false :reason :missing-fields})
      (if-let [{:keys [tag raw remaining]} (take-field remaining)]
        (let [field (tag->field tag)
              v (if (or (= field :destination) (= field :asset))
                  (ascii->str raw)
                  (bytes->int raw))]
          (recur (seq remaining) (assoc acc field v)))
        {:ok? false :reason :decode-failed}))))

;; ----------------------------- verify --------------------------------

(defn verify
  "The load-bearing rule. Decode `raw-bytes` on two independent paths,
  require they agree, AND require they match the operator's `intent`
  (destination/asset/amount/fee/chain-id). Any disagreement -> flag 0.

  Returns {:verifier-match-flag 0|1 :reason kw :decoded map|nil} — the
  flag drops straight into cryptoexchange.kernels.custody's wire row."
  [raw-bytes intent]
  (let [ra (decode-a raw-bytes)
        rb (decode-b raw-bytes)]
    (cond
      (not (:ok? ra)) {:verifier-match-flag 0 :reason (keyword (str "decode-a-" (name (:reason ra)))) :decoded nil}
      (not (:ok? rb)) {:verifier-match-flag 0 :reason (keyword (str "decode-b-" (name (:reason rb)))) :decoded nil}
      (not= (:fields ra) (:fields rb)) {:verifier-match-flag 0 :reason :decoders-disagree :decoded nil}
      (not= (:fields ra) (select-keys intent [:destination :asset :amount-minor :fee-minor :chain-id]))
      {:verifier-match-flag 0 :reason :intent-mismatch :decoded (:fields ra)}
      :else {:verifier-match-flag 1 :reason :match :decoded (:fields ra)})))
