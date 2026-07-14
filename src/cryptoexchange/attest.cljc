(ns cryptoexchange.attest
  "PoR + PoL attestation (INV-7 of ADR-2607141200): a Merkle-SUM tree
  over customer liabilities with per-user inclusion proofs, combined
  with an externally-attested reserve figure and judged by the
  SOLVENCY KERNEL. The daily public artifact is `attestation` — and a
  reserves-only statement is non-conforming by construction here: you
  cannot build the artifact without the liability root.

  Why a SUM tree (Maxwell-style): every internal node commits to the
  SUM of its children as well as their hashes, so the root's :sum IS
  the total customer liability, and any user's inclusion proof
  re-derives a slice of that total. Hiding liabilities (Mt. Gox A3,
  FTX A1) would require publishing a smaller root sum — which every
  user's proof then contradicts. The verifier also rejects any
  negative intermediate sum (the classic trick for shrinking a sum
  tree).

  Determinism: leaves are sorted by account name; node hashes are
  SHA-256 over ASCII strings (hex child hashes + decimal sums), so
  JVM and ClojureScript builds produce byte-identical roots — the
  test suite pins a fixture root hash to hold both runtimes to it.
  An odd node is carried UP unchanged (never duplicated — duplication
  would double-count its sum).

  Scope note (M2c): the reserve side arrives as attested inputs
  (:reserve-minor + :reserve-refs, e.g. signed on-chain address
  proofs). Wiring real chain attestations and the nbb publishing
  script is later work; the artifact shape and the kernel judgment
  are fixed here."
  (:require [cryptoexchange.governor :as governor]
            [cryptoexchange.ledger :as ledger]
            #?(:clj [clojure.string :as str])))

;; ------------------------------ hashing ------------------------------

#?(:cljs (def ^:private node-crypto (js/require "crypto")))

(defn sha256-hex
  "Hex SHA-256 of an ASCII/UTF-8 string. Portable: JVM MessageDigest /
  Node crypto (the CLJS primary gate runs on --target node; a browser
  build needs an async subtle-crypto adapter and is out of scope)."
  [s]
  #?(:clj
     (let [d (java.security.MessageDigest/getInstance "SHA-256")]
       (str/join (map #(format "%02x" (bit-and % 0xff))
                      (.digest d (.getBytes ^String s "UTF-8")))))
     :cljs
     (-> (.createHash node-crypto "sha256")
         (.update s "utf8")
         (.digest "hex"))))

(defn leaf-hash [account asset amount]
  (sha256-hex (str "leaf|" account "|" asset "|" amount)))

(defn node-hash [left-hash left-sum right-hash right-sum]
  (sha256-hex (str "node|" left-hash "|" left-sum "|" right-hash "|" right-sum)))

;; ------------------------------ building -----------------------------

(defn liability-leaves
  "Deterministic leaf row: customer balances (operator excluded) for
  one asset, sorted by account name, zero balances dropped."
  [ledger asset]
  (->> (dissoc (ledger/balances ledger) ledger/operator-account)
       (keep (fn [[account assets]]
               (let [amount (get assets asset 0)]
                 (when (pos? amount)
                   {:account account
                    :amount amount
                    :hash (leaf-hash account asset amount)
                    :sum amount}))))
       (sort-by (comp str :account))
       vec))

(defn- level-up
  "Combine one level pairwise; an odd trailing node carries up as-is."
  [nodes]
  (loop [nodes nodes acc []]
    (cond
      (empty? nodes) acc
      (= 1 (count nodes)) (conj acc (first nodes))
      :else
      (let [[l r & more] nodes]
        (recur more
               (conj acc {:hash (node-hash (:hash l) (:sum l) (:hash r) (:sum r))
                          :sum (+ (:sum l) (:sum r))}))))))

(defn build-tree
  "Merkle-sum tree over one asset's liabilities.
  {:asset a :leaves [...] :levels [[leaf-level] [level-1] ... [root]]
   :root {:hash h :sum total}} — empty book gets a defined empty root."
  [ledger asset]
  (let [leaves (liability-leaves ledger asset)]
    (if (empty? leaves)
      {:asset asset :leaves [] :levels []
       :root {:hash (sha256-hex "empty") :sum 0}}
      (let [levels (loop [level leaves acc [leaves]]
                     (if (= 1 (count level))
                       acc
                       (let [next-level (level-up level)]
                         (recur next-level (conj acc next-level)))))]
        {:asset asset
         :leaves leaves
         :levels levels
         :root (first (peek levels))}))))

;; ------------------------------ proofs -------------------------------

(defn inclusion-proof
  "Sibling path for `account`'s leaf: [{:side :left|:right :hash h
  :sum s} ...] from leaf level upward (carried-up levels contribute no
  step). nil when the account has no leaf."
  [tree account]
  (when-let [idx (first (keep-indexed
                         (fn [i leaf] (when (= (:account leaf) account) i))
                         (:leaves tree)))]
    (loop [i idx
           levels (:levels tree)
           proof []]
      (let [level (first levels)]
        (if (or (nil? level) (= 1 (count level)))
          proof
          (let [sibling-i (if (even? i) (inc i) (dec i))
                carried? (>= sibling-i (count level))
                proof' (if carried?
                         proof
                         (let [s (nth level sibling-i)]
                           (conj proof {:side (if (even? i) :right :left)
                                        :hash (:hash s)
                                        :sum (:sum s)})))]
            (recur (quot i 2) (rest levels) proof')))))))

(defn verify-inclusion
  "Third-party verification: recompute from the claimed (account,
  asset, amount) leaf through the proof to the published root. Rejects
  any negative sum along the path (sum-shrinking attack) and any
  root mismatch in HASH or SUM."
  [account asset amount proof root]
  (if (or (not (integer? amount)) (neg? amount))
    false
    (loop [h (leaf-hash account asset amount)
           s amount
           steps proof]
      (if (empty? steps)
        (and (= h (:hash root)) (= s (:sum root)))
        (let [{:keys [side] :as step} (first steps)]
          (if (or (neg? (:sum step)) (nil? (:hash step)))
            false
            (let [[nh nsum] (if (= side :left)
                              [(node-hash (:hash step) (:sum step) h s)
                               (+ (:sum step) s)]
                              [(node-hash h s (:hash step) (:sum step))
                               (+ s (:sum step))])]
              (recur nh nsum (rest steps)))))))))

;; ---------------------------- attestation ----------------------------

(defn attestation
  "The daily public artifact for one asset (INV-7): liability root
  (PoL), attested reserves (PoR inputs), and the SOLVENCY KERNEL's
  judgment — including the intake-halt consequence (INV-1). There is
  no reserves-only variant of this function on purpose.

  `reserve` is {:reserve-minor n :self-token? bool :reserve-refs [...]}
  — :self-token? must be explicitly attested false for the reserve to
  count at all (INV-3, fail-closed at the governor boundary)."
  [ledger asset {:keys [reserve-minor self-token? reserve-refs]}]
  (let [tree (build-tree ledger asset)
        liability (get-in tree [:root :sum])
        solvency (governor/solvency-check {:reserve-minor reserve-minor
                                           :liability-minor liability
                                           :self-token? self-token?})]
    {:asset asset
     :liability-root (:root tree)
     :leaf-count (count (:leaves tree))
     :reserve-minor reserve-minor
     :reserve-refs (vec (or reserve-refs []))
     :solvency solvency
     :halt-intake? (:halt-intake? solvency)}))
