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
            [merkle-sum.core :as merkle]
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

(defn- pname
  "Stable public name for an account/asset: a keyword's name WITHOUT its
  leading colon (:alice -> \"alice\", :btc -> \"btc\"), a string as-is.
  The published artifact renders accounts/assets this same way, so a
  third party recomputes the identical leaf preimage from the JSON —
  the leaf hash must NOT depend on Clojure's keyword print form."
  [x]
  (if (keyword? x) (name x) (str x)))

(defn leaf-hash
  "Domain leaf preimage: colon-free names so the published EDN string is
  exactly what was hashed (see docs/verify-inclusion.md). The generic
  tree/proof/verify are `merkle-sum.core`'s; this is the PoR-specific
  part that stays here."
  [account asset amount]
  (sha256-hex (str "leaf|" (pname account) "|" (pname asset) "|" amount)))

;; ------------------------------ building -----------------------------

(defn liability-leaves
  "Deterministic leaf row for `merkle-sum.core`: customer balances
  (operator excluded) for one asset, zero balances dropped. `:id` is the
  account (the tree's sort/lookup key); `:hash`/`:sum` feed the tree;
  `:account`/`:amount` are kept for this ns's own convenience."
  [ledger asset]
  (->> (dissoc (ledger/balances ledger) ledger/operator-account)
       (keep (fn [[account assets]]
               (let [amount (get assets asset 0)]
                 (when (pos? amount)
                   {:id account
                    :account account
                    :amount amount
                    :hash (leaf-hash account asset amount)
                    :sum amount}))))
       vec))

(defn build-tree
  "Merkle-sum tree over one asset's liabilities — delegates to
  `merkle-sum.core/build-tree` (leaves sorted by account id via `str`).
  Returns its `{:leaves :levels :root}` with `:asset` assoc'd."
  [ledger asset]
  (assoc (merkle/build-tree sha256-hex (liability-leaves ledger asset))
         :asset asset))

;; ------------------------------ proofs -------------------------------

(defn inclusion-proof
  "Sibling path for `account`'s leaf (see `merkle-sum.core/inclusion-proof`)."
  [tree account]
  (merkle/inclusion-proof tree account))

(defn verify-inclusion
  "Third-party verification of an (account, asset, amount) claim against
  a published root — recomputes the leaf preimage here, then delegates
  the walk (incl. sum-shrinking rejection) to `merkle-sum.core/verify`."
  [account asset amount proof root]
  (if (integer? amount)
    (merkle/verify sha256-hex (leaf-hash account asset amount) amount proof root)
    false))

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
