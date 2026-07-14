(ns cryptoexchange.publish
  "Daily PoR + PoL public-artifact builder (INV-7 of ADR-2607141200) —
  the pure, testable core of the publishing pipeline. It folds the
  event-sourced ledger into the per-asset Merkle-sum attestation
  (`cryptoexchange.attest`) plus every account's inclusion proof, and
  renders a canonical EDN artifact and a human-readable Markdown
  summary.

  Runtime split (repo rule: logic in portable .cljc, scripts in nbb):
  this ns is the logic and is exercised by the CLJS primary + JVM
  compat gates; `scripts/publish_attestation.cljs` is the thin nbb
  shell that does the file I/O around it.

  Reserves come in as attested inputs, per asset:
    {:btc {:reserve-minor N :self-token? false :reserve-refs [\"addr:..\"]}
     :jpy {...}}
  `:self-token?` must be explicitly attested false for a reserve to
  count (INV-3, fail-closed at the governor boundary). `as-of` is a
  caller-supplied timestamp string (kept out of this ns so the builder
  stays deterministic and unit-testable)."
  (:require [clojure.string :as str]
            [cryptoexchange.attest :as attest]))

(defn build-artifact
  "Fold `ledger` + `reserves` into the daily public artifact map.
  Deterministic given its inputs (asof is passed in)."
  [ledger reserves as-of]
  (let [assets (sort (keys reserves))
        per-asset
        (mapv (fn [asset]
                (let [att (attest/attestation ledger asset (get reserves asset))
                      tree (attest/build-tree ledger asset)]
                  {:asset asset
                   :liability-root (:liability-root att)
                   :leaf-count (:leaf-count att)
                   :reserve-minor (:reserve-minor att)
                   :reserve-refs (:reserve-refs att)
                   :solvent? (get-in att [:solvency :ok?])
                   :halt-intake? (:halt-intake? att)
                   :inclusion-proofs
                   (into {}
                         (map (fn [leaf]
                                [(:account leaf)
                                 {:amount (:amount leaf)
                                  :proof (attest/inclusion-proof tree (:account leaf))}]))
                         (:leaves tree))}))
              assets)]
    {:kind :cryptoexchange/attestation
     :spec "ADR-2607141200 INV-7 (PoR + PoL, Merkle-sum liabilities)"
     :as-of as-of
     :overall-solvent? (every? :solvent? per-asset)
     :assets per-asset}))

(defn render-edn
  "Canonical EDN serialization — the machine-verifiable artifact."
  [artifact]
  (pr-str artifact))

(defn- yn [b] (if b "yes" "no"))

(defn render-summary-md
  "Human-readable Markdown summary. The reserves-only shortcut is
  structurally impossible: every row shows the liability root sum
  (PoL) beside the reserve (PoR), and any user can recompute their own
  leaf against the published root using their inclusion proof."
  [artifact]
  (let [{:keys [as-of overall-solvent? assets]} artifact]
    (str/join
     "\n"
     (concat
      [(str "# Proof of Reserves + Liabilities — " as-of)
       ""
       (str "Overall solvent: **" (yn overall-solvent?) "**")
       ""
       "| Asset | Liability (PoL root sum) | Reserves (PoR) | Solvent | Accounts | Intake |"
       "|---|---:|---:|:---:|---:|:---:|"]
      (map (fn [{:keys [asset liability-root reserve-minor solvent? leaf-count halt-intake?]}]
             (str "| " (name asset)
                  " | " (:sum liability-root)
                  " | " reserve-minor
                  " | " (yn solvent?)
                  " | " leaf-count
                  " | " (if halt-intake? "HALTED" "open")
                  " |"))
           assets)
      [""
       "Each asset's liability figure is the root **sum** of a Merkle-sum"
       "tree over customer balances; every account holds an inclusion proof"
       "(in the EDN artifact) that recomputes its own balance up to that"
       "published root. Reserve figures are attested on-chain (see"
       "`:reserve-refs`). A reserves-only statement is not a conforming"
       "artifact under INV-7."
       ""
       "Roots:"]
      (map (fn [{:keys [asset liability-root reserve-refs]}]
             (str "- **" (name asset) "** liability-root `"
                  (:hash liability-root) "` (sum " (:sum liability-root) ")"
                  (when (seq reserve-refs)
                    (str " · reserves " (str/join ", " reserve-refs)))))
           assets)))))
