;; Thin nbb (ClojureScript-on-Node) shell around cryptoexchange.publish —
;; the repo's runtime rule (logic in portable .cljc, scripts in nbb;
;; superproject CLAUDE.md 2026-07-10). ALL the load-bearing logic lives
;; in src/cryptoexchange/publish.cljc (+ attest/ledger), which the CLJS
;; primary and JVM compat gates test; this file only reads the ledger
;; and reserve EDN, folds them, and writes the two public artifacts.
;;
;; Run (verified 2026-07-14 with nbb via npx):
;;   nbb -cp src scripts/publish_attestation.cljs \
;;       <ledger.edn> <reserves.edn> <as-of> <out-dir>
;;
;; ledger.edn   — the append-only event vector (cryptoexchange.ledger events)
;; reserves.edn — {:btc {:reserve-minor N :self-token? false
;;                       :reserve-refs ["addr:.."]} :jpy {...}}
;; as-of        — a timestamp string, e.g. 2026-07-14T00:00:00Z
;; out-dir      — writes attestation-<as-of>.edn + attestation-<as-of>.md
;;
;; Emitting a reserves-only file is impossible: build-artifact always
;; folds the Merkle-sum liability tree in (INV-7).
(ns publish-attestation
  (:require [cljs.reader :as reader]
            [clojure.string :as str]
            ["fs" :as fs]
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.publish :as publish]))

(defn -main [& args]
  (let [[ledger-path reserves-path as-of out-dir] args]
    (when (or (nil? ledger-path) (nil? reserves-path) (nil? as-of) (nil? out-dir))
      (println "usage: publish_attestation.cljs <ledger.edn> <reserves.edn> <as-of> <out-dir>")
      (throw (ex-info "missing args" {})))
    (let [events (reader/read-string (str (fs/readFileSync ledger-path)))
          reserves (reader/read-string (str (fs/readFileSync reserves-path)))
          ;; replay validates every event — a tampered log is refused here,
          ;; so we never publish an attestation over a non-replayable ledger.
          replay (ledger/replay events)
          _ (when-not (:ok? replay)
              (throw (ex-info "ledger does not replay" (select-keys replay [:reason :at]))))
          artifact (publish/build-artifact (:ledger replay) reserves as-of)
          safe (str/replace as-of #"[^0-9A-Za-z-]" "_")
          edn-path (str out-dir "/attestation-" safe ".edn")
          md-path (str out-dir "/attestation-" safe ".md")]
      (fs/writeFileSync edn-path (publish/render-edn artifact))
      (fs/writeFileSync md-path (publish/render-summary-md artifact))
      (println "overall-solvent?" (:overall-solvent? artifact))
      (println "wrote" edn-path)
      (println "wrote" md-path))))

(apply -main *command-line-args*)
