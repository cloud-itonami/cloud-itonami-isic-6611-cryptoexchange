(ns cryptoexchange.store
  "Persistence seam for the two append-only logs (M2d of
  ADR-2607141200), behind a `Store` protocol so the backend is a swap,
  not a rewrite — the same seam the wave-0 finance actors use
  (`underwriting.store` / `formation.store` / `realty.store`):

    - `MemStore`     — atom of EDN. The deterministic default for
                       dev/tests/demo (no deps).
    - `DatomicStore` — backed by `langchain.db`, a Datomic-API-
                       compatible EAV store (datalog q / upsert). Pure
                       `.cljc`, so it runs offline AND can be pointed
                       at a real Datomic Local or a kotoba-server pod
                       by swapping `langchain.db`'s `:db-api`
                       (see langchain.kotoba-db) — 'kotoba-datomic を
                       唯一の状態層とする' is this seam.

  The store persists EVENTS ONLY — the ledger event log (settlement)
  and the order log (matching). Balances, books and attestation roots
  are always folds over what the store returns; no backend holds a
  materialized balance anywhere (INV-5: there is nothing mutable to
  backdoor, on any backend).

  Every append VALIDATES through the domain fold first
  (`cryptoexchange.ledger/append`, `cryptoexchange.matching/submit` /
  `cancel-order`): an event a fresh replay would reject is never
  persisted, so a stored log is always fully replayable by a third
  party — on either backend."
  (:require #?(:clj [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.matching :as matching]
            [langchain.db :as d]))

(defprotocol Store
  (ledger-events [s] "the totally-ordered settlement event vector")
  (order-events [s] "the totally-ordered order/cancel event vector")
  (append-ledger-event! [s event]
    "validate via the ledger fold, persist when valid; the fold's
     {:ok? ..} result either way")
  (append-order-event! [s event]
    "validate via the matching fold, persist when valid; the fold's
     {:ok? ..} result (with :fills on a fill) either way"))

;; --------------------------- derived views ---------------------------
;; Folds over the store's logs — identical on every backend by
;; construction, because they only consume the protocol reads.

(defn ledger-of
  "The folded ledger {:events [...]} (see cryptoexchange.ledger)."
  [s]
  {:events (vec (ledger-events s))})

(defn book-of
  "The folded {:book .. :fills ..} replay of the order log."
  [s]
  (let [r (matching/replay-book (order-events s))]
    {:book (:book r) :fills (:fills r)}))

;; ---------------------- backend-agnostic appends ---------------------

(defn- try-ledger-append
  "Validate against the CURRENT stored log; nil when invalid."
  [s event]
  (ledger/append (ledger-of s) event))

(defn- try-order-append
  [s event]
  (let [{:keys [book]} (book-of s)]
    (case (:kind event)
      :order (matching/submit book event)
      :cancel (matching/cancel-order book event)
      {:ok? false :reason :unknown-kind :book book})))

;; ----------------------------- MemStore ------------------------------

(defrecord MemStore [a]
  Store
  (ledger-events [_] (:ledger-events @a))
  (order-events [_] (:order-events @a))
  (append-ledger-event! [s event]
    (let [r (try-ledger-append s event)]
      (when (:ok? r) (swap! a update :ledger-events conj event))
      r))
  (append-order-event! [s event]
    (let [r (try-order-append s event)]
      (when (:ok? r) (swap! a update :order-events conj event))
      r)))

(defn mem-store []
  (->MemStore (atom {:ledger-events [] :order-events []})))

;; --------------------------- DatomicStore ----------------------------

(def ^:private schema
  "Events are stored one datom-entity per event, keyed by their
  sequencer number (:db.unique/identity — an accidental double-append
  of a seq upserts instead of forking history), with the event map as
  an EDN string so langchain.db doesn't expand it into sub-entities —
  the same convention the sibling stores use."
  {:ledger-event/seq {:db/unique :db.unique/identity}
   :order-event/seq  {:db/unique :db.unique/identity}})

(defn- enc [v] (pr-str v))
(defn- dec* [s] (when s (edn/read-string s)))

(defn- read-stream [conn seq-attr edn-attr]
  (->> (d/q [:find '?s '?v
             :where ['?e seq-attr '?s] ['?e edn-attr '?v]]
            (d/db conn))
       (sort-by first)
       (mapv (comp dec* second))))

(defrecord DatomicStore [conn]
  Store
  (ledger-events [_] (read-stream conn :ledger-event/seq :ledger-event/edn))
  (order-events [_] (read-stream conn :order-event/seq :order-event/edn))
  (append-ledger-event! [s event]
    (let [r (try-ledger-append s event)]
      (when (:ok? r)
        (d/transact! conn [{:ledger-event/seq (:seq event)
                            :ledger-event/edn (enc event)}]))
      r))
  (append-order-event! [s event]
    (let [r (try-order-append s event)]
      (when (:ok? r)
        (d/transact! conn [{:order-event/seq (:seq event)
                            :order-event/edn (enc event)}]))
      r)))

(defn datomic-store []
  (->DatomicStore (d/create-conn schema)))
