(ns cryptoexchange.matching
  "Deterministic matching engine (INV-11 of ADR-2607141200): a pure
  fold of a totally-ordered order log. Same log in, same book and same
  fills out — on any runtime, for any third party. That property is
  the wash-trade/front-running countermeasure: the exchange cannot
  produce an execution it cannot re-derive in public, and an auditor
  holding the order log re-derives every fill.

  Design decisions (M2b):
  - Single sequencer: every order/cancel event carries
    :seq == (inc last-seq) of the book. A gap or replay is rejected —
    same total-order discipline as `cryptoexchange.ledger`.
  - Price-time priority: best price first; within a price, earliest
    :seq first. Priority keys are explicit composite keys
    ([price seq] vectors), so determinism never depends on a sort
    implementation's stability.
  - Maker price rule: fills execute at the RESTING order's price.
    A taker never gets a worse price than they asked; makers get
    exactly what they quoted (no engine discretion, no improvement
    that could be selectively granted — INV-4).
  - Self-trade prevention, strictest form (reject-taker): if ANY
    resting order in the incoming order's crossing region belongs to
    the same account, the entire incoming order is rejected before a
    single fill. Wash trading is refused at the engine, not policed
    after the fact (A9).
  - Limit orders only. Price is integer quote minor units PER base
    minor unit; a fill's quote leg is (* qty price) — pure integer
    arithmetic, no rounding branch to litigate.

  Events (plain data, the public order log):
    {:kind :order  :seq n :id oid :account a :side :buy|:sell
     :price-minor p :qty-minor q}
    {:kind :cancel :seq n :id oid :account a}

  `submit`/`cancel-order`/`replay-book` are the only constructors;
  like the ledger, there is no mutation API."
  )

(def empty-book {:last-seq 0 :bids [] :asks []})

;; --------------------------- priority keys ---------------------------

(defn- priority-key
  "Composite [price-rank seq]: lower sorts first on both sides."
  [side order]
  [(if (= side :buy)
     (- (:price-minor order))
     (:price-minor order))
   (:seq order)])

(defn- insert-resting
  "Insert preserving price-time priority via explicit composite keys."
  [orders side order]
  (vec (sort-by #(priority-key side %) (conj orders order))))

;; ----------------------------- crossing ------------------------------

(defn- crosses?
  [side price-minor resting]
  (if (= side :buy)
    (<= (:price-minor resting) price-minor)
    (<= price-minor (:price-minor resting))))

(defn- crossing-region
  "All resting opposite orders the incoming order could reach, in
  priority order."
  [book side price-minor]
  (let [opposite (if (= side :buy) (:asks book) (:bids book))]
    (vec (take-while #(crosses? side price-minor %) opposite))))

;; ---------------------------- validation -----------------------------

(defn- amount? [x] (and (integer? x) (pos? x)))

(defn- find-order [book oid]
  (some #(when (= (:id %) oid) %) (concat (:bids book) (:asks book))))

(defn- validate-order
  [book {:keys [kind seq id account side price-minor qty-minor]}]
  (cond
    (not= kind :order) :unknown-kind
    (not= seq (inc (:last-seq book))) :out-of-order
    (not (and id account
              (or (= side :buy) (= side :sell))
              (amount? price-minor)
              (amount? qty-minor))) :malformed
    (find-order book id) :duplicate-id
    (some #(= (:account %) account)
          (crossing-region book side price-minor)) :self-trade-prevented
    :else nil))

;; ------------------------------ matching -----------------------------

(defn- match-loop
  "Walk the crossing region in priority order, filling at maker
  prices. Returns {:fills [...] :consumed n :reduced order|nil
  :remaining qty}."
  [region taker-order]
  (loop [region region
         remaining (:qty-minor taker-order)
         fills []
         consumed 0]
    (if (or (= remaining 0) (empty? region))
      {:fills fills :consumed consumed :reduced nil :remaining remaining}
      (let [maker (first region)
            fill-qty (min remaining (:qty-minor maker))
            fill {:maker-id (:id maker)
                  :taker-id (:id taker-order)
                  :price-minor (:price-minor maker)
                  :qty-minor fill-qty
                  :buyer (if (= (:side taker-order) :buy)
                           (:account taker-order)
                           (:account maker))
                  :seller (if (= (:side taker-order) :buy)
                            (:account maker)
                            (:account taker-order))
                  :taker-seq (:seq taker-order)}
            maker-left (- (:qty-minor maker) fill-qty)]
        (if (= 0 maker-left)
          (recur (rest region) (- remaining fill-qty)
                 (conj fills fill) (inc consumed))
          {:fills (conj fills fill)
           :consumed consumed
           :reduced (assoc maker :qty-minor maker-left)
           :remaining 0})))))

(defn submit
  "Apply one :order event. {:ok? true :book b' :fills [...]} or
  {:ok? false :reason kw :book book} (unchanged on failure)."
  [book {:keys [seq side price-minor] :as order}]
  (if-let [reason (validate-order book order)]
    {:ok? false :reason reason :book book}
    (let [region (crossing-region book side price-minor)
          {:keys [fills consumed reduced remaining]} (match-loop region order)
          opposite-key (if (= side :buy) :asks :bids)
          own-key (if (= side :buy) :bids :asks)
          opposite' (vec (concat (if reduced [reduced] [])
                                 (drop (+ consumed (if reduced 1 0))
                                       (get book opposite-key))))
          book' (cond-> (assoc book
                               :last-seq seq
                               opposite-key opposite')
                  (pos? remaining)
                  (update own-key insert-resting side
                          (assoc order :qty-minor remaining)))]
      {:ok? true :book book' :fills fills})))

(defn cancel-order
  "Apply one :cancel event. Only the owner may cancel."
  [book {:keys [kind seq id account]}]
  (cond
    (not= kind :cancel) {:ok? false :reason :unknown-kind :book book}
    (not= seq (inc (:last-seq book))) {:ok? false :reason :out-of-order :book book}
    :else
    (let [order (find-order book id)]
      (cond
        (nil? order) {:ok? false :reason :unknown-order :book book}
        (not= (:account order) account) {:ok? false :reason :not-owner :book book}
        :else
        (let [strip (fn [orders] (vec (remove #(= (:id %) id) orders)))]
          {:ok? true
           :book (-> book
                     (assoc :last-seq seq)
                     (update :bids strip)
                     (update :asks strip))})))))

;; ------------------------------ replay --------------------------------

(defn replay-book
  "Rebuild book + full fill history from a raw event seq, re-validating
  every event — the third-party recomputation path (an auditor
  re-derives every execution from the public order log). Stops at the
  first invalid event: {:ok? false :reason kw :at seq-no ...}."
  [events]
  (reduce (fn [{:keys [book fills]} {:keys [kind] :as event}]
            (let [r (case kind
                      :order (submit book event)
                      :cancel (cancel-order book event)
                      {:ok? false :reason :unknown-kind :book book})]
              (if (:ok? r)
                {:ok? true :book (:book r)
                 :fills (into fills (:fills r []))}
                (reduced {:ok? false :reason (:reason r)
                          :at (:seq event) :book book :fills fills}))))
          {:ok? true :book empty-book :fills []}
          events))

;; --------------------------- ledger seam ------------------------------

(defn fill->trade-event
  "Shape one fill as a `cryptoexchange.ledger` :trade event for the
  market {:base .. :quote ..}. The quote leg is (* qty price) — price
  is quote minor units per base minor unit."
  [fill market ledger-seq]
  {:kind :trade
   :seq ledger-seq
   :buyer (:buyer fill)
   :seller (:seller fill)
   :base (:base market)
   :quote (:quote market)
   :base-amount-minor (:qty-minor fill)
   :quote-amount-minor (* (:qty-minor fill) (:price-minor fill))})
