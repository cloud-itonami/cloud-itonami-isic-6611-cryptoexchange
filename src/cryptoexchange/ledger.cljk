(ns cryptoexchange.ledger
  "Append-only event-sourced ledger — the ONLY state layer of the
  exchange (INV-5 of ADR-2607141200). Balances and every aggregate are
  pure folds of the event vector; there is no mutation API in this
  namespace or anywhere else in the repo, and `append`/`replay` are
  the only constructors. Any third party holding the same event log
  reproduces the same balances and the same conservation sums
  (INV-6), which is what makes the PoR/PoL artifacts (M2c) verifiable
  rather than trusted.

  Design decisions (M2a):
  - Total order: every event carries :seq == (inc last-seq). A gap or
    replay is rejected — this is the groundwork for the deterministic
    matching engine's single-sequencer order log (INV-11).
  - No negative balances BY CONSTRUCTION: a withdrawal/fee/trade leg
    that would overdraw is rejected at append time. The conservation
    kernel still re-checks the folded sums (defense in depth: a
    tampered event vector that bypassed `append` is caught on replay
    or by the kernel — the FTX allow_negative backdoor has no home).
  - Manual corrections exist only as :adjustment events with >= 2
    distinct approvers (dual control, INV-5) and land on the public
    log like everything else. They may not overdraw either.
  - Customer liabilities vs operator revenue: fees move value from a
    customer account to the reserved :operator account. Conservation
    (INV-6) is stated over CUSTOMER balances:
        sum(customer balances) == deposits - withdrawals - fees
    per asset, which is exactly what the conservation kernel checks.

  All amounts are integer minor units. Events are plain data:
    {:kind :deposit    :seq n :account a :asset k :amount-minor x}
    {:kind :withdrawal :seq n :account a :asset k :amount-minor x}
    {:kind :fee        :seq n :account a :asset k :amount-minor x}
    {:kind :trade      :seq n :buyer b :seller s :base k :quote k2
                       :base-amount-minor x :quote-amount-minor y}
    {:kind :adjustment :seq n :account a :asset k :delta-minor d
                       :approvers [p q ...] :evidence \"...\"}

  `append` returns {:ok? true :ledger l'} or {:ok? false :reason kw}
  — no exceptions, portable .cljc."
  (:require [cryptoexchange.governor :as governor]))

(def operator-account
  "Reserved account that accrues fees. Excluded from customer sums."
  :operator)

(def empty-ledger {:events []})

;; ------------------------------ folds -------------------------------

(defn- credit [balances account asset amount]
  (update-in balances [account asset] (fnil + 0) amount))

(defn- debit [balances account asset amount]
  (update-in balances [account asset] (fnil - 0) amount))

(defn- apply-event
  "Fold one ALREADY-VALIDATED event into a balances map."
  [balances {:keys [kind account asset amount-minor buyer seller base quote
                    base-amount-minor quote-amount-minor delta-minor]}]
  (case kind
    :deposit    (credit balances account asset amount-minor)
    :withdrawal (debit balances account asset amount-minor)
    :fee        (-> balances
                    (debit account asset amount-minor)
                    (credit operator-account asset amount-minor))
    :trade      (-> balances
                    (debit seller base base-amount-minor)
                    (credit buyer base base-amount-minor)
                    (debit buyer quote quote-amount-minor)
                    (credit seller quote quote-amount-minor))
    :adjustment (update-in balances [account asset] (fnil + 0) delta-minor)))

(defn balances
  "Pure fold: the full balances map {account {asset amount}}."
  [ledger]
  (reduce apply-event {} (:events ledger)))

(defn balance
  "Pure fold: one account/asset balance."
  [ledger account asset]
  (get-in (balances ledger) [account asset] 0))

;; --------------------------- validation -----------------------------

(defn- amount? [x] (and (integer? x) (pos? x)))

(defn- last-seq [ledger]
  (if (seq (:events ledger))
    (:seq (peek (:events ledger)))
    0))

(defn- covered?
  "true when `account` holds at least `amount` of `asset`."
  [bals account asset amount]
  (<= amount (get-in bals [account asset] 0)))

(defn- validate
  "nil when the event may append, else a reason keyword."
  [ledger {:keys [kind seq account asset amount-minor buyer seller base quote
                  base-amount-minor quote-amount-minor delta-minor approvers]}]
  (let [bals (balances ledger)]
    (cond
      (not= seq (inc (last-seq ledger))) :out-of-order

      (= kind :deposit)
      (when-not (and account asset (amount? amount-minor)) :malformed)

      (= kind :withdrawal)
      (cond (not (and account asset (amount? amount-minor))) :malformed
            (not (covered? bals account asset amount-minor)) :insufficient-balance
            :else nil)

      (= kind :fee)
      (cond (not (and account asset (amount? amount-minor))) :malformed
            (= account operator-account) :malformed
            (not (covered? bals account asset amount-minor)) :insufficient-balance
            :else nil)

      (= kind :trade)
      (cond (not (and buyer seller base quote
                      (not= buyer seller) (not= base quote)
                      (amount? base-amount-minor)
                      (amount? quote-amount-minor))) :malformed
            (not (covered? bals seller base base-amount-minor)) :insufficient-balance
            (not (covered? bals buyer quote quote-amount-minor)) :insufficient-balance
            :else nil)

      (= kind :adjustment)
      (cond (not (and account asset (integer? delta-minor)
                      (not= 0 delta-minor))) :malformed
            (< (count (set approvers)) 2) :dual-control-required
            (< (+ (get-in bals [account asset] 0) delta-minor) 0) :insufficient-balance
            :else nil)

      :else :unknown-kind)))

;; --------------------------- constructors ---------------------------

(defn append
  "The ONLY way to grow a ledger. {:ok? true :ledger l'} or
  {:ok? false :reason kw :ledger ledger} (unchanged on failure)."
  [ledger event]
  (if-let [reason (validate ledger event)]
    {:ok? false :reason reason :ledger ledger}
    {:ok? true :ledger (update ledger :events conj event)}))

(defn replay
  "Rebuild a ledger from a raw event seq, re-validating every event —
  the third-party recomputation path. Stops at the first invalid
  event: {:ok? false :reason kw :at seq-no :ledger valid-prefix}."
  [events]
  (reduce (fn [{:keys [ledger]} event]
            (let [r (append ledger event)]
              (if (:ok? r)
                {:ok? true :ledger (:ledger r)}
                (reduced {:ok? false :reason (:reason r)
                          :at (:seq event) :ledger ledger}))))
          {:ok? true :ledger empty-ledger}
          events))

;; ------------------------ conservation seam -------------------------

(defn conservation-sums
  "Per-asset aggregates over CUSTOMER accounts (operator excluded),
  shaped for `cryptoexchange.governor/conservation-check`. Reproducible
  by any third party from the same event log."
  [ledger asset]
  (let [events (:events ledger)
        bals (balances ledger)
        sum-of (fn [kind]
                 (reduce + 0 (map :amount-minor
                                  (filter #(and (= (:kind %) kind)
                                                (= (:asset %) asset))
                                          events))))
        adj-sum (reduce + 0 (map :delta-minor
                                 (filter #(and (= (:kind %) :adjustment)
                                               (= (:asset %) asset))
                                         events)))
        customer-balances (reduce + 0
                                  (map #(get % asset 0)
                                       (vals (dissoc bals operator-account))))]
    ;; Adjustments are folded into the deposit column (a positive
    ;; correction is economically a deposit-shaped entry, a negative
    ;; one a withdrawal-shaped entry) so the kernel equation stays
    ;; exactly balances == deposits - withdrawals - fees.
    {:sum-balances-minor customer-balances
     :sum-deposits-minor (+ (sum-of :deposit) adj-sum)
     :sum-withdrawals-minor (sum-of :withdrawal)
     :sum-fees-minor (sum-of :fee)}))

(defn conservation-check
  "Run the conservation KERNEL over this ledger's folded sums for one
  asset. Any nonzero code halts intake/trading (INV-6)."
  [ledger asset]
  (governor/conservation-check (conservation-sums ledger asset)))
