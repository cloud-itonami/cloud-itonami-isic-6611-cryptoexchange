(ns cryptoexchange.phase
  "Phase 0→3 staged rollout for the exchange actor — the crypto-exchange
  analog of `underwriting.phase`: start narrow (read-only), widen as
  trust grows. Where the ExchangeGovernor (`cryptoexchange.censor`)
  answers 'is this allowed?', the phase answers 'how much autonomy does
  the actor have *yet*?'. It can only ever make the actor MORE
  conservative than the governor, never the reverse.

    Phase 0  read-only        — balance / attestation reads only.
    Phase 1  assisted-intake  — deposit recording allowed, every write
                                needs human approval.
    Phase 2  + trading        — adds order placement (still approval).
    Phase 3  supervised-auto  — governor-clean deposit/order writes may
                                auto-commit.

  `:withdrawal/broadcast` and `:adjustment/apply` (the actuation ops —
  a real chain broadcast, a dual-control correction) are deliberately
  ABSENT from every phase's `:auto` set, INCLUDING phase 3. This is a
  permanent structural fact about this table, not a rollout milestone
  still to come — a withdrawal is always a human sign-off (§4 of the
  custody ADR, WYSIWYS). The censor's actuation gate enforces the same
  invariant independently — two layers agree, deliberately.

  Reads pass through every phase (phase restricts autonomy, not reads).
  A governor HOLD always stays HOLD (compliance wins)."
  (:require [cryptoexchange.censor :as censor]))

(def phases
  "phase → {:label .. :writes <ops allowed to write> :auto <ops allowed
  to auto-commit when governor-clean>}."
  {0 {:label "read-only"       :writes #{}                                :auto #{}}
   1 {:label "assisted-intake" :writes #{:deposit/record}                 :auto #{}}
   2 {:label "assisted-trading" :writes #{:deposit/record :order/place}   :auto #{}}
   3 {:label "supervised-auto" :writes #{:deposit/record :order/place
                                         :withdrawal/broadcast :adjustment/apply}
      :auto #{:deposit/record :order/place}}})

(def default-phase 3)

;; NOTE the invariant: the actuation ops are members of phase 3's
;; :writes (they are governor-gated writes) but are NEVER members of
;; any phase's :auto set. Do not add them there.

(defn verdict->disposition
  "Map a censor verdict to a base disposition before the phase gate."
  [verdict]
  (cond (:hard? verdict) :hold
        (:escalate? verdict) :escalate
        :else :commit))

(defn gate
  "Adjust a base disposition for the rollout phase. Returns
  {:disposition kw :reason kw|nil}.

  - reads pass through unchanged.
  - a base HOLD stays HOLD.
  - a write op not enabled in this phase → HOLD (:phase-disabled).
  - a write op enabled but not auto-eligible → ESCALATE
    (:phase-approval), even if the governor was clean.
  - the actuation ops are never auto-eligible, so once the governor
    clears them they always escalate."
  [phase {:keys [op]} base-disposition]
  (let [p (get phases (if (contains? phases phase) phase default-phase))
        writes (:writes p)
        auto (:auto p)]
    (cond
      (= base-disposition :hold) {:disposition :hold :reason nil}
      (contains? censor/read-ops op) {:disposition base-disposition :reason nil}
      (not (contains? writes op)) {:disposition :hold :reason :phase-disabled}
      (and (= base-disposition :commit)
           (not (contains? auto op))) {:disposition :escalate :reason :phase-approval}
      :else {:disposition base-disposition :reason nil})))
