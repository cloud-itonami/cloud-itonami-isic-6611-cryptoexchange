(ns cryptoexchange.actor
  "OperationActor — one exchange operation = one supervised actor run,
  expressed as a langgraph-clj StateGraph (M4 of ADR-2607141200). The
  advisor (Exchange-LLM) is sealed into a single node (:advise); its
  proposal is ALWAYS routed through the ExchangeGovernor (:govern) and
  the rollout phase gate (:decide) before anything commits to the
  store.

  Everything the actor depends on is injected, so each is a swap:
    - the Store    (MemStore | DatomicStore, cryptoexchange.store) — `store` arg
    - the Advisor  (mock | real LLM)                               — :advisor opt
    - the Phase    (0→3 rollout)                                   — :phase in context

  One graph run = one operation (advise → assemble evidence → govern →
  decide → commit | hold | sign-off). No unbounded inner loop; each run
  is auditable and checkpointed.

  Human-in-the-loop = real sign-off: `interrupt-before #{:request-signoff}`
  pauses the actor and hands the decision to a human operator. The
  actuation ops (:withdrawal/broadcast, :adjustment/apply) ALWAYS reach
  this node when the governor is clean — a withdrawal is never
  auto-broadcast (custody ADR §4). The signer resumes with
  `{:approval {:status :approved :by ..}}` (or :rejected).

  INV-14 boundary: even on :approved, :withdrawal/broadcast only APPENDS
  the settlement event to the store — the actual chain broadcast is out
  of scope here (no real funds/keys). The seam where a real broadcaster
  would be invoked is the commit node's :ledger/withdrawal branch, and
  it is gated on the custody kernel + this human sign-off, never on the
  advisor."
  (:require [langgraph.graph :as g]
            [langgraph.checkpoint :as cp]
            [cryptoexchange.advisor :as advisor]
            [cryptoexchange.censor :as censor]
            [cryptoexchange.ledger :as ledger]
            [cryptoexchange.phase :as phase]
            [cryptoexchange.store :as store]))

(defn- assemble-context
  "Fold the store into censor evidence for this request. Operator
  attestations, the daily reserve figure and the withdrawal's custody
  params come from `context` (operator-supplied); solvency liabilities
  and conservation sums are recomputed from the store's ledger — the
  actor never trusts a supplied liability number."
  [store request context]
  (let [asset (:asset request)
        led (store/ledger-of store)
        customer-liability (reduce + 0 (map #(get % asset 0)
                                            (vals (dissoc (ledger/balances led)
                                                          ledger/operator-account))))]
    (cond-> context
      (contains? censor/intake-ops (:op request))
      (assoc :solvency (assoc (:reserve context) :liability-minor customer-liability)
             :conservation (ledger/conservation-sums led asset))

      (= (:op request) :withdrawal/broadcast)
      (assoc :custody (:custody context)))))

(defn- commit-event!
  "Append the proposal's domain event through the store (which
  re-validates via the domain fold — defense in depth). For an
  :adjustment, attach the approvers (dual control): the operator plus
  the human signer."
  [store proposal approval]
  (let [{:keys [effect event]} proposal]
    (case effect
      (:ledger/deposit :ledger/withdrawal)
      (store/append-ledger-event! store event)

      :order/place
      (store/append-order-event! store event)

      :ledger/adjustment
      (store/append-ledger-event!
       store (assoc event :approvers (vec (distinct (remove nil?
                                                            [:operator (:by approval)])))))
      {:ok? true})))

(defn build
  "Compile an OperationActor bound to `store` (any cryptoexchange.store/Store).
  opts:
    :advisor      — a cryptoexchange.advisor/Advisor (default: mock-advisor)
    :checkpointer — langgraph checkpointer (default: in-mem)"
  [store & [{:keys [advisor checkpointer]
             :or {advisor (advisor/mock-advisor)
                  checkpointer (cp/mem-checkpointer)}}]]
  (-> (g/state-graph
       {:channels
        {:request {:default nil}
         :context {:default nil}
         :proposal {:default nil}
         :evidence {:default nil}
         :verdict {:default nil}
         :disposition {:default nil}
         :approval {:default nil}
         :audit {:reducer into :default []}}})

      (g/add-node :intake (fn [s] s))

      (g/add-node :advise
        (fn [{:keys [request]}]
          (let [p (advisor/-advise advisor request)]
            {:proposal p :audit [(advisor/trace request p)]})))

      (g/add-node :assemble
        (fn [{:keys [request context]}]
          {:evidence (assemble-context store request context)}))

      (g/add-node :govern
        (fn [{:keys [request evidence]}]
          {:verdict (censor/check request evidence)}))

      (g/add-node :decide
        (fn [{:keys [request context verdict]}]
          (let [base (phase/verdict->disposition verdict)
                ph (:phase context phase/default-phase)
                {:keys [disposition reason]} (phase/gate ph request base)]
            (case disposition
              :hold {:disposition :hold
                     :audit [(cond-> (censor/hold-fact request context verdict)
                               reason (assoc :phase-reason reason :phase ph))]}
              :escalate {:disposition :escalate
                         :audit [{:t :signoff-requested :op (:op request)
                                  :reason (or reason (when (:high-stakes? verdict) :actuation))
                                  :phase ph}]}
              :commit {:disposition :commit}))))

      (g/add-node :request-signoff
        (fn [{:keys [request context approval verdict]}]
          (if (= :approved (:status approval))
            {:disposition :commit
             :audit [{:t :signoff-granted :op (:op request) :by (:by approval)}]}
            {:disposition :hold
             :audit [(merge (censor/hold-fact request context
                                              (assoc verdict :violations
                                                     [{:rule :signer-rejected}]))
                            {:t :signoff-rejected})]})))

      (g/add-node :commit
        (fn [{:keys [request proposal approval]}]
          (let [r (commit-event! store proposal approval)]
            {:audit [{:t :committed :op (:op request) :effect (:effect proposal)
                      :store-ok? (:ok? r) :store-reason (:reason r)}]})))

      (g/add-node :hold (fn [_] {}))

      (g/set-entry-point :intake)
      (g/add-edge :intake :advise)
      (g/add-edge :advise :assemble)
      (g/add-edge :assemble :govern)
      (g/add-edge :govern :decide)

      (g/add-conditional-edges :decide
        (fn [{:keys [disposition]}]
          (case disposition
            :commit :commit
            :escalate :request-signoff
            :hold)))

      (g/add-conditional-edges :request-signoff
        (fn [{:keys [disposition]}]
          (if (= :commit disposition) :commit :hold)))

      (g/set-finish-point :commit)
      (g/set-finish-point :hold)

      (g/compile-graph
       {:checkpointer checkpointer
        :interrupt-before #{:request-signoff}})))
