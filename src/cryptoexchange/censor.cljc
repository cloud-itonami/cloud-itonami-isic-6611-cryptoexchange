(ns cryptoexchange.censor
  "ExchangeGovernor — the independent compliance layer that earns the
  Exchange-LLM the right to commit (M4 actor of ADR-2607141200). The
  advisor has no notion of solvency, custody quorum or self-dealing;
  this MUST be a separate system able to REJECT a proposal and fall
  back to HOLD — the crypto-exchange analog of the wave-0 finance
  governors (RegistrarGovernor / UnderwritingGovernor / …).

  Pure function over ALREADY-ASSEMBLED evidence (the actor folds the
  store into this shape at the boundary; the censor never touches a
  store, so it is fully unit-testable and CLJS-portable). All decisions
  are delegated to the four safety kernels via `cryptoexchange.governor`
  — this ns only routes the right evidence to the right kernel per op
  and applies HARD-over-escalate-over-commit precedence.

  Checks, in priority order (first three HARD — human approval CANNOT
  override; the last is SOFT — a human signs off):
    1. Conflict     (INV-2/4) — on every WRITE op (reads commit nothing,
                                so they pass through, like the phase
                                gate). Operator self-dealing /
                                rehypothecation attestations must be
                                clean before anything commits.
    2. Solvency     (INV-1/3) — on INTAKE ops (deposit/order). Insolvent
                                book halts new intake/trading.
    3. Conservation (INV-6)   — on INTAKE ops. A broken book halts.
    4. Custody      (INV-8/9/10) — on withdrawal. A denial is HARD:
                                collect the missing fact and re-propose;
                                you cannot approve past a verifier
                                mismatch or a velocity breach.
    5. Actuation gate — a real-world act (:stake :actuation — a chain
                        broadcast or a dual-control correction) always
                        escalates to a human, at every phase.

  `:stake :actuation` is derived structurally from the op (withdrawal
  broadcast + adjustment), never taken from the advisor's word."
  (:require [cryptoexchange.governor :as governor]))

(def intake-ops
  "Ops that add customer intake/trading and are gated on a solvent,
  conserved book."
  #{:deposit/record :order/place})

(def actuation-ops
  "Ops whose commit is a real-world act — always a human call, at every
  phase (structural, like underwriting's :policy/bind)."
  #{:withdrawal/broadcast :adjustment/apply})

(def read-ops #{:balance/report :attestation/report})

(defn actuation?
  "Structural stake of an op — never read from the advisor."
  [op]
  (contains? actuation-ops op))

;; ------------------------------- checks ------------------------------

(defn- conflict-violations [{:keys [op]} {:keys [attestations]}]
  (when-not (contains? read-ops op)
    (let [r (governor/conflict-check (or attestations {}))]
      (when-not (:clean? r)
        (mapv (fn [v] {:rule :self-dealing :structure v}) (:violations r))))))

(defn- solvency-violations [{:keys [op]} {:keys [solvency]}]
  (when (contains? intake-ops op)
    (let [r (governor/solvency-check (or solvency {}))]
      (when (:halt-intake? r)
        [{:rule :insolvent :reason (:reason r)}]))))

(defn- conservation-violations [{:keys [op]} {:keys [conservation]}]
  (when (contains? intake-ops op)
    (let [r (governor/conservation-check (or conservation {}))]
      (when (:halt-intake? r)
        [{:rule :conservation-broken :reason (:reason r)}]))))

(defn- custody-violations [{:keys [op]} {:keys [custody]}]
  (when (= op :withdrawal/broadcast)
    (let [r (governor/withdrawal-check (or custody {}))]
      (when-not (:allow? r)
        [{:rule :custody-denied :reason (:reason r)}]))))

(defn check
  "Censor a proposal for `request` against assembled `context` evidence.
  Returns {:ok? :hard? :escalate? :high-stakes? :violations [..]}.

  - :hard?      — ≥1 HARD violation. Forces HOLD; no human override.
  - :escalate?  — soft: actuation. A human signs off.
  - :ok?        — clean AND not escalating: safe to auto-commit
                  (subject to the phase gate, which can only add caution)."
  [{:keys [op] :as request} context]
  (let [hard (into []
                   (concat (conflict-violations request context)
                           (solvency-violations request context)
                           (conservation-violations request context)
                           (custody-violations request context)))
        stakes? (actuation? op)]
    {:ok? (and (empty? hard) (not stakes?))
     :hard? (boolean (seq hard))
     :escalate? (and (empty? hard) stakes?)
     :high-stakes? stakes?
     :violations hard}))

(defn hold-fact
  "Audit fact written when a proposal is rejected (HOLD)."
  [request context verdict]
  {:t :governor-hold
   :op (:op request)
   :actor (:actor-id context)
   :subject (:subject request)
   :disposition :hold
   :basis (mapv :rule (:violations verdict))
   :violations (:violations verdict)})
