(ns cryptoexchange.advisor
  "Exchange-LLM client — the *contained intelligence node*. It drafts
  operational actions (record a deposit, place an order, propose a
  withdrawal broadcast, propose a dual-control correction) as
  PROPOSALS: a proposal carries the domain event a commit would append,
  never a committed record and never a real chain broadcast. Every
  output is censored by `cryptoexchange.censor` before anything touches
  the store, and the actuation ops NEVER auto-commit at any phase (see
  `cryptoexchange.phase`).

  Deterministic mock so the actor graph runs offline and the governor
  contract is exercised end-to-end (same role as
  `underwriting.underwriterllm/mock-advisor`). In production this calls
  a real LLM with the same proposal shape.

  Proposal shape:
    {:summary  str
     :effect   kw    ; :ledger/deposit :order/place :ledger/withdrawal
                     ; :ledger/adjustment | :noop (read)
     :event    map   ; the domain event a commit would append (nil for reads)
     :stake    kw    ; :actuation for the real-world ops, else nil
     :confidence 0..1}"
  )

(defn- deposit [{:keys [account asset amount-minor seq]}]
  {:summary (str "入金記録: " account " " amount-minor " " asset)
   :effect :ledger/deposit
   :event {:kind :deposit :seq seq :account account :asset asset
           :amount-minor amount-minor}
   :stake nil
   :confidence 0.97})

(defn- place-order [{:keys [order]}]
  {:summary (str "注文: " (:side order) " " (:qty-minor order) " @ " (:price-minor order))
   :effect :order/place
   :event (assoc order :kind :order)
   :stake nil
   :confidence 0.95})

(defn- propose-withdrawal [{:keys [account asset amount-minor seq]}]
  {:summary (str "出金ブロードキャスト提案: " account " " amount-minor " " asset
                 " — 実ブロードキャストは custody 手順 + 人手サインオフの後のみ")
   :effect :ledger/withdrawal
   :event {:kind :withdrawal :seq seq :account account :asset asset
           :amount-minor amount-minor}
   :stake :actuation
   :confidence 0.9})

(defn- propose-adjustment [{:keys [account asset delta-minor seq evidence]}]
  {:summary (str "二重統制補正提案: " account " " delta-minor " " asset)
   :effect :ledger/adjustment
   :event {:kind :adjustment :seq seq :account account :asset asset
           :delta-minor delta-minor :evidence evidence}
   :stake :actuation
   :confidence 0.6})

(defn infer
  "Route a request to the right proposal generator."
  [{:keys [op] :as request}]
  (case op
    :balance/report {:summary "残高照会" :effect :noop :event nil :stake nil :confidence 1.0}
    :attestation/report {:summary "PoR/PoL 照会" :effect :noop :event nil :stake nil :confidence 1.0}
    :deposit/record (deposit request)
    :order/place (place-order request)
    :withdrawal/broadcast (propose-withdrawal request)
    :adjustment/apply (propose-adjustment request)
    {:summary (str "未対応の操作: " op) :effect :noop :event nil :stake nil :confidence 0.0}))

(defprotocol Advisor
  (-advise [advisor request] "request -> proposal map"))

(defn mock-advisor
  "The deterministic advisor (the `infer` logic above). Default everywhere."
  []
  (reify Advisor (-advise [_ req] (infer req))))

(defn trace
  "Decision-grounded audit record."
  [request proposal]
  {:t :advisor-proposal
   :op (:op request)
   :summary (:summary proposal)
   :effect (:effect proposal)
   :confidence (:confidence proposal)})
