;; Regression check for docs/verify.html — the self-contained browser
;; inclusion-proof verifier (INV-7 follow-up, ADR-2607141200 Addendum 6/7).
;; That page is deliberately written in dependency-free vanilla JS, not
;; ClojureScript: its entire value is being independently auditable and
;; runnable without trusting (or even having) this project's own
;; toolchain — so its own logic must NOT be reused/imported here. This
;; script instead extracts the page's embedded <script> text and
;; evaluates it in an isolated scope, the same way a suspicious end user
;; would read the page source and reason about it, then exercises it
;; against a real project-generated fixture to confirm it agrees with
;; cryptoexchange.attest's own verify-inclusion.
;;
;; Run (verified 2026-07-15 with nbb via npx):
;;   nbb scripts/verify_docs_verify_html.cljs
;;
;; This is a standalone script, not wired into the cognitect test-runner/
;; portable-cljs-test-runner suites: it tests a static HTML deliverable,
;; not a .cljc namespace, so it doesn't fit either harness's contract.
(ns verify-docs-verify-html
  (:require ["fs" :as fs]))

(defn- extract-page-logic
  "Pull the parser/hash/verify logic out of docs/verify.html's <script>
  block, stopping before the DOM-wiring section (which needs a real
  document) -- mirrors exactly what a from-scratch auditor would read."
  [html]
  (let [start (+ (.indexOf html "<script>\n\"use strict\";") (count "<script>\n"))
        marker "/* ---------------------------------------------------------------------\n * UI wiring"
        end (.indexOf html marker)]
    (when (or (neg? start) (neg? end))
      (throw (js/Error. "could not locate the expected <script> markers in docs/verify.html")))
    (subs html start end)))

(defn- check-account [page asset-name proofs root acct]
  (let [entry (aget proofs acct)]
    (.then ((.-verifyInclusion page) acct asset-name (aget entry "amount") (aget entry "proof") root)
           (fn [result]
             (println " " acct "amount=" (aget entry "amount")
                      (if (.-ok result) "PASS" (str "FAIL: " (.-reason result))))
             (when-not (.-ok result)
               (throw (js/Error. (str acct " should have PASSed and did not"))))
             true))))

(defn- check-tampered [page asset-name proofs root]
  (.then ((.-verifyInclusion page) "alice" asset-name 999999 (aget (aget proofs "alice") "proof") root)
         (fn [tampered]
           (println "  alice with a wrong claimed amount:"
                    (if (.-ok tampered) "PASS (BUG!)" "correctly FAILS"))
           (when (.-ok tampered)
             (throw (js/Error. "tampered claim incorrectly PASSED"))))))

(defn -main [& _]
  (let [html (.readFileSync fs "docs/verify.html" "utf8")
        logic (extract-page-logic html)
        factory (js/Function. (str logic "\nreturn {ednParse, verifyInclusion, ednName};"))
        page (factory)
        artifact-text (.readFileSync fs "test/fixtures/verify-html-fixture.edn" "utf8")
        artifact ((.-ednParse page) artifact-text)
        asset (aget (.-assets artifact) 0)
        root (aget asset "liability-root")
        asset-name ((.-ednName page) (aget asset "asset"))
        proofs (aget asset "inclusion-proofs")
        accounts (js/Object.keys proofs)]
    (println "Loaded docs/verify.html logic; testing against" (count accounts)
             "real accounts for asset" asset-name)
    (-> (js/Promise.all (map #(check-account page asset-name proofs root %) accounts))
        (.then #(check-tampered page asset-name proofs root))
        (.then #(println "\nAll checks passed."))
        (.catch (fn [err]
                  (js/console.error "FAILED:" (.-message err))
                  (js/process.exit 1))))))

(apply -main *command-line-args*)
