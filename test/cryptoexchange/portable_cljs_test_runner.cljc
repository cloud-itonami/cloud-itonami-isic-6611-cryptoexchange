(ns cryptoexchange.portable-cljs-test-runner
  "PRIMARY automated quality gate for this repo under a real
  ClojureScript host (cljs.main --target node) — the same runtime-
  priority rule as gftdcojp/cloud-itonami's ADR-0016 / the superproject
  CLAUDE.md:

      kotoba wasm runtime  >  clojurewasm  >  ClojureScript  >  nbb
      (JVM / babashka are last-resort compat, not the design target)

  The whole test suite is portable .cljc and runs UNCHANGED here and on
  the JVM (`clojure -M:test`, secondary compat gate).

  Invoke from the repo root (the :test alias's :main-opts would steal
  -m if combined, hence -Sdeps for the extra path):

    clojure -Sdeps '{:paths [\"src\" \"test\"]}' \\
      -M:cljs -m cljs.main --target node \\
      -m cryptoexchange.portable-cljs-test-runner"
  (:require [clojure.test :as t :refer [run-tests]]
            [cryptoexchange.governor-facade-test]
            [cryptoexchange.kernels.conflict-test]
            [cryptoexchange.kernels.conservation-test]
            [cryptoexchange.kernels.custody-test]
            [cryptoexchange.kernels.solvency-test]
            [cryptoexchange.ledger-test]))

#?(:cljs
   (defmethod t/report [:cljs.test/default :end-run-tests] [m]
     (when-not (t/successful? m)
       (set! (.-exitCode js/process) 1))))

(defn -main []
  (run-tests 'cryptoexchange.kernels.solvency-test
             'cryptoexchange.kernels.custody-test
             'cryptoexchange.kernels.conservation-test
             'cryptoexchange.kernels.conflict-test
             'cryptoexchange.governor-facade-test
             'cryptoexchange.ledger-test))
