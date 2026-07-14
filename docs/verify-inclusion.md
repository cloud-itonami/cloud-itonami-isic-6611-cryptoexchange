# Verifying your balance in the PoR/PoL attestation

This is the **independent** verification spec for the daily attestation
artifact (INV-7 of ADR-2607141200). Proof of Liabilities only means
something if you can check your own balance **without trusting the
exchange's code** — so this document specifies the algorithm precisely
enough to implement in any language, and the worked example below is
reproduced with plain `sha256` (no project code at all).

The exchange publishes, per day, `attestation-<as-of>.edn` (the single
canonical format; see `cryptoexchange.publish` /
`scripts/publish_attestation.cljs`). EDN reads natively in the fleet's
own runtime stack (kotoba wasm > clojurewasm > ClojureScript > nbb); in
any other language, an EDN parser or a couple of lines of parsing gets
you the fields — the verification below is serialization-agnostic. You
need three things from the artifact, for your asset:

- your `:inclusion-proofs {<account> {:amount .. :proof ..}}` — your
  balance and the sibling path;
- the asset's `:liability-root` (`{:hash .. :sum ..}`);
- the asset name.

## Hashing

All hashes are **SHA-256 over a UTF-8 ASCII string**, rendered as
lowercase hex. There are exactly two preimages. The account/asset go in
by their **plain name with no leading colon** — even though EDN prints
them as keywords (`:alice`), the hash preimage uses `alice`, so the
preimage never depends on a serialization's syntax:

```
leaf  hash:  sha256_hex( "leaf|" + account + "|" + asset + "|" + amount )
node  hash:  sha256_hex( "node|" + leftHash + "|" + leftSum + "|" + rightHash + "|" + rightSum )
```

`amount` and the sums are decimal integers (minor units). The tree is a
**Merkle *sum* tree**: every node commits to the SUM of its children as
well as their hashes, so the root's `sum` *is* the total customer
liability. That is what makes hidden liabilities impossible — shrinking
the published root sum contradicts every user's proof.

## Algorithm

```
verify(account, asset, amount, proof, root):
    if amount < 0: return FAIL
    h = leaf_hash(account, asset, amount)
    s = amount
    for step in proof:                      # leaf -> root order
        if step.sum < 0: return FAIL        # reject sum-shrinking
        if step.side == "left":             # sibling is on the left
            h = node_hash(step.hash, step.sum, h, s)
            s = step.sum + s
        else:                               # sibling is on the right
            h = node_hash(h, s, step.hash, step.sum)
            s = s + step.sum
    return (h == root.hash) and (s == root.sum)
```

A `FAIL` (or any mismatch at the end) means the artifact does not
actually account for your balance — escalate publicly. A single-customer
asset has an empty proof and the leaf IS the root.

## Worked example (reproduce with any sha256 tool)

From a fixture artifact where `alice` holds `300` and `bob` holds `200`
in `btc`:

```
liability-root: { hash: 761d744d192581c6246ebb4a0e1d72ee27bc3a046c7715109276906054b0c35a, sum: 500 }
alice: amount 300, proof [ { side: "right", hash: 762d490e...e6c3e81a, sum: 200 } ]
```

Verify alice, by hand:

```sh
# leaf
printf 'leaf|alice|btc|300' | sha256sum
# -> 5d89ef379d3d26b491464b4fc915a3e11da6a72f20aaaf2b4b9e531d94438d64

# sibling is on the right, so node(leafHash, 300, siblingHash, 200):
printf 'node|5d89ef379d3d26b491464b4fc915a3e11da6a72f20aaaf2b4b9e531d94438d64|300|762d490e3c71a64349f98fd154c1f7f2b2c99267c744e4a841c9305ee6c3e81a|200' | sha256sum
# -> 761d744d192581c6246ebb4a0e1d72ee27bc3a046c7715109276906054b0c35a   == root.hash  ✓
# sum: 300 + 200 = 500                                                    == root.sum   ✓
```

(`sha256sum` on Linux; `shasum -a 256` on macOS. Both were used to
reproduce these exact digests independently of the project code.)

## What this does and does not prove

- **Proves**: your balance is included in the published liability total,
  and the total is the root sum. Combined with the reserve figure and
  `reserve-refs` (on-chain PoR) in the same artifact, and the solvency
  judgment (`solvent?`), you can check reserves ≥ liabilities yourself.
- **Does not prove**: that the reserve addresses are solely controlled by
  the exchange (that's the on-chain multisig's job — custody ADR §1), nor
  that *other* users' balances are correct (only the aggregate). Broad
  liability correctness comes from many users each verifying their own
  leaf — so verify yours, every day.
