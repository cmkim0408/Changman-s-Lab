# CACL-OC R4.5.1 amendment V2 — exact pre-reveal contract

## Why V2 exists

The unpublished amendment draft in
`30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT` correctly diagnosed and corrected
the R4.5 phase error, but its downstream receipt validator did not recompute
enough of the public-evidence chain. That draft was never uploaded and never
authorized target reveal. It is retained and hash-bound here as a rejected
draft.

V2 preserves the same narrow infrastructure correction and adds fail-closed
validation of:

- exact amendment, dependency, critical-original, and public-path keysets;
- the exact original failure fingerprint;
- the two historical plus eight authorized UCI 967 paths;
- all 8 authorized artifacts against the Stage-B lock;
- the complete patched Stage-B chain (34 checks, 82 files, 4 bindings);
- amendment ACK schema, status, commit, timestamp, file count, paths, hashes,
  and byte evidence;
- live GitHub commit metadata and raw bytes at verification and again before
  authorization/evaluation;
- Stage-A < Stage-B < amendment < reveal timestamp ordering;
- every load-bearing amendment verification field and count;
- a final amendment audit binding the original verification, reveal, verdict,
  and independent final audit.

## Scientific invariants

No frozen R4.5 file is edited. No feature, split, seed, tree, route, action,
estimand, alpha, threshold, certificate, or success gate changes. The only
runtime correction scopes the Stage-A prior-access census to its public
pre-access snapshot. The invalid post-access replay is replaced by an exact
whitelist and Stage-B-lock rehash of the eight authorized files.

The correction and all evidence in this V2 contract must be publicly
timestamped and byte-verified before target outcome reveal. Any unexpected
failure, path, hash, field, count, timestamp, or prior output aborts.

## Claim boundary

A successful run is a target-outcome-uninformed computational confirmation
under a transparently amended infrastructure validator. It is not an
unamended verifier run, independent custody, prospective physical
acquisition, causal or biological proof, clinical utility, wet-lab
validation, or field-safety evidence.
