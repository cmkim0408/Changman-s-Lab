# R4.4 Stage-A registration: eligibility-aware untouched UCI expansion

This record is locked and publicly timestamped before any instance row from
UCI 367, 891, 942 or 967 is requested in this campaign.

## Preserved failures

R4.2 stopped before instance access because the UCI 855 metadata endpoint had
no standardized `data_url`. R4.3 repaired only that transport, was publicly
locked, then stopped on its first preparation call because UCI 855 contained
a missing target value. R4.3 wrote no prepared census, fitted no model,
computed no route or action, and never requested UCI 967. R4.4 binds the
R4.2 and R4.3 locks, ACKs, verification receipts and invalidation records.
UCI 855 remains a registered eligibility failure and cannot contribute to
any R4.4 success count.

## New mandatory registrations

Four datasets were selected from UCI metadata, public documentation and
workspace filename auditing, without opening their instance tables in this
campaign. Before this lock, only their public metadata snapshots were found
in the audited paths; this is not proof that no person or machine ever
accessed them. `R4_4_PRIOR_ACCESS_AUDIT_V2.json` binds the earlier R1
selection/preparation receipts, the R2 verified-fetch ledger and code, the
R4.2/R4.3 invalidations, and a candidate-ID full-relative-path census. Its claim is
limited to no instance trace found in those recorded campaign paths and the
shared package. The earlier basename-only V1 audit is preserved and
explicitly invalidated before Stage A; V2 searches complete relative paths.

1. UCI 367, Dota2 Games Results: 102,944 rows, 115 numeric/binary features,
   exact-feature grouping, group-complete cap 100,000.
2. UCI 891, CDC Diabetes Health Indicators: 253,680 rows, 21 numeric/binary
   features, exact-feature grouping, group-complete cap 100,000.
3. UCI 942, RT-IoT2022: 123,117 rows and 83 raw features. `proto` and
   `service` are excluded by name before access, leaving 81 numeric features.
   The exact 13-label normal/attack taxonomy printed on the official UCI
   dataset page is copied into
   `registration/uci_942_official_taxonomy.json` before instance access and
   hash-bound here. Matching is exact after trimming outer whitespace;
   substring or inferred-family matching is forbidden, and an unknown label
   stops.
4. UCI 967, PhiUSIIL: 235,795 rows and 54 raw features. `URL`, `Domain`,
   `TLD`, `Title`, `URLSimilarityIndex`, `CharContinuationRate`,
   `TLDLegitimateProb` and `URLCharProb` are excluded, leaving 46 numeric
   predictors. Normalized Domain is a grouping key only; whole domain groups
   form a group-complete archive capped at 100,000 rows.

All four are mandatory and cannot be replaced after access. The exact
metadata snapshot hashes, ordered raw/primary feature hashes, official
`data.csv` URLs, target columns, exclusions, transforms and byte caps are
fixed in `config/r4_4_contract.json`.

For UCI 367, 891 and 967, the binary transform is also fixed before access:
positive numeric values map to 1 and nonpositive numeric values map to 0.
No vocabulary is fitted from source or target labels and no observed class
value is printed in a preparation receipt.

## Frozen preparation and decision contract

- The official CSV must remain on HTTPS at the same UCI origin and decoded
  path, without query or fragment. The resolved URL, CSV byte count and hash
  are recorded.
- The locked metadata snapshot supplies the ordered feature and target roles;
  any snapshot hash, role, row-count, feature-count or URL mismatch stops.
- Missing targets, nonnumeric or infinite primary predictors, over-20%
  predictor missingness, an all-missing predictor or an invalid binary
  estimand stops.
- Whole exact-pattern/domain groups are assigned by the unchanged R4.2
  group-complete and source/target hash salts.
- One deterministic, label-blind representative per group is the
  certification unit. Raw within-group duplicates never inflate a bound.
- Preparation may decode labels only to write separated source-label and
  target-outcome archives. The downloaded CSV bytes and raw label strings
  are preserved under hash for post-reveal independent reconstruction, but
  no target vocabulary, count, prevalence or performance summary is printed
  before reveal and no model is fitted.
- The scientific engine cannot semantically open target-outcome archives
  until the Stage-B policy/action lock is separately public and byte-verified.

The scientific rule is unchanged: the same tree grid, thresholds,
opportunity-normalized estimand, harm/recall/compression gates, routing and
one-shot reveal are used. With six inferential tasks, source and target alpha
are conservatively fixed at `0.025 / (6 * 5) = 0.0008333333333333334`.

R4.4 confirmatory success requires at least two inferential source ACT routes,
at least one from the four new registrations, at least two target ACT passes,
at least one new target ACT pass, zero inferential false ACTs and complete
integrity checks. If source-only viability is absent, Stage B and target
reveal are refused.
