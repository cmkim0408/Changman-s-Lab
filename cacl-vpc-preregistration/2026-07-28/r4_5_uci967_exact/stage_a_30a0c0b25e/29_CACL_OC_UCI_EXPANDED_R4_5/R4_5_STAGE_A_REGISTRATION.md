# CACL-OC R4.5 Stage-A registration

## Purpose

R4.5 is a one-shot computational confirmation of UCI 967 (PhiUSIIL).
The instance table and its labels must remain unopened until the exact files
in the Stage-A lock have been published and independently fetched back
byte-for-byte from a public GitHub commit.

This is an adaptive follow-up after the preserved R4.2-R4.4 failures. It is
not independent custody and it is not a claim that the dataset was unknown
to the world. “Unopened” means no recorded UCI 967 instance artifact or
preparation fetch exists in the audited shared package.

## Failure lineage retained

- R4.2 stopped before any new instance fetch because its UCI 855 transport
  lacked a usable data URL.
- R4.3 read UCI 855 and failed its locked target eligibility rule before
  preparation; it never requested UCI 967.
- R4.4 read UCI 367, 891 and 942, then failed the locked exact UCI 942
  taxonomy before persisting any prepared data or fitting a model. Its
  write-once invalidation records UCI 967 instance and labels as unread.

Those four non-evaluated units remain in the campaign ledger. None is
silently replaced or reclassified as a scientific result.

## Frozen metadata screen

Before this registration, the 208 metadata snapshots in the frozen R2
catalog are screened by one new, explicitly declared metadata-only rule:

1. classification task;
2. exactly one metadata `Binary` target;
3. 20-500 predictors, all Binary/Integer/Continuous/Real;
4. 4,000-100,000 rows;
5. metadata declares no missing feature or target values; and
6. the exact official HTTPS static CSV URL is present.

Only UCI 94 and 350 pass. Both already have raw ZIP artifacts in the shared
package, so neither is untouched. No additional dataset is selected.
UCI 967 is not selected by this screen; it is carried forward from its
earlier pre-instance registrations with the R4.4 preprocessing unchanged.

## UCI 967 registration

- official URL:
  `https://archive.ics.uci.edu/static/public/967/data.csv`
- locked metadata: 235,795 rows, 54 feature-role columns, target `label`;
- primary numeric predictors: the unchanged 46-column R4.4 list;
- excluded from predictors: `URL`, `Domain`, `TLD`, `Title`,
  `URLSimilarityIndex`, `CharContinuationRate`, `TLDLegitimateProb`,
  `URLCharProb`;
- group key: normalized, nonempty `Domain`, used only for grouping and never
  as a predictor;
- group-complete deterministic cap: 100,000 rows;
- target rule: exactly two finite numeric values, with the positive value
  mapped to 1 and the nonpositive value mapped to 0. No target vocabulary,
  orientation, threshold or mapping is fitted;
- source/target group split, within-source split, trees, thresholds,
  certificates and all scientific gates: unchanged from R4.4;
- source and target alpha: the R4.4 value
  `0.0008333333333333334`, retained without relaxation.

The raw official CSV and raw labels are preserved for post-reveal
independent reconstruction. Preparation emits no target prevalence, class
vocabulary, source performance, route or action before the corresponding
lock permits it.

## Success and failure

Stage B is permitted only if:

- at least two of UCI 327, 572 and 967 receive source-only ACT routes; and
- UCI 967 itself receives a source-only ACT route.

The final campaign passes only if:

- at least two inferential ACT tasks pass their frozen target certificates;
- UCI 967 passes its frozen target certificate;
- every pre-reveal ACT passes (zero false ACT); and
- all denominator, hash, split, direct-path and independent-rebuild checks
  pass.

If UCI 967 is ineligible, routes ABSTAIN, or fails on target, R4.5 fails.
There is no replacement, target-informed repair, threshold relaxation or
second reveal.

