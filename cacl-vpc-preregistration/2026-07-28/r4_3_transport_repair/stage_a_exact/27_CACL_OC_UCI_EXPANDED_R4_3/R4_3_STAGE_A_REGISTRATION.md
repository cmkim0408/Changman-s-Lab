# R4.3 Stage-A registration: pre-instance-data UCI expansion

This record is locked and publicly timestamped before downloading either new
dataset.

R4.2 was locally invalidated before instance data were obtained because the
UCI metadata API returned no downloadable `data_url` for UCI 855. Its
invalidation record is bound into, and will be publicly timestamped with, the
R4.3 Stage-A record. R4.3
changes only that transport layer. The registered datasets, feature schemas,
grouping/splitting rules, estimand, model grid, bounds, thresholds and success
criteria are unchanged. The R4.2 invalidation record is included in the R4.3
Stage-A hash lock.
All label-blind selection, grouping and source/target hash namespaces retain
their exact R4.2 salt strings; `R4.3` is only the receipt/schema version.

## New registered datasets

1. UCI 855, TUANDROMD: exactly 4,464 Android-binary rows and 241 numeric
   permission/API features.
2. UCI 967, PhiUSIIL: exactly 235,795 URL rows and 54 raw features. Four
   categorical text features (`URL`, `Domain`, `TLD`, `Title`) and four
   precomputed similarity/probability/continuation features with elevated
   proxy risk (`URLSimilarityIndex`,
   `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb`) are excluded
   by name, leaving 46 locked primary predictors. Normalized Domain is used
   only as a label-blind grouping key. Whole domain groups are selected into
   a finite archive capped at 100,000 rows.

These datasets were chosen from official UCI metadata because the resulting
registered archives satisfy the pre-existing binary tabular size rule (4,000
to 100,000 rows and 20--500 numeric features), expose app/URL row units rather
than the known multiple-conformation structure of UCI 75, and have no
instance-level access trace in the audited campaign paths. Metadata for UCI
967 existed in an earlier registry snapshot, but no row data or outcomes were
found. This is an audited-path statement, not proof of universal non-access.
Both datasets are mandatory; neither may be replaced after access.

## Frozen preparation

- exact script: `code/prepare_r4_3_new_data.py`;
- UCI 855 transport: the official UCI static archive at
  `https://archive.ics.uci.edu/static/public/855/tuandromd%2B%28tezpur%2Buniversity%2Bandroid%2Bmalware%2Bdataset%29.zip`,
  with exactly one member named `TUANDROMD.csv`, target column `Label`, an
  archive cap of 33,554,432 bytes and an uncompressed CSV cap of 268,435,456
  bytes. Redirects are accepted only when HTTPS origin and decoded path remain
  identical and no query or fragment is introduced; the resolved URL is
  recorded;
- UCI 967 transport: `ucimlrepo==0.0.7` official API;
- schema: exact ordered raw and primary feature-name SHA-256 values;
- group key: UCI 855 exact 241-bit signature; UCI 967 normalized Domain;
- registration: label-blind group-hash order, with whole groups retained;
- split: independent group hash assigns approximately 65% to source and 35%
  to target without group overlap;
- certificate unit: one label-blind representative row per group selected by
  the locked minimum row hash; raw within-group rows never inflate confidence
  bounds;
- target mapping: deterministic lexicographic mapping of the two label strings
  to 0 and 1;
- outputs: source features/labels, target features, target outcomes and
  hash receipts;
- no model fitting, routing, target summary or outcome-dependent choice during
  preparation.

The preparation layer necessarily decodes labels to make the separated files.
The scientific engine is prohibited from decoding target outcomes until the
later Stage-B policy/action lock has been publicly timestamped and verified.

## Frozen decision

The complete R4.3 denominator is UCI 75, 327, 572, 855 and 967. UCI 75 remains
descriptive only. The inferential set is 327, 572, 855 and 967. Confirmatory
success still requires at least two source ACT routes, two target ACT passes
and zero false ACTs within that inferential set, with at least one source ACT
and one target ACT pass contributed by UCI 855 or 967.

If Stage A detects a transport, redirect, member-name, schema, metadata,
download, missing-target or binary-target mismatch, it stops without
substituting another source. If the
later source-only freeze yields fewer than two
inferential ACT routes or no new-data ACT route, the Stage-B lock stops before
any target reveal.
