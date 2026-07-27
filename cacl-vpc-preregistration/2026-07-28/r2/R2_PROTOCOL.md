# CACL-VPC UCI closed batch R2: binary eligibility verified before draw

## Why R2 exists

Batch 1 is permanently retained as `INCONCLUSIVE_EXTERNAL`: three of four
registered draws were multiclass tasks and the one binary task correctly
abstained. The failure occurred because UCI metadata did not expose target
cardinality before the draw.

R2 repairs only that eligibility defect. It does not change CACL-VPC, beta,
confidence levels, harm, coverage, compression, candidate budgets, source
selection, or confirmatory success thresholds.

## Pre-draw custodian scan

After this R2 bundle receives its own public external timestamp:

1. enumerate a new UCI importable-registry snapshot;
2. apply metadata-only row, predictor, task, type and table filters;
3. in an isolated eligibility process, download each provisional candidate and
   emit only:
   - actual row and predictor counts;
   - target column count and cardinality;
   - numeric-conversion compatibility; and
   - overall missing fraction;
4. do not emit class proportions, feature-outcome associations, performance,
   per-row values, or model results;
5. exclude every dataset already appearing in the original ledger or Batch 1;
6. sample four datasets from the fully verified binary pool with
   `random.Random(2302001).sample(sorted(pool), 4)`;
7. never replace a selected dataset.

The eligibility custodian's access to target cardinality is disclosed. Target
values, associations and performance remain unavailable to the modeling
process until the frozen source policy is sealed.

## Eligibility

- UCI only;
- 4,000 to 100,000 actual rows;
- 20 to 500 original numerical predictors;
- exactly one target column with exactly two observed non-missing labels;
- classification, multivariate tabular data;
- overall feature missing fraction at most 0.20;
- research use permitted under the UCI dataset-page CC BY 4.0 license;
- not in the prior-project or Batch-1 ledger.

## Unchanged CACL-VPC contract

- candidate budgets: 2, 4 and 8;
- full-information HGB reference;
- value-retention target \(\beta=0.90\);
- familywise alpha 0.025;
- harm UCB at most 0.20;
- coverage LCB at least 0.20;
- average compression at least 8;
- exact compiled-parent action agreement;
- terminal states `COMPRESS`, `FULL`, `ABSTAIN`, `EXTERNAL_FAIL`.

The source-authorized candidate is chosen by minimum audit mean query count.
The full registered denominator is four. Confirmatory PASS still requires at
least two source-authorized `COMPRESS` datasets and at least two untouched
target value-retention passes, with no deployed harm, compression or
action-equivalence violation.

## Claim boundary

R2 is a computational closed batch with an automated binary-cardinality
eligibility custodian. It is not wet-lab, causal, clinical, field-safety, or
independent-human-custodian evidence.
