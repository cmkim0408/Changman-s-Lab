# CACL-VPC R3: census of every remaining verified binary UCI task

R2 found exactly three fully verified, previously unused UCI tasks under its
publicly timestamped eligibility rule: IDs 75, 327 and 572. R2 correctly
stopped because its registered batch size was four.

R3 removes the impossible sampling step by registering the **complete census**
of those three tasks. There is no choice among datasets and no replacement.
No model, feature-outcome association, class proportion, source result or
target performance has been computed for these tasks before this R3 lock.
The eligibility custodian has observed only schema, missing fraction and binary
target cardinality.

## Registered denominator

- UCI 75: Musk (Version 2)
- UCI 327: Phishing Websites
- UCI 572: Taiwanese Bankruptcy Prediction

The R2 verified-eligibility ledger and insufficient-pool receipt are inputs to
this lock.

## Unchanged model and gates

R3 executes the byte-identical staged CACL-VPC engine frozen for Batch 1:

- budgets 2, 4 and 8;
- full HGB reference;
- beta 0.90;
- familywise alpha 0.025;
- harm UCB at most 0.20;
- coverage LCB at least 0.20;
- average compression at least 8;
- exact compiled-parent action agreement;
- `COMPRESS`, `FULL`, or `ABSTAIN`.

The engine retains its conservative Batch-1 target alpha of 0.00125 even
though the denominator is three.

## Success criterion

`CONFIRMATORY_PASS` requires:

1. at least two of the three tasks source-route to `COMPRESS`;
2. at least two have positive untouched-target LCB for 90% full-policy value
   retention;
3. every deployed compiler has action agreement 1.0;
4. every deployed compiler satisfies target harm UCB at most 0.20 and average
   compression at least 8; and
5. all three tasks remain in the denominator.

No threshold or dataset is changed after the R3 external timestamp.

## Claim boundary

This is a cardinality-screened, outcome-value-blind computational external
validation. It is not causal, clinical, wet-lab, field-safety, or an
independent-human-custodian experiment.
