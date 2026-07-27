# CACL-OC R4: source-informed, target-outcome-untouched UCI census

## Why this amendment exists

R3 stopped before target-outcome evaluation because all three source routes
abstained.  The source-only audit proved that the old pair
`absolute coverage >= 0.20` and `changed-action harm <= 0.20` is impossible
whenever the opportunity prevalence is below 0.16.  That condition held for
two of the three registered tasks.  The R3 receipts remain unchanged.

R4 corrects the denominator rather than lowering the harm limit.  For binary
actions, an opportunity is a row on which the outcome differs from the static
majority action.  Useful reach is the fraction of those opportunities that
the policy correctly changes.  R4 therefore certifies opportunity recall,
not the fraction of all rows changed.

This is a source-informed algorithm amendment.  It is not a new
dataset-level untouched study.  The target outcomes for UCI 75, 327 and 572
remain unopened for model evaluation at the time of this lock, so their
post-timestamp evaluation is a target-outcome-untouched confirmation.

## Registered denominator

The complete R2 verified census remains fixed:

- UCI 75: Musk (Version 2)
- UCI 327: Phishing Websites
- UCI 572: Taiwanese Bankruptcy Prediction

No dataset may be removed or replaced.

## Opportunity feasibility identity

Let `S` be the static binary action, `A` the candidate action and `Y` the
binary outcome.  Define `O = 1[Y != S]` and `C = 1[A != S]`.  Because the
opposite binary action is unique,

`harm = P(C=1,Y=S | C=1) >= max(0, 1 - P(O=1)/P(C=1))`.

Consequently, fixed absolute coverage `kappa` and harm cap `eta` can coexist
only if `P(O=1) >= (1-eta) kappa`.  R4 emits this feasibility frontier before
policy fitting and distinguishes structural infeasibility, insufficient
opportunities, policy failure and certified action.

## Frozen learning rule

For each registered source task:

1. order rows by SHA-256 with salt
   `CACL-OC-UCI-TRAIN-CAL-AUDIT-v1`;
2. use 50% for training, 20% for model selection and 30% for a disjoint
   source audit;
3. median-impute from training rows only;
4. fit the fixed library of class-balanced decision trees:
   depth 1--12, minimum leaf size 10, 30 or 60, log-loss criterion;
5. pair every tree with the locked minority-action probability grid;
6. on model-selection rows retain only candidates with positive
   policy-geometry gain LCB, opportunity-recall CP LCB at least 0.20,
   average feature compression at least 8 and harm CP UCB at most 0.15;
7. select maximum gain LCB, then maximum mean gain, then fewer mean queries,
   shallower depth, smaller leaf size and lower threshold;
8. authorize pre-reveal `ACT` only if the selected unchanged policy also
   passes the disjoint source audit with harm CP UCB at most 0.20 and the
   other unchanged external gates.

The 0.15 model-selection harm ceiling is a pre-target safety buffer.  The
scientific harm cap remains 0.20.

The executable action is evaluated by traversing the selected tree.  Query
cost is the number of distinct features encountered on that row's path.
Direct model actions and path-executor actions must agree exactly.

## Statistical gates

- source alpha per bound: `0.025 / (3 datasets * 5 bounds)`;
- target alpha per bound: 0.00125 (retained from Batch 1);
- policy-geometry mean-gain LCB greater than 0;
- Clopper--Pearson opportunity-recall LCB at least 0.20;
- Clopper--Pearson changed-action harm UCB at most 0.20;
- average feature-count compression at least 8;
- direct/path action agreement exactly 1.

## Batch success

`R4_CONFIRMATORY_PASS` requires:

1. all three datasets remain in the denominator;
2. at least two source routes are sealed as `ACT` before target outcomes;
3. at least two sealed ACTs pass every untouched-target gate;
4. no sealed ACT produces a false-ACT verdict; and
5. all hashes, action maps and direct/path agreement checks pass.

No threshold, model, dataset or verdict rule changes after the public R4
timestamp.

## Claim boundary

R4 can support an externally timestamped, source-informed,
target-outcome-untouched computational ACT for binary tabular decisions.  It
does not support a dataset-level untouched algorithm-discovery claim,
multiclass generalization, causal validity, clinical utility, wet-lab
efficacy, field safety or independent-human custody.
