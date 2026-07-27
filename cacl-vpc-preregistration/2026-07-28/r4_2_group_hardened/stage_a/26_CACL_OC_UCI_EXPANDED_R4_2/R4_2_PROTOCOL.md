# CACL-OC R4.2: pre-data-registered, integrity-hardened UCI campaign

## Why R4.2 exists

R3 stopped before target evaluation because a fixed all-row action-coverage
gate was structurally infeasible on two registered binary tasks. R4 corrected
that denominator but was invalidated after its public timestamp and before
target reveal because its hash-chain authorization and feature-query
accounting were not sufficiently strong. R4.1 repaired those engineering
defects, but pre-lock review found that UCI 75 (Musk v2) contains many
conformations from the same molecule. Row-level confidence bounds cannot be
treated as independent molecule-level evidence.

R4.2 therefore:

1. retains every prior registered dataset in the denominator;
2. reports UCI 75 only as a finite-archive descriptive conformation replay;
3. registers UCI 855 (TUANDROMD) and UCI 967 (PhiUSIIL) **before any
   instance-level data are downloaded in the audited campaign paths**;
4. preserves the requirement for at least two inferential source ACT routes
   and at least two untouched-target ACT passes; and
5. retains the R4.1 integrity repairs.

No prior target outcome from UCI 75, 327 or 572 has been semantically opened
for model evaluation. The new-data registration, download/preparation code,
split rule and scientific thresholds are publicly timestamped before UCI 855
or 967 is fetched. Public metadata were used to define eligibility; no
instance-level feature or outcome trace was found in the audited campaign
paths.

## Registered denominator and roles

- UCI 75, Musk (Version 2): descriptive clustered-conformation replay only;
- UCI 327, Phishing Websites: inferential registered-row task;
- UCI 572, Taiwanese Bankruptcy Prediction: inferential registered-firm task;
- UCI 855, TUANDROMD: inferential newly registered Android-binary task; and
- UCI 967, PhiUSIIL: inferential newly registered URL task using a
  group-complete, label-blind archive capped at 100,000 rows and 46 locked
  low-leakage numeric predictors.

No dataset may be removed or replaced. UCI 75 cannot contribute to the
minimum-ACT or minimum-target-PASS counts.

## Two-stage timestamp contract

### Stage A: before new-data access

The public Stage-A record fixes UCI 855 and 967, exact expected raw row and
feature counts, ordered feature-schema hashes, primary exclusions, the
group-disjoint source-target hash split, label mapping rule, preparation code,
roles and all scientific gates. UCI 967 is grouped by normalized Domain while
the Domain itself is never a predictor. UCI 855 is grouped by its exact
241-bit feature signature. Whole groups, not rows, are assigned to one side.
The preparation layer necessarily reads labels to write separate source-label
and target-outcome archives, but prints no target summary and performs no
model fitting or scientific decision.

### Stage B: before target-outcome reveal

The scientific engine may load source labels and target features but may not
semantically decode target outcomes. It may read outcome-archive bytes only
to verify their pre-existing preparation hashes. It freezes source routes,
models, instrumented target action traces and a complete hash lock. The exact
lock is published and independently fetched back. Only then may
target-outcome archives be semantically decoded once.

This is computational separation and public timestamping, not independent
human custody.

## Opportunity-normalized target

For static binary action `S`, policy action `A` and outcome `Y`, define a
baseline-error opportunity (not a causal opportunity) as `O = 1[Y != S]` and
a changed action as `C = 1[A != S]`. For `P(C=1)>0`, the unique opposite
binary action gives

`harm >= max(0, 1 - P(O=1)/P(C=1))`.

Thus fixed all-row coverage `kappa` and harm cap `eta` require
`P(O=1) >= (1-eta)kappa`. R4.2 retains the harm ceiling and certifies useful
reach on the baseline-error opportunity denominator.

## Frozen source-only learning rule

For each dataset:

1. deterministic SHA-256 group assignment;
2. one deterministic label-blind representative row per registered group,
   chosen by the minimum locked row hash;
3. approximately 50% source training, 20% source calibration and 30% source
   audit with no group crossing those partitions;
4. training-only median imputation;
5. class-balanced log-loss decision trees over the locked depth, leaf-size
   and probability-threshold grid;
6. calibration screening only with positive gain LCB, opportunity-recall
   lower bound at least 0.20, average compression at least 8 and changed-action
   harm upper bound at most 0.15;
7. locked lexicographic selection; and
8. inferential ACT only if the unchanged policy also passes the source audit
   with scientific harm upper bound at most 0.20 and all other gates.

Calibration bounds are screening values, not simultaneous post-selection
confidence statements. Confirmatory authorization comes from the disjoint
source audit.

UCI 75 is always routed `DESCRIPTIVE_REPLAY`, even if its candidate passes
source screening/audit. It is never dispatched or counted as inferential ACT.
For every other dataset, any exact registered group overlap between source and
target also forces `ABSTAIN`. This makes the known exact-pattern sensitivity
of UCI 327 a routing condition rather than an unreported robustness caveat.
All confidence bounds count group representatives, never raw rows. Target
actions and certification likewise cover only one locked representative per
target group; non-representative archive rows are not decision units.
The concentration bounds are conditional on the registered group
representatives being independent task units. They do not cover dependence
between distinct provided Domain strings, near-duplicate APKs or malware
families; those stronger entity structures are unavailable in these archives.

## Instrumented feature-access replay

The action generator traverses the tree and indexes only features encountered
on that row's path. It seals the per-row access mask and distinct-feature
count. A separate full-feature prediction is allowed only to audit exact
action equivalence.

The implementation receives a preloaded matrix; it is therefore an
**instrumented tree-path access replay**, not a capability-isolated oracle and
not prospective physical feature acquisition.

## Statistical gates

For the four inferential datasets, source and target alpha per gate family are
`0.025 / (4 datasets * 5 families) = 0.00125`. The five registered families
are gain, changed-action harm, opportunity recall, access compression and
direct/path equivalence; the latter two are deterministic checks, so this
allocation is conservative for the three stochastic bounds.

- gain lower bound greater than zero;
- baseline-error opportunity-recall lower bound at least 0.20;
- changed-action harm upper bound at most 0.20;
- average feature-count compression at least 8; and
- direct/path action agreement exactly 1.

The calibration harm screen remains 0.15 as a pre-target safety buffer.

`R4_2_CONFIRMATORY_PASS` requires the complete five-dataset denominator,
at least two inferential source ACT routes before target reveal, at least two
inferential target ACT passes, at least one source ACT and one target ACT pass
from the two pre-instance-data registrations (UCI 855/967), zero inferential
false ACTs and all integrity checks. If fewer than two inferential source
routes or no newly registered source route passes, the lock script must stop
and no target outcome may be opened.

## Integrity and one-shot reveal

- Freeze, lock, verification, reveal-start and verdict artifacts are
  write-once.
- The lock derives routes and counts from frozen receipts; none are hardcoded.
- `create_r4_2_public_ack.py` fetches the named GitHub commit and every
  published file as raw bytes, compares them with the local public set and
  writes an ACK only after exact equality; a hand-authored boolean is not the
  verification procedure.
- The evaluator rehashes every locked artifact instead of trusting a status.
- Every target archive is bound to its preparation hash.
- Target features and outcomes are hashed and decoded from the same immutable
  byte snapshot, closing check/use races.
- Frozen actions, access masks and costs are recomputed before outcome load.
- A reveal-start receipt is written before the first target byte snapshot is
  semantically decoded; interruption cannot be silently retried.
- The post-reveal audit independently recomputes actions, certificates, gates
  and the batch verdict.

## Claim boundary

A passing campaign supports a publicly timestamped, source-informed,
target-outcome-untouched computational confirmation on at least two
registered inferential UCI group-representative tasks, plus instrumented
tree-path access replay. The newly added UCI 855 and 967 are registered before instance-level
download in the audited campaign paths, but the preparation and analysis
occur in the same local environment. Workspace search found no prior UCI 855
instance trace and only UCI 967 metadata snapshots; this is not an absolute
proof that no person or machine ever accessed the datasets.

UCI 327 and UCI 967 are related phishing tasks, so their joint success is not
presented as two-domain evidence. UCI 855 supplies a distinct malware-binary
unit, but this campaign still does not establish broad domain generality.

It is not independent custody, a row-population guarantee, superpopulation
or universal generalization,
prospective physical acquisition, molecule-level Musk validation, causal
evidence, clinical utility, wet-lab efficacy, field safety or multiclass
generalization.
