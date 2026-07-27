# CACL-OC R4.4: eligibility-aware, publicly timestamped UCI campaign

## Purpose

R4.4 asks a narrow confirmatory question: can the frozen CACL opportunity
contract authorize sparse tree-path actions from source labels and then pass
on target outcomes that were unavailable to policy fitting, routing and
action generation?

It is not a retry of R4.3. R4.3 remains invalid because UCI 855 failed its
pre-registered missing-target rule. R4.4 keeps that failure visible and
registers four different UCI tasks from metadata and public documentation
before their instance data are accessed.

## Denominators

The campaign ledger is UCI 75, 327, 572, 855, 367, 891, 942 and 967.

- UCI 75: descriptive clustered-conformation replay only.
- UCI 327 and 572: retained inferential registered tasks.
- UCI 855: retained data-eligibility failure; never fitted or counted.
- UCI 367, 891, 942 and 967: new inferential pre-instance registrations.

The model-evaluation denominator is therefore UCI 75, 327, 572, 367, 891,
942 and 967; the inferential denominator excludes UCI 75. No registered
model-evaluation task may be removed or replaced.

## Two public locks

### Stage A — before new instance data

Stage A fixes the datasets, metadata snapshots, official CSV transports,
ordered feature hashes, exclusions, UCI 942 binary estimand, grouping,
registration caps, splits, scientific model, thresholds, error control and
success criteria. The complete text set and local lock are uploaded to a
public GitHub commit, fetched back and byte-compared. Every transport entry
point revalidates this chain before opening a network response.

The three numeric targets use a fixed positive-versus-nonpositive rule that
is not fitted to either split. UCI 942 uses the exact class table copied
from the official UCI dataset page and locked in
`registration/uci_942_official_taxonomy.json`; substring matching is not
allowed.

### Stage B — before target-outcome semantics

Preparation separates source labels, target features and target outcomes.
The scientific engine may load source labels and target features and may
hash target archive bytes, but it cannot decode target outcomes. It freezes
source routes, fitted policies, target actions and per-row feature-access
masks. The complete Stage-B lock is again publicly timestamped and
byte-verified. A write-once reveal-start receipt is written before the first
target outcome snapshot is decoded. Retries are forbidden.

This is computational separation and public timestamping in one local
environment, not independent human custody.

## Frozen scientific rule

For each model-evaluation dataset:

1. source and target contain disjoint registered groups;
2. one label-blind representative per group is selected;
3. source representatives are group-hash split 50%/20%/30% into
   train/calibration/audit;
4. training-only median imputation is used;
5. class-balanced log-loss trees use depths 1–12, leaf sizes 10/30/60 and
   the locked confidence-threshold grid;
6. calibration screens positive gain LCB, opportunity recall LCB at least
   0.20, average compression at least 8 and changed-action harm UCB at most
   0.15;
7. a locked lexicographic rule selects among eligible candidates; and
8. ACT requires the unchanged policy to pass disjoint source audit with
   positive gain LCB, recall LCB at least 0.20, compression at least 8,
   harm UCB at most 0.20 and direct/path action agreement exactly 1.

For static action `S`, path-policy action `A` and outcome `Y`, the
baseline-error opportunity is `O = 1[Y != S]`; action change is
`C = 1[A != S]`. This is a predictive decision estimand, not a causal
estimand.

The six inferential tasks and five gate families give Bonferroni alpha
`0.0008333333333333334` for source audit and target confirmation.

## Success and failure

`R4_4_CONFIRMATORY_PASS` requires:

- the complete seven-task model-evaluation denominator;
- at least two inferential source ACT routes;
- at least one source ACT from UCI 367/891/942/967;
- at least two inferential target ACT passes;
- at least one target ACT pass from UCI 367/891/942/967;
- zero false ACTs among source-authorized inferential tasks; and
- every hash-chain and independent audit check.

ABSTAIN is a valid task result, not a failed prediction. An ACT route that
fails target gates is a false ACT and makes the campaign fail. Missing source
viability stops before Stage B.

## Integrity

- R4.2 and R4.3 failure provenance is mechanically rehashed and bound.
- Earlier R1/R2 selection and instance-fetch records plus a candidate-ID
  full-relative-path workspace census are hash-bound before access; this
  supports only a campaign-workspace “no trace found” statement, not
  absolute non-access.
- Dataset and result paths are write-once.
- Each new official CSV is preserved byte-for-byte under the Stage-B lock;
  source and sealed-target raw labels are retained so the final auditor can
  rebuild parsing, capping, grouping, splitting and target conversion.
- Target features/outcomes are hashed and decoded from the exact verified
  byte snapshots.
- Tree-path actions are generated by instrumented feature access; a
  full-feature calculation is audit-only.
- The independent final auditor does not import the scientific engine. It
  refits the full grid, recomputes group representatives, splits, policies,
  actions, masks, certificates, routes, verdicts and batch gates.

## Claim boundary

A pass supports a publicly timestamped computational confirmation in which
policy fitting, routing and target actions were target-outcome-uninformed on
at least two registered UCI group-representative tasks, including at least
one newly accessed task. The preparation layer itself decoded labels in the
same environment to create separated archives.

It does not establish independent custody, physical prospective feature
acquisition, row-population or universal generalization, biological
causality, wet-lab efficacy, clinical utility, field deployment or power-grid
safety. Confidence statements are conditional on distinct registered group
representatives being independent task units; hidden entities or dependence
not represented in the archives are outside the guarantee.
