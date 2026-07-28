# CACL-OC R4.5.1 pre-reveal infrastructure amendment

## Scope

This amendment corrects one temporal validation error in the already public
CACL-OC R4.5 campaign. It does not change a scientific function, dataset,
feature, split, seed, tree, route, query action, estimand, alpha level,
certificate, success threshold, or final gate.

The original Stage-B verifier re-runs a Stage-A pre-access path census after
authorized data acquisition. The frozen Stage-A census contains two metadata
paths. After the public Stage-A authorization, the preparation and source
freeze correctly create eight UCI 967 artifacts. Those eight artifacts are
already byte- and SHA-256-bound by the public Stage-B lock. Consequently,
`validate_prelock_static_audit()` fails only
`current_prelock_path_census_exact` even though the historical Stage-A
evidence remains intact.

## Frozen correction

The phase-aware correction does all of the following before target reveal:

1. reproduces the unmodified failure and requires its fingerprint to be
   exactly `current_prelock_path_census_exact`;
2. runs the original prior-access audit against its historical, public
   Stage-A snapshot rather than against the post-authorization filesystem;
3. requires the current UCI 967 census to equal the two historical metadata
   paths plus exactly eight authorized post-authorization artifacts;
4. rehashes all eight artifacts against the already public Stage-B lock;
5. revalidates the complete original Stage-B chain, including all locked
   files and outcome bindings, without semantically loading target outcomes;
6. requires all target-reveal, target-verdict, and final-audit outputs to be
   absent;
7. publicly timestamps this protocol, the amendment runner, the amendment
   lock, and the original Stage-A/Stage-B chain before reveal.

The runtime correction maps only the post-authorization call
`validate_prior_access_audit(recompute_current_census=True)` to the original
historical audit with `recompute_current_census=False`. Every other original
check remains active. The same correction is applied before the original
timestamp verifier, scientific evaluator, and independent final auditor are
imported.

## Interpretation

If the amendment is publicly byte-verified before target reveal, the
subsequent result remains a target-outcome-uninformed computational
confirmation under a transparently amended infrastructure validator. It is
not an unamended R4.5 run, independent custody, prospective physical
acquisition, biological causality, clinical utility, or field-safety
evidence.

Any failure other than the single registered temporal-census failure aborts
the amendment. Scientific criteria may not be changed after seeing target
outcomes.
