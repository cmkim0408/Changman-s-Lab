# CACL-VPC UCI-only untouched closed batch

## Purpose

This protocol is the confirmatory gate for CACL-VPC. It is intentionally
separate from the opened NATICUSdroid development campaign.

The batch asks whether a source-authorized low-measurement policy can retain at
least 90% of a full-information reference policy's incremental decision value
on datasets selected by a registry rule fixed before enumeration.

## Non-negotiable ordering

1. Freeze this document, both JSON configurations, the executable CACL-VPC
   development core, and the existing-dataset exclusion ledger.
2. Place the freeze receipt at a public, externally dated location.
3. Record and verify the public timestamp acknowledgement.
4. Only then enumerate the UCI registry.
5. Select the batch by the locked seeded rule.
6. Prepare source/target objects, freeze policies using source outcomes only,
   and seal target outcomes.
7. Reveal the full registered denominator, including external failures.

No registry enumeration, candidate download, schema inspection, outcome
inspection, or replacement is permitted before step 3.

## Dataset rule

The registry is UCI only. OpenML is excluded to avoid mirror ambiguity.
Eligibility is mechanical and is fully specified in
`config/eligibility_rule.json`. A registry key already present in the prior
project ledger is ineligible.

## Algorithm

For each eligible dataset:

1. Source-fitted preprocessing maps the declared numerical predictors to one
   binary measurement per original predictor using source-design medians.
2. The source-design split ranks predictors by mutual information.
3. HGB candidates use the first \(k\in\{2,4,8\}\) measurements, subject to
   \(k\leq p\).
4. A full HGB using all \(p\) binary measurements is the reference.
5. Source audit applies simultaneous gates for:
   - positive full-reference incremental gain;
   - positive LCB for \(G_k-0.90G_f\);
   - changed-action harm UCB at most 0.20;
   - changed-action coverage LCB at least 0.20; and
   - compiled average compression at least 8 relative to \(p\).
6. Every passing candidate is compiled into an exact Boolean query tree.
7. The lowest source-audit mean query cost wins; ties use smaller \(k\), then
   lexicographic feature order.
8. No passing sparse candidate but a certified full policy emits `FULL`.
9. An uncertified full policy emits `ABSTAIN`.

The static action is the source-design majority class. The binary utility is
classification accuracy. Harm means a changed action that is worse than the
static action for the realized outcome.

## Splits and multiplicity

Rows are ordered by a content hash with locked salts.

- 65% source and 35% untouched target;
- source is divided 70% design and 30% audit;
- familywise alpha 0.025;
- per-dataset sparse family: three budgets times five gates;
- target confirmation uses the registered batch-level correction in the
  contract JSON.

## Comparators

Every selected dataset reports:

- static action;
- fixed two-sentinel CACL;
- CACL-VPC;
- full HGB;
- universal interval compilation of full HGB; and
- a source-tuned cost-sensitive decision tree with the same measurement-cost
  accounting and target gates.

Predictive superiority over the full HGB is not a success criterion.

## Confirmatory success

The batch-level result is `CONFIRMATORY_PASS` only if:

1. at least two registered datasets reach source-authorized `COMPRESS`;
2. at least two independently satisfy the untouched 90%-retention LCB;
3. every target-deployed compiled policy has exact action agreement with its
   frozen parent;
4. no target-deployed `COMPRESS` policy violates the 0.20 harm UCB or 8-fold
   average compression rule; and
5. the complete registered denominator and all external failures are reported.

Otherwise the result is `CONFIRMATORY_FAIL` or `INCONCLUSIVE_EXTERNAL` according
to the locked external-failure rule. Thresholds and datasets are not replaced.

## Claim boundary

This is a computational closed-batch validation. It is not causal, clinical,
wet-lab, field-safety, or independent-custodian evidence.
