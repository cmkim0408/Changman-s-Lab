# CACL-OC R4.5: exact pre-instance registration and one-shot target reveal

## Frozen ledger

- complete campaign ledger: UCI 75, 327, 572, 855, 367, 891, 942, 967;
- model-evaluation units: UCI 75, 327, 572, 967;
- inferential units: UCI 327, 572, 967;
- descriptive-only unit: UCI 75;
- historical non-evaluated units: UCI 855, 367, 891, 942;
- new/carry-forward pre-instance unit: UCI 967;
- replacement: forbidden.

The historical units have different failure mechanisms and retain their
exact roles in `config/r4_5_contract.json`.

## Two-lock order

1. Build the frozen metadata-screen and prior-access receipts without
   opening the UCI 967 instance endpoint.
2. Hash all Stage-A registration, lineage, code, config and receipts.
3. Publish the exact text bytes at a unique GitHub path.
4. Fetch the public commit and every file back byte-for-byte; write the
   Stage-A ACK and verification.
5. Download and prepare UCI 967 once. The raw CSV is preserved, but no target
   summary is emitted.
6. Recompute source-only policies and routes for the full registered
   denominator. Target outcomes remain sealed.
7. Refuse Stage B unless the locked source viability gates hold.
8. Hash every policy, action and target-outcome byte binding; publish and
   fetch back the exact Stage-B text bytes.
9. Write a one-shot reveal-start receipt, semantically load target outcomes,
   compute certificates, write the final verdict and independent audit.

Every output path is write-once. Loaders revalidate the public chain and the
reveal-start receipt at the point of semantic target use.

## Fixed scientific rule

The CACL-OC estimator, candidate trees, threshold grid, group-representative
certificate unit, source selection rules, harm/recall/compression gates and
R4.4 alpha are unchanged. R4.5 changes only the ledger and provenance needed
to evaluate the still-unopened carry-forward dataset.

The source and target stages each use alpha
`0.0008333333333333334`. With three inferential tasks and five registered
gate families this is no more than 1.25% family-wise error per stage and no
more than 2.5% under a two-stage union bound.

## Required headline gates

- complete registered denominator;
- inferential source ACT count at least 2;
- UCI 967 source ACT count exactly 1;
- inferential target ACT-pass count at least 2;
- UCI 967 target ACT-pass count exactly 1;
- zero false ACT;
- all frozen-file, transport, split, action, certificate and reconstruction
  checks pass.

Any pre-reveal ACT that fails its target certificate makes the confirmatory
campaign fail. An ABSTAIN is not a false ACT, but UCI 967 ABSTAIN prevents
the required target-outcome-uninformed confirmation.

## Claim boundary

A pass supports only this statement:

> A pre-instance-registered UCI task was authorized from source data and
> confirmed on target outcomes unused for policy fitting, routing or action
> generation, within the finite registered group-representative archive.

It does not prove independent custody, field or clinical utility, biological
causality, universal generalization, or that every copy of the public
dataset was historically unseen. Preparation and reveal occur in the same
controlled workspace; the public commits establish ordering and byte
identity, not external custodianship.
