# R4.3 data-eligibility invalidation

R4.3 was stopped on its first post-Stage-A preparation attempt. The locked
official UCI 855 archive and member were read, but the preparation code found
at least one missing value in the locked `Label` column and raised:

`RuntimeError: UCI 855: target contains missing values`

This is a pre-registered data-eligibility failure. It occurred before any
prepared or registered census was written, before model fitting or routing,
and before any scientific-engine target reveal. Python evaluated UCI 855
first and stopped, so UCI 967 instance data were not requested or opened.

R4.3 will not be retried and the missing-label rows will not be deleted
post hoc. It cannot supply a scientific result. A later campaign may retain
this failure in its denominator, bind this invalidation record, and
pre-register a new untouched dataset before any new instance-data access.

- Stage-A public commit:
  `5a188bce5dce6d4d1562aff47a9883c167231987`
- Stage-A lock SHA-256:
  `142484054b7350cdab2cbee079d176f4e908ca7651ff374414a89f75aa2b306b`
- invalidation time: `2026-07-27T22:38:09.3193052Z`
