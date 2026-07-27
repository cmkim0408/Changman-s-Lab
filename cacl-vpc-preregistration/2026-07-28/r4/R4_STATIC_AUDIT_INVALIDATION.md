# R4 pre-reveal invalidation

R4 was publicly timestamped at GitHub commit
`db218a15d6db62d72741e94a0652b57c84d1f293` on
`2026-07-27T21:25:04Z`, but **no target outcome was revealed or evaluated**.

An independent static audit performed after the timestamp and before reveal
found three infrastructure defects:

1. the evaluator trusted a status field instead of rechecking every locked
   artifact against the externally timestamped lock;
2. target-outcome file identity was not explicitly bound to the pre-existing
   R3 preparation hashes; and
3. freeze outputs could be overwritten by rerunning the freeze command.

The audit also found that the target policy counted tree-path feature access
after a full-matrix imputation, so the result could only support a
computational path-cost proxy, not a literal sparse-acquisition claim.

R4 is therefore retained as an invalidated pre-reveal protocol. It produced
no target result. R4.1 repairs these issues, uses an oracle-mediated
query-only executor, and requires a new public timestamp before the same
unopened outcomes may be evaluated.
