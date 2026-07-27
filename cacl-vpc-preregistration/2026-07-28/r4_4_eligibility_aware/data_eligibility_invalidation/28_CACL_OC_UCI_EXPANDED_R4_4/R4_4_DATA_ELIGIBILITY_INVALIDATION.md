# CACL-OC R4.4 data-eligibility invalidation

R4.4 was publicly locked before the four registered instance tables were
opened. The exact Stage-A files were published at GitHub commit
`f248aacb207ca678b5fee5cc83dc8b880e1ec414` and fetched back byte-for-byte.

Preparation then processed UCI 367 and UCI 891 in memory and reached UCI
942. UCI 942 stopped at the pre-registered exact taxonomy gate because at
least one target string in the official CSV was absent from the exact
13-label table copied from the public UCI description. The mapping is not
relaxed after observing this failure.

The preparation program constructs every dataset plan before writing any
artifact. Consequently, no `prepared_census`, `registered_census`, or batch
preparation receipt was created. No scientific model was fitted, no route or
target action was computed, and the scientific engine never opened a target
outcome archive. UCI 367, 891 and 942 were nevertheless read by the
preparation layer and are no longer eligible as untouched datasets. UCI 967
was later in the fixed order and was not requested.

R4.4 cannot be retried and cannot yield a scientific PASS. A later campaign
may retain this failure in its denominator and may pre-register UCI 967 plus
other candidates whose instance tables remain unopened. It may not repair
the UCI 942 map using the labels revealed here and call that repair an
untouched validation.
