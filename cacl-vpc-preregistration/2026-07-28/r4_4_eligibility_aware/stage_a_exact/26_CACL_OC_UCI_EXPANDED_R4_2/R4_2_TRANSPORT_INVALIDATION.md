# R4.2 Stage-A transport invalidation

R4.2 was stopped after its valid public Stage-A timestamp and before any
instance-level row was downloaded or prepared.

- Stage-A public commit:
  `583e45ec554d04fa21962bd1cd79922f2c0bfa47`
- Stage-A lock SHA-256:
  `d9a6a4190ca18ade2602b2b701b480e98279d1d05921d19710534827de7d8fc6`
- failure time: `2026-07-27T22:21:16.7234299Z`
- failing dependency: `ucimlrepo==0.0.7`
- failing dataset: UCI 855

The installed client fetched only UCI metadata, found a null standardized
`data_url`, and raised `DatasetNotFoundError` at `ucimlrepo/fetch.py:88-91`
before the `pandas.read_csv(data_url)` instance-data call at lines 94-97.
No `prepared_census` or `registered_census` directory was created and no
preparation receipt exists.

The scientific estimand, models, thresholds, grouping, representative-unit
rule and success gates were not evaluated and are not changed in the repair.
R4.3 may change only the UCI 855 transport layer by registering the official
UCI archive URL and a deterministic ZIP/CSV reader before retrying access.
R4.2 cannot authorize data access or provide a scientific result.
