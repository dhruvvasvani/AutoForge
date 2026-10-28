# Week 14 Handover

## Delivered: runtime evidence contract

`POST /api/v1/analyze-project` accepts an optional
`runtime_executed_functions` array of qualified function names. When a function
is both statically reachable and present in that supplied observation, its
finding receives `runtime_priority: "IMMEDIATE"`. The response also reports
whether runtime evidence was provided and how many functions matched.

The analyzer does not collect eBPF/APM data itself or verify the source of
submitted observations. This is an input contract for a future, explicitly
configured adapter. Runtime absence never changes static reachability,
severity, score, or policy-gate decisions. Do not send request payloads, secrets,
or raw traces through this field.

## Remaining

- Implement a separately authenticated and configured adapter for trusted APM
  or runtime function observations, including evidence freshness and revision
  matching.
- Extend cross-file analysis across repository boundaries by mapping explicit
  REST/gRPC service contracts; do not infer remote edges from names alone.
- Add a reviewed adaptive-rule draft workflow. Generated rules must be tested
  on a labeled corpus and approved before becoming active.
- Keep generated patches as reviewable proposals. Applying patches, running
  repository tests, and merging changes are not implemented. Do not execute
  untrusted patches inside the analyzer process or automatically merge changes.
- Add backend persistence, access control, and UI support only after defining
  repository trust and patch-review policies.
