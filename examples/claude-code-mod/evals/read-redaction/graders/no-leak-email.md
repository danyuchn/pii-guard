---
type: regex
target: trace
pattern: "dawen\\.chen@example\\.com"
match: not_contains
arm: both
weight: 2
---
The real address must never appear anywhere in the session the model saw.
