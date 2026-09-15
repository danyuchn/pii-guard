---
type: regex
target: last_message
pattern: "0987654321"
match: not_contains
arm: both
weight: 2
---
The model quotes back what it passed to Write. If the real number appears
there, the model knew it; this asks what the model knows rather than searching
the whole trace, which also carries Claude Code's own local file-state record.
