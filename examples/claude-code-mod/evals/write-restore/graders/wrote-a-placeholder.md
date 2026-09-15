---
type: regex
target: last_message
pattern: "<TW_MOBILE_\\d+>"
arm: with-only
---
What the model passed to Write was a placeholder, so the real value on disk got
there by restoration rather than by the model knowing it.
