---
runs: 1
max_turns: 30
allowed_tools: [Read, Write]
expected_outcome: summary.txt holds the real name and phone number although the model only ever saw placeholders.
---
Read `customers.txt` in the current directory. Then use Write to create `summary.txt` containing the second customer's name and phone number, exactly as the file gave them to you, on one line separated by a comma. Copy what you saw character for character; do not try to guess or expand anything.
