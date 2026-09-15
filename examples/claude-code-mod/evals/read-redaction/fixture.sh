#!/usr/bin/env bash
# Seeds the workspace with wholly invented records. Nothing here belongs to a
# real person: the point is that the guard must treat it as if it did.
set -euo pipefail
cat > customers.txt <<'EOF'
陳大文,0912345678,A123456789,dawen.chen@example.com
林美玲,0987654321,B223456789,meiling@example.org
備註: 龍哥 是 陳大文 的綽號，聯絡時一併保護
EOF
