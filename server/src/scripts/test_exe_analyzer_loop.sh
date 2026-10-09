
#!/usr/bin/env bash
set -euo pipefail

# Run from the server directory:
# bash scripts/test_exe_analyzer_loop.sh 3

ITERATIONS="${1:-3}"

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: bash scripts/test_exe_analyzer_loop.sh [positive-number]"
  exit 2
fi

for ((run = 1; run <= ITERATIONS; run++)); do
  echo
  echo "========== EXE ANALYZER TEST RUN ${run}/${ITERATIONS} =========="

  python3 -m unittest discover \
    -s tests \
    -p 'test_analyze_exe.py' \
    -v

  echo "Run ${run} passed."
done

echo
echo "SUCCESS: all ${ITERATIONS} regression runs passed."