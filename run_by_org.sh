#!/usr/bin/env bash
# 기관별로 나눠 순차 실행 + 기관 사이 휴식.
#
# 왜 기관별로 나누나:
#   - 기관마다 exposure-lens 프로세스를 새로 띄우므로 요청 예산(max_requests)이
#     기관마다 리셋된다. --all-enabled 한 번이면 100개 기관이 예산 1000개를
#     나눠 쓰다가 뒤쪽 기관이 굶지만, 나눠 돌리면 각자 온전한 예산을 쓴다.
#   - 기관마다 --output 을 분리해 collect.jsonl / scan.jsonl 이 섞이지 않는다.
#   - 기관 사이에 쉬어서 공개 색인·대상 서버 부담을 낮춘다.
#
# 사용법:
#   bash run_by_org.sh                 # collect + scan, 기관 사이 30초 휴식
#   PAUSE=60 bash run_by_org.sh        # 휴식 60초
#   DO_PROBE=1 bash run_by_org.sh      # active probe 까지 (대상에 라이브 GET!)
#   RESUME=1 bash run_by_org.sh        # 이미 끝난 기관은 건너뛰고 이어서
#   ONLY="hancom truen" bash run_by_org.sh   # 이 기관들만
#
# 환경변수(기본값):
#   CONFIG=config  OUT_ROOT=runs  PAUSE=30  MIN_SEV=low
#   DO_PROBE=0  RESUME=0  ONLY=""
set -u

CONFIG="${CONFIG:-config}"
OUT_ROOT="${OUT_ROOT:-runs}"
PAUSE="${PAUSE:-30}"
MIN_SEV="${MIN_SEV:-low}"
DO_PROBE="${DO_PROBE:-0}"
RESUME="${RESUME:-0}"
ONLY="${ONLY:-}"

# 파이썬 인터프리터 자동 선택 (python / python3).
if command -v python >/dev/null 2>&1; then
  PY="python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  echo "python 을 찾을 수 없습니다."; exit 1
fi

# 설치돼 있으면 exposure-lens, 아니면 소스로 실행.
if command -v exposure-lens >/dev/null 2>&1; then
  EL="exposure-lens"
else
  EL="$PY -m exposure_lens"
  export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"
fi

# 실행할 기관 목록: ONLY 가 있으면 그것, 없으면 config 의 enabled 전부.
if [ -n "$ONLY" ]; then
  orgs="$ONLY"
else
  orgs=$($PY - "$CONFIG" <<'PY'
import sys
sys.path.insert(0, "src")
from exposure_lens.core.config import load_config
for o in load_config(sys.argv[1]).get_enabled():
    print(o.org_id)
PY
  ) || { echo "config 로드 실패: $CONFIG"; exit 1; }
fi

total=$(printf '%s\n' $orgs | grep -c .)
[ "$total" -eq 0 ] && { echo "실행할 기관이 없습니다."; exit 1; }

echo "총 $total 개 기관 | 휴식 ${PAUSE}s | probe=$DO_PROBE | 출력 $OUT_ROOT/<org>/"
echo

i=0
done_ok=0
failed=""
for org in $orgs; do
  i=$((i + 1))
  out="$OUT_ROOT/$org"
  printf '==== [%d/%d] %s ====\n' "$i" "$total" "$org"

  # RESUME: 이미 scan 결과가 있으면 건너뛴다.
  if [ "$RESUME" = "1" ] && ls "$out"/*/scan.jsonl >/dev/null 2>&1; then
    echo "  이미 완료 → 건너뜀"
    done_ok=$((done_ok + 1))
    continue
  fi

  ok=1
  # 1) 수집 (대상 무접촉)
  $EL collect --org "$org" -o "$out" -i "$CONFIG" || { echo "  collect 실패"; ok=0; }

  # 2) passive 검사 (대상 무접촉). collect 가 성공했을 때만.
  if [ "$ok" = "1" ]; then
    $EL scan -o "$out" -i "$CONFIG" --min-severity "$MIN_SEV" \
      || { echo "  scan 실패"; ok=0; }
  fi

  # 3) active 검사 (대상에 라이브 GET). DO_PROBE=1 일 때만.
  if [ "$ok" = "1" ] && [ "$DO_PROBE" = "1" ]; then
    $EL probe -o "$out" -i "$CONFIG" --min-severity "$MIN_SEV" \
      || echo "  probe 실패(계속)"
  fi

  if [ "$ok" = "1" ]; then
    done_ok=$((done_ok + 1))
  else
    failed="$failed $org"
  fi

  # 마지막 기관 뒤에는 쉬지 않는다.
  if [ "$i" -lt "$total" ] && [ "$PAUSE" -gt 0 ]; then
    echo "  ${PAUSE}s 휴식..."
    sleep "$PAUSE"
  fi
  echo
done

echo "======================================"
echo "완료 $done_ok/$total"
[ -n "$failed" ] && echo "실패:$failed"
echo "결과: $OUT_ROOT/<org>/YYYYMMDD/"
