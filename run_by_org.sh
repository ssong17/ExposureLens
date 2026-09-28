#!/usr/bin/env bash
# 기관별 순차 실행. 기관마다 프로세스를 새로 띄우고(요청 예산 리셋), 출력 디렉토리를
# runs/<org>/ 로 분리하고, 기관 사이에 PAUSE 초 쉰다.
#
# 사용:
#   bash run_by_org.sh                       collect + scan
#   DO_PROBE=1 bash run_by_org.sh            probe 까지 (대상에 라이브 GET)
#   ONLY="hancom truen" bash run_by_org.sh   지정 기관만
#   RESUME=1 bash run_by_org.sh              끝난 기관 건너뛰고, 끊긴 기관은 끊긴 곳부터
#
# 네트워크가 끊기면(exit 3) 거기서 멈춘다. 복구 후 RESUME=1 로 다시 실행.
#
# 환경변수: CONFIG(config) OUT_ROOT(runs) PAUSE(30) MIN_SEV(low)
#           DO_PROBE(0) RESUME(0) ONLY("")
set -u

CONFIG="${CONFIG:-config}"
OUT_ROOT="${OUT_ROOT:-runs}"
PAUSE="${PAUSE:-30}"
MIN_SEV="${MIN_SEV:-low}"
DO_PROBE="${DO_PROBE:-0}"
RESUME="${RESUME:-0}"
ONLY="${ONLY:-}"

# 파이썬 인터프리터: python 우선, 없으면 python3.
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

# 대상 기관: ONLY 가 있으면 그 목록, 없으면 config 의 enabled 전부.
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

# 네트워크 끊김(exit 3): 남은 기관을 헛돌지 않고 멈춘다. 진행 파일이 남아 있어
# RESUME=1 로 다시 돌리면 이 기관의 끊긴 지점부터 이어서 한다.
network_down() {
  echo
  echo "======================================"
  echo "네트워크 끊김으로 중단: $1 ($i/$total)"
  echo "연결 복구 후 이어서 실행:  RESUME=1 bash run_by_org.sh"
  exit 3
}
for org in $orgs; do
  i=$((i + 1))
  out="$OUT_ROOT/$org"
  printf '==== [%d/%d] %s ====\n' "$i" "$total" "$org"

  # RESUME: 끝난 기관은 건너뛰고, 중단된 단계는 --resume 으로 끊긴 곳부터.
  collect_args=""
  scan_args=""
  skip_collect=0
  if [ "$RESUME" = "1" ]; then
    if ls "$out"/*/*_scan.progress.jsonl >/dev/null 2>&1; then
      echo "  scan 중단 지점부터 이어서"
      skip_collect=1
      scan_args="--resume"
    elif ls "$out"/*/*_collect.progress.json >/dev/null 2>&1; then
      echo "  collect 중단 지점부터 이어서"
      collect_args="--resume"
    elif ls "$out"/*/*_scan.jsonl >/dev/null 2>&1; then
      echo "  이미 완료 → 건너뜀"
      done_ok=$((done_ok + 1))
      continue
    fi
  fi

  ok=1
  # 수집 (대상 무접촉)
  if [ "$skip_collect" = "0" ]; then
    $EL collect --org "$org" -o "$out" -i "$CONFIG" $collect_args
    rc=$?
    [ "$rc" = "3" ] && { network_down "$org"; }
    [ "$rc" != "0" ] && { echo "  collect 실패"; ok=0; }
  fi

  # passive 검사 (대상 무접촉). collect 성공 시에만.
  if [ "$ok" = "1" ]; then
    $EL scan -o "$out" -i "$CONFIG" --min-severity "$MIN_SEV" $scan_args
    rc=$?
    [ "$rc" = "3" ] && { network_down "$org"; }
    [ "$rc" != "0" ] && { echo "  scan 실패"; ok=0; }
  fi

  # active 검사 (대상에 라이브 GET). DO_PROBE=1 일 때만.
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
