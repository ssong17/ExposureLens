# ExposureLens

기관 이름으로 공개 색인(인증서 투명성 로그, 웹 아카이브, 공개 DNS)에서 외부 노출 자산을 모으고, 그 안에서 민감한 노출 지점을 찾는 CLI. Python 3.11+, 외부 의존성 없음.

세 단계로 나뉜다.

| 단계 | 명령 | 대상 접촉 | 내용 |
| --- | --- | --- | --- |
| 수집 | `collect` | 없음 | 기관명 → apex → 서브도메인·엔드포인트·IP·ASN |
| passive 검사 | `scan` | 없음 | 수집 자산을 제3자 데이터만으로 검사 |
| active 검사 | `probe` | 있음 | 아는 주소에 라이브 GET, 본문·도달성 확인 |

## 설치

```bash
pip install -e .
```

설치 없이 실행: `PYTHONPATH=src python -m exposure_lens <명령>`.

## 설정

설정은 `config/` 폴더로 관리한다. 폴더가 있으면 자동으로 사용하고, 없으면 `config.toml` 단일 파일을 쓴다.

```
config/
  _collector.toml            공통 수집기 설정 ([collector])
  config_<분야>.toml          분야별 기관 목록 ([[orgs]] 여러 개)
```

기관 하나당 파일 하나(`<org_id>.toml`) 형태도 된다. 폴더 안 모든 `.toml`의 `[collector]`는 병합되고 `[[orgs]]`는 합쳐진다.

### `[collector]` (config/_collector.toml)

```toml
[collector]
user_agent = "PublicAssetResearch/0.2 (+security-research)"
request_interval_seconds = 2.0   # 요청 간격(초), 호스트별 적용
timeout_seconds = 30.0
max_retries = 5
retry_delays_seconds = [2, 4, 8, 16, 32]  # 재시도 전 대기(초): 1~5회차
max_requests = 0                 # 0 = 무제한
max_apex_per_org = 0             # 0 = 무제한
max_endpoints_per_org = 0        # 0 = 무제한
max_endpoint_variants_per_path = 5  # 같은 (호스트,경로) 쿼리 변형 보관 수 (0=무제한)
org_pause_seconds = 5.0          # 기관 사이 휴식(초)
max_response_bytes = 8000000     # 색인 응답 상한
max_body_bytes = 1000000         # 본문 규칙 대상 상한(응답 상한 이하)
wayback_max_pages = 40           # Wayback CDX 페이지네이션: apex당 최대 페이지 (0=전부)
search_limit = 20                # --search 시 apex당 검색결과 상한 (키 없으면 무동작)
# search_queries = ["관리자", "백업"]  # (선택) --search 기본 쿼리 덮어쓰기. 키워드는 site:apex "kw"로
```

한도(`max_*`)는 0이면 무제한이며, 발견된 것을 전부 처리한다. 기관 사이에는 `org_pause_seconds`만큼 쉰다.

일시적 오류(429/5xx, 연결 실패·타임아웃)는 `retry_delays_seconds` 간격으로 재시도한다(짧게 시작해 배로 증가, 흔한 블립을 빨리 넘긴다). 연결 자체가 연속 3번(각각 재시도 소진 후) 실패하면 네트워크 끊김으로 보고 단계를 멈춘다(exit 3). 502 같은 서버 응답이나 읽기 타임아웃(crt.sh 지연)은 끊김으로 세지 않는다.

### `[[orgs]]`

```toml
[[orgs]]
org_id = "snu"                   # 영소문자/숫자/_/-, 32자 이내, 고유
name = "Seoul National University"  # crt.sh 조직 검색어
org_type = "school"              # apex 힌트, 자유 문자열
enabled = true                   # true 인 기관만 대상
groups = ["pilot"]               # (선택) --group 실행용
search_names = ["서울대학교"]      # (선택) 별칭·한글명
seed_domains = ["snu.ac.kr"]     # (선택) 아는 apex, 있으면 confidence high
```

## 명령

`--config`/`-i`는 기본이 `config/`(없으면 `config.toml`)이며 생략 가능하다. 대상 범위는 `--org <id>` / `--group <group>` / `--all-enabled` 중 하나로 지정한다.

### validate

설정 파일/폴더를 검증한다.

```bash
exposure-lens validate
```

### discover-apex

기관명으로 apex 후보만 뽑는다(수집 전 확인용). crt.sh 조직 검색 → 인증서 수 랭킹 → confidence 판정.

```bash
exposure-lens discover-apex --org snu
```

### collect

apex 발견부터 자산 수집까지 수행한다. 대상 무접촉.

```bash
exposure-lens collect --org snu
exposure-lens collect --all-enabled
```

- apex 발견: crt.sh 조직 검색, 동명 타 기관은 confidence로 격리
- 서브도메인: crt.sh + Wayback
- 엔드포인트: Wayback(과거) + urlscan.io(최근)
  - Wayback은 apex 단위(`*.apex`)를 **CDX 페이지네이션**으로 훑는다(`showNumPages`로 페이지 수를 받고 `page=0..N-1` 순회). 결과가 호스트 알파벳 순이라 1회 조회로 1000건에서 자르면 뒤쪽 서브도메인이 빠지는데, 페이지네이션은 **모든 서브도메인의 모든 경로**를 적은 요청으로 받는다(대부분 1~5페이지, `wayback_max_pages`로 상한). 조회가 실패하면 그 apex는 미완료로 남아 `--resume` 시 재수집된다
  - 게시글·목록처럼 **숫자만 다른 경로(`/news/pr/1`,`/2`…)와 쿼리 변형(`?page=`)은 "틀"로 묶어** `max_endpoint_variants_per_path`개만 저장(전수 저장 방지)
- IP: 시스템 DNS 해석 / ASN: Team Cymru

| 옵션 | 설명 |
| --- | --- |
| `--fresh` | 누적하지 않고 기존 결과를 버리고 새로 시작 |
| `--resume` | 중단된 최신 collect를 끊긴 곳부터 이어서 |
| `--no-resolve` | IP/ASN 조회 생략 |
| `--no-endpoints` | Wayback 엔드포인트 생략 |

기본 동작은 기존 collect 결과에 누적(중복 제거)이다. 공개 색인은 실행마다 결과가 달라, 여러 번 실행하면 합집합이 커진다. 기관 하나가 끝날 때마다 결과 파일을 다시 쓴다.

#### 이어서 실행 (`--resume`)

실행 중에는 `<시각>_collect.progress.json`이 결과 옆에 생기고, 정상 종료하면 지워진다. 파일이 남아 있으면 그 실행이 중간에 끊겼다는 뜻이다(네트워크 끊김, Ctrl-C, 오류).

```bash
exposure-lens collect --all-enabled            # 도중에 끊김
exposure-lens collect --all-enabled --resume   # 끊긴 곳부터
```

- 끝난 기관은 건너뛰고, 진행 중이던 기관은 apex 단위로 이어서 한다(이미 받은 apex 후보·호스트·엔드포인트 재사용)
- 연결 실패로 잘린 단계(apex 탐색, apex 하나, DNS 해석)는 완료로 치지 않는다. 실행이 끝나도 진행 파일이 남아 `--resume` 때 그 단계만 다시 한다
- 같은 시각 접두사의 파일에 이어 쓴다(새 파일을 만들지 않음)

### scan (passive)

수집 자산을 대상 무접촉으로 검사한다.

```bash
exposure-lens scan
exposure-lens scan --assets output/20260928/143052_collect.jsonl
```

- 이름/URL 규칙
  - 민감 호스트: `git.`·`jenkins.`·`vpn.`·`dev.`·`admin.` 등 (이름 기반 후보)
  - 민감 경로: `/.env`·`/.git/`·`*.sql`·`config.*`·`/admin` 등
  - URL 쿼리 시크릿: `api_key=`·`token=` 등
- 현재 열린 서비스: 수집된 IP → Shodan InternetDB → 위험 포트(mysql·redis·mongodb·rdp 등). 제3자 스캔 결과이므로 대상 무접촉

| 옵션 | 설명 |
| --- | --- |
| `--assets`, `-a` | 검사할 collect JSONL (생략 시 최신) |
| `--min-severity` | 보고 하한 (기본 medium) |
| `--no-services` | Shodan 현재-서비스 검사 생략 |
| `--resume` | 중단된 최신 scan을 이어서 (이미 받은 Shodan 응답 재사용) |

scan 도 IP마다 Shodan 응답을 `<시각>_scan.progress.jsonl`에 기록한다. 끊기면 `scan.jsonl`을 쓰지 않고(미완료가 완료처럼 보이지 않게) 멈추며, `--resume`은 남은 IP만 조회한다. 조회에 실패한 IP는 "열린 포트 없음"으로 치지 않고 Problems에 남긴다.

### probe (active)

아는 주소에 라이브 GET을 보낸다. high confidence apex만, 엔드포인트/경로당 한 번, 새 경로 추측·payload 없음. 같은 경로의 쿼리 변형(`?page=1..N`)은 대표 몇 개만 읽는다(본문이 대부분 동일하므로).

```bash
exposure-lens probe
exposure-lens probe --scripts
exposure-lens probe --source wayback
```

- 본문 검사: 엔드포인트/JS 본문 → 하드코딩 시크릿, 백엔드 설정(API 주소·Firebase·Supabase·커스텀 인증 헤더), DB 접속정보, 개인정보, API 경로, 클라이언트 권한 체크. `sourceMappingURL`이 있으면 소스맵을 받아 원본 소스까지 검사
- 도달성 확인: scan finding의 경로가 지금 응답하는지, 인증 없이 2xx인지 확정
- `--source wayback`: 본문을 Wayback 아카이브에서 읽어 대상 무접촉으로 실행(도달성·인증 확인은 생략)

| 옵션 | 설명 |
| --- | --- |
| `--source` | `fetch`(기본, 라이브) / `wayback`(아카이브) |
| `--scripts` | 클라이언트 코드(.js/.json/.map)만 |
| `--only-findings` | 규칙 기준 critical/high URL만 (과거 기록이라 한 단계 낮아진 후보 포함) |
| `--confidence` | 이 confidence 이상만 (기본 high) |
| `--assets`, `-a` | collect JSONL (생략 시 최신) |
| `--findings`, `-f` | scan JSONL (생략 시 최신) |
| `--min-severity` | 보고 하한 (기본 low) |

### run

한 번에 수행하는 전체 파이프라인. **passive로 후보를 최대한 뽑고, `--probe`를 붙이면 active로 확인·보완**하는 흐름이다.

```bash
exposure-lens run --all-enabled
exposure-lens run --org snu --probe
exposure-lens run --all-enabled --resume         # 끊긴 단계(collect 또는 scan)부터
exposure-lens run --all-enabled --no-archive-bodies   # 아카이브 본문 패스 생략(빠름)
exposure-lens run --all-enabled --vibe                 # AI 빌더(Lovable·v0·Replit 등) 핑거프린트 추가
exposure-lens run --all-enabled                       # 검색 발견은 기본 on (키 있을 때만 실제 동작)
exposure-lens run --all-enabled --no-search           # 검색 발견 끄기
exposure-lens run --all-enabled --search-query 관리자 --search-query 백업  # 키워드 추가 지정
```

단계:

1. **collect** (passive) — 호스트·URL·포트 수집
2. **scan** (passive) — 호스트 이름·URL·포트 규칙
3. **아카이브 본문** (passive, 기본 실행) — Wayback 스냅샷 본문을 읽어 하드코딩 시크릿·백엔드 주소·Supabase/Firebase 설정 등 규칙만으론 못 보는 것을 추출한다. **대상에 요청하지 않는다.** 스냅샷이 없는 엔드포인트는 따로 기록해 둔다. (`--no-archive-bodies`로 생략)
4. **probe** (active, `--probe`일 때만) — 위 passive 후보를 라이브로 **확인**(도달성·인증 없는 2xx·본문 재확인)하고, **아카이브에 스냅샷이 없던 엔드포인트만** 라이브로 읽어 passive가 못 본 것을 메운다. 아카이브가 이미 커버한 것은 다시 요청하지 않는다.

즉 대량 본문 추출은 무접촉(아카이브)으로 끝내고, active 요청은 "확인 + 아카이브 누락분"으로 최소화된다. `--no-archive-bodies`면 3단계를 건너뛰고 probe가 모든 본문을 라이브로 읽는다(과거 동작).

> `--probe`가 확인하는 것: API 키·Supabase/Firebase 설정 등이 **현재 서빙되는 본문에 들어 있는지**까지다. 그 자격증명이 실제로 유효한지·접근되는지는 테스트하지 않는다(active exploitation 금지).

### 기관별 순차 실행

`run_by_org.sh`는 기관을 하나씩 순차 실행하고 기관 사이에 쉰다. 기관마다 출력 디렉토리(`runs/<org>/`)를 분리한다.

```bash
bash run_by_org.sh                 # collect + scan
DO_PROBE=1 bash run_by_org.sh      # probe 까지
ONLY="snu kaist" bash run_by_org.sh
RESUME=1 bash run_by_org.sh        # 끝난 기관 건너뛰고, 끊긴 기관은 끊긴 곳부터
```

네트워크 끊김(exit 3)이면 남은 기관을 헛돌지 않고 그 자리에서 멈춘다. 복구 후 `RESUME=1`로 다시 실행하면 그 기관의 끊긴 단계(`collect --resume` 또는 `scan --resume`)부터 이어간다.

> 같은 색인(crt.sh·Wayback)을 여러 collect가 동시에 두드리면 503/타임아웃이 늘어 서로를 느리게 만든다. collect는 한 번에 하나만 돌리는 것을 권장한다(probe는 대상 서버로, collect는 색인으로 가므로 겹쳐도 무방).

환경변수: `CONFIG`(기본 config), `OUT_ROOT`(runs), `PAUSE`(30), `MIN_SEV`(low), `DO_PROBE`(0), `RESUME`(0), `ONLY`.

## 출력

`output/YYYYMMDD/` 아래에 `<HHMMSS>_<단계>.jsonl`(데이터)과 `<HHMMSS>_<단계>_summary.md`(요약)로 저장된다. 같은 단계를 안 준 `scan`/`probe`는 같은 출력 루트에서 가장 최근 collect/scan JSONL을 자동으로 사용한다.

| 파일 | 단계 | 내용 |
| --- | --- | --- |
| `<time>_collect.jsonl` / `_summary.md` | collect | 수집 자산 + 기관별 개수 |
| `<time>_scan.jsonl` / `_summary.md` | scan | 이름/URL 규칙 + 현재 열린 서비스 |
| `<time>_probe.jsonl` / `_summary.md` | probe | 본문 탐지 + 인증 없이 열린 접근 |
| `<time>_liveness.jsonl` | probe | 도달성(접속됨/인증필요/리다이렉트/응답없음) |
| `<time>_apex.jsonl` / `_summary.md` | discover-apex | apex 후보 |
| `<time>_run_summary.md` | run | 통합 실행 요약 |

## 결과 해석

### summary.md 구조

```
# scan - 20260928

> 실행 명령
```
exposure-lens scan --all-enabled
```

노출 2건 — critical 1, high 0, medium 1, low 0

## 기관
| org_id | 이름 | 발견 | C | H | M | L |
| kosha  | 한국산업안전보건공단 | 1 | 0 | 1 | 0 | 0 |

## 발견된 유형
| 유형 | 건수 | 최고 심각도 | category |
| 백업·덤프 파일 | 1 | high | backup-exposure |

## high (1)
- `kosha` [백업·덤프 파일] [현재] http://www.kosha.or.kr/…/InnoGMP_Win.zip  /…/InnoGMP_Win.zip
```

- 맨 위: 실행 명령
- 노출 건수: 심각도별(critical/high/medium/low) 집계. 접속 상태(도달성)는 노출이 아니라 별도 한 줄로 집계되며 상세는 `liveness.jsonl`에 있다
- 기관 표: `org_id | 이름 | 발견 | C H M L`
- 발견된 유형 표: 어떤 종류가 몇 건 나왔는지, 심각도 높은 순
- 심각도별 항목: `` `org_id` [유형] [태그] URL  근거``

### 항목 태그

- `[현재]` : 지금 관측됨 (호스트 DNS 해석 / urlscan 최근 / Shodan 현재 포트 / probe 라이브 응답)
- `[과거]` : Wayback 아카이브에만 존재
- `[200]` 등 : probe 가 관측한 HTTP 상태

### 값의 의미

- severity: 이름이 얼마나 위험해 보이는지가 아니라 **증거가 얼마나 강한지**로 매긴다

| severity | 기준 | 예 |
| --- | --- | --- |
| `critical` | 실제로 쓸 수 있는 값을 봄, 또는 시크릿 파일·DB 포트가 **지금** 관측됨 | AKIA 키, 비밀번호 든 DB URI, 개인키, 현재 `/.env`, 열린 3306 |
| `high` | 민감 파일·경로가 **지금** 관측됨, 또는 probe가 인증 없는 2xx 확인 | 현재 `/.git/config`, `db.sql`, `index.php.bak`, `www_backup.zip` |
| `medium` | probe로 확인해야 할 **후보** | 해석되는 `git.`·`dev.` 호스트, Wayback에만 있는 `/.git/` |
| `low` | 노출이 아닌 공격면 정보 | `/admin` 경로, 죽은 호스트, 공개 브라우저 키 |

  - Wayback에만 있는 경로는 한 단계 낮춘다(과거 흔적). 단 URL에 박힌 시크릿은 아카이브에서 누구나 읽을 수 있으므로 낮추지 않는다
  - probe가 라이브로 확인하면 규칙 본래 등급으로 되돌린다. 이름 기반 호스트는 예외(로그인 페이지도 2xx를 준다)
  - 일반 `.zip` 다운로드는 백업으로 보지 않는다. 파일명에 `backup`·`db`·`www`·`src` 등이 있거나 `/backup/` 아래일 때만
  - 같은 경로의 쿼리 변형(`?page=1`, `?page=2`…)은 한 건으로 묶고 `(+N query variants)`로 표시
- confidence(apex 소유 확신도): `high`(seed 일치 또는 인증서 지배) / `medium`(TLD 클래스 일치) / `low`. 이름 기반 호스트 finding은 medium 후보로 제한되고, probe 가 실제 응답을 확인해야 상향된다
- freshness: `current`(현재) / `archived`(과거)
- 시크릿 값은 마스킹되어 저장된다(`AIza****fe`). 라우트·주소·설정 값은 그대로 저장된다

### JSONL 레코드

자산(collect):

```json
{"record_id":"SNU_20260914_000001","org_id":"snu","org_name":"Seoul National University",
 "apex":"snu.ac.kr","apex_confidence":"high","asset_type":"subdomain",
 "host":"portal.snu.ac.kr","resolved_ip":"147.46.10.129","asn":"AS9488",
 "freshness":"current","last_seen":""}
```

finding(scan/probe):

```json
{"finding_id":"P_20260914_000001","org_id":"snu","org_name":"Seoul National University",
 "asset_ref":"SNU_20260914_000512","severity":"critical","category":"db-exposure",
 "rule":"body-db-uri","host":"legacy.snu.ac.kr","url":"https://legacy.snu.ac.kr/config.js",
 "path":"/config.js","evidence":"postgres://ad****db","status":"200",
 "source":"fetch-body","freshness":"current"}
```

`asset_ref`로 원본 자산을 역추적한다. `source`는 finding 출처(`shodan-internetdb`, `wayback-body`, `fetch-body`, `verify-confirmed` 등).

## 프로젝트 구조

```
src/exposure_lens/
  cli.py            명령 처리 + 단계 오케스트레이션
  core/             config, models, net(레이트리밋 HTTP), progress(--resume 상태)
  sources/          crtsh, wayback, urlscan, shodan, cymru, body
  collect/          collector, resolve, merge, discovery, tldclass
  scan/             rules, scanner, services          (passive)
  probe/            inspect, verify                   (active)
  report/           output, summary
```

## 테스트

```bash
python -m pytest -q
```
