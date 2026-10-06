# ExposureLens

기관 이름으로 공개 색인(인증서 투명성 로그, 웹 아카이브, 공개 DNS)에서 외부 노출 자산을 모으고, 그 안에서 민감한 노출 지점을 찾는 CLI. Python 3.11+, 외부 의존성 없음.

세 단계로 나뉜다.

| 단계 | 명령 | 대상 접촉 | 내용 |
| --- | --- | --- | --- |
| collect | `collect` | 없음 | 기관명 → apex → 서브도메인·엔드포인트·IP·ASN |
| scan | `scan` | 없음 | 수집 자산을 제3자 데이터·아카이브 본문만으로 검사 |
| probe | `probe` | 있음 | 아는 주소에 라이브 GET, 본문·도달성 확인 |

## 설치 (conda)

```bash
conda create -n exposure-lens python=3.11
conda activate exposure-lens
pip install -e .
```

설치 없이 실행하려면: `PYTHONPATH=src python -m exposure_lens <명령>`.

## 설정

설정은 `config/` 폴더로 관리한다. 폴더가 있으면 자동으로 사용하고, 없으면 `config.toml` 단일 파일을 쓴다. 폴더 안 모든 `.toml`의 `[collector]`는 병합되고 `[[orgs]]`는 합쳐진다(기관 하나당 파일 하나 형태도 가능).

```
config/
  _collector.toml            공통 수집기 설정 ([collector])
  config_<분야>.toml          분야별 기관 목록 ([[orgs]] 여러 개)
```

### `[collector]`

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

한도(`max_*`)는 0이면 무제한이다. 일시적 오류(429/5xx, 연결 실패·타임아웃)는 `retry_delays_seconds` 간격으로 재시도하고, 연결이 연속 3번 실패하면 네트워크 끊김으로 보고 단계를 멈춘다(exit 3).

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

### 검색엔진 발견 API 키 (선택, `--search`)

`--search`(기본 on)는 `site:` 연산자로 아카이브가 못 본 관리자/CMS 페이지를 찾는다. 환경변수로 키를 줄 때만 실제 동작한다(키 없으면 무동작).

```bash
export GOOGLE_API_KEY=...        # Google Custom Search
export GOOGLE_CSE_ID=...
export BRAVE_SEARCH_API_KEY=...  # 또는 Brave
```

검색 결과는 **한국 운영대상만** 남긴다(.kr 계열 TLD이거나 결과 제목/스니펫에 한글 포함). 접속 없이 검색 API 메타데이터만으로 판단한다.

## 명령

`--config`/`-i`는 기본이 `config/`(없으면 `config.toml`)이며 생략 가능하다. 대상 범위는 `--org <id>` / `--group <group>` / `--all-enabled` 중 하나로 지정한다.

### validate — 설정 검증

```bash
exposure-lens validate
```

### discover-apex — apex 후보만 확인

```bash
exposure-lens discover-apex --org snu
```

### collect — 자산 수집 (대상 무접촉)

```bash
exposure-lens collect --org snu
exposure-lens collect --all-enabled
exposure-lens collect --all-enabled --resume   # 끊긴 곳부터
```

| 옵션 | 설명 |
| --- | --- |
| `--fresh` | 누적하지 않고 기존 결과를 버리고 새로 시작 (기본은 누적·중복제거) |
| `--resume` | 중단된 최신 collect를 끊긴 곳부터 이어서 |
| `--no-resolve` | IP/ASN 조회 생략 |
| `--no-endpoints` | Wayback 엔드포인트 생략 |
| `--no-search` | 검색엔진 발견 끄기 |
| `--search-query KW` | 검색 키워드/템플릿 추가 지정 (반복 가능) |

### scan — 대상 무접촉 검사

이름/URL 규칙 + 현재 열린 서비스(Shodan InternetDB) + Wayback 아카이브 본문을 한 번에 검사한다.

```bash
exposure-lens scan
exposure-lens scan --assets output/20260928/143052_collect.jsonl
exposure-lens scan --resume          # 끊긴 곳부터 (Shodan·아카이브 응답 재사용)
```

| 옵션 | 설명 |
| --- | --- |
| `--assets`, `-a` | 검사할 collect JSONL (생략 시 최신) |
| `--min-severity` | 보고 하한 (기본 medium) |
| `--no-services` | Shodan 현재-서비스 검사 생략 |
| `--no-archive-bodies` | Wayback 아카이브 본문 검사 생략 |
| `--no-vibe` | AI 빌더 핑거프린트 끄기 (기본 on) |
| `--resume` | 중단된 최신 scan을 이어서 |

### probe — 라이브 GET (대상 접촉)

high confidence apex만, 엔드포인트/경로당 한 번, 새 경로 추측·payload 없음.

```bash
exposure-lens probe
exposure-lens probe --scripts
```

| 옵션 | 설명 |
| --- | --- |
| `--scripts` | 클라이언트 코드(.js/.json/.map)만 |
| `--only-findings` | 규칙 기준 critical/high URL만 |
| `--assets`, `-a` | collect JSONL (생략 시 최신) |
| `--findings`, `-f` | scan JSONL (생략 시 최신) |
| `--min-severity` | 보고 하한 (기본 low) |
| `--no-vibe` | AI 빌더 핑거프린트 끄기 |

### run — 전체 파이프라인

collect → scan 을 한 번에 수행하고, `--probe`를 붙이면 probe까지 이어서 한다.

```bash
exposure-lens run --all-enabled
exposure-lens run --org snu --probe
exposure-lens run --all-enabled --resume              # 끊긴 단계부터
exposure-lens run --all-enabled --no-archive-bodies   # 아카이브 본문 생략(빠름)
exposure-lens run --all-enabled --no-search           # 검색 발견 끄기
exposure-lens run --all-enabled --search-query 관리자 --search-query 백업
```

주요 옵션: `--probe`(probe 단계 추가), `--no-services` / `--no-archive-bodies`(scan 하위 생략), `--no-resolve` / `--no-endpoints`(collect 하위 생략), `--no-search` / `--search-query`(검색 발견), `--no-vibe`, `--min-severity`(기본 medium), `--fresh`, `--resume`.

> `--probe`가 확인하는 것: API 키·Supabase/Firebase 설정 등이 **현재 서빙되는 본문에 들어 있는지**까지다. 그 자격증명이 실제로 유효한지·접근되는지는 테스트하지 않는다(active exploitation 금지).

## 출력

`output/YYYYMMDD/` 아래에 `<HHMMSS>_<단계>.jsonl`(데이터)과 `<HHMMSS>_<단계>_summary.md`(요약)로 저장된다. `--assets`/`--findings`를 생략하면 같은 출력 루트에서 가장 최근 collect/scan JSONL을 자동으로 사용한다.

| 파일 | 단계 | 내용 |
| --- | --- | --- |
| `<time>_collect.jsonl` / `_summary.md` | collect | 수집 자산 + 기관별 개수 |
| `<time>_scan.jsonl` / `_summary.md` | scan | 이름/URL 규칙 + 현재 열린 서비스 + 아카이브 본문 |
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
- 기관 표 → 발견된 유형 표(심각도 높은 순) → 심각도별 항목: `` `org_id` [유형] [태그] URL  근거``

### 항목 태그

- `[현재]` : 지금 관측됨 (호스트 DNS 해석 / urlscan 최근 / Shodan 현재 포트 / probe 라이브 응답)
- `[과거]` : Wayback 아카이브에만 존재
- `[200]` 등 : probe 가 관측한 HTTP 상태

### severity (증거 강도)

이름이 얼마나 위험해 보이는지가 아니라 **증거가 얼마나 강한지**로 매긴다.

| severity | 기준 | 예 |
| --- | --- | --- |
| `critical` | 실제로 쓸 수 있는 값을 봄, 또는 시크릿 파일·DB 포트가 **지금** 관측됨 | AKIA 키, 비밀번호 든 DB URI, 개인키, 현재 `/.env`, 열린 3306 |
| `high` | 민감 파일·경로가 **지금** 관측됨, 또는 probe가 인증 없는 2xx 확인 | 현재 `/.git/config`, `db.sql`, `index.php.bak`, `www_backup.zip` |
| `medium` | probe로 확인해야 할 **후보** | 해석되는 `git.`·`dev.` 호스트, Wayback에만 있는 `/.git/` |
| `low` | 노출이 아닌 공격면 정보 | `/admin` 경로, 죽은 호스트, 공개 브라우저 키, AI 빌더 핑거프린트 |

- Wayback에만 있는 경로는 한 단계 낮춘다(과거 흔적). URL에 박힌 시크릿은 아카이브에서 누구나 읽을 수 있으므로 낮추지 않는다
- probe가 라이브로 확인하면 규칙 본래 등급으로 되돌린다. 이름 기반 호스트는 예외(로그인 페이지도 2xx를 준다)
- 같은 경로의 쿼리 변형(`?page=1`, `?page=2`…)은 한 건으로 묶고 `(+N query variants)`로 표시

### 그 밖의 값

- confidence(apex 소유 확신도): `high`(seed 일치 또는 인증서 지배) / `medium`(TLD 클래스 일치) / `low`
- freshness: `current`(현재) / `archived`(과거)
- 시크릿 값·라우트·주소·설정 값 모두 **마스킹 없이 원문 그대로** 저장된다(운영자 분류·검증용 로컬 출력). `output/`은 gitignore 대상이다

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
 "path":"/config.js","evidence":"postgres://admin:s3cr3tpw@db.internal:5432/prod","status":"200",
 "source":"fetch-body","freshness":"current"}
```

`asset_ref`로 원본 자산을 역추적한다. `source`는 finding 출처(`shodan-internetdb`, `wayback-body`, `fetch-body`, `verify-confirmed` 등).

## 테스트

```bash
python -m pytest -q
```
