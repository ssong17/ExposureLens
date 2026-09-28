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
max_retries = 3
max_requests = 0                 # 0 = 무제한
max_apex_per_org = 0             # 0 = 무제한
max_endpoints_per_org = 0        # 0 = 무제한
org_pause_seconds = 5.0          # 기관 사이 휴식(초)
max_response_bytes = 8000000     # 색인 응답 상한
max_body_bytes = 1000000         # 본문 규칙 대상 상한(응답 상한 이하)
```

한도(`max_*`)는 0이면 무제한이며, 발견된 것을 전부 처리한다. 기관 사이에는 `org_pause_seconds`만큼 쉰다.

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
- IP: 시스템 DNS 해석 / ASN: Team Cymru

| 옵션 | 설명 |
| --- | --- |
| `--fresh` | 누적하지 않고 기존 결과를 버리고 새로 시작 |
| `--no-resolve` | IP/ASN 조회 생략 |
| `--no-endpoints` | Wayback 엔드포인트 생략 |

기본 동작은 기존 collect 결과에 누적(중복 제거)이다. 공개 색인은 실행마다 결과가 달라, 여러 번 실행하면 합집합이 커진다. 기관 하나가 끝날 때마다 결과 파일을 다시 쓴다.

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

### probe (active)

아는 주소에 라이브 GET을 보낸다. high confidence apex만, 엔드포인트/경로당 한 번, 새 경로 추측·payload 없음.

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
| `--only-findings` | scan 의 critical/high URL만 |
| `--confidence` | 이 confidence 이상만 (기본 high) |
| `--assets`, `-a` | collect JSONL (생략 시 최신) |
| `--findings`, `-f` | scan JSONL (생략 시 최신) |
| `--min-severity` | 보고 하한 (기본 low) |

### run

collect → scan 을 한 번에 수행한다. `--probe`를 붙이면 probe까지.

```bash
exposure-lens run --all-enabled
exposure-lens run --org snu --probe
```

### 기관별 순차 실행

`run_by_org.sh`는 기관을 하나씩 순차 실행하고 기관 사이에 쉰다. 기관마다 출력 디렉토리(`runs/<org>/`)를 분리한다.

```bash
bash run_by_org.sh                 # collect + scan
DO_PROBE=1 bash run_by_org.sh      # probe 까지
ONLY="snu kaist" bash run_by_org.sh
RESUME=1 bash run_by_org.sh        # 끝난 기관 건너뛰고 이어서
```

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

- severity: `critical` > `high` > `medium` > `low`
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
  core/             config, models, net(레이트리밋 HTTP)
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
