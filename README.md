# ExposureLens

기관 목록만 주면 공개 색인에서 그 기관의 외부 노출 자산을 수집하고, 수집된 자산에서 민감한 노출 지점을 찾아내는 CLI 도구다.

대상 서버에 직접 요청하지 않고 제3자 공개 색인(인증서 투명성 로그, 웹 아카이브, 공개 DNS)만 조회하는 **비파괴(passive)** 방식으로 동작한다. 외부 의존성 없이 Python 표준 라이브러리만 사용한다.

## 특징

- **기관 목록 기반 자동화**: 도메인을 일일이 나열할 필요 없이, 기관명만 주면 소유 apex 도메인을 자동으로 찾는다.
- **비파괴 수집**: crt.sh, Wayback, Team Cymru 등 공개 색인만 조회한다. 대상 서버에 요청을 보내지 않는다.
- **소유 신뢰도(confidence) 판정**: 발견한 apex마다 근거와 함께 high/medium/low를 매겨, 엉뚱한 기관의 자산이 섞이는 것을 격리한다.
- **다중 소스 복원력**: 한 소스가 장애여도(crt.sh는 502가 잦다) Wayback 등 다른 소스로 보완한다.
- **민감정보 스캐너**: 수집된 자산에서 노출된 Git/CI 호스트, 설정·백업 파일 경로, URL에 유출된 시크릿을 심각도별로 탐지한다. 발견한 시크릿은 마스킹하며 절대 검증하지 않는다.
- **무의존성**: `pip install` 추가 패키지가 없다. Python 3.11 이상이면 된다.

## 동작 원리

```
기관 목록(config.toml)
  │
  ├─ apex 발견        crt.sh 조직 검색 -> 인증서 수 기준 랭킹 -> confidence 판정
  │
  ├─ 자산 수집        high+medium apex 하위에서
  │     ├─ 서브도메인   crt.sh + Wayback
  │     ├─ 엔드포인트   Wayback CDX
  │     ├─ IP           시스템 리졸버
  │     └─ ASN          Team Cymru 벌크 whois
  │
  └─ 노출 스캔        수집된 자산을 규칙으로 검사 -> 심각도별 findings
```

## 설치

```bash
git clone <repo>
cd ExposureLens
pip install -e .
```

Conda 환경에서 쓸 경우 환경을 먼저 활성화한 뒤 설치한다.

```bash
conda create -n exposurelens python=3.12 -y
conda activate exposurelens
pip install -e .
```

설치 후 `exposure-lens` 명령을 쓸 수 있다. 설치 없이 실행하려면 `PYTHONPATH=src python -m exposure_lens ...` 형태로도 된다.

## 사용법

### 1. 설정 준비

`config.example.toml`을 복사해 `config.toml`을 만들고 조사할 기관을 채운다. `config.toml`은 gitignore 대상이다.

```bash
cp config.example.toml config.toml
exposure-lens validate -i config.toml
```

### 2. apex 발견 (선택)

수집 전에 어떤 apex가 어떤 신뢰도로 잡히는지 확인하고 싶을 때 쓴다. 후보를 화면과 `apex.jsonl`로 뽑을 뿐, 설정을 바꾸지 않는다.

```bash
exposure-lens discover-apex -i config.toml --org snu
```

### 3. 자산 수집

apex 발견부터 서브도메인·엔드포인트·IP·ASN 수집까지 한 번에 수행한다.

```bash
exposure-lens collect -i config.toml --org snu          # 기관 하나
exposure-lens collect -i config.toml --group pilot      # 그룹 단위
exposure-lens collect -i config.toml --all-enabled      # 활성 기관 전부
```

진행 상황은 stderr로 실시간 출력되고, 결과는 `assets.jsonl`에 저장된다.

| 옵션 | 설명 |
| --- | --- |
| `--no-resolve` | IP/ASN 조회를 건너뛴다 |
| `--no-endpoints` | Wayback 엔드포인트 수집을 건너뛴다 |
| `--quiet`, `-q` | 진행 로그를 끈다 |

### 4. 노출 스캔

수집 결과(`assets.jsonl`)를 입력으로 받아 노출 지점을 찾는다.

```bash
exposure-lens scan -a output/20260914/assets.jsonl
exposure-lens scan -a output/20260914/assets.jsonl --min-severity high
```

## 설정

```toml
[collector]
user_agent = "PublicAssetResearch/0.2 (+security-research)"
request_interval_seconds = 2.0   # 요청 간격(초). 무료 색인 레이트리밋 방어
timeout_seconds = 30.0
max_retries = 1
max_requests = 1000              # 한 실행의 총 요청 상한
max_apex_per_org = 25            # 기관당 수집할 apex 상한
max_endpoints_per_org = 3000

# 기관 목록: org_id / name / org_type / enabled 만 채우면 된다.
[[orgs]]
org_id = "snu"
name = "Seoul National University"  # crt.sh 조직 검색에 그대로 쓰인다
org_type = "school"                 # company | gov | school | nonprofit | research | other
enabled = true
groups = ["pilot"]                  # (선택) 그룹 단위 실행용
search_names = ["서울대학교"]         # (선택) 별칭/한글명으로 커버리지 보강
seed_domains = ["snu.ac.kr"]        # (선택) 아는 도메인. 있으면 confidence high
```

`name`은 인증서 주체 조직명과 매칭되므로 실제 인증서에 박히는 이름이어야 한다. 애매하면 `search_names`에 영문·한글을 함께 넣는다. `org_type`은 한국 규제 TLD(.go.kr / .ac.kr / .or.kr)를 소유 근거로 활용해 정확도를 높인다.

## 출력

실행마다 `output/YYYYMMDD/` 아래에 결과가 쌓인다. 성공 결과는 JSONL과 stdout에 남기고, `summary.md`에는 문제(실패·중단)만 기록한다.

| 파일 | 생성 명령 | 내용 |
| --- | --- | --- |
| `apex.jsonl` | discover-apex | apex 후보 전체(low 포함) |
| `assets.jsonl` | collect | 수집된 자산(모든 기관 통합, `org_id`로 구분) |
| `findings.jsonl` | scan | 탐지된 노출 |
| `summary.md` / `findings_summary.md` | 각 명령 | 문제 또는 조치가 필요한 항목 |

자산 레코드 예시:

```json
{"record_id":"SNU_20260914_000001","org_id":"snu","apex":"snu.ac.kr",
 "apex_confidence":"high","asset_type":"subdomain","host":"portal.snu.ac.kr",
 "source":"crt.sh+wayback","discovered_at":"2026-09-14T01:07:19+09:00",
 "url":"","resolved_ip":"147.46.10.129","asn":"AS9488","in_scope":true}
```

탐지 레코드 예시(`asset_ref`로 원본 자산까지 역추적된다):

```json
{"finding_id":"F_20260914_000001","org_id":"snu","asset_ref":"SNU_20260914_000178",
 "severity":"high","category":"sensitive-host","rule":"host-vcs",
 "host":"git.csap.snu.ac.kr","url":"","evidence":"git.csap.snu.ac.kr",
 "discovered_at":"2026-09-14T01:41:54+09:00"}
```

## confidence 와 severity

**apex confidence** — 발견한 apex가 정말 그 기관 소유인지에 대한 신뢰도다.

- `high`: seed 일치, 또는 인증서 수 최상위이면서 점유율이 유의미한 apex
- `medium`: org_type과 TLD 클래스가 일치하고 인증서 수가 임계치 이상
- `low`: 롱테일·형제 기관 의심 (수집 대상에서 제외)

수집기는 high+medium apex만 수집하고, 능동적인 후속 작업은 high로 좁히는 것을 전제로 설계했다.

**finding severity** — 노출의 위험도다.

- `critical`: 시크릿 파일(.env, 개인키), 유출된 AWS/Slack 키
- `high`: 노출된 Git/CI 호스트, 설정·백업 파일, URL 내 시크릿
- `medium`: 비운영(dev/staging/test)·내부 호스트, 관리자 페이지 경로
- `low`: API 문서/스키마 표면

## 안전 원칙

- 수집·스캔은 전부 비파괴다. 대상 서버에 직접 요청하지 않는다.
- 포트 스캔, 엔드포인트 프로빙, DNS 브루트포스 같은 능동 행위는 이 도구에 포함하지 않는다. 이런 작업은 대상별 명시적 허가 아래에서만 별도로 다룬다.
- 발견한 자격증명은 마스킹만 하고 절대 사용·검증하지 않는다.
- 결과 파일에는 쿼리 문자열 등 민감정보가 포함될 수 있으므로 외부에 공유하거나 버전 관리에 포함하지 않는다.

## 프로젝트 구조

```
src/exposure_lens/
├── cli.py               명령 처리
├── core/                config, models, net(레이트리밋 HTTP)
├── sources/             crtsh, wayback, cymru
├── apex/                discovery, tldclass
├── collect/             collector, resolve
├── scan/                rules, scanner
└── report/              output(JSONL, summary)
```

## 한계

- apex 발견은 crt.sh 조직 검색에 크게 의존하며, 인증서에 조직명이 없는 자산은 seed로 보완해야 한다.
- 공개 색인에 없는 최신·비색인 자산은 발견하지 못한다.
- Wayback 결과는 과거 기록이므로 현재도 접근 가능하다는 보장은 없다.
- IPv6 자산의 ASN 매핑은 아직 지원하지 않는다.
