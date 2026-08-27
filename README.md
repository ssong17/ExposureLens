# ExposureLens — 기업 직접 노출 자산 URL 수집기

기업이 직접 공개한 자산의 URL 후보를 제3자 공개 색인에서 수집하여 JSONL로 저장하는 CLI 도구이다. 모든 후보는 `DIRECT` 트랙과 `DIR_` ID를 사용한다.

이 버전은 **URL 후보 수집만 수행**한다. 로그인, 경로 추측, API 호출, 키 검증, DB 접속 및 스토리지 목록 조회는 수행하지 않는다.

## 프로젝트 구조

```text
src/exposure_lens/
├── __init__.py            # Python 패키지 정의와 버전
├── __main__.py            # `python -m exposure_lens` 실행 진입점
├── cli.py                 # CLI 명령과 옵션 처리
├── candidate_filter.py    # URL 그룹화와 분석 우선순위 분류
├── config.py              # TOML 설정 로드와 유효성 검사
├── direct_collector.py    # DIRECT 트랙 공개 색인 수집기
├── discovery.py           # HTML, sitemap, robots.txt 파서
├── http_client.py         # 제한적 직접 수집용 HTTP 클라이언트
├── models.py              # 공통 후보 데이터 모델
├── pipeline.py            # 제한적 직접 수집과 결과 저장
└── urltools.py            # URL 정규화, 도메인 검사와 유형 판별
```

- `collector_tests/test_collector.py`: 설정, URL 수집과 출력 기능 테스트
- `config.example.toml`: 설정 파일 예시
- `config.toml`: 실제 실행 설정
- `output/YYYYMMDD/`: 날짜별 원본·분석 후보 JSONL과 실행 요약
- `pyproject.toml`: 패키지, 실행 명령과 개발 도구 설정

## 안전장치

- `--company`, `--group`, `--all-enabled` 중 하나로 실행 범위를 명시
- 설정에 `enabled = true`인 기업만 실행
- 검증된 `allowed_domains`에 속하는 URL만 후보로 저장
- 대상 기업 서버가 아닌 CT, 공개 DNS, Common Crawl, Wayback만 조회
- `site:` 검색은 자동 스크래핑하지 않고 검색 쿼리만 생성
- 공개 색인 요청 수, 응답 크기, 요청 간격과 재시도 횟수 제한
- 발견한 API, 자격증명, DB 및 스토리지에 직접 접근하지 않음

## 시작하기

Python 3.11 이상이 필요하다.

```bash
python -m pip install -e .
cp config.example.toml config.toml
```

`config.toml`에서 예시 기업을 실제 조사 기업으로 교체한다. 도메인과 소유 근거를 직접 검증한 후에만 `enabled = true`로 바꾼다.

설정 검사:

```bash
exposure-lens validate --config config.toml
```

요청 없이 실행 계획 확인:

```bash
exposure-lens collect --config config.toml --company example --dry-run
```

수집 실행:

```bash
exposure-lens collect \
  --config config.toml \
  --company example
```

`--company`에는 설정의 `company_id`를 입력한다. 여러 기업은 그룹 단위로 순차 실행한다.

```bash
exposure-lens collect \
  --config config.toml \
  --group pilot
```

결과는 `output/YYYYMMDD/`에 저장된다. `_raw.jsonl`에는 공개 색인에서 발견한 URL 원문을 보존하고, `_candidates.jsonl`에는 HTTP/HTTPS, `www`, 쿼리 변형을 통합한 대표 URL과 우선순위를 기록한다. 
뉴스·보도자료·사진 등 낮은 우선순위는 원본에만 남기고 분석 후보에서는 제외한다.

`summary.md`에는 실행 대상, 수집 방식, 출처, `site:` 검색 쿼리와 오류가 함께 기록된다. 
출력 상위 경로는 `--output`으로 변경할 수 있으며, 모든 활성 기업은`--all-enabled`로 선택할 수 있다.

수집기는 대상 기업 웹사이트에 직접 요청하지 않는다. URL은 쿼리 문자열을 마스킹하지 않고 저장하므로 결과 파일에 비밀정보가 포함될 수 있다. 결과를 외부에 공유하거나 버전 관리에 포함하지 않는다.

`PASSIVE`는 수집 방식이지 트랙 이름이 아니다. 
공개 색인에서 발견했더라도 기업이 직접 공개한 자산이면 `track`은 `DIRECT`이며 후보 ID는 `DIR_`로 시작한다.

## 설정 원칙

- `allowed_domains`: 해당 기업의 소유 관계가 검증된 공식 도메인
- `fetch_domains`: 향후 승인된 직접 수집에서만 사용할 요청 허용 도메인
- `seed_urls`: 공식 도메인에서 확인된 기본 URL 후보
- `ownership_evidence_urls`: 도메인 소유 관계를 사람이 검증한 근거
- `official_repositories`: 기업 소유가 확인된 GitHub·GitLab 저장소
- `security_contact`: 발견 시 연락할 공식 보안 채널
- `indicator`: 후보 레코드에 기록할 기업 식별자
- `company_code`: 후보 ID에 사용할 2~12자의 영문 대문자·숫자 코드
- `groups`: 여러 기업을 순차 실행할 때 사용할 그룹 이름

외부 CDN이나 저장소는 기업과의 소유·연결 관계가 검증된 경우에만 공식 자산으로 분류한다.

## 출력 예시

```json
{
  "candidate_id":"DIR_EXAMPLE_20260827_000001",
  "track":"DIRECT",
  "company_name":"예시기업",
  "source_platform":"common_crawl",
  "source_url":"https://index.commoncrawl.org/...",
  "target_platform":"company_web",
  "target_url":"https://example.com/openapi.json",
  "discovery_method":"common_crawl",
  "matched_indicator":"예시기업 공식 도메인",
  "discovered_at":"2026-08-27T15:30:00+09:00",
  "content_hint":"json"
}
```

`source_url`은 후보를 제공한 공개 색인이고 `target_url`은 기업 자산 후보이다.
실제 노출 여부나 현재 접근 가능 여부는 검증하지 않는다.

## 현재 MVP의 한계

- 검색엔진 결과를 자동으로 가져오지 않고 `site:` 쿼리만 생성
- 공개 색인에 포함되지 않은 최신·비색인 URL은 발견할 수 없음
- HTTP/HTTPS, `www`, 쿼리 변형에 대한 의미 기반 중복 제거는 아직 없음
- Wayback 후보는 과거 기록이며 현재 자산임을 보장하지 않음
- 자산 소유 관계는 자동 판정하지 않음
- 민감성 및 공개 의도는 자동 판정하지 않음

## 트랙 확장

- `DIRECT`: 기업이 직접 공개한 공식 도메인·저장소 자산
- `REDISTRIBUTION`: 팀원이 별도 수집기로 구현할 재배포·유통 자산

두 트랙은 설정과 공통 후보 모델을 공유하되 수집기와 출력은 분리한다. 
URL 수집과 후속 민감정보 분석도 별도 단계로 유지한다.