# 기업 공식 공개 자산 URL 수집기 (MVP)

검증된 기업 공식 도메인에서 `robots.txt`, `sitemap.xml`, 공개 HTML의 링크를 제한된 깊이로 수집하고 공통 후보 형식의 JSONL로 저장하는 CLI 도구입니다.

이 버전은 **URL 후보 수집만 수행**합니다. 개인정보·비밀키 탐지, 로그인, 폼 제출, 경로 추측, API 키 검증, 스토리지 목록 조회 기능은 포함하지 않습니다.

## 프로젝트 구조

```text
src/exposure_lens/
├── __init__.py      # Python 패키지 정의와 버전
├── __main__.py      # `python -m exposure_lens` 실행 진입점
├── cli.py           # CLI 명령과 옵션 처리
├── config.py        # TOML 설정 로드와 유효성 검사
├── discovery.py     # HTML, sitemap, robots.txt 링크 추출
├── http_client.py   # 요청 제한과 보안 검사가 적용된 HTTP 클라이언트
├── models.py        # 후보 데이터 모델
├── passive.py       # 공개 색인 기반 수동적 URL 후보 수집
├── pipeline.py      # URL 수집 흐름과 JSONL 저장
└── urltools.py      # URL 정규화, 도메인 검사와 유형 판별
```

- `collector_tests/test_collector.py`: 설정, URL 수집과 출력 기능 테스트
- `config.example.toml`: 설정 파일 예시
- `config.toml`: 실제 실행 설정
- `output/YYYYMMDD/`: 날짜별 JSONL 결과와 대상 기업 요약
- `pyproject.toml`: 패키지, 실행 명령과 개발 도구 설정

## 안전장치

- `--company`, `--group`, `--all-enabled` 중 하나로 실행 범위를 명시
- 설정에 `enabled = true`인 기업만 실행
- 검증된 `allowed_domains`만 실제 요청
- 외부 CDN·스토리지 링크는 후보로만 기록하며 `fetch_domains`에 없으면 요청하지 않음
- `GET` 요청만 사용
- 탐색 깊이, 최대 요청 수, 응답 크기, 요청 간격, 재시도 횟수 제한
- 사설 IP, localhost, URL 사용자정보, 비 HTTP(S) 주소 차단
- 쿼리 문자열이 포함된 URL은 기본적으로 실제 요청하지 않고 후보로만 기록
- `robots.txt`의 접근 제한 적용

## 시작하기

Python 3.11 이상이 필요합니다.

```bash
python -m pip install -e .
cp config.example.toml config.toml
```

`config.toml`에서 예시 기업을 실제 조사 기업으로 교체합니다. 도메인과 소유 근거를 직접 검증한 후에만 `enabled = true`로 바꿉니다.

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

`--company`에는 설정의 `company_id`를 입력합니다. 여러 기업은 그룹 단위로 순차 실행합니다.

```bash
exposure-lens collect \
  --config config.toml \
  --group pilot
```

결과는 `output/YYYYMMDD/`에 저장됩니다. 기업별 JSONL에는 CT, 공개 DNS,
Common Crawl, Wayback Machine 및 공식 저장소에서 발견한 URL 후보가 기록됩니다.
`_site_queries.md`에는 수동 또는 허용된 검색 API에서 사용할 `site:` 쿼리가,
`summary.md`에는 실행 대상 기업 목록이 기록됩니다. 출력 상위 경로는 `--output`으로
변경할 수 있으며, 모든 활성 기업은 `--all-enabled`로 선택할 수 있습니다.

수집기는 대상 기업 웹사이트에 직접 요청하지 않습니다. URL은 쿼리 문자열을 마스킹하지
않고 저장하므로 결과 파일에 비밀정보가 포함될 수 있습니다. 결과를 외부에 공유하거나
버전 관리에 포함하지 마세요.

## 설정 원칙

- `allowed_domains`: 해당 기업의 소유 관계가 검증된 공식 도메인
- `fetch_domains`: 실제 HTTP 요청을 허용할 도메인. 보통 `allowed_domains`와 동일하게 시작
- `seed_urls`: 수집 시작점인 공식 홈페이지
- `ownership_evidence_urls`: 도메인 소유 관계를 사람이 검증한 근거
- `security_contact`: 발견 시 연락할 공식 보안 채널
- `indicator`: 후보 레코드에 기록할 기업 식별자
- `company_code`: 후보 ID에 사용할 2~12자의 영문 대문자·숫자 코드
- `groups`: 여러 기업을 순차 실행할 때 사용할 그룹 이름

외부 CDN이나 스토리지를 실제로 요청해야 한다면 소유·연결 관계를 먼저 검토하고 해당 호스트를 `fetch_domains`에 명시적으로 추가합니다. 단순히 공식 페이지에서 링크되었다는 이유만으로 외부 호스트 전체를 허용하지 마세요.

## 출력 예시

```json
{"candidate_id":"DIR_EXAMPLE_20260826_000001","track":"DIRECT","company_name":"예시기업","source_platform":"official_web","source_url":"https://example.com/sitemap.xml","target_platform":"company_web","target_url":"https://example.com/files/guide.pdf","discovery_method":"sitemap","matched_indicator":"예시기업 공식 도메인","discovered_at":"2026-08-26T15:30:00+09:00","content_hint":"pdf"}
```

`source_url`은 대상을 발견한 페이지이고 `target_url`은 실제 후보입니다. 동일한 콘텐츠가 여러 페이지에서 발견되면 콘텐츠 중복 제거 전까지 발견 관계가 각각 남을 수 있습니다.

## 현재 MVP의 한계

- JavaScript 안에 문자열로 들어 있는 URL은 아직 추출하지 않음
- 콘텐츠 해시 중복 제거는 실제로 가져온 응답에만 적용
- 동적 렌더링 페이지는 처리하지 않음
- 자산 소유 관계는 자동 판정하지 않음
- 민감성 및 공개 의도는 자동 판정하지 않음

다음 단계에서는 플랫폼별 어댑터를 추가하되 URL 수집과 민감정보 탐지 모듈을 계속 분리하는 것이 좋습니다.
