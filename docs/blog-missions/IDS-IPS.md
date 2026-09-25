# IDS/IPS 학습 및 블로그 작성

- 미션 목표: IDS/IPS의 동작 원리, 유형, 활용 방법, 장단점과 차이점 학습 및 글 작성.
- 범위: 공식 문서 조사와 개념 비교. 장비 구축·공격 재현·성능 실험·배포는 포함하지 않음.
- 현재 상태: 완료
- 글: `_drafts/IDS-IPS.md`
- 하네스: `docs/BLOG_MISSION_HARNESS.md`
- 수행 기록: `docs/blog-missions/IDS-IPS.md`
- 실습 코드·이미지 폴더: 없음. 문헌 학습이므로 실행 증빙 스크린샷이 필요하지 않으며 설명용 text 도식 사용.

## 사용자 지시

- 2026-09-22: “Front matter 부분은 항상 내가 작성하도록 하네스 수정해주고, 이번에도 비워서 작성해줘”
- 적용: 새 글에는 빈 YAML 구분선만 유지. 기존 글의 사용자 메타데이터 보존. 게시 정보 확인 질문 제거.
- 날짜를 임의 생성하지 않도록 날짜 없는 `_drafts/IDS-IPS.md` 사용.
- 구현 선택 없음: 학습·정리 미션이므로 도구 설치나 배포 대안을 가상으로 만들지 않음.
- 느낀 점은 하네스에 따라 제목만 유지.

## 환경 및 수행

- 확인일: 2026-09-22, Asia/Seoul.
- 블로그 작업 디렉터리: `/home/wnsgur/Dev/tls456.github.io`.
- Ubuntu 26.04 LTS, WSL2 커널 `6.18.33.2-microsoft-standard-WSL2`.
- Ruby 3.3.8, Bundler 2.6.7.
- 시작 Git 상태: 변경 없음. 적용할 AGENTS.md는 조사한 상위 경로와 저장소에서 발견되지 않음.
- `_config.yml`, `.editorconfig`, 기존 EDR·Golang·CodeQL 글의 형식과 빌드 스크립트 확인.
- `bundle check`: 최초 실행은 저장소가 쓰기 허용 범위 밖이어서 Gemfile.lock 쓰기 시도 차단. 권한 요청 후 재실행 성공, 의존성 충족. Git 추적 파일 변경 없음 확인.
- 임시 작업 경로: `/tmp/ids-ips-mission`. 저장소 수정 전 하네스 diff와 글 구조 검토.
- 하네스 변경 범위: 실행 원칙, 입력 항목, 저장 경로, 기본 골격, 제목 규칙, 검증·완료 조건. front matter를 질문하거나 자동 작성하는 상충 지침 제거.

## 자료 조사와 완료 조건

2026-09-22에 다음 페이지를 열어 확인하였다.

| 자료 | 확인 내용 |
| --- | --- |
| [NIST SP 800-94 소개](https://csrc.nist.gov/pubs/sp/800/94/final) 및 [원문](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-94.pdf) | 정의, 관찰 대상 분류, 상태 기반 프로토콜 분석. 2007년 문서라는 한계 명시 |
| [IBM IDS 설명](https://www.ibm.com/think/topics/intrusion-detection-system) | 시그니처·이상 탐지, 오탐·미탐 |
| [Suricata 8.0.1 IPS 개념](https://docs.suricata.io/en/suricata-8.0.1/ips/ips-concept.html) | 인라인, 기본 정책과 예외 정책, 스트림 처리 |
| [규칙 형식](https://docs.suricata.io/en/suricata-8.0.1/rules/intro.html) | 규칙 구성, alert/drop/reject/pass, 정규화 |
| [패킷 수집](https://docs.suricata.io/en/suricata-8.0.1/performance/packet-capture.html) | 양방향 흐름, 순서, 큐 처리 |
| [EVE JSON 출력](https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-output.html) | 경고·drop 기록과 최종 verdict 구분 |
| [Suricata 설정](https://docs.suricata.io/en/suricata-8.0.1/configuration/suricata-yaml.html) | 암호화 처리와 검사 제한 |
| [Cisco AIP-SSM 설명](https://community.cisco.com/t5/security-knowledge-base/aip-ssm-bypass-mode-vs-fail-open-fail-closed/ta-p/3122399) | 모듈 장애와 센서 앱 장애 정책의 차이. 특정 제품 사례로만 사용 |

- 원리·유형·활용·장단점·차이점: 위 문서와 대조하여 학습 완료 후 본문 작성.
- 접근하지 못한 일부 Cisco·Fortinet 소개 페이지, Suricata 예외 정책 추정 경로는 근거로 사용하지 않음.
- 문헌 사실, 가상 예시, 운영 제안을 본문에서 구분. 실제 실습 결과를 만들지 않음.

## 검토

- 수동 IDS와 인라인 IPS 비교를 네트워크 방식으로 한정하여 호스트 제품에 대한 일반화 방지.
- alert와 차단의 혼동, IPS의 소급 차단, full 설정을 복호화로 해석하는 오류 방지.
- 빈 front matter, 비어 있는 느낀 점, 코드 펜스 짝, H1 없음, 자리표시자·Liquid 구문 없음 확인.
- 307행, 본문 text 도식 3개. 별도 이미지 없음.
- `BUNDLE_FROZEN=true bundle exec jekyll build --drafts --disable-disk-cache --destination /tmp/ids-ips-mission/site`: 종료 코드 0. 기존 `_site`를 수정하지 않고 임시 출력 경로에 빌드.
- `BUNDLE_FROZEN=true bundle exec htmlproofer /tmp/ids-ips-mission/site --disable-external --no-enforce-https`: 종료 코드 0. HTML 83개, 내부 링크 478개, 40개 파일의 내부 앵커 검사 통과. 외부 링크 자동 검사는 실행하지 않음; 인용 자료는 웹 도구로 열어 확인.
- Nokogiri HTML 검사: H2 4개, 표 11개, text 도식 컨테이너 3개, hard break 58개 확인. 최초 검사 스크립트가 표 수를 8개로 잘못 예상하여 실패했으며, 원문을 재확인해 11개로 수정. Rouge가 줄 번호와 본문을 별도 pre로 생성하므로 도식은 language-text 컨테이너로 확인. 글 수정 없이 검사 기준을 바로잡아 통과.
- 브라우저 시각 검사는 수행하지 않음. 생성 HTML의 구조를 검사한 범위만 확인.
- front matter의 YAML 경계, 모든 H2 사이 구분선, 후행 공백 두 개, 빈 느낀 점, 펜스와 본문 검토 완료.
- 최종 변경 범위는 하네스·글·수행 기록 3개 파일. 커밋·푸시·발행 없음.
- 남은 사용자 작성 영역: front matter와 느낀 점. 사용자 직접 작성 지시에 따른 영역이며 미션 완료를 막지 않음.
