# PCAP 프로그래밍 미션 수행 기록

현재 상태: 개선 완료 — 설명 개선, 출력 요약, 통계 3종, 두 번째 실제 PCAP 비교, 학습 내용 정리, 소스 묶음 제거 및 블로그 검증 완료.

## 목표와 경로

- 목표: PCAP 순차 읽기, Ethernet/IP/TCP/UDP/ICMP 헤더 분석, IP·포트·프로토콜 출력, 패킷 수 및 프로토콜 통계, 통신 해석, 분석 보고서·블로그 글 작성.
- 실습 코드: `/home/wnsgur/seKUrity/pcap-analyzer` (사용자 확정).
- 블로그 글: `/home/wnsgur/Dev/tls456.github.io/_posts/2026-09-20-pcap-analyzer.md` (사용자 확정).
- 이미지 폴더: `/home/wnsgur/Dev/tls456.github.io/assets/images/pcap-analyzer/`.
- 원본 PCAP은 게시하지 않음. 사용자 답변으로 로컬 IP·MAC 공개 가능 확정.
- 이 파일은 작업용 기록이며 블로그 `docs/blog-missions/pcap-analyzer.md`에 동기화한다.

## 사용자 결정

### D-01 구현 방식

| 후보 | 장점 | 단점 |
| --- | --- | --- |
| C + libpcap | 바이트 위치와 헤더 구조를 직접 다루며 학습 가능 | 길이 검사·바이트 순서 직접 구현 |
| Python + dpkt | 파일 순차 읽기와 계층별 헤더·통계 구현이 간결 | 라이브러리가 헤더 해석 일부 담당 |
| Python + scapy | 패킷 조회·생성이 편리 | 자동 해석에서 내부 구조가 가려질 수 있음 |

선택: C + libpcap.
사용자 이유 원문: “학습 목적의 프로그램이기 때문에 최대한 많은 부분을 코드로 직접 확인하고 싶다.”
본문 요약: 패킷 구조를 코드로 직접 확인하는 학습 목적을 우선하여 C + libpcap을 선택하였다.
Codex는 dpkt를 추천했으나 사용자 선택은 C이며 추천을 채택 이유로 사용하지 않는다.
본문의 구현 방식 비교와 선택 절에 반영 완료. 미채택 방식의 성능 비교 실험은 하지 않았다.

### D-02 PCAP 출처 및 캡처 환경

초기 후보: 기존 파일 사용 / 실제 통신 발생 후 캡처 / 통제된 실습 PCAP 생성.
사용자는 준비된 파일이 없고 실습용 PCAP을 원하지 않으므로 직접 실제 트래픽을 캡처하기로 했다.

| 후보 | 장점 | 단점 |
| --- | --- | --- |
| A: WSL eth0 외부 HTTP·DNS·ping | 실제 외부 통신과 Ethernet 관찰 | 인터넷 응답 여부에 영향 |
| B: 로컬 컨테이너 간 HTTP·UDP·ping | 재현 용이 | 별도 컨테이너 구성 필요 |

선택: A.
사용자 이유 원문: “통제된 실습 환경이 아닌 실제 PCAP을 분석하고 싶어서”.
본문 요약: 통제된 실습 환경이 아닌 실제 외부 통신을 분석하기 위해 WSL eth0 캡처를 선택하였다.
PCAP을 합성하거나 다운로드하지 않는다. 캡처 중 실제 일반 네트워크 요청을 보낸다.

## 환경과 사전 점검 (2026-09-20, Asia/Seoul)

- WSL Ubuntu 26.04 LTS, 커널 `6.18.33.2-microsoft-standard-WSL2`.
- GCC `15.2.0`, Python `3.14.4`.
- `libpcap.so.1.10.6` 존재. 개발 헤더·tcpdump·pkg-config는 초기 점검 시 없음.
- 블로그 `git status --short`: `?? docs/`. 기존 사용자 파일을 변경하지 않음.
- 블로그 부모 경로 및 실습 작업 경로에서 적용 AGENTS.md를 발견하지 못함.
- 네트워크 조회가 샌드박스에서 `Cannot open netlink socket: Operation not permitted`로 실패.
- 승인된 샌드박스 외부 `ip -brief address`로 eth0 UP 확인. 로컬 주소 원문은 이 공개 가능 기록에 복사하지 않음.
- `sudo -n true`는 `sudo: interactive authentication is required`, 종료 코드 1.
- 사용자에게 WSL 터미널에서 `sudo apt-get update` 및 `sudo apt-get install -y libpcap-dev tcpdump`를 실행하도록 안내. 설치 완료는 아직 확인하지 않음.
- 블로그 하네스 전체, 지정된 Golang/EDR/CodeQL 예시, `.editorconfig`, `_config.yml` 확인. docs 제외 및 Asia/Seoul 설정 확인.

## 단계 기록

### S-01 사전 조사 및 구조 설계

시각: 2026-09-20 21:08~21:16 +0900 (작업 중).
환경: WSL, 실습 코드 경로.
수행: 환경 조회, 공식 문서 조회, C 소스와 Makefile 작성.
관찰: 의존성 부족으로 아직 빌드·실제 분석을 수행하지 않음.

- `src/main.c`: 전역 PCAP 헤더 24바이트 직접 확인, libpcap 순차 레코드 읽기, Ethernet/VLAN/IPv4/TCP/UDP/ICMP 직접 해석.
- 가변 헤더 길이·caplen 경계 검사, IP 단편 해석 생략, 프로토콜별 상호 배타적 카운터와 별도 오류 속성.
- `Makefile`: 일반 빌드 및 AddressSanitizer/UndefinedBehaviorSanitizer 빌드.
- `capture-real.sh`: eth0에서 외부 TCP/UDP/ICMP 실제 통신을 30초간 캡처하는 스크립트. 아직 실행하지 않음.
- `README.md`: 실행 명령·필드·통계 정의·지원 범위.
- 원본 PCAP/결과는 gitignore로 제외. 통신 원본은 아직 없음.

다음 단계: 설치 확인 → 컴파일 및 정적 검사 → 사용자 인증을 통한 캡처 → C 분석기와 tcpdump 대조 → 통신 해석 → 증빙 이미지 확인 → 보고서·본문 작성.

## 참고 자료

확인 날짜: 2026-09-20.

- RFC 791: https://www.rfc-editor.org/rfc/rfc791 — IPv4 헤더 구조, IHL, fragmentation.
- RFC 9293: https://www.rfc-editor.org/rfc/rfc9293 — TCP 헤더와 flags.
- RFC 768: https://www.rfc-editor.org/rfc/rfc768 — UDP 헤더.
- RFC 792: https://www.rfc-editor.org/rfc/rfc792 — ICMP type/code 및 Echo.
- libpcap `pcap_next_ex` 공식 저장소: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap_next_ex.3pcap — 순차 레코드 읽기 API 확인.
- tcpdump.org manpage 웹 접근은 robots 제한으로 실패. 읽은 자료로 취급하지 않음.
- raw.githubusercontent.com의 추정 태그 경로 접근은 실패. 읽은 자료로 취급하지 않음.

## 완료 조건별 상태 (사전 점검 시점의 기록)

| 조건 | 검증 방법 | 현재 상태 |
| --- | --- | --- |
| 실제 PCAP 확보 | tcpdump 캡처 로그·필터·시각·SHA-256 | 미충족 |
| 순차 읽기와 헤더 출력 | 실제 캡처 실행·tcpdump 대조 | 미확인 |
| TCP/UDP/ICMP 통계 | 독립 tcpdump 필터별 개수 대조 | 미확인 |
| 통신 해석 | 요청 로그·패킷 flags/주소/포트/ICMP 대조 | 미충족 |
| 분석 결과 보고서 | 검증된 결과와 한계 기록 | 미충족 |
| 블로그 글과 증빙 | 본문 작성·스크린샷 시각 검토·렌더링 검증 | 미충족 |

## 대기 사항

- 대기 사항 없음. 로컬 산출물 완료.
- S-01(패킷별 헤더), S-02(최종 통계와 tcpdump 대조 결과) 모두 적합 판정.
- 실제 캡처는 종료됨. 추가로 유지해야 하는 외부 자원 없음.

## S-02 실제 캡처 및 검증 (2026-09-20 21:20~21:30 +0900)

실행 환경과 작업 디렉터리: 위 WSL, `/home/wnsgur/seKUrity/pcap-analyzer`.

사용자 보고: “캡쳐 완료”. 이에 의존하여 성공으로 단정하지 않고 실제 파일·로그를 확인했다.

- 입력: `captures/real-20260920-212040-SwqNBO/traffic.pcap`, 1,070바이트.
- SHA-256: `8adb7657a7678f9793da481ae68bb254fa09d8b8c7832b8dfaa54eec9d8cf41c`; `sha256sum -c` 통과.
- 캡처: 21:20:40~21:21:10 +0900, eth0/EN10MB, 10 captured, 10 received by filter, 0 dropped by kernel.
- 설치 확인: 개발 헤더 존재, tcpdump 4.99.6 / libpcap 1.10.6.
- `make all sanitize`: 초기 sanitizer 빌드에서 `file16()` 삼항식 정수 승격 경고. 명시적 if 분기로 수정하여 재빌드, 경고 없음.
- 일반 분석: 종료 코드 0, 정상 EOF, TCP 2 / UDP 1 / ICMP 7, 캡처 바이트 886, malformed/truncated/fragments 모두 0.
- sanitizer 첫 실행: ptrace 환경에서 LeakSanitizer fatal error. 샌드박스 외부 실행 승인 후 동일 파일 재검증, 종료 코드 0, 진단 없음.
- `cmp results/analysis.txt results/analysis-asan.txt`: 동일.
- tcpdump BPF `ip proto 6`, `ip proto 17`, `ip proto 1` 별도 읽기: 2 / 1 / 7로 C와 일치. 전체 10개 레코드의 시각·순서도 일치.
- `gcc ... -fanalyzer -c src/main.c -o build/main-analyzer.o`: 진단 없음.
- 인자 없음·존재하지 않는 파일·빈 입력은 각각 종료 코드 1로 거부.
- `--hex` 실제 입력 실행: `results/analysis-hex.txt` 생성, 첫 TCP 패킷의 IHL 20 / TCP data offset 40과 바이트 배치를 확인.
- 산출물: `docs/analysis-report.md`, `results/analysis.txt`, `results/analysis-asan.txt`, `results/tcpdump.txt`, `results/verification.json`.

관찰한 통신:

1. TCP SYN → RST/ACK. HTTP 메시지 전송 전 연결 거절. curl exit 7과 일치.
2. UDP DNS A 질의 → ICMP type 3/code 3. tcpdump 인용 데이터그램의 IP ID·포트가 원래 질의와 일치. DNS 클라이언트 ConnectionRefusedError와 일치.
3. ICMP Echo Request/Reply 세 쌍. ping 3 transmitted / 3 received와 일치.

추론의 한계: 응답의 실제 생성 주체·차단 장비는 미확인. 송신 checksum 불일치의 오프로딩 원인은 미확인. TCP handshake·HTTP·DNS 성공을 주장하지 않음.
실제 파일에 없는 VLAN·단편·손상 패킷 분기는 동작 검증하지 않았음.

## D-03 게시 정보 및 D-04 공개 범위

- 제안한 게시 정보: 제목 ‘C와 libpcap으로 실제 네트워크 패킷 분석하기’, slug PCAP-Programming, 2026-09-20 21:20:00 +0900, categories [개발], tags [C, libpcap, PCAP, Network].
- 초기 답변: “게시 정보를 직접 지정”. 위 제안값은 채택되지 않았다.
- 확정 제목: `pcap 파일 분석기 개발`.
- 확정 파일명: `2026-09-20-pcap-analyzer.md`; slug: `pcap-analyzer`.
- 확정 게시 일시: `2026-09-20 21:41:00 +0900`.
- 확정 categories: `[개발]`.
- 확정 tags: `[pcap, network, C, IP, 패킷]`.
- 해당 게시글 경로에 기존 파일이 없음을 확인한 뒤 새 본문을 작성하였다.
- 공개 범위 사용자 답변: “로컬 IP·MAC도 공개 가능, 원본 PCAP은 게시하지 않음”.
- 원본 PCAP·전체 로컬 로그를 블로그 자산으로 복사하지 않음.

## 추가 문서·블로그 준비 확인

- 설치된 `pcap-savefile(5)`, `pcap_next_ex(3PCAP)`, `pcap_open_offline(3PCAP)` 매뉴얼 원문 확인.
- PCAP 24바이트 전역 헤더, 16바이트 레코드 헤더, magic/byte order/time resolution 및 EOF 반환값을 확인.
- 블로그 `bundle check`: 샌드박스 쓰기 제한으로 최초 실패, 승인된 외부 재실행에서 dependencies satisfied.
- 재실행 후 `git status --short`는 `?? docs/`만 표시. Gemfile.lock 등 기존 추적 파일 변경 없음.
- `tools/test.sh`는 `_site` 삭제를 포함하므로 실행하지 않음. 본문 작성 후 임시 출력 경로에 Jekyll 빌드 예정.

## 갱신된 완료 조건

| 조건 | 실제 근거 | 상태 |
| --- | --- | --- |
| 실제 PCAP 확보 | 원본·SHA-256·캡처 로그 | 충족 |
| 순차 읽기와 헤더 출력 | C 출력·tcpdump 시각/필드 대조 | 충족 |
| TCP/UDP/ICMP 통계 | C와 별도 BPF 카운트 2/1/7 일치 | 충족 |
| 통신 해석 | SYN/RST·UDP/ICMP 오류·Echo 세 쌍 및 클라이언트 로그 | 충족 |
| 분석 결과 보고서 | docs/analysis-report.md | 충족 |
| 블로그 글과 증빙 | 확정 정보·채택 이미지·본문·Jekyll/HTML-Proofer 검사 | 충족 |

최종 상태: 모든 미션 및 로컬 글 작성 완료 조건 충족. 느낀 점은 제목만 남김.

## S-03 스크린샷 검토

- 사용자 제출 원본 2장을 view_image로 직접 열어 확인. 첫 이미지 1125×604, 두 번째 759×465.
- S-01: PCAP 형식, 패킷 1~4의 Ethernet/IPv4/TCP/UDP/ICMP 필드, SYN 및 RST/ACK, ICMP type 3/code 3이 판독 가능. 긴 줄은 줄바꿈되지만 필수 정보 누락 없음. results/analysis.txt와 일치. 적합.
- S-02: SUMMARY 10/886, TCP 2/UDP 1/ICMP 7, malformed/truncated/fragments 0, verification.json의 개수·시각·sanitizer 출력 일치가 판독 가능. 적합.
- 로컬 IP·MAC은 사용자 공개 허용 범위. 이미지에 비밀번호·토큰·쿠키·알림 없음.
- 채택 경로: assets/images/pcap-analyzer/01-packet-headers.png, 02-statistics-verification.png.
- 원본 이미지 바이트를 그대로 복사할 것. 원본 PCAP은 블로그에 복사하지 않음.
- 모든 미션 완료 조건과 필수 증빙 확인 후 본문 작성 시작.

## S-04 본문 작성·비판적 검토·최종 검증 (2026-09-20 21:50~22:01 +0900)

### 최종 산출물

- 글: `_posts/2026-09-20-pcap-analyzer.md`. 확정 제목·시각·categories·tags와 일치.
- 이미지: `assets/images/pcap-analyzer/01-packet-headers.png`, `02-statistics-verification.png`.
- 이미지 복사 후 다시 view_image로 직접 확인하고 원본 바이트 일치도 확인.
- 이미지 SHA-256: 01=`2a3e916663c6e8a1b4021b47382aeb1426b7d57fa136e87557d7b6681921278d`, 02=`58d76006086350644c6d0a238f136674c886de99f9d1ddf5768e3bd5de737a15`.
- 코드: 실습 프로젝트 `src/main.c`, `Makefile`, `capture-real.sh`.
- 분석 보고서: 실습 프로젝트 `docs/analysis-report.md`; 핵심 결과를 블로그 본문에 반영.
- 재현용 소스 묶음: 블로그 `assets/code/pcap-analyzer-source.zip`. C 소스·Makefile·캡처 스크립트·README·분석 보고서 등 8개 파일. 원본 PCAP·실행 파일·전체 로그 제외.
- ZIP 무결성 검사 및 핵심 3개 파일의 검증된 로컬 소스와 바이트 일치 확인.

### 독자 관점 검토와 수정

1. 발췌 코드만으로 실행 파일을 재현하기 어렵다는 점 발견 → 전체 소스 ZIP과 다운로드 링크 추가. README에서 묶음에 없는 수행 기록 참조는 분석 보고서 참조로 바꿈.
2. IP 헤더 길이와 TCP 헤더 길이가 혼동되지 않도록 ihl=20/header=40을 구분하여 설명.
3. DNS 해석은 C 구현 기능이 아니므로 tcpdump/클라이언트 로그로 확인했다고 명시.
4. ICMP 인용 UDP의 중복 집계 방지 기준과 TCP 데이터 0에 따른 HTTP 미교환을 명시.
5. checksum 불일치를 패킷 손상으로 단정하지 않음. 원인 미확인 및 검사 기능 부재를 별도로 기술.
6. 후보 비교와 사용자 채택 이유를 D-01/D-02 기록과 대조하여 본문 반영 확인.
7. 실제 캡처에 없는 VLAN·단편·손상 헤더 분기는 미검증이라고 기술.
8. 마지막 `## 느낀 점` 뒤에는 내용·주석·안내 없음.

### 실행한 검증

작업 위치: `/home/wnsgur/Dev/tls456.github.io`.

```bash
BUNDLE_FROZEN=true JEKYLL_ENV=production bundle exec jekyll build --destination /tmp/pcap-blog-20260920 --disable-disk-cache --strict_front_matter
BUNDLE_FROZEN=true bundle exec htmlproofer /tmp/pcap-blog-20260920 --disable-external
```

HTML-Proofer 실제 실행에는 기존 test.sh의 localhost/127.0.0.1/0.0.0.0 무시 패턴을 적용하였다. 외부 링크 검사는 껐으며 RFC/libpcap 자료는 앞선 조사에서 확인한 내용을 사용했다.

- Jekyll 빌드 성공. 소스 다운로드 추가 후 최종 빌드도 성공. 기존 `_site` 대신 `/tmp` 출력 사용.
- HTML-Proofer Images/Links/Scripts 검사 성공. 최종 82개 HTML 파일, 내부 링크 451개 및 39개 파일의 fragment 검사.
- front matter를 Ruby YAML로 파싱하여 제목·게시 시각·categories·tags를 정확히 대조.
- Nokogiri로 생성 HTML의 본문 h2 순서(개요/사전 조사/실제 구현/느낀 점), 두 이미지의 alt/파일 존재, 섹션 anchor, 코드·표·hard break 확인.
- 마지막 소스 다운로드 링크 및 빌드 출력 ZIP 바이트 일치 확인.
- Markdown의 모든 인접 h2 사이 구분선, 닫힌 코드 펜스, 본문 h1 부재, 공백 두 개 줄바꿈, 빈 느낀 점 확인.
- 브라우저 도구 및 설치된 Playwright/Chromium을 찾지 못하여 브라우저 화면 전체의 시각 검증은 하지 못함. 생성 HTML 구조와 원본·복사 이미지의 직접 시각 검토로 검증.
- Git 추적 파일 변경 없음. 새 글·전용 이미지·소스 ZIP·수행 기록만 추가. 기존 docs 사용자 파일 보존.
- 커밋·푸시·원격 발행은 실행하지 않음.

## 개선 요청 R-01

사용자 요청: 초반 설명 직관화, 출력 기능 통합 요약, TCP Flag 통계, Top Talkers, 목적지 포트 통계, 더 큰 두 번째 실제 PCAP, 객관적 학습 내용 정리, 불필요한 설명 축약.

- 최신 블로그 파일을 먼저 확인하고 `results/revision-2/post-before.md`에 보존. 이전 대화 이후 사용자가 표·구분선 정리, 소스 다운로드 안내 및 느낀 점 제목 삭제를 수행한 상태. 삭제한 내용을 임의로 복원하지 않음.
- 기존 C+libpcap / WSL eth0 실제 캡처 / 원본 PCAP 비공개 방침 유지.
- 추가 통계 정의: TCP flags 비트별 독립 집계. Top Talkers는 유효한 IPv4 헤더의 출발지별 패킷 수 상위 5개, 동률은 IP 오름차순, 바이트는 IPv4 Total Length 합계. 목적지 포트는 해석 가능한 TCP/UDP 헤더를 프로토콜별로 집계하고 응답의 임시 포트도 포함.
- `src/main.c`에 통계 추가, `verify-stats.py`에서 tcpdump 출력 및 BPF로 독립 대조.
- 첫 실제 PCAP: flags SYN=1/RST=1/ACK=1, Top Talkers 두 IP 각각 5개, IPv4 bytes 377/369, TCP 80 및 45262 각각 1개, UDP 53 1개. 모든 값 tcpdump와 일치.
- `make all sanitize`, 승인된 외부 ASan/UBSan/LSan 실행, GCC -fanalyzer 통과. 일반·sanitizer 출력 일치.
- 두 번째 원본 파일은 아직 없음. `capture-more.sh` 작성 및 Bash 문법 검사 통과. 90초 eth0 캡처, example.com/www.iana.org HTTPS 각 3회, 공개 DNS 두 곳 질의 각 3회, ping 각 20회. 캡처 필터는 이 대상 IPv4 주소 및 TCP443/UDP53/ICMP로 제한. 실제 수신 여부는 결과로 판정 예정.
- `sudo -n true`: 샌드박스 제한 후 승인된 외부 확인에서도 대화형 인증 필요. 사용자에게 WSL 터미널에서 `bash capture-more.sh` 실행 안내.
- 두 번째 파일을 기존 패킷 복제·합성으로 대체하지 않음. 새 통계와 실제 두 번째 결과의 증빙은 수령 후 확인.

- 기존 본문을 기준으로 수정본 `publish/revised-post.md` 작성: 도입을 ping/웹 연결의 차이로 설명, 최종 출력 표 통합, 중복 구현·검증 설명 축약, 첫 PCAP 새 통계 반영, 마지막에 객관적 학습 원리 3개 정리. 기존 부분은 13,975자에서 11,320자로 약 19% 축약. 두 번째 PCAP 결과는 아직 작성하지 않음.
- 원본 블로그 글 및 배포용 소스 ZIP은 두 번째 실제 결과 확인 전까지 이전 검증 버전 유지. 최종 수정본에 대기 문구나 가상 결과를 넣지 않을 것.
- 다음 단계: 사용자가 capture-more.sh 실행 → 실제 원본과 로그 확인 → 통계 독립 대조·메모리 검사 → 새 출력 증빙 확인 → 두 번째 분석을 본문/보고서에 반영 → 소스 ZIP 갱신·Jekyll/링크 검사.

## R-02 두 번째 캡처 확인 및 소스 묶음 제거

- 사용자 실행 완료 보고 후 실제 `captures/larger-20260920-234145-JWptnA/traffic.pcap` 확인. 2026-09-20 23:41:45~23:43:15 +0900, 90초 eth0, 225개, 87,190바이트.
- SHA-256 `053726220b2589b3c5f804904afde14a194c493aab7206ae770e7cb83324ab60` 대조 통과. 캡처 드롭 0.
- TCP133 / UDP9 / ICMP83, caplen 합계 83,566. malformed/truncated/fragments 0.
- Flag: SYN12 FIN12 RST0 PSH52 ACK127, 기타0. 실제 TCP 6개 흐름에서 최초 3개 flags가 SYN/SYN|ACK/ACK, 각 FIN2개 확인.
- Top Talkers: 로컬 IP118개, IANA 대상 IP34개, example.com 대상 IP27개, DNS 대상2개 각23개. 패킷 수와 IP bytes 순위가 다른 점을 기록.
- 목적지 포트: TCP443=72, 응답 TCP 임시 포트 총61, UDP53=6, 응답 UDP임시포트 총3.
- HTTPS 요청6회 모두 curl exit0/HTTP200(클라이언트 로그 근거). DNS 8.8.8.8 성공3회, 1.1.1.1 오류3회. ping두 대상 각각20회 성공.
- `verify-stats.py`가 모든 새 통계·기본통계·시각·순서를 tcpdump로 대조하여 PASS. sanitizer 외부 실행 종료0/진단없음. 일반출력과 cmp 일치.
- `docs/analysis-report.md`에 두 번째 결과 반영. `publish/revised-post.md`에 비교 분석과 핵심 원리를 반영한 수정본 준비. 13,975자 → 12,616자로 약9.7% 축약(추가 분석 포함).
- 추가 증빙 요청 예정: `cat results/revision-2/second-summary.txt`의 225개 통계, Flag, Top Talkers, 목적지 포트가 보이는 화면. 기존 스크린샷은 최초10개 기본통계의 증거이며 새기능의 검증 화면으로 혼용하지 않음.

사용자 최신 지시: 소스 묶음을 제공하지 않으려는 의도로 묶음과 관련 문구를 삭제했음을 명시.
- 블로그 assets/code/pcap-analyzer-source.zip과 실습 publish/pcap-analyzer-source.zip 삭제 완료. 이전의 ZIP 제공 방침은 철회됨.
- 현재 블로그에 소스 다운로드 문구 없음 확인. 예전 로컬 게시글 준비본에 남은 소스 다운로드 문구도 제거.
- 소스 ZIP을 다시 생성하거나 링크하지 않을 것. C 소스와 실습 파일은 사용자 로컬 프로젝트에 유지.

## R-03 확장 통계 증빙 검토

- 사용자 제출 스크린샷 2026-09-20 234808.png를 view_image로 직접 검토.
- 전체225/TCP133/UDP9/ICMP83, caplen83,566, Flag8종, Top Talkers5개, 목적지 포트11개가 모두 판독 가능하고 second-summary.txt와 일치.
- 마지막 프롬프트 일부가 화면 아래에 있으나 마지막 UDP56896=1까지 출력은 완전하므로 증빙 정보 손실 없음.
- 원본 PCAP 노출 없음. 공개 허용된 로컬 IP와 외부 대상 주소 외 비밀번호·토큰·알림 없음. 적합 판정.
- 채택 경로: assets/images/pcap-analyzer/03-extended-statistics.png.
- 기존02이미지 설명을 첫PCAP의 기본통계로 명시, 새기능 증거는03이미지로 구분.
- 수정 대상 원본을 post-before.md와 cmp하여 추가 사용자 편집이 없음을 확인한 뒤 적용 준비.

## R-04 최종 개선 반영 및 검사

- 블로그 `_posts/2026-09-20-pcap-analyzer.md` 갱신. 기존 사용자 삭제 사항(소스 제공 문구·느낀 점 제목)을 복원하지 않음. 끝에는 객관적인 `### 이번 분석으로 배운 점` 3항목 배치.
- 도입 직관화, 출력 표 통합, 구현·검증 반복 축약, 통계 집계 기준과 10개/225개 실제 캡처 비교 반영.
- 원문13,975자 → 최종13,004자(새 분석·명령·이미지 설명 포함), 약7% 축약. 중간19%는 두 번째 분석 추가 전 기준.
- 새 이미지 원본·복사본 바이트 일치 및 직접 시각검토 완료. SHA-256 `f770500c8151f2a9cc213aa73b3589d65263fdb0a2ef420972210ecf19d3d42a`.
- Jekyll production 빌드 성공. 임시 출력 `/tmp/pcap-blog-20260920` 사용.
- HTML-Proofer Images/Links/Scripts 검사 통과: HTML82개, 내부링크453개, fragment 대상39개. 외부 링크 검사 비활성화.
- Ruby YAML/Nokogiri로 확정 메타데이터, h2/h3 구조, 이미지3개 파일·alt, 추가통계, 소스ZIP 링크 및 빌드출력 ZIP 부재 확인.
- Markdown 코드펜스·h2 구분선·본문 h1 부재·placeholder 부재·이미지 참조 검사 통과.
- 원본 PCAP 두 개는 로컬 실습 프로젝트에만 유지. 소스 ZIP 두 사본 삭제 완료, 재생성하지 않음.
- 브라우저 시각검증 도구 부재로 전체 페이지 화면 검토는 미실시. 생성 HTML과 실제 이미지로 검증.
- 코드와 두 PCAP의 통계 대조·메모리 검사는 R-01/R-02 결과 유지. 이번 턴은 문서/이미지만 변경.
- 최종 기록 갱신 Python의 변수 초기화 누락(NameError)로 첫 갱신 실패. 파일은 그 실행에서 변경되지 않았으며 초기화 후 재실행하여 수정함.
- 요청한 개선 범위 완료. 추가 입력 대기 없음. 커밋·푸시·원격발행 없음.
