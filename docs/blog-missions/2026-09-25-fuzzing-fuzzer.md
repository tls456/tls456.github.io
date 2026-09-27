# Fuzzing과 Fuzzer 개요 수행 기록

- 미션 목표: 퍼징의 개념과 종류를 학습하고 여러 퍼저의 차이를 블로그로 정리한다.
- 대상: `_posts/2026-09-25-fuzzing-fuzzer.md`
- 현재 상태: 완료 — 본문·설명 도식·출처 정리와 최종 빌드·링크 검사 완료.
- 범위: 문헌 학습과 비교 설명. 퍼저 실행·성능 측정은 이번 미션의 수행 결과에 포함하지 않는다.
- 이미지 폴더: `assets/images/fuzzing-fuzzer/`에 직접 작성한 설명용 SVG 도식 3개를 저장했다.
- 실습 코드 경로: 해당 없음.
- 미해결 질문: 없음. 사용자 요청이 개념 학습·도구 비교·작성으로 구체적이며, 추가 내용 작성도 명시적으로 위임되었다.

## 입력과 편집 범위

사용자 지시: “목차에 없는거여도 있으면 좋을 내용이면 추가로 작성해줘”.
기존 `## Fuzzing`, `## Fuzzer`, `## 참고 문헌`의 상대 순서와 모든 기존 하위 제목을 유지한다.
추가 내용 작성 권한으로 개요, 보충 하위 절, 비워 둔 느낀 점을 추가한다.
이는 사용자가 별도로 구현 방식을 선택했다는 뜻이 아니며, 선택 이유를 만들어 쓰지 않는다.

변경 전 front matter 원문:

```yaml
---
title: Fuzzing과 Fuzzer 개요
date: 2026-09-25 23:22:00 +0900
categories: [Bug Bounty]
tags: [Bug Bounty, Fuzzing, Fuzzer]
---
```

기존 목차:

```text
## Fuzzing
### 정의
### 동작 원리
### 종류
## Fuzzer
### 정의
### 종류
### 장단점
#### 장점
#### 단점 및 한계
## 참고 문헌
```

## 완료 조건

| 조건 | 확인 방법 | 현재 상태 |
| --- | --- | --- |
| 퍼징의 정의·동작·분류 설명 | 공식 개념 문서와 대조 | 충족 |
| 여러 퍼저의 특징과 차이 비교 | 7종 도구의 공식 문서·기능 비교 | 충족 |
| 추가 개념과 설명 도식 | 하네스·오라클·계측·커버리지 설명 및 SVG 3개 시각 검토 | 충족 |
| 기존 파일에 본문 작성 | 메타데이터 원문·기존 제목 보존 검사 | 충족 |
| 출처 배치와 문서 검증 | 사용자 링크/직접 조사 자료 구분, 최종 Jekyll 빌드와 내부 링크 66개 검사 | 충족 |

## S-01 사전 확인

- 실행 환경: WSL2 Linux `6.18.33.2-microsoft-standard-WSL2`, Bash, 저장소 루트.
- Ruby `3.3.8`, Bundler `4.0.10` 확인.
- 적용할 `AGENTS.md`는 상위 경로 및 대상 하위 디렉터리에서 발견되지 않았다.
- `git status --short`: 대상 포스트만 미추적 상태이며 본문은 없는 목차 파일이다.
- `docs/BLOG_MISSION_HARNESS.md`, `_config.yml`, `.editorconfig`, 기존 Golang·EDR·CodeQL 게시글을 읽었다.
- Jekyll/Chirpy 사용, 사이트 시간대 `Asia/Seoul`, `docs` 빌드 제외, Markdown 후행 공백 보존을 확인했다.
- 결과: 파일명과 front matter 변경 없이 작성할 수 있다. 커밋·푸시·발행은 수행 범위에 없다.

## S-02 자료 조사

아래 날짜는 문서 확인 날짜이며 퍼저 실행 날짜가 아니다. 확인일: 2026-09-25.

| 제공 주체 | 문서 | 확인 내용 | 목록 배치 |
| --- | --- | --- | --- |
| 사용자 제공 | [AFL++](https://github.com/AFLplusplus/AFLplusplus) | 커버리지 기반 퍼저, 컴파일 계측과 바이너리 대상 문서 구분 | 개요 |
| 사용자 제공 | [Jackalope](https://github.com/googleprojectzero/Jackalope) | TinyInst, 구성 요소 교체, Windows/macOS/Linux/Android 지원 명시 | 개요 |
| 사용자 제공 | [google/fuzzing](https://github.com/google/fuzzing/tree/master) | 퍼저 제품이 아닌 자료 모음, 2025-12-27 보관 처리 표시 | 개요 |
| Codex 직접 조사 | [Introduction to fuzzing](https://github.com/google/fuzzing/blob/master/docs/intro-to-fuzzing.md) | Sanitizer, 퍼징 대상, 차등 검사 | 참고 문헌 |
| Codex 직접 조사 | [Fuzzing glossary](https://github.com/google/fuzzing/blob/master/docs/glossary.md) | Corpus, seed, dictionary, engine, target 용어 | 참고 문헌 |
| Codex 직접 조사 | [What makes a good fuzz target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md) | 결정성, 상태 관리, 작은 대상, seed·회귀 테스트 | 참고 문헌 |

GitHub 본문 및 raw Markdown을 열어 내용을 확인했다. 동일 README의 raw 주소는 별도 출처로 중복 계산하지 않는다.

추가로 열어 확인한 공식 문서(모두 Codex 직접 조사, 2026-09-25, 참고 문헌 배치 완료):

| 문서 | 본문에 사용할 내용 |
| --- | --- |
| [The Art, Science, and Engineering of Fuzzing](https://arxiv.org/html/1812.00140) | 실행 정보 활용 정도에 따른 black/grey/white-box 분류 |
| [Structure-Aware Fuzzing](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md) | 변이·생성·구조 인지의 관계 |
| [AFL++: Fuzzing in depth](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md) | 커버리지 기반 변이, persistent mode, libFuzzer 하네스 호환 |
| [AFL++: Binary-only targets](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_binary-only_targets.md) | QEMU/FRIDA를 통한 바이너리 계측 |
| [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) | in-process 방식, SanitizerCoverage, 유지보수 상태 |
| [Honggfuzz](https://github.com/google/honggfuzz) | 소프트웨어·하드웨어 커버리지, persistent mode |
| [boofuzz](https://boofuzz.readthedocs.io/en/stable/) | 프로토콜 프레임워크, 장애 감지와 대상 재설정 |
| [boofuzz Quickstart](https://boofuzz.readthedocs.io/en/stable/user/quickstart.html) | 메시지 모델과 순서 그래프 |
| [syzkaller](https://github.com/google/syzkaller) | 커버리지 기반 커널 퍼저 |
| [How syzkaller works](https://github.com/google/syzkaller/blob/master/docs/internals.md) | 시스템 호출 시퀀스와 VM 관리 |
| [Go Fuzzing](https://go.dev/doc/security/fuzz/) | 표준 도구 모음과 testing 통합, 커버리지 피드백 |
| [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) | 범위 밖 접근·해제 후 사용 감지 |
| [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) | signed overflow 등, 계속 실행하는 진단도 존재 |
| [OSS-Fuzz](https://google.github.io/oss-fuzz/) | 여러 엔진을 운용하는 지속적 퍼징 서비스 |
| [FuzzBench](https://google.github.io/fuzzbench/) | 반복 시행과 다양한 대상에 대한 비교 평가 |

### 조사 결과 검토

- 소스 유무와 black/grey/white-box 분류를 분리한다. 바이너리 계측으로도 grey-box 피드백을 얻을 수 있다.
- Jackalope의 현재 README에는 Windows/macOS뿐 아니라 Linux/Android도 명시되어 있다.
- libFuzzer는 중요한 버그 수정은 지원하지만 원저자의 적극적인 새 기능 개발은 중단된 상태라고 공식 문서가 설명한다.
- 도구의 절대적인 속도 순위나 실제 크래시 발견 결과를 주장하지 않는다.
- 오류 신호와 취약점 확정, 커버리지와 안전성 보장을 구분한다.
- 개념 및 도구 비교에 필요한 자료 확인을 마쳤다. 도식 검토 후 본문 작성으로 진행한다.

## 작성 계획

1. 개요: 목표·수행 과정·사용자 제공 링크, 문헌 기반 범위.
2. Fuzzing: 정의, 피드백 반복 구조, 구성 요소, 서로 다른 분류 축, 오류 판정과 한계.
3. Fuzzer: 엔진 정의, AFL++·Jackalope 및 대표 도구, 비교표, 선택 기준, 장단점과 결과 해석.
4. 느낀 점: 제목만 남겨 비워 둔다.
5. 참고 문헌: 직접 열어 실제 활용한 공식 문서만 배치한다.

직접 작성할 도식은 실행 화면이 아닌 개념 설명 이미지임을 본문에서 밝힌다.

## S-03 설명 도식 검토

- 외부 이미지를 복제하지 않고 텍스트·도형으로 SVG 3개를 직접 작성했다. 영어 용어에 대응하는 한국어 설명·대체 텍스트를 본문에 제공한다.
- 그림 1: `assets/images/fuzzing-fuzzer/01-feedback-loop.svg` — 코퍼스·변이·하네스·피드백·오라클 관계.
- 그림 2: `assets/images/fuzzing-fuzzer/02-classification-axes.svg` — 서로 다른 분류 축, 구조 인지와 실행 방식의 중첩.
- 그림 3: `assets/images/fuzzing-fuzzer/03-instrumentation-paths.svg` — 컴파일 시점 계측과 동적 바이너리 계측.
- SVG를 로컬 librsvg/cairo로 `/tmp`의 PNG에 렌더링하고 3개 모두 이미지 도구로 직접 열었다. 텍스트 잘림·도형 겹침 없음, 화살표 방향·분류의 의미 확인. 판정: 모두 적합.
- Python GdkPixbuf 바인딩은 설치되어 있지 않아 첫 미리보기 시도가 실패했다. 이미 설치된 librsvg/cairo로 정상 렌더링했다. 추가 패키지는 설치하지 않았다.
- 자료의 라이선스가 필요한 외부 그림·사진·실행 화면은 사용하지 않았다.
- 본문 작성 전 완료 확인: 개념·분류 및 7종 도구의 비교 근거 확보, 시각 자료 검토 충족. 이제 조사한 내용을 대상 글에 작성한다.

## S-04 본문 작성과 비판적 검토

- 개요·Fuzzing·Fuzzer·빈 느낀 점·참고 문헌으로 본문을 완성했다. 기존 11개 제목의 상대 순서와 front matter 원문을 보존했다.
- 대상 7종: AFL++, Jackalope, libFuzzer, Honggfuzz, boofuzz, syzkaller, Go 내장 퍼징.
- 사용자 제공 URL 3개는 개요에, 직접 조사 자료 18개는 참고 문헌에 배치했다. 본문 근처에도 해당 주장과 관련된 링크를 달았다.
- 처음 읽는 독자 관점에서 Seed/Corpus/Harness 등의 한국어 표기를 보완하고, forkserver와 회귀 테스트의 의미를 명시했다.
- 실습·벤치마크 수치·사용자 소감은 작성하지 않았다. 구조도와 JSON은 설명용 자료라고 밝혔다.
- Black-box 바이너리와 Black-box 탐색의 구분, 실행 방식의 중첩, 커버리지와 오류 판정의 차이, 크래시와 취약점 확정의 차이를 검토했다.

## S-05 빌드와 링크 검증

환경: 저장소 루트의 Bash, 기존 Ruby/Bundler/Jekyll/HTML-Proofer 사용. 1차 검증 확인 시각: 2026-09-25 23:21 +0900.

실행한 빌드:

```bash
JEKYLL_ENV=production bundle exec jekyll build --future --destination /tmp/fuzzing-fuzzer-site-20260925
JEKYLL_ENV=production bundle exec jekyll build --destination /tmp/fuzzing-fuzzer-site-normal-20260925
```

- 두 빌드 모두 종료 코드 0. 일반 빌드에도 `posts/fuzzing-fuzzer/index.html` 생성 확인.
- Bundler는 홈 디렉터리가 쓰기 불가하다는 안내 후 임시 디렉터리를 사용했으며 빌드는 정상 완료했다.
- `HTMLProofer.check_file`에 빌드 루트를 `root_dir`로 제공하여 대상 게시글의 이미지·링크·스크립트를 검사했다. 외부 URL 재검사는 비활성화했고, 외부 출처는 조사 단계에서 웹 도구로 확인했다.
- HTML-Proofer: 내부 링크 66개, 게시글 1개 검사 통과. 전체 기존 게시글에 대한 링크 검사는 수행하지 않았다.
- 생성 HTML의 제목 계층 33개·표 9개·이미지 3개·줄 끝 공백에 의한 줄바꿈을 원문과 대조했다.
- 첫 HTML 점검 스크립트는 예상 표 개수를 10개로 잘못 적어 실패했다. 실제 원문은 표 9개이며, 원문의 표 수와 비교하도록 검사 기준을 바로잡아 통과했다. 렌더링 오류는 아니었다.
- 브라우저 전체 페이지 시각 검토는 수행하지 않았다. 생성 HTML을 검사했고, SVG 자체는 PNG로 렌더링하여 시각 검토했다.
- Python 검사로 YAML 파싱, front matter 바이트 보존, 기존 목차 순서, 빈 느낀 점, `##` 사이 구분선, 이미지 경로, 출처 목록 구분·중복 여부를 확인했다.
- `git diff --check` 통과. 대상 산출물은 미추적 파일이므로 별도 내용·서식 검사를 병행했다.
- 작업 도중 이번 작업과 무관한 `_posts/2026-04-10-bugbounty-init.md` 삭제 상태가 나타났다. 이 파일을 편집하거나 삭제하는 명령은 실행하지 않았으며 해당 변경을 복구하지 않았다.
- 마지막 용어 보완 후 `/tmp/fuzzing-fuzzer-site-final-20260925`에 일반 빌드를 재실행했다. 종료 코드 0, 대상 게시글 HTML 생성 및 HTML-Proofer 내부 링크 66개 검사 재통과.
- 최종 생성 HTML: 제목 계층 33개, 표 9개, 줄바꿈 82개, 설명 도식 3개. 본문 435줄.
- YAML의 `+0900` 날짜를 문자열로 반환하는 PyYAML 특성을 반영해 검사 스크립트에서 날짜로 변환했다. 파일명 날짜·UTC+09:00 시간대 일치 확인, 원문 메타데이터 수정 없음.
- 최종 출처 목록 18개와 수행 기록의 URL 일치, 중복 없음, 기존 제목 11개 보존, 자리표시자 없음 확인.

## 완료 및 인계

- 미션 목표인 개념 학습·여러 퍼저의 비교·블로그 정리를 로컬 산출물로 완료했다.
- 완료 시점의 대기 질문·필수 증빙·실행 중 프로세스 없음.
- 사용자 직접 작성 영역인 `## 느낀 점`은 비워 두었다.
- 최종 변경 산출물: 대상 포스트 1개, SVG 3개, 이 수행 기록 1개.
