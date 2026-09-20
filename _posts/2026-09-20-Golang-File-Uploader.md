---
title: Golang으로 파일 업로드 서비스 개발
date: 2026-09-20 01:22:00 +0900
categories: [개발]
tags: [개발, 블로그/기술문서/리서치, File Upload, Golang, Go]
---
## 개요

**미션 목표**

1. Golang을 공부하고 난 후 직접 개발을 통해 웹 백엔드 구조를 익히고,   
파일 업로드 및 외부 공유 기능을 직접 구현하며 웹 서비스 보안 개념을 학습합니다.
2. 웹 사이트와 curl 명령어 양쪽 모두로 파일을 업로드하고 공유할 수 있도록 개발합니다.

**핵심 기능 구현하기**

- 파일 업로드 기능 구현 (서버 내 안전한 경로에 저장)
- 업로드된 파일에 대한 외부 접근용 공유 링크 생성
- 웹 UI 및 curl 기반 업로드/다운로드 기능 지원
- 업로드 시 MIME 타입, 확장자, 경로 검증 등 보안 처리 필수 적용

**수행 과정**

1. 파일 업로드 기능 구현 (서버 내 안전한 경로에 저장)
2. 업로드된 파일에 대한 외부 접근용 공유 링크 생성
3. 웹 UI 및 curl 기반 업로드/다운로드 기능 지원
4. 업로드 시 MIME 타입, 확장자, 경로 검증 등 보안 처리 필수 적용
5. 구현 과정을 본인 블로그에 정리하고, 주요 코드와 배운 점을 기술합니다.
6. 실제 외부에서 접근 가능한 서버에 배포하여 동작 상태를 확인합니다.

**구현한 서비스**

[https://go-file-share.onrender.com](https://go-file-share.onrender.com)

> 파일은 최대 24시간 공유된다.

**참고 링크**

- [Go net/http 문서](https://pkg.go.dev/net/http)
- [Supabase Storage 문서](https://supabase.com/docs/guides/storage)  

---

## 사전 조사

### Go와 HTTP 서버

**Go(Golang)**: 컴파일하여 실행 파일을 만드는 프로그래밍 언어.  
이번 실습에서는 표준 라이브러리인 `net/http`로 웹 서버를 구현하였다.  

**HTTP 서버**: 요청을 처리하고 상태 코드·헤더·본문으로 결과를 반환하는 프로그램

**핸들러(Handler)**: HTTP 요청을 처리하는 구성 요소.  
이번 구현에서는 요청을 처리할 함수를 등록하였다.  

이번 서비스에서 필요한 요청은 다음과 같다.

| 요청              | 역할                             |
| ----------------- | -------------------------------- |
| `GET /`           | 파일 업로드 웹 화면 제공         |
| `GET /health`     | 서버 응답 상태 확인              |
| `POST /api/files` | 파일 검증·저장 및 공유 링크 생성 |
| `GET /files/<ID>` | 공유 파일 다운로드               |

---

### 파일 업로드에 필요한 개념

#### multipart/form-data

**multipart/form-data**: 하나의 HTTP 요청 안에 파일과 폼 데이터를 구분해서 담는 전송 형식

이번 구현에서는 `file`이라는 이름의 필드에 파일 하나를 담아 전송한다.   
웹에서는 `FormData`, 터미널에서는 `curl -F`를 사용한다.

```bash
curl -F 'file=@testdata/sample.png' http://127.0.0.1:8081/api/files
```

`@`는 뒤에 지정한 경로의 파일 내용을 읽어 전송한다는 의미이다.

---

#### 확장자와 MIME 타입

**확장자**: `.png`, `.pdf`처럼 파일 이름에 붙는 형식 표시

**MIME 타입**: `image/png`, `application/pdf`처럼 데이터의 형식을 나타내는 값

업로드 요청의 파일명과 MIME 헤더는 클라이언트가 지정할 수 있다.   
따라서 이름이 `sample.png`이고 헤더가 `image/png`라고 해서 실제 PNG 파일이라고 판단할 수 없다.

서버에서는 허용 확장자를 확인한 뒤, 실제 파일 내용에서 감지한 MIME 타입이 확장자와 일치하는지 검사해야 한다.

---

#### 경로 조작(Path Traversal)

**경로 조작**: `../` 등의 경로 표현을 이용해 의도한 디렉터리 밖의 파일에 접근하려는 입력

원본 파일명을 저장 경로에 그대로 붙이면 경로 조작이나 같은 이름의 파일 덮어쓰기를 고려해야 한다.   
이번 구현에서는 원본 파일명을 검사하고, 실제 저장에는 서버가 생성한 난수 ID를 사용하였다.

---

### 공유 링크, 만료, 삭제

세 가지 동작을 구분하여 구현하였다.

| 구분      | 의미                                         |
| --------- | -------------------------------------------- |
| 공유 링크 | 파일 ID를 이용해 다운로드에 접근하는 주소    |
| 만료      | 정해진 시각 이후 새로운 다운로드 요청을 거부 |
| 삭제      | 저장소의 실제 파일과 메타데이터를 제거       |

링크가 만료되었다고 저장소의 파일까지 즉시 없어지는 것은 아니다.   
요청 시 만료 검사와 주기적인 삭제 작업이 각각 필요하다.

---

## 실제 구현

### 구현 구조

처음에는 로컬 디스크에 파일을 저장하며 기능을 구현하였다.  
최종 배포에서는 Render의 Go 서버가 요청을 처리하고,  
Supabase가 파일과 메타데이터를 보관하도록 분리하였다.  

```text
[브라우저 / curl]
        │ HTTPS
        ▼
[Render: Go 서버]
  ├─ 웹 UI 제공
  ├─ 파일명·확장자·실제 내용 검증
  ├─ 공유 링크 생성과 다운로드
  │
  ├── [Supabase Storage]
  │      └─ uploads/<난수 ID>/content
  │
  └── [Supabase PostgreSQL]
         └─ 파일명·크기·MIME·만료 시각·상태

[Supabase Cron: 5분 주기]
  └─ 만료 대상 조회 → Storage API로 파일 삭제 → DB 기록 제거
```

### 실습 환경

| 구성 요소               | 사용 목적                              |
| ----------------------- | -------------------------------------- |
| Windows + WSL           | 로컬 개발 및 curl 실습                 |
| Go 1.27.1 / net/http    | 업로드·다운로드 서버 구현              |
| HTML / CSS / JavaScript | 파일 선택, 업로드, 링크 복사 화면      |
| GitHub                  | 소스 저장 및 Render 연결               |
| Render Free             | Go 서버 외부 실행                      |
| Supabase Free           | 파일과 메타데이터 보관, 만료 파일 정리 |

---

### 로컬 저장소로 기본 기능 구현

#### 1. Go 서버 실행과 응답 확인

`/health` 요청에 JSON을 반환하는 서버부터 실행하였다.  

```bash
cd /home/wnsgur/seKUrity/go-file-share
source ./env.sh
go run -buildvcs=false ./cmd/server
```

`source ./env.sh`는 프로젝트에서 사용하는 Go 실행 환경을 현재 셸에 적용한다.  
초기에는 상위 Git 메타데이터 조회 문제가 있어 `-buildvcs=false`로 빌드 시 VCS 정보 삽입을 생략하였다.

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /health", health)
```

`NewServeMux`로 라우터를 만들고,  
`GET /health` 요청을 `health` 함수에 연결하였다.  

```bash
curl -i http://127.0.0.1:8080/health
```

![로컬 Go 서버 실행과 HTTP 200 응답](/assets/images/Golang/01-health.png)

서버 실행 로그와 `HTTP/1.1 200 OK` 응답을 확인하였다.  
`-i` 옵션을 사용하면 응답 본문과 함께 상태 코드와 헤더도 출력된다.

이후 서비스 이름을 추가한 응답은 다음과 같다.  

```json
{"service":"go-file-share","status":"ok"}
```

이후 로컬 업로드 실습은 8081 포트에서 진행하였다.  

```bash
LISTEN_ADDR=127.0.0.1:8081 go run -buildvcs=false ./cmd/server
```

---

#### 2. multipart 요청에서 파일 정보 읽기

![초기 multipart 수신 실습](/assets/images/Golang/02-multipart-upload.png)

초기에는 파일명과 크기만 읽어 `saved: false`를 반환하였다.  
이때 사용한 TXT 파일은 최종 버전에서는 허용하지 않는다.  

요청 크기 제한과 임시 파일 정리도 적용하였다.

```go
r.Body = http.MaxBytesReader(w, r.Body, MaxFileSize+(1<<20))
err := r.ParseMultipartForm(1 << 20)
if r.MultipartForm != nil {
    defer r.MultipartForm.RemoveAll()
}
```

> 위 코드는 크기 제한과 정리 부분을 발췌한 것이다.  
> 실제 코드에서는 `err`를 확인하여 요청 크기 초과는 413,  
> 그 외 multipart 파싱 오류는 400을 반환하고 처리를 종료한다.

**`defer`**: 현재 함수가 종료될 때 실행할 정리 작업을 예약하는 Go 문법


`ParseMultipartForm`의 인자는 업로드 최대 크기와 다르다.  
파일 부분의 메모리 보관 기준을 넘으면 임시 파일이 사용될 수 있으므로,  
함수 종료 시 이를 정리하도록 하였다.  

일반 폼 필드와 파싱 자료구조에는 별도 메모리가 필요하며,  
이후 파일 읽기와 이미지 디코딩에서도 추가 메모리를 사용한다.  

따라서 이 설정이 요청 처리 전체의 메모리 사용량을 1 MiB로 제한하는 것은 아니다.  
[Go multipart 문서](https://pkg.go.dev/mime/multipart#Reader.ReadForm)

파일 하나는 최대 10 MiB, 요청 전체는 multipart 헤더 등을 포함해 최대 11 MiB로 제한하였다.  
파일이 여러 개이거나 필드 이름이 `file`이 아닌 요청, 불필요한 일반 폼 필드가 있는 요청도 거부하였다.

---

#### 3. 파일 검증과 안전한 저장 경로 적용

**검증 순서**

```text
요청 크기 → multipart 구성 → 원본 파일명 → 허용 확장자
                                              ↓
저장 ← 이미지 크기·디코딩 검사 ← 실제 내용의 MIME 타입
```

원본 파일명은 `Content-Disposition` 헤더를 파싱하여 확인하였다.

```go
disposition, params, err := mime.ParseMediaType(
    header.Header.Get("Content-Disposition"),
)
name := params["filename"]
```

실제 코드에서는 파싱 오류와 `disposition` 값도 검사한다.    
Go의 multipart 파일명 처리 과정에서 경로 부분이 제거될 수 있으므로,   
원래 입력이 `../sample.png`였는지 확인하기 위해 헤더의 원본 값을 검사하였다.   
[Go multipart 문서](https://pkg.go.dev/mime/multipart#Part.FileName)

| 검사 항목 | 적용 내용                                                          |
| --------- | ------------------------------------------------------------------ |
| 파일명    | 경로 구분자, 숨김 파일명, 앞뒤 공백, 제어 문자 등 거부             |
| 확장자    | PNG, JPG, JPEG, PDF만 허용                                         |
| MIME      | 실제 내용에서 감지한 타입과 확장자의 대응 관계 확인                |
| 이미지    | 가로·세로 각각 4096 이하, 총 1,600만 픽셀 이하 및 디코딩 성공 여부 |

```go
want := map[string]string{
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".pdf":  "application/pdf",
}[ext]
detected := http.DetectContentType(data)
if detected != want {
    return "", fmt.Errorf("file content does not match extension")
}
```

확장자별 예상 MIME을 `map`에 넣고, 실제 파일 바이트에서 감지한 값과 비교하였다.  
`http.DetectContentType`은 최대 첫 512바이트로 MIME 타입을 추정하므로,  
이 함수만으로 파일 전체 구조를 검증할 수는 없다.  
[Go DetectContentType 문서](https://pkg.go.dev/net/http#DetectContentType)

PNG/JPEG는 이미지 크기를 확인하고 추가로 디코딩하여,  
시그니처만 있는 손상된 파일도 거부하였다.  
다만 이미지를 재인코딩하지 않고 원본 바이트를 저장하므로,  
디코딩 성공이 파일의 모든 부가 데이터나 악성코드 부재를 보장하지는 않는다.  

PDF는 MIME 시그니처 수준만 확인한다.  
이 검사로 PDF 내부 스크립트나 악성코드까지 검사한 것은 아니다.  

검증을 통과한 파일은 다음 구조로 저장하였다.

```text
data/uploads/
└── <난수 ID>/
    ├── content
    └── metadata.json
```

```go
var token [16]byte
if _, err := rand.Read(token[:]); err != nil {
    return Metadata{}, err
}
id := hex.EncodeToString(token[:])
```

`crypto/rand`로 16바이트 난수를 만들고 32자리 16진수 ID로 변환하였다.  
원본 파일명은 표시와 다운로드 이름에만 사용한다.

저장 디렉터리는 0700, 파일은 0600 권한으로 생성하였다.  
`os.Root`로 저장 루트 밖으로 벗어나는 접근을 제한하고, 기존 파일을 덮어쓰지 않도록 배타적으로 생성하였다.  
저장 도중 실패한 경우에는 불완전한 업로드를 정리하였다.

![정상 PNG 검증 및 저장 성공](/assets/images/Golang/03-validated-upload.png)

정상 PNG는 `201 Created`와 함께 난수 ID, `mime: image/png`, `saved: true`를 반환하였다.

---

#### 4. 잘못된 업로드 요청 확인

![위장 PNG와 경로 조작 요청 거부](/assets/images/Golang/04-upload-rejected.png)

| 요청                                             | 결과                      |
| ------------------------------------------------ | ------------------------- |
| 실제 내용이 PNG가 아닌 파일을 `image/png`로 전송 | 415, 내용과 확장자 불일치 |
| 파일명을 `../sample.png`로 지정                  | 400                       |

---

#### 5. 공유 링크와 다운로드 구현

저장이 완료되면 다음 형식의 링크를 반환하도록 하였다.

```text
https://서비스주소/files/<난수 ID>
```

공유 링크에는 원본 파일명이나 서버 내부 경로를 넣지 않는다.  
도메인도 요청의 `Host` 값을 그대로 사용하지 않고 서버에 설정한 공개 주소를 사용하였다.  

이 서비스에서는 별도 로그인 없이 링크를 아는 사람이 파일을 다운로드할 수 있다.  
난수 ID는 링크 추측을 어렵게 하지만, 링크를 전달받은 사람의 접근을 막지는 않는다.  
Supabase 버킷이 비공개여도 Go 서버의 공유 링크를 통한 다운로드는 이 정책에 따라 허용된다.

다운로드 요청에서는 ID 형식, 메타데이터, 파일 크기와 만료 시각을 확인한다.  

응답에는 다음 헤더를 적용하였다.

| 헤더                              | 목적                            |
| --------------------------------- | ------------------------------- |
| `Content-Disposition: attachment` | 파일을 첨부 다운로드로 제공     |
| `X-Content-Type-Options: nosniff` | 브라우저의 MIME 추측 제한       |
| `Cache-Control: no-store`         | HTTP 캐시에 응답 저장 금지 지시 |
| `Referrer-Policy: no-referrer`    | 리퍼러 정보 전송 제한           |

![공유 링크 다운로드와 파일 해시 비교](/assets/images/Golang/05-share-download.png)
 
공유 링크의 HTTP 200 응답과 원본·다운로드 파일의 SHA-256 일치를 확인하였다.  
바이트 비교도 통과하여 파일 내용이 그대로 전달되는 것을 확인하였다.  

---

#### 6. 웹 UI 연결

웹 화면에서는 `FormData`로 같은 업로드 API에 파일을 전송하였다.  
성공하면 공유 링크와 다운로드·링크 복사 버튼을 표시한다.  

![로컬 웹 화면에서 파일 업로드와 공유 링크 생성](/assets/images/Golang/06-web-upload.png)

![위장 파일 업로드 시 웹 오류 안내](/assets/images/Golang/07-web-upload-error.png)

정상 PNG가 아닌 `fake.png`를 선택하면 내용 불일치 또는 손상된 이미지라는 오류가 표시되었다.

curl 요청에도 적용되도록 최종 검증은 Go 서버에서 수행한다.  

HTML/CSS/JavaScript는 `embed`로 Go 실행 파일에 포함하였다.  
파일명은 `innerHTML` 대신 `textContent`로 표시하여 HTML로 해석되지 않게 하였다.

---

#### 7. 운영 제한과 공유 만료 적용

최종 배포 버전에는 다음 제한을 적용하였다.  

| 항목                   | 제한                                    |
| ---------------------- | --------------------------------------- |
| 파일 하나              | 최대 10 MiB                             |
| 파일 내용 총량 / 개수  | 최대 100 MiB / 100개                    |
| 업로드 시도            | 서버 프로세스 전체 1분 고정 구간당 20회 |
| 동시 업로드            | 최대 2개                                |
| Supabase 동시 다운로드 | 최대 2개                                |
| 공유 기간              | 24시간                                  |

파일 하나 또는 요청 전체의 크기 제한 초과는 `413`, 전체 저장량·파일 개수 제한 초과는 `507`을 반환하도록 하였다.  
빈도 초과는 `429`, 동시 처리 초과는 `503`을 반환한다.

업로드 빈도와 동시 처리 제한은 서버 프로세스의 메모리에서 관리하므로, 재시작 시 초기화된다.  
또한 모든 사용자가 같은 한도를 공유하므로, 한 사용자의 반복 요청으로 다른 사용자의 업로드가 제한될 수 있다.

`scripts/demo-limits.sh`로 다음 항목의 Go 테스트를 실행하였다.  

```bash
bash scripts/demo-limits.sh
```

| 검증 항목             | 확인 내용                                                   |
| --------------------- | ----------------------------------------------------------- |
| 저장 용량과 파일 개수 | 저장소를 다시 열어도 제한이 유지되는지 확인                 |
| 파일 만료와 삭제      | 만료 전후 응답과 정리 후 파일 제거 확인                     |
| 요청 빈도             | 제한 초과 시 차단되고 다음 시간 구간에 다시 허용되는지 확인 |
| 동시 업로드           | 동시 처리 제한과 처리 종료 후 제한 해제 확인                |
| 동시 저장             | 여러 저장 요청이 전체 할당량을 초과하지 않는지 확인         |
| 만료 공간 회수        | 새 파일 저장 전 만료된 파일의 공간이 회수되는지 확인        |
| 다른 출처의 업로드    | 허용하지 않은 출처의 브라우저 업로드 요청이 차단되는지 확인 |

![운영 제한 테스트 재검증 결과](/assets/images/Golang/09-operational-limits-tests.png)

임시 저장소와 테스트에서 변경 가능한 시간 함수를 사용하여 모든 검사를 통과하였다.  

---

### 외부 배포 환경 구성

#### 8. Render와 Supabase 선택

Render Free는 15분 동안 들어오는 트래픽이 없으면 절전 상태로 전환되며,  
로컬 파일은 절전·재시작·재배포 시 유지되지 않는다.  
따라서 Go 서버는 Render에서 실행하고,  
파일과 공유 정보는 Supabase에 보관하였다.  
[Render 무료 서비스 문서](https://render.com/docs/free)

`STORAGE_BACKEND=local`은 서버 디스크를 사용하고,  
`supabase`는 외부 저장소를 사용한다.  

---

#### 9. Supabase 저장소 연결

`uploads`라는 비공개 버킷을 만들고, 파일 정보를 저장하는 테이블을 구성하였다.  
Data API는 사용하되 새 테이블 자동 권한 부여는 끄고 RLS를 적용하였다.

**RLS(Row Level Security)**: 데이터베이스 테이블의 행에 접근할 수 있는 조건을 제어하는 기능

서버 키는 Go 서버의 환경 변수에서만 읽고 브라우저나 Git 저장소에 넣지 않았다.  
새 `sb_secret_...` 키는 JWT가 아니므로 Storage 요청의 `apikey` 헤더로 전달하였다.  

이 서버 키는 `service_role`로 동작하여 RLS를 우회한다.  
따라서 Go 서버에서 파일 ID와 메타데이터를 검증하고,  
`ready` 상태이며 만료되지 않은 파일만 다운로드할 수 있도록 처리하였다.  
일반 클라이언트의 직접 접근은 RLS와 테이블·함수 권한 설정으로 제한하였다.  
[Supabase API 키 문서](https://supabase.com/docs/guides/getting-started/api-keys)

외부 저장소에서는 DB 기록과 파일 저장이 각각 이루어지므로, 중간 실패를 처리하기 위해 상태를 나누었다.

```text
용량 예약 및 pending 행 생성
          ↓
Storage에 파일 저장
          ↓
DB 상태를 ready로 변경
          ↓
공유 링크 반환
```

`pending`은 저장 진행 중, `ready`는 다운로드 가능한 상태이다.  
DB 잠금을 이용해 용량 확인과 예약을 처리하며, 오래된 `pending`은 정리 작업이 제거하도록 하였다.

Storage 업로드가 타임아웃되면 실제 파일 저장 여부가 불확실할 수 있으므로 예약을 즉시 제거하지 않는다.  
파일 저장 후 DB의 완료 처리가 실패한 경우에도 해당 요청에서 공유 링크를 반환하지 않는다.  
`pending`으로 남은 기록과 파일은 후속 정리 작업에서 처리한다.

DB 기록과 Storage 객체를 하나의 트랜잭션으로 처리하는 구조는 아니므로,  
이처럼 중간 실패를 상태 관리와 정리 작업으로 처리하였다.  

전체 저장량과 파일 개수 계산에는 `pending`과 만료 후 삭제 대기 기록도 포함한다.  
따라서 공유 링크가 만료되었다고 저장 할당량이 즉시 회수되는 것은 아니다.

![Supabase Storage에 저장된 파일](/assets/images/Golang/10-supabase-stored-file.png)

---

#### 10. 만료 파일 자동 삭제와 Vault 오류 해결

Go 서버는 만료된 공유 링크에 404를 반환하고,  
Supabase Cron은 5분 주기로 실제 파일을 정리한다.  
Supabase 데이터베이스가 실행 중이면 Render의 절전 여부와 별개로 정리할 수 있다.  

삭제 대상은 만료된 파일과 15분 넘게 완료되지 않은 업로드이다.  
Storage 삭제 API의 성공 응답을 확인한 뒤 DB 기록을 제거한다.

Storage의 내부 테이블을 SQL로 직접 삭제하면 실제 파일까지 삭제되는 것은 아니므로,  
파일 삭제에는 Storage API를 사용하였다.  
[Supabase Storage 스키마 문서](https://supabase.com/docs/guides/storage/schema/design)

**Vault 설정**

정리 함수가 사용할 프로젝트 URL과 서버 키를 Supabase Vault에 등록하였다.

![값을 가린 Supabase Vault 항목 목록](/assets/images/Golang/10b-vault-masked.png)


**만료 상태 재현**

검증용 SQL로 테스트 파일의 생성 시각을 25시간 전으로,  
만료 시각을 1시간 전으로 변경하여 24시간 간격을 유지한 만료 상태를 재현하였다.  
`expired: true`를 확인한 뒤 직접 삭제하지 않고 다음 Cron 실행을 기다렸다.  

![검증용 파일의 expired true 확인](/assets/images/Golang/14a-expiry-test-query.png)

Cron 실행 기록에서는 다음 오류가 확인되었다.  

```text
ERROR: Configure gofs_supabase_url and gofs_supabase_secret_key in Vault
```

등록 결과의 `schedule = 1`은 작업 ID이므로,  
실제 실행 성공 여부는 별도로 확인해야 했다.  

**항목 세분화 진단**

![Vault 항목 존재 여부와 형식 진단](/assets/images/Golang/14b-vault-name-diagnosis.png)

정확한 이름으로 URL 항목이 조회되지 않았고,  
키 항목의 존재와 형식은 정상이었다.  
URL 항목의 이름 불일치를 해결하기 위해 정확한 이름으로 다시 등록하였다.  

URL과 키 형식 검사가 모두 true인 것을 확인한 뒤 다음 Cron 실행을 기다렸다.  

다음 Cron 실행 후 조회 전용 SQL로 실행 결과와 대상 기록의 존재 여부를 확인하였다.  

![Cron 실행 성공과 대상 기록 제거](/assets/images/Golang/14c-cleanup-success.png)

| 결과 항목                      | 의미                           |
| ------------------------------ | ------------------------------ |
| `active: true`                 | 예약 작업 활성화               |
| `status: succeeded`            | 해당 실행 성공                 |
| `metadata_exists: false`       | 대상 파일의 앱 메타데이터 없음 |
| `storage_record_exists: false` | 대상 Storage 객체 기록 없음    |

`return_message: 1 row`는 쿼리 결과 행 수이며 삭제한 파일 수를 의미하지 않는다.  
별도 인증된 파일 조회에서도 `Object not found`를 확인하였다.

정리 전에는 공유 링크가 404여도 파일은 남아 있었고,  
Cron 실행 후 파일과 기록이 제거되어 만료와 삭제를 각각 확인하였다.  

---

#### 11. GitHub 연결 및 Render 배포

GitHub 저장소에 소스와 `render.yaml`을 올리고 Render Blueprint로 연결하였다.  

```yaml
runtime: docker
plan: free
healthCheckPath: /health
```

Render 환경 변수에는 Supabase 주소와 서버 키를 등록하였다.  
서버는 Render에서 제공하는 포트를 사용하고,  
공유 링크에는 공개 서비스 주소가 들어가도록 하였다.  

Docker 빌드 단계에서 Go 테스트와 빌드를 수행하고,  
실행 단계에서는 root가 아닌 사용자로 서버를 실행한다.  
Supabase HTTPS 연결에 필요한 CA 인증서도 이미지에 포함하였다.

---

### 외부 동작 확인

#### 12. 공개 웹 화면과 curl 업로드·다운로드

공개 주소에서 `sample.png`를 업로드하여 공유 링크와 만료 시각을 확인하였다.  

![Render 공개 주소에서 웹 업로드 성공](/assets/images/Golang/11-public-web-upload.png)

화면의 “최대 보관 시각”은 다운로드 만료 시각을 뜻하며,  
실제 삭제는 이후 정리 작업에서 처리한다.  

curl에서도 같은 API를 사용하였다.  

```bash
curl -i -F 'file=@testdata/sample.png' \
  https://go-file-share.onrender.com/api/files

# 아래 주소는 업로드 응답의 share_url로 바꾼다.
curl 'https://go-file-share.onrender.com/files/<응답의-ID>' \
  -o downloaded.png

sha256sum testdata/sample.png downloaded.png
```

같은 절차를 자동화한 `scripts/demo-public.sh`에서는 HTTP 오류와 바이트 불일치를 검사하고,  
모두 통과한 경우에만 PASS를 출력하였다.  

![공개 curl 업로드·다운로드와 해시 비교 결과](/assets/images/Golang/12-public-curl-verify.png)

업로드는 HTTP/2 201, 다운로드는 HTTP/2 200을 반환하였다.  
원본과 다운로드 파일의 해시가 같고 바이트 비교도 통과하였다.

위장 PNG는 415,  
숨김 파일명은 400으로 거부되었다.  
`../sample.png` 요청은 Cloudflare에서 먼저 차단되어 403이 반환되었으므로,  
Go 자체의 경로 검증은 앞의 로컬 400 응답과 테스트로 확인하였다.  

---

#### 13. Render 재시작 후 기존 파일 유지 확인

Render의 재시작 완료를 확인한 뒤,  
`scripts/check-public-restart.py`로 기존 공유 링크를 검사하였다.  
새 업로드 없이 HTTP 200 응답과 원본 파일의 바이트 일치를 확인하였다.  

![Render 재시작 후 기존 파일 유지 검증 로그](/assets/images/Golang/13-restart-persistence.png)

위 화면은 당시 검증 로그이며,  
재시작 후에도 기존 공유 링크와 파일 내용이 유지된 것을 보여 준다.  


### 검증 결과와 남은 한계

| 항목        | 확인 내용                                                   |
| ----------- | ----------------------------------------------------------- |
| 업로드      | 정상 파일 저장, 위장 MIME·경로 조작 거부                    |
| 다운로드    | 공유 링크 응답과 원본 바이트 일치                           |
| 웹 UI       | 업로드 성공·오류 안내, 공개 화면과 모바일 화면              |
| 운영 제한   | 임시 저장소와 테스트 시계를 이용한 용량·만료·동시 처리 검증 |
| 코드 검사   | Go 테스트, race 검사, vet 통과                              |
| 외부 저장소 | 실제 Supabase 저장 및 비인증 직접 접근 거부                 |
| 자동 삭제   | Cron 실행과 대상 파일·메타데이터 제거                       |
| 재시작      | 기존 공유 링크와 파일 내용 유지                             |

Render Free는 절전 후 첫 접속에 기동 시간이 걸릴 수 있다.  
Supabase Free에도 비활성 프로젝트 일시 중지와 저장량·대역폭 제한이 있으며,  
프로젝트가 정지하면 정리 작업도 정상 실행을 기대할 수 없다.  
무료 플랜 조건은 서비스 운영 시 다시 확인해야 한다.  
[Render Free](https://render.com/docs/free), [Supabase 요금제](https://supabase.com/pricing)

현재 구현에는 사용자 인증, 비밀번호 공유, 악성코드 검사 기능이 없다.  
또한 Supabase 모드에서는 Range 요청도 내부적으로 파일 전체를 읽으므로,  
다운로드 대역폭을 줄이려면 추가 구현이 필요하다.

---

## 느낀 점
웹 해킹을 공부하며 파일 업로드 취약점을 공격자 입장에서만 바라보았는데,  
방어자 관점에서 서비스를 구축해 보니 재미있었다.  

앞으로는 내가 만든 서비스를 다시 공격자 관점에서 점검하며,  
검증을 우회할 수 있는 부분을 찾아 보안 기능을 강화해 보고 싶다.  

또한 Go 언어를 처음 접해 보았는데 AI를 활용하니 새로운 언어로도 코드 작성에 어려움은 없었지만, 코드 읽는 속도가 오래 걸리는 것은 어쩔 수 없었다.   

바로 개발에 들어가서 Go 언어의 특징과 장단점에 대해서 조사하지 못했는데,   
Go 언어의 장점과 특징을 조사해보고 왜 이 미션이 Golang으로 작성하도록 요구되었는지 알아보고 싶다.