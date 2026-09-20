---
title: pcap 파일 분석기 개발
date: 2026-09-20 21:41:00 +0900
categories: [개발]
tags: [pcap, network, C, IP, 패킷]
---

## 개요

`ping`에는 응답이 오는데 웹 연결은 실패한다면, 무엇을 확인해야 할까?  
PCAP에는 그때 오간 패킷이 순서대로 남는다. 이 파일에서 주소·포트·TCP Flag·ICMP 응답을 읽으면 어디까지 통신했는지 구분할 수 있다.

이번 미션에서는 **C + libpcap으로 실제 캡처 파일을 읽는 분석기**를 만들었다.  
libpcap은 레코드 읽기를 담당하고 Ethernet·IPv4·TCP·UDP·ICMP 헤더와 통계는 직접 코드로 처리하였다.

**수행 과정**

1. PCAP과 패킷 헤더 구조 이해
2. 실제 외부 통신 캡처
3. 헤더를 직접 읽는 C 프로그램 작성
4. 프로토콜·Flag·IP·포트별 통계 계산
5. tcpdump 대조 및 통신 결과 해석

---

## 사전 조사

### PCAP 파일과 패킷의 구조

PCAP은 **패킷과 캡처 시각을 함께 보관하는 기록 파일**로 볼 수 있다.  
이번에 사용한 classic PCAP은 다음 구조이며, 별도 형식인 pcapng는 지원하지 않는다.

```text
전역 헤더 24바이트: 파일 형식·바이트 순서·최대 캡처 길이·링크 유형
  ├─ 레코드 헤더 16바이트: 시각·캡처 길이·원본 길이
  │   └─ 실제 패킷 바이트
  ├─ 다음 레코드 헤더
  │   └─ 다음 패킷 바이트
  └─ 반복
```

`caplen`은 실제 저장된 길이이다. 원래 패킷이 더 길어도 저장되지 않은 바이트까지 읽으면 안 된다.  
파일 헤더의 바이트 순서는 magic number로 판별하고, 네트워크 헤더의 여러 바이트 정수는 big-endian으로 읽는다.  
이 구분은 설치된 libpcap의 `pcap-savefile(5)` 매뉴얼과 실제 파일을 대조하여 확인하였다.

---

### Ethernet에서 전송 프로토콜까지

이번 캡처는 Ethernet 프레임 안에 IPv4 패킷이 들어 있고, IPv4의 Protocol 필드로 다음 헤더를 구분한다.

```text
Ethernet 헤더 → IPv4 헤더 → TCP / UDP / ICMP → 나머지 데이터
  EtherType       Protocol
   0x0800       6 / 17 / 1
```

| 헤더     | 주요 필드                                          | 다음 데이터를 찾는 기준                   |
| -------- | -------------------------------------------------- | ----------------------------------------- |
| Ethernet | 목적지·출발지 MAC, EtherType                       | VLAN이 없는 기본 헤더는 14바이트          |
| IPv4     | IHL, Total Length, TTL, Protocol, 출발지·목적지 IP | IHL × 4바이트                             |
| TCP      | 포트, SEQ/ACK, Data Offset, Flags, Window          | Data Offset × 4바이트                     |
| UDP      | 포트, Length, Checksum                             | 헤더 8바이트, Length는 헤더와 데이터의 합 |
| ICMP     | Type, Code, Checksum, 유형별 필드                  | Echo에서는 Identifier와 Sequence도 확인   |

IPv4와 TCP에는 옵션이 들어갈 수 있으므로 헤더 길이를 항상 20바이트로 가정하면 안 된다.  
IPv4 IHL과 TCP Data Offset은 4바이트 단위이며, 실제 값으로 다음 헤더나 데이터의 시작 위치를 계산해야 한다.  
이 구조는 [IPv4 명세 RFC 791](https://www.rfc-editor.org/rfc/rfc791)과 [TCP 명세 RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)에서 확인하였다.

UDP는 연결 수립 절차 없이 데이터그램을 전송한다.  
ICMP에는 TCP·UDP와 같은 포트 번호가 없으며, Type과 Code로 메시지 종류를 구분한다.  
따라서 ICMP 출력에는 `ports=N/A`를 표시하였다.  
헤더 정의는 [UDP 명세 RFC 768](https://www.rfc-editor.org/rfc/rfc768)과 [ICMP 명세 RFC 792](https://www.rfc-editor.org/rfc/rfc792)를 참고하였다.

---

## 실제 구현

### 구현 방식 비교와 선택

패킷 구조를 직접 확인하는 학습 목적에 맞춰 다음 방법을 비교하였다.

| 고려한 방법    | 장점                                                      | 단점·제약                                       |
| -------------- | --------------------------------------------------------- | ----------------------------------------------- |
| C + libpcap    | 바이트 위치와 헤더 구조를 직접 다룰 수 있음               | 길이 검사와 바이트 순서 변환을 직접 구현해야 함 |
| Python + dpkt  | 파일 순차 읽기와 헤더·통계 처리를 간결하게 구현할 수 있음 | 헤더 해석 일부를 라이브러리가 담당함            |
| Python + scapy | 패킷 조회와 생성이 편리함                                 | 자동 해석 과정에서 내부 구조가 가려질 수 있음   |

**채택한 방법과 이유**

학습용 프로그램에서 최대한 많은 부분을 코드로 직접 확인하기 위해 C + libpcap을 선택하였다.  
libpcap으로 파일 레코드를 읽되, Ethernet·IPv4·TCP·UDP·ICMP 필드는 직접 해석하였다.  
다른 라이브러리와의 성능 비교 실험은 수행하지 않았다.

분석할 파일이 없었으므로 실제 통신을 캡처할 환경도 비교하였다.

| 고려한 환경                          | 장점                                            | 단점·제약                             |
| ------------------------------------ | ----------------------------------------------- | ------------------------------------- |
| WSL eth0에서 외부 HTTP·DNS·ping 캡처 | 실제 외부 통신과 Ethernet 헤더를 관찰할 수 있음 | 인터넷 연결과 상대 응답에 영향을 받음 |
| 로컬 컨테이너 사이에서 통신 후 캡처  | 통신 조건을 통제하고 재현하기 쉬움              | 별도 컨테이너 구성이 필요함           |

통제된 실습 환경이 아닌 실제 통신의 PCAP을 분석하고자 WSL `eth0` 캡처를 선택하였다.  
예제 PCAP을 다운로드하거나 패킷 레코드를 합성하지 않았다.

### 최종 프로그램이 출력하는 정보

| 출력             | 확인할 수 있는 내용                                                     |
| ---------------- | ----------------------------------------------------------------------- |
| PCAP 정보        | 파일 버전, 바이트 순서, 시각 단위, snaplen, 링크 유형                   |
| 패킷별 헤더      | 순서·시각·길이, MAC/IP, TCP·UDP 포트, TCP SEQ/ACK/Flags, ICMP Type/Code |
| 기본 통계        | 전체 및 프로토콜별 개수, 캡처 바이트, 잘못된 헤더·잘린 패킷·IP 단편 수  |
| TCP Flag 통계    | FIN/SYN/RST/PSH/ACK/URG/ECE/CWR가 설정된 패킷 수                        |
| Top Talkers      | 출발지 IPv4별 송신 패킷 수 상위 5개와 IPv4 바이트 합계                  |
| 목적지 포트 통계 | TCP·UDP를 구분한 목적지 포트별 패킷 수                                  |
| `--hex`          | 각 패킷의 앞 96바이트와 오프셋                                          |

Flag는 비트별로 세므로 SYN·ACK 하나는 SYN과 ACK에 각각 더해진다.  
Top Talkers는 양방향 대화량이 아닌 **출발지별 패킷 수** 순위이며, 동률이면 IP 오름차순이다. 바이트는 IPv4 Total Length의 합이다.  
목적지 포트에는 응답을 받는 임시 포트도 포함된다. 따라서 이 통계를 서비스별 연결 수로 해석하면 안 된다.

### 구현 구조와 환경

```text
capture-real.sh / capture-more.sh
  ├─ tcpdump로 eth0 캡처
  └─ 실제 HTTP·HTTPS 요청, UDP DNS 질의, ping
          ↓
      traffic.pcap
          ↓
src/main.c
  ├─ PCAP 전역 헤더 확인
  ├─ libpcap으로 레코드 순차 읽기
  ├─ 캡처 길이 검사 및 각 헤더 해석
  └─ 패킷별 정보와 프로토콜별 통계 출력
          ↓
tcpdump 결과·클라이언트 로그와 대조
```

| 구성 요소 | 확인한 환경·버전                           | 용도                                |
| --------- | ------------------------------------------ | ----------------------------------- |
| 실행 환경 | Windows에서 사용하는 WSL2 Ubuntu 26.04 LTS | 빌드·캡처·분석                      |
| WSL 커널  | 6.18.33.2-microsoft-standard-WSL2          | 네트워크 실행 환경                  |
| GCC       | 15.2.0                                     | C 컴파일 및 검사                    |
| libpcap   | 1.10.6                                     | PCAP 파일 읽기                      |
| tcpdump   | 4.99.6                                     | 실제 캡처와 분석 결과 대조          |
| Python    | 3.14.4                                     | 실제 DNS 질의 전송과 결과 대조 보조 |

`src/main.c`, `Makefile`, 두 캡처 스크립트를 만들고 `captures/`에 원본, `results/`에 분석 출력을 저장하였다.  

### 수행 과정

#### 1. 의존성 준비와 실제 PCAP 확보

WSL 터미널에서 개발 헤더와 캡처 도구를 설치하였다.

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev tcpdump
cd /home/wnsgur/seKUrity/pcap-analyzer
bash capture-real.sh
```

작성한 스크립트는 관리자 인증 후 `eth0`에서 30초간 캡처하였다.  
캡처 필터는 다음과 같다.

```text
host 1.1.1.1 and (tcp port 80 or udp port 53 or icmp)
```

캡처 준비가 끝난 뒤 `http://1.1.1.1/`에 HTTP 연결을 시도하고,  
`1.1.1.1:53`으로 `example.com A` DNS 질의를 보낸 후 ping을 3회 실행하였다.  
DNS 메시지는 Python UDP 소켓으로 전송했으며, 운영체제가 실제 송수신한 패킷을 tcpdump가 파일에 기록하였다.

Linux의 `any` 장치는 Ethernet과 다른 cooked 헤더를 제공할 수 있다.  
따라서 `eth0`를 지정하고 실제 캡처 로그의 `link-type EN10MB (Ethernet)`을 확인하였다.  
분석기에서도 `pcap_datalink()`의 반환값을 검사하여 지원하지 않는 링크 유형은 거부한다.

캡처 시각은 2026-09-20 21:20:40~21:21:10 +0900이며, 생성된 파일은 다음과 같다.

```text
captures/real-20260920-212040-SwqNBO/traffic.pcap
```

캡처 로그에는 10개 패킷 저장, 필터 수신 10개, 커널 드롭 0개가 기록되었다.  
원본 파일은 1,070바이트이며 SHA-256을 저장하고 다시 대조하였다.  
이후 명령의 캡처 폴더명은 이번 실행에서 생성된 값이므로 재실행할 때는 새로 출력되는 경로를 사용해야 한다.

#### 2. 레코드를 읽고 헤더를 직접 해석하기

파일 앞 24바이트를 직접 확인한 결과, 버전 2.4·little-endian·마이크로초 단위·Ethernet 캡처였다.  
그다음 `pcap_open_offline_with_tstamp_precision()`으로 파일을 열고 `pcap_next_ex()`로 레코드를 순서대로 읽었다.

반환값 `1`은 패킷, `PCAP_ERROR_BREAK`는 정상 EOF, `PCAP_ERROR`는 오류이다.  
패킷 메모리는 libpcap이 관리하므로 다음 레코드를 읽기 전에 해석한다.  
[pcap_next_ex 문서](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap_next_ex.3pcap)에서 반환값과 버퍼 수명을 확인하였다.

네트워크 헤더는 구조체로 캐스팅하지 않고 바이트를 직접 조합하였다. 아래는 핵심 코드 발췌이다.

```c
static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
```

예를 들어 `00 50`은 포트 80이다. 읽기 전에 `caplen` 안에 해당 필드가 있는지 검사해야 한다.

#### 3. 고정 길이로 가정하지 않기

```c
size_t ihl = (size_t)(ip[0] & 0x0fU) * 4;
size_t total = be16(ip + 2);
size_t header = (size_t)(transport[12] >> 4) * 4;
```

위 발췌의 `ihl`은 IPv4 헤더 길이, `header`는 TCP 헤더 길이이다.  
실제 구현은 최소 길이와 남은 캡처 바이트를 확인한 후 필드를 읽고, 선언된 길이가 상위 계층의 데이터 범위를 넘으면 거부한다.

첫 SYN은 **Ethernet 14 + IPv4 20 + TCP 40 = 74바이트**였다.  
TCP 옵션 때문에 TCP 헤더가 40바이트이며, 20바이트로 고정하면 옵션을 데이터로 잘못 읽는다.  
UDP는 Length를 검사하고, ICMP는 Type·Code와 Echo의 Identifier·Sequence를 읽었다. IP 단편은 재조립하지 않아 전송 헤더 해석을 건너뛴다.

#### 4. 빌드와 패킷별 출력

일반 빌드에는 C11, `-Wall -Wextra -Wpedantic -Wconversion -Wshadow` 경고 옵션을 적용하였다.  
`make sanitize`에서는 AddressSanitizer와 UndefinedBehaviorSanitizer를 추가하였다.

```bash
make all sanitize
./build/pcap-analyzer captures/real-20260920-212040-SwqNBO/traffic.pcap > results/analysis.txt
./build/pcap-analyzer --hex captures/real-20260920-212040-SwqNBO/traffic.pcap > results/analysis-hex.txt
```

`--hex`는 각 패킷의 앞 96바이트까지 오프셋과 함께 출력한다.  
일반 출력에서는 출발지·목적지, 헤더 길이, TCP Flags, UDP Length, ICMP Type·Code를 확인하였다.

![실제 PCAP의 Ethernet·IPv4·TCP·UDP·ICMP 헤더 분석 결과](/assets/images/pcap-analyzer/01-packet-headers.png)

1번 패킷의 TCP SYN, 2번의 RST·ACK, 3번의 UDP 질의, 4번의 ICMP 오류가 순서대로 보인다.  
출력의 `header=40`은 TCP 헤더 길이이며, IPv4 헤더 길이는 별도의 `ihl=20`이다.

#### 5. 프로토콜별 통계와 대조

분류는 TCP, UDP, ICMP, 기타 IPv4, 비IPv4, 미분류 중 하나로 정하였다.  
각 레코드는 한 분류에만 더하므로 분류별 개수의 합은 전체 패킷 수와 같다.  
`malformed`, `truncated`, `fragments`는 별도 속성이며 프로토콜 분류와 중복될 수 있다.

| 분류 | C 분석기 | tcpdump 별도 필터링 |
| ---- | -------: | ------------------: |
| 전체 |       10 |                  10 |
| TCP  |        2 |                   2 |
| UDP  |        1 |                   1 |
| ICMP |        7 |                   7 |

다음 명령으로 tcpdump의 패킷 상세 정보와 프로토콜별 출력을 얻었다.

```bash
tcpdump -nn -tt -S -vvv -r captures/real-20260920-212040-SwqNBO/traffic.pcap
tcpdump -nn -tt -r captures/real-20260920-212040-SwqNBO/traffic.pcap 'ip proto 6'
tcpdump -nn -tt -r captures/real-20260920-212040-SwqNBO/traffic.pcap 'ip proto 17'
tcpdump -nn -tt -r captures/real-20260920-212040-SwqNBO/traffic.pcap 'ip proto 1'
```

각 출력에서 캡처 시각으로 시작하는 레코드를 세어 C 결과와 대조하였다.  
ICMP 오류 메시지 안에 인용된 UDP 데이터그램은 별도 캡처 레코드가 아니므로 UDP 수에 다시 더하지 않았다.  
전체 10개 패킷의 순서와 시각도 일치하였다.

![첫 번째 PCAP의 기본 통계와 tcpdump 대조 결과](/assets/images/pcap-analyzer/02-statistics-verification.png)

캡처 길이와 원본 길이의 합계는 각각 886바이트였다.  
전역 헤더 24바이트와 레코드 헤더 160바이트를 더하면 실제 PCAP 파일 크기인 1,070바이트가 된다.

```text
24 + (16 × 10) + 886 = 1,070바이트
```

이 값은 파일 및 캡처 레코드 기준이며 물리 계층의 모든 전송 오버헤드를 포함하는 것은 아니다.

---

### 분석 결과 보고서

#### 첫 번째 PCAP: 실패 응답도 통신의 결과이다

| 패킷 | 관찰                                                     | 해석                              |
| ---- | -------------------------------------------------------- | --------------------------------- |
| 1~2  | `172.24.31.89:45262 → 1.1.1.1:80` SYN, 반대 방향 RST·ACK | TCP 연결 수립 실패                |
| 3~4  | 목적지 UDP 53 질의, ICMP type 3/code 3                   | DNS 질의 뒤 Port Unreachable 수신 |
| 5~10 | Echo Request/Reply 세 쌍                                 | ping 3회 성공                     |

TCP의 응답 ACK 2952802683은 SYN SEQ 2952802682보다 1 크다.  
두 TCP 패킷 모두 데이터 길이가 0이고 curl도 종료 코드 7을 기록했으므로, HTTP 메시지를 교환하기 전에 연결이 거절된 것이다.

DNS 내용은 C 분석기의 범위 밖이므로 tcpdump와 클라이언트 로그를 대조하였다.  
`example.com A` 질의의 ID는 54658이며, 뒤따른 ICMP에 인용된 원래 IP ID와 UDP 포트가 질의 패킷과 일치하였다.  
이름 해석은 성공하지 않았고 클라이언트도 `ConnectionRefusedError`를 기록하였다.

반면 ICMP Echo는 Identifier 36093과 Sequence 1·2·3이 각각 대응했다.  
**ping 성공은 TCP 80이나 UDP 53 서비스의 성공을 보장하지 않는다.** 거절 응답을 실제로 생성한 장비는 이 캡처만으로 확정할 수 없다.

#### 첫 번째 PCAP에 추가 통계 적용

```text
TCP_FLAGS: SYN=1 RST=1 ACK=1 (나머지 0)
TOP_TALKERS:
  1.1.1.1       packets=5 ipv4_bytes=377
  172.24.31.89  packets=5 ipv4_bytes=369
DESTINATION_PORTS:
  TCP 80=1, TCP 45262=1, UDP 53=1
```

위 블록은 실제 추가 출력의 핵심 값을 축약한 것이다.  
RST·ACK는 두 Flag에 각각 집계되고, 서버 응답의 목적지인 임시 포트 45262도 나타난다.  
Top Talkers의 바이트 합계 746은 Ethernet 헤더 140바이트를 제외한 값이므로, 기존 캡처 바이트 886과 다르다.

---

#### 두 번째 PCAP: 225개 패킷으로 비교하기

`capture-more.sh`로 외부 HTTPS 요청과 DNS 질의, ping을 발생시키며 90초간 다시 캡처하였다.  
두 번째 파일은 225개 패킷으로 첫 파일의 22.5배이다. 합성하거나 첫 파일을 복제한 결과가 아니다.

```bash
./build/pcap-analyzer captures/larger-20260920-234145-JWptnA/traffic.pcap > results/revision-2/second-analysis.txt
python3 verify-stats.py captures/larger-20260920-234145-JWptnA/traffic.pcap
```

![두 번째 PCAP의 TCP Flag·Top Talkers·목적지 포트 통계](/assets/images/pcap-analyzer/03-extended-statistics.png)

위 화면은 확장한 프로그램의 실제 출력이다. 프로토콜 개수와 추가 통계 모두 tcpdump와 대조하여 일치를 확인하였다.

| 항목             | 첫 번째 PCAP | 두 번째 PCAP |
| ---------------- | -----------: | -----------: |
| 전체 패킷        |           10 |          225 |
| TCP / UDP / ICMP |    2 / 1 / 7 | 133 / 9 / 83 |
| 캡처 바이트      |          886 |       83,566 |
| SYN / FIN / RST  |    1 / 0 / 1 |  12 / 12 / 0 |
| PSH / ACK        |        0 / 1 |     52 / 127 |

TCP 흐름을 주소·포트로 나누어 확인하니, 6개 흐름 모두 SYN → SYN·ACK → ACK가 관찰되었다.  
**SYN=12는 연결 12개가 아니다.** 6개 흐름의 SYN과 SYN·ACK가 각각 포함된 값이다.  
HTTPS 요청 6회의 HTTP 200은 curl 로그로 확인했다. C 분석기가 암호화된 HTTP 응답을 해독한 것은 아니다.

**Top Talkers — 출발지 패킷 수 기준**

| 출발지 IPv4   | 패킷 수 | IPv4 바이트 |
| ------------- | ------: | ----------: |
| 172.24.31.89  |     118 |      18,114 |
| 104.18.25.232 |      34 |      37,539 |
| 104.20.23.154 |      27 |      20,881 |
| 1.1.1.1       |      23 |       1,935 |
| 8.8.8.8       |      23 |       1,947 |

로컬 호스트의 패킷 수가 가장 많지만, 바이트는 `www.iana.org`에 접속한 `104.18.25.232`가 가장 많았다.  
같은 트래픽이라도 패킷 수와 바이트 중 어느 기준을 쓰는지에 따라 순위가 달라진다.

**목적지 포트**는 TCP 443에 72개, TCP 임시 포트 6개에 합계 61개였다.  
UDP 53은 질의 6개이며, 응답 목적지 임시 포트 3개에 각각 1개씩 기록되었다. 전체 포트 통계 142개는 TCP 133 + UDP 9와 같다.

DNS는 `8.8.8.8`에 보낸 3회가 응답을 받았고, `1.1.1.1`에 보낸 3회는 ICMP Port Unreachable을 받았다.  
ping은 각 대상에 20회씩 성공하였다. 따라서 ICMP 83개는 Echo 요청·응답 80개와 DNS 관련 오류 3개의 합이다.

---

### 검증 결과와 남은 한계

기본 통계·패킷 순서·시각에 더해 새 Flag·Top Talkers·포트 통계도 `verify-stats.py`로 tcpdump와 대조하였다.  
첫 10개와 두 번째 225개 파일 모두 통계 대조와 메모리 검사(ASan·UBSan·LeakSanitizer)를 통과하였다. 일반 빌드와 GCC 정적 분석도 통과하였다.

지원 범위는 classic PCAP + Ethernet + IPv4이다. IPv6 해석, IP 단편·TCP 스트림 재조립, 체크섬 검증은 하지 않는다.  
송신 체크섬 불일치는 tcpdump에서 관찰했지만 오프로딩 등 실제 원인은 확인하지 않았다.  
실제 캡처에 없는 VLAN·손상 헤더 분기까지 검증한 것으로 일반화하지 않는다.

---
