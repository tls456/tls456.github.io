---
title: Over The Wire Bandit Level 12 -> Level 13
date: 2026-05-15 11:15:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 12 -> Level 13](https://overthewire.org/wargames/bandit/bandit13.html)

## 풀이 과정
mktemp -d 명령어를 사용하여 temp 디렉토리를 만들고, cp 명령어를 사용하여 data.txt를 복사, mv 명령어로 이름을 변경하였다.  

![image24](/assets/images/Bandit/24.png)

헥스(16진수) 파일 덤프 복구 명령어 사용  
`xxd -r data.txt > data.bin`: data.txt를 복구 후 data.bin에 저장

---
그 이후 압축된 파일 형식에 맞게 확장자를 변경 후 압축 해제를 반복하였다. 

`file filename` 으로 압축형태 확인

`tar -xf file.bin`

`gzip -d file.gz`

`bzip2 -d file.bz2`

![image25](/assets/images/Bandit/25.png)
![image26](/assets/images/Bandit/26.png)
