---
title: Over The Wire Bandit Level 14 -> Level 15
date: 2026-05-15 11:40:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 14 -> Level 15](https://overthewire.org/wargames/bandit/bandit15.html)

## 풀이 과정
localhost 30000번 포트에 연결 후 이전 레벨 비밀번호를 입력하면 된다.

nmap으로 로컬호스트 포트 확인
![image32](/assets/images/Bandit/32.png)

30000번 포트 확인, 연결 상태 확인
![image33](/assets/images/Bandit/33.png)

telnet으로 접속 후 이전 비번 입력
![image34](/assets/images/Bandit/34.png)
