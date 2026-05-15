---
title: Over The Wire Bandit Level 10 -> Level 11
date: 2026-05-15 11:09:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 10 -> Level 11](https://overthewire.org/wargames/bandit/bandit11.html)

## 풀이 과정
data.txt가 base64 인코딩 되어있다. 문제 설명에 나온 명령어 중 `base64` 명령어 사용

`base64 -d file.txt`: file.txt 디코딩

![image22](/assets/images/Bandit/22.png)