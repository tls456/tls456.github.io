---
title: Over The Wire Bandit Level 5 -> Level 6
date: 2026-05-15 10:17:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 5 -> Level 6](https://overthewire.org/wargames/bandit/bandit6.html)

## 풀이 과정

[블로그](https://coding-factory.tistory.com/804)를 참고하여 `fild` 명령어 사용
``` bash
# 현재 디렉토리에서 1024byte인 파일 검색
find . -size 1024c # find [경로] [옵션]
```
- b: 블록단위
- c: byte
- k: kbyte
- w: 2byte (워드)

![image13](/assets/images/Bandit/13.png)