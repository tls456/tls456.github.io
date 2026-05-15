---
title: Over The Wire Bandit Level 17 -> Level 18
date: 2026-05-15 12:34:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 17 -> Level 18](https://overthewire.org/wargames/bandit/bandit18.html)

## 풀이 과정
문제 설명과 사용 명령어 목록을 보고 diff 명령어를 사용해야겠다 생각했다.  

`diff [옵션] file1 file2`: file1과 file2를 비교하여 차이점을 찾아낸다.  
< 는 file1에만 있는 내용, >는 file2에만 있는 내용을 나타낸다.
![image43](/assets/images/Bandit/43.png)

passwords.new에 있는 내용이 비밀번호라고 했으므로 `x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO`가 비밀번호다.  

그런데 접속해도 ByeBye!가 출력되며 접속이 종료되었다. 
![image44](/assets/images/Bandit/44.png)

문제 설명에 다음 문제를 보면 알 수 있다하니 다음 문제로 넘어가자.