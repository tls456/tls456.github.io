---
title: Over The Wire Bandit Level 9 -> Level 10
date: 2026-05-15 10:55:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 9 -> Level 10](https://overthewire.org/wargames/bandit/bandit10.html)

## 풀이 과정
data.txt를 출력하니 다음과 같이 읽을 수 없는 형태로 출력된다. 

![image19](/assets/images/Bandit/19.png)

`grep` 명령어로 ==를 찾으려 했지만 binary 파일이라 실패했다. 
![image20](/assets/images/Bandit/20.png)

`strings` 명령어로 바이너리 파일에서 문자열을 추출하고, `grep`

![image21](/assets/images/Bandit/21.png)