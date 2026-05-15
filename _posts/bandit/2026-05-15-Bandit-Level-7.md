---
title: Over The Wire Bandit Level 6 -> Level 7
date: 2026-05-15 10:34:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 6 -> Level 7](https://overthewire.org/wargames/bandit/bandit7.html)

## 풀이 과정
`find / -group bandit6 -user bandit7 -size 33c` 로  사용자 소유가 bandit7이고 그룹 소유자가 bandit6이고 사이즈가 33바이트인 파일 탐색  

대부분 Permission denied이고 딱 하나만 정상적으로 출력되었다. 

![image14](/assets/images/Bandit/14.png)
![image15](/assets/images/Bandit/15.png)