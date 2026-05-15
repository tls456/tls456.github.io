---
title: Over The Wire Bandit Level 22 -> Level 23
date: 2026-05-15 19:33:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 22 -> Level 23](https://overthewire.org/wargames/bandit/bandit23.html)

## 풀이 과정
초반 접근 과정은 Level 22와 유사하다. 
![image56](/assets/images/Bandit/56.png)

스크립트에 있는 파일을 실행하면 현재 사용자가 bandit22이기 때문에, bandit22의 비밀번호가 출력된다. 
![image57](/assets/images/Bandit/57.png)

그렇다면 bandit23의 비밀번호가 복사되는 경로는 mytarget을 저장하는 코드를 실행하여 얻을 수 있다.
![image58](/assets/images/Bandit/58.png)
