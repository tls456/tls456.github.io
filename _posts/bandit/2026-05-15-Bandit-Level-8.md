---
title: Over The Wire Bandit Level 7 -> Level 8
date: 2026-05-15 10:38:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 7 -> Level 8](https://overthewire.org/wargames/bandit/bandit8.html)

## 풀이 과정
data.txt를 출력하니 정말 매우 길다. 

문제 설명을 잘 이해하는게 중요했는데, 100만번째 단어 옆에 있다는 뜻이 아니라 "millionth"라는 단어 옆에 있다는 거였다. 

[data.txt]
![image16](/assets/images/Bandit/16.png)

grep 함수로 "millionth" 탐색
![image17](/assets/images/Bandit/17.png)