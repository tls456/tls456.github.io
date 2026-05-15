---
title: Over The Wire Bandit Level 21 -> Level 22
date: 2026-05-15 19:09:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 21 -> Level 22](https://overthewire.org/wargames/bandit/bandit22.html)

## 풀이 과정
`cron`: 특정 시간에 특정 작업을 하는 데몬  
`crontab`: Cron이라는 데몬이 원하는 시간에 원하는 명령 또는 프로그램 을 수행하도록 명령 리스트를 만드는 것

문제 설명에 나와있는 경로로 가서 파일 확인
![image54](/assets/images/Bandit/54.png)
- "* * * * *"                 -> 실행 시간
- bandit22                   -> 실행할 사용자
- /usr/bin/cronjob_bandit22.sh  -> 실행할 스크립트
- &> /dev/null               -> 출력 버림

실행할 스크립트를 확인해보니 tmp의 특정 경로로 비밀번호를 저장하고 있었다. 
![image55](/assets/images/Bandit/55.png)
