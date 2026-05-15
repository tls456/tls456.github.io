---
title: Over The Wire Bandit Level 16 -> Level 17
date: 2026-05-15 11:47:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 16 -> Level 17](https://overthewire.org/wargames/bandit/bandit17.html)

## 풀이 과정
31000~32000 포트 중 하나의 서버만 자격증명을 수행하고 나머지는 단순 반환만 수행한다고 한다. 

nmap을 특정 포트 범위로 탐색, 서비스 분석 옵션 추가
![image37](/assets/images/Bandit/37.png)
31790번 포트가 ssl/unknown으로 유일하게 echo가 아니다.

SSL이기 때문에 s_client로 접속
![image38](/assets/images/Bandit/38.png)
이전 레벨 비밀번호를 입력하니 KEYUPDATE라는 문구가 출력되었다.

문제 설명을 참고하여 `man openssl-s_client` 명령어로 메뉴얼 확인 
![image39](/assets/images/Bandit/39.png)
맨 앞자리가 k여서 key update가 처리된 것이었다. 

`echo "kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx" | openssl s_client -connect localhost:31790 -quiet` 명령어로 외부에서 전송
![image40](/assets/images/Bandit/40.png)

**RSA 키를 활용해 Level 13 -> Level 14와 같이 접속 후 비밀번호 출력**

vi 편집기로 기존 sshkey.private 텍스트를 수정해 이번 문제의 RSA키로 변경
![image41](/assets/images/Bandit/41.png)

`ssh -i sshkey.private bandit17@bandit.labs.overthewire.org -p 2220` 명령어 실행  
이전 문제와 같은 경로로 이동하여 비밀번호 획득

![image42](/assets/images/Bandit/42.png)
