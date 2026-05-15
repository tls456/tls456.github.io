---
title: Over The Wire Bandit Level 20 -> Level 21
date: 2026-05-15 18:43:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 20 -> Level 21](https://overthewire.org/wargames/bandit/bandit21.html)

## 풀이 과정
`ls -al`로 확인 시 Level 20과 같은 형태의 권한을 가진 파일 "suconnect"이 있었다. 
![image51](/assets/images/Bandit/51.png)

도움말을 보기 위해 인자 없이 실행
![image52](/assets/images/Bandit/52.png)

localhost를 TCP를 이용하여 접속 후 반대편에서 받은 비밀번호가 올바르면, 다음 비밀번호를 전송해주는 프로그램이다.  

사용 명령어 목록 중 tmux가 있어서 두 개의 터미널을 사용해야 한다는 힌트를 얻었고,  
한쪽에서 이전 레벨 패스워드를 보내고, 다른 한 쪽에서 suconnect를 실행했다. 
![image53](/assets/images/Bandit/53.png)
- 이전 레벨 비밀번호 `echo`
- `-lp` 옵션으로 localhost에서 listen 모드로 포트 오픈
- 다른 터미널에서 suconnect 실행