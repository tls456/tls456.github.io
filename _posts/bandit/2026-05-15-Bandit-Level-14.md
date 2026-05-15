---
title: Over The Wire Bandit Level 13 -> Level 14
date: 2026-05-15 11:33:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 13 -> Level 14](https://overthewire.org/wargames/bandit/bandit14.html)

## 풀이 과정
HINT와 sshkey.private를 확인해봤다. 
![image27](/assets/images/Bandit/27.png)
![image28](/assets/images/Bandit/28.png)

RSA 키를 로컬에 저장  
`scp -P 2220 bandit13@bandit.labs.overthewire.org:~/sshkey.private .` 
![image29](/assets/images/Bandit/29.png)


private key로 ssh 접속하는 명령어  
`ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220`

실행하니 권한이 너무 열려있어 실행할 수 없다고 나온다. 
![image30](/assets/images/Bandit/30.png)

`chmod 600 sshkey.private` 로 권한 변경 후 다시 위 명령어 실행하여 로그인, 문제 설명에 나오는 경로로 비밀번호 획득

![image31](/assets/images/Bandit/31.png)