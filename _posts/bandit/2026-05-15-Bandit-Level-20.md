---
title: Over The Wire Bandit Level 19 -> Level 20
date: 2026-05-15 18:39:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 19 -> Level 20](https://overthewire.org/wargames/bandit/bandit20.html)

## 풀이 과정
**setuid**는 set user id의 약자로, 한 파일이나 디랙토리를 사용할때는 그 파일의 소유자 권한으로 실행이 되는것을 의미한다. 

홈 디렉토리에 있는 파일이 setuid file이다.
![image46](/assets/images/Bandit/46.png)

파일 권한 확인
![image47](/assets/images/Bandit/47.png)

bandit19는 그룹 사용자이고, 실행 및 읽기 권한이 있다.  
문제 설명에서 인자없이 실행하여 힌트를 얻으라 했으니 실행해보자.
![image48](/assets/images/Bandit/48.png)

다른 유저로서 명령어가 실행된다고 한다.  
`whoami` 명령어를 그대로 쳐보자.
![image49](/assets/images/Bandit/49.png)

bandit20으로서 명령어가 실행된다.  
문제 설명에 나와있는 경로의 파일을 읽는다. 
![image50](/assets/images/Bandit/50.png)
