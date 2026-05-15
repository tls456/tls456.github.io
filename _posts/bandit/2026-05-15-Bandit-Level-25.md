---
title: Over The Wire Bandit Level 24 -> Level 25
date: 2026-05-15 20:36:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 24 -> Level 25](https://overthewire.org/wargames/bandit/bandit25.html)

## 풀이 과정
숫자 4자리 브루트포스하는 shell을 만들고 실행하여 비밀번호를 알아내야 한다.  
아래 사진과 같은 방식으로 이전 Level 비밀번호 + 숫자 4자리를 입력하면 된다.
![image66](/assets/images/Bandit/66.png)  

temp 디렉토리를 생성하고 이동한다. 
![image67](/assets/images/Bandit/67.png)  

vi 편집기로 쉘을 생성한다.   
쉘 내용은 루프를 통해 비밀번호 + 숫자 4자리를 txt파일로 저장하는 코드이다. 
![image68](/assets/images/Bandit/68.png)  

파일 실행 권한을 부여한다. 
![image69](/assets/images/Bandit/69.png)  

다음과 같이 파일이 작성된다.
![image70](/assets/images/Bandit/70.png)  

파일 내용을 전부 30002번 포트로 넘겨준다.  
`cat text.txt | nc localhost 30002`
![image71](/assets/images/Bandit/71.png)  

해당 비밀번호로 Level 25에 잘 접속되는 것을 확인했다.  
![image72](/assets/images/Bandit/72.png)  
