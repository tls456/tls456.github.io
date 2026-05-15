---
title: Over The Wire Bandit Level 23 -> Level 24
date: 2026-05-15 19:36:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 23 -> Level 24](https://overthewire.org/wargames/bandit/bandit24.html)

## 풀이 과정
초기 접근 방법이 Level 22, 23과 같다. 
![image59](/assets/images/Bandit/59.png)

스크립트 내용
- 1분마다 cronjob으로 cd /var/spool/"$myname"/foo 경로로 이동
- cronjob이 실행하면 경로가 cd /var/spool/bandit24/foo
- 경로 안의 파일들 확인, 소유자가 bandit23이면 실행
- 실행 후 파일 삭제

### exploit
temp 디렉토리 안에 디렉토리를 생성한다.
![image60](/assets/images/Bandit/60.png)



vi 편집기로 shell 파일 생성, shell 내부에 비밀번호가 저장된 파일을 읽어서 현재 디렉토리 안의 파일로 복사하는 명령어를 작성한다.
![image61](/assets/images/Bandit/61.png)



shell 파일 실행 권한을 부여한다.
![image62](/assets/images/Bandit/62.png)



temp 디렉토리를 모두에게 접근 허가한다.
![image63](/assets/images/Bandit/63.png)



/var/spool/bandit24/foo 경로로 shell 복사한다.
![image64](/assets/images/Bandit/64.png)



cronjob이 파일을 실행한 후, password 파일의 내용을 확인한다.
![image65](/assets/images/Bandit/65.png)

