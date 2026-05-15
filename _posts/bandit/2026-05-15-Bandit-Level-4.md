---
title: Over The Wire Bandit Level 3 -> Level 4
date: 2026-05-15 10:03:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 3 -> Level 4](https://overthewire.org/wargames/bandit/bandit4.html)

## 풀이 과정
다음 레벨의 비밀번호는 inhere 디렉토리의 숨겨진 파일에 저장된다고 친절히 알려준다. 
inhere 디렉토리로 이동하여 `ls`로 목록을 확인해 봤지만 아무것도 없었다.  
Tab 자동완성을 활용하여 숨겨진 파일을 찾았다.
![image7](/assets/images/Bandit/7.png)

## 숨겨진 파일 확인 방법
- Linux에서 파일/경로를 숨기고자 할 때 파일명 앞에 점(.)을 찍는다.  
- 숨겨진 파일/경로를 확인하기 위해 `ls` 명령어에 `-a` 옵션을 추가한다.   
- `ls -a`: 현재 경로에서 모든 결과를 무시하지 않고 출력 (전부 출력)
![image8](/assets/images/Bandit/8.png)
![image9](/assets/images/Bandit/9.png)