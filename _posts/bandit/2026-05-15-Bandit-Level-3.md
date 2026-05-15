---
title: Over The Wire Bandit Level 2 -> Level 3
date: 2026-05-15 09:51:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 2 -> Level 3](https://overthewire.org/wargames/bandit/bandit3.html)

## 풀이 과정
space(공백) escape sequence가 문제이지만 `Tab`을 이용한 자동완성으로 손쉽게 풀었다. 
![image5](/assets/images/Bandit/5.png)

## 다른 풀이 방법
### 1. escape sequence 직접 작성  
당연히 이스케이프 문자를 직접 작성하여 출력할 수 있다. (작성 결과는 같다.)

### 2. 따옴표(") 사용
따옴표로 파일명을 묶어 공백을 자유롭게 사용할 수 있다.  
-- 가 있기 때문에 옵션으로 인식하지 않도록 앞에 경로 명시는 동일하게 해줘야 한다. 
![image6](/assets/images/Bandit/6.png)