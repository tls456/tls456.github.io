---
title: Over The Wire Bandit Level 8 -> Level 9
date: 2026-05-15 10:43:00 +0900
categories: [블로그/기술문서, Bandit]
tags: [Linux, Unix, Bandit]
---
## 문제
[Bandit Level 8 -> Level 9](https://overthewire.org/wargames/bandit/bandit9.html)

## 풀이 과정
[블로그](https://websecurity.tistory.com/80)를 참고하여 `sort`로 정렬 후 `uniq`로 중복 제거 (반드시 정렬 후에 진행해야 한다.)

```
sort [-옵션] [-o 저장될 파일명] 정렬할 파일명 [-m 병합할 파일명....]
```

-  -n: 라인의 각 필드를 비교하는 대상을 숫자로 한정 
-  -f: 영어를 정렬할 때, 대소문자 구별안함 
-  -r: 출력 순서를 역순으로 
-  -b: 앞에 붙는 공백 무시
-  -t: 필드 구분자 지정
-  -m: 정렬된 파일을 병합
-  -u: 정렬후, 중복행 제거
-  -o: 저장할 파일명을 명시, 명시하지 않으면 화면에 출력
---
```
uniq [-옵션] [파일명]
```
-  -c: 같은 라인이 몇번 나오는지를 표시
-  -d: 중복되어 나오는 라인 중 한 라인만 표시 
-  -D: 중복되는 모든 라인을 보여준다. 
-  -N: 필터링은 무시할 라인을 정한다. 시작 라인부터 N번째 라인까지는 검사하지 않는다.
-  -i:  중복 라인을 한라인으로 생각하고 출력한다.
-  -u: 중복 라인이 없는 것만 보여준다.
-  -w: N번째 문자까지만 비교대상으로 하여 uniq 명령을 수행
-  -s: N번째 문자까지는 비교대상에서 제외하고 uniq 명령을 수행
-  -f: N번째 필드를 비교대상에서 제외하고 uniq명령을 수행

![image18](/assets/images/Bandit/18.png)