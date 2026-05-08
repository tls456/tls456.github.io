---
title: Learn Git Branching 풀이
date: 2026-05-8 08:54:00 +0900
categories: [개발]
tags: [Git]
---
## 개요
[Learn Git Branching](https://learngitbranching.js.org/?locale=ko) 사이트에서 모든 미션을 클리어하며 배운 Git 명령어에 대해서 정리한다.  
해당 사이트는 다음과 같이 오른쪽에 목표 구조를 보여주고, 명령어를 실행하여 실시간으로 반영되는 모습을 시각적으로 보여준다. 
![image1](/assets/images/LearnGitBranching/1.png)
## 1. git commit
```bash
git commit: 커밋을 생성합니다.

# 커밋은 Git 저장소에 현재 디렉토리의 모든 파일을 스냅샷하여 기록하는 것과 같다.

git commit --amend : 가장 최근의 커밋을 수정
```

## 2. git branch
```bash
git branch <브랜치명>: 새 브랜치 생성

git branch -u <원격 브랜치> <브랜치명>: <브랜치명>이 <원격 브랜치>를 추적하게 설정 
# 브랜치명 생략 시 현재 브랜치로 설정

원격 브랜치 <remote name>/<branch name> : 원격 저장소의 상태를 반영하여 원격과 로컬의 차이 파악에 도움
# 체크아웃 시 별도의 HEAD로 이동 (원격 브랜치에서 작업 불가)
# 다른 곳에서 작업 후 원격 저장소에 공유 -> 원격 브랜치 갱신
```

## 3. git checkout
```bash
git checkout <브랜치명>: 브랜치로 이동

git checkout -b <브랜치명>: 새 브랜치를 생성하고 이동

git checkout -b <브랜치명> <원격 브랜치> : 새 브랜치를 생성하고 <원격 브랜치>를 추적
```

## 4. git merge
```bash
git merge <브랜치명>: 현재 브랜치에 <브랜치명>을 병합

# 병합 이력이 보존됨
```

## 5. git rebase
```bash
git rebase <브랜치명>: 현재 브랜치의 베이스 커밋을 <브랜치명>으로 재설정

# 한 줄로 병합하는 느낌

git rebase <브랜치1> <브랜치2>: 현재 위치와 무관하게 브랜치2의 베이스 커밋을 브랜치1로 재설정
# git checkout <브랜치2>; git rebase <브랜치1> 과 동일

git rebase -i <대상>: <대상> 커밋을 대상으로 인터렉티브 리베이스 대화창 열기
# <대상> 커밋들의 순서 변경, 제거, 병합을 UI를 통해 가능
```

## 6. HEAD
```bash
HEAD: 현재 체크아웃된(작업중인) 커밋

^ : 상위 커밋으로 이동 # e.g., HEAD^
# 부모가 여럿일 경우 ^ 뒤에 숫자로 숫자번째 부모를 선택 (생략시 첫 번째 선택)

~<num> : num번 위의 커밋으로 이동 # e.g., HEAD~4
```

## 7. git reset
```bash
git reset <커밋 ID>: <커밋 ID>로 이동

# 히스토리를 고쳐쓰기 때문에 다른 사람이 작업하는 리모트 브랜치에서 사용 불가
```

## 8. git revert
```bash
git revert <커밋 ID>: <커밋 ID>에서 이루어진 작업을 전부 반대로 수행 (되돌리기)

# 리모트 브랜치에서 사용 가능
```

## 9. git cherry-pick
```bash
git cherry-pick <Commit1> <Commit2> <Commit3>... : 현재 위치 아래에 선택된 커밋을의 복사본 생성
```

## 10. git tag
```bash
git tag <태그명> <커밋 ID>: <커밋 ID> 위치에 <태그명> 태그 생성

# 태그는 브랜치와 달리 변경 불가
```

## 11. git describe
```bash
git describe <ref>: <ref>를 기준으로 <가장 가까운 태그>-<그 태그까지 거리>-<커밋의 해시> 

# 해시: 커밋을 식별하는 고유 ID e.g., C2, f8a3b1c9d2e
```

## 12. git clone
```bash
git clone <원격 저장소 URL>: 원격 저장소의 복사본을 로컬에 생성 # remote 생략 시 origin

remote: 원격 저장소 별명

git clone -o <remote name> <원격 저장소 URL>: 원격 저장소 복사본을 로컬에 생성 후 remote name 정의
```

## 13. git fetch
```bash
git fetch: 원격 저장소에 있지만 로컬에 없는 커밋을 다운로드, 원격 브랜치 위치 업데이트

git fetch <remote> <place>: 원격 저장소 remote의 place에서 로컬로 커밋 불러오기

git fetch <remote> <source>:<destination>: 원격 저장소 source 커밋을 destination으로 불러오기
# source를 생략하면 새 브랜치 생성

# 로컬 상태를 바꾸지 않는다. 
```

## 14. git pull
```bash
git pull: git fetch; git merge 와 동일 (원격 저장소에서 불러온 후 병합)

git pull --rebase: fetch와 merge 대신 rebase로 병합

git pull <remote> <place>: git fetch remote place; git merge remote/place

git pull <remote> <source>:<destination>: 원격의 source를 로컬 destination에 fetch하고, destination이 현재 브랜치면 merge까지 수행
```

## 15. git push
```bash
git push: 원격 저장소로 내보내기
# 로컬 작업을 원격 브랜치의 최신 상태를 기반으로 병합 후 push해야 한다. 

git push <remote> <place>: 현재 로컬에 있는 place 브랜치 내용을 remote의 place로 보내기

git push <remote> <source>:<destination>: 로컬의 source 브랜치를 remote의 destination으로 보내기
# destination이 없을 경우 생성하고 진행
# source 생략 시 해당 브랜치 삭제
```

## 인증
![image2](/assets/images/LearnGitBranching/2.png)
![image3](/assets/images/LearnGitBranching/3.png)