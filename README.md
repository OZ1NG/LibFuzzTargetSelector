# LibFuzzTargetSelector

## Intro
- 라이브러리에는 수 많은 함수들이 있습니다. </br>
  때문에 라이브러리를 대상으로 퍼징을 하는 경우, 먼저 어떤 함수를 대상으로 진행을 할지 정해야하는데, 이때 도움을 줄 수 있는 모듈입니다.
- 퍼징 대상 라이브러리의 함수들을 Memory Corruption이 발생할 가능성이 높은 순서대로 순위를 매겨주는 모듈입니다.
- 흥미로운 Memory Reference 접근에 대한 횟수를 카운팅하여 순위를 매깁니다.
- ELF 파일로 바로 사용할 수도 있고 라이브러리로도 사용할 수 있습니다. (Makefile 참고)

## IDEA
- 보통 프로그램에서 주로 나오는 취약점은 Memory Corruption에 대한 것들입니다.
- 그래서 단순하게 다음과 같이 생각하여 만들게 되었습니다.
  - Memory Corruption이 발생한다 
    => Memory Reference가 존재했다 
    => Memory Reference 횟수가 많으면 Memory Corruption이 발생할 가능성이 높을 것이다

## 지원
- 지원 운영체제: Linux
- 지원 타겟 라이브러리 환경: x86, x64
- 대상 라이브러리는 not stripped 파일만 지원합니다. (심볼이 있어야함)
- 꼭 라이브러리 뿐만 아니라 ELF 파일을 대상으로 해도 잘 작동합니다.

## Build
```bash
# Build to ELF
$ make

# Build to Shared Library
$ make libfts.so
```

## Usage
```bash
$ ./fts <library path>
```

## Options

- 추가 예정
