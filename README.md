# hash-validator

파일 시스템의 무결성 검증을 위한 해시 검증 도구입니다. `hash-maker`로 생성된 해시 정보를 바탕으로 파일 시스템의 무결성을 검증합니다.

## 주요 기능

- 디렉토리 내 파일들의 해시 무결성 검증
- 명령줄 인터페이스(CLI) 제공
- DLL 형태로 외부 응용 프로그램에서 활용 가능

## 설치 방법

```bash
git clone https://github.com/kihyun1998/hash-validator.git
cd hash-validator
go build -o hash-validator ./cmd/validator/main.go
```

## 사용 방법

### 1. CLI 도구로 사용

```bash
# 현재 디렉토리 검증
./hash-validator

# 특정 디렉토리 검증
./hash-validator -path "대상/디렉토리/경로"
```

### 2. DLL로 빌드

```bash
# DLL 빌드
go build -buildmode=c-shared -o hash-validator.dll ./lib/main/
```

### 3. DLL 활용 예시 (C++)

```cpp
#include <iostream>
#include "hash-validator.h"

int main() {
    const char* path = ".";
    char* result = ValidateDirectory(path);
    
    std::cout << "Validation result: " << result << std::endl;
    
    // 메모리 해제 (중요!)
    FreeString(result);
    
    return 0;
}
```

## 검증 과정

1. 대상 디렉토리에서 `hash_sum.txt` 파일을 찾습니다.
2. 파일 시스템을 재귀적으로 순회하면서 각 파일에 대한 무결성 검증을 수행합니다.
3. 각 파일에 대해:
   - 파일 경로의 SHA-256 해시를 계산하여 기록된 값과 비교합니다.
   - 파일 내용의 SHA-256 해시를 계산하여 기록된 값과 비교합니다.
4. 검증 결과를 출력합니다.

## 프로젝트 구조

```
hash-validator/
├── cmd/
│   └── validator/
│       └── main.go             # CLI 도구 진입점
├── internal/
│   ├── domain/
│   │   ├── model/              # 도메인 모델
│   │   │   ├── file.go
│   │   │   └── validation.go
│   │   └── repository/         # 저장소 인터페이스
│   │       ├── filesystem.go
│   │       └── validator.go
│   ├── infrastructure/         # 인프라스트럭처 구현
│   │   ├── fsys/
│   │   │   └── local_filesystem.go
│   │   └── hashval/
│   │       └── sha256_validator.go
│   └── service/                # 비즈니스 로직
│       └── validator/
│           └── validation_service.go
└── lib/
    └── main/
        └── validator.go        # DLL 익스포트용 코드
```

## 검증 결과 형식

CLI 도구를 사용할 경우, 각 파일에 대한 검증 결과가 다음과 같이 출력됩니다:

```
✓ 파일1.txt: 유효함
✗ 파일2.txt: 유효하지 않음 - 해시가 일치하지 않음
```

DLL을 통해 반환되는 결과는 JSON 형식으로, 다음과 같은 구조를 갖습니다:

```json
{
  "success": true,
  "results": [
    {
      "FilePath": "파일1.txt",
      "IsValid": true,
      "ErrorMessage": ""
    },
    {
      "FilePath": "파일2.txt",
      "IsValid": false,
      "ErrorMessage": "해시가 일치하지 않음"
    }
  ]
}
```

## 관련 프로젝트

- [hash-maker](https://github.com/kihyun1998/hash-maker): 파일 시스템의 무결성을 보장하기 위한 해시 생성 도구

## 기여하기

버그 리포트, 기능 요청, 풀 리퀘스트를 환영합니다.

## 라이선스

MIT License