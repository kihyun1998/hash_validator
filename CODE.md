# hash_validator
## Project Structure

```
hash_validator/
├── cmd/
    └── validator/
    │   └── main.go
├── internal/
    ├── domain/
    │   ├── model/
    │   │   ├── file.go
    │   │   └── validation.go
    │   └── repository/
    │   │   ├── filesystem.go
    │   │   └── validator.go
    ├── infrastructure/
    │   ├── fsys/
    │   │   └── local_filesystem.go
    │   └── hashval/
    │   │   └── sha256_validator.go
    └── service/
    │   └── validator/
    │       └── validation_service.go
├── lib/
    └── main/
    │   └── validator.go
└── README.md
```

## README.md
```md
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
```
## cmd/validator/main.go
```go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kihyun1998/hash_validator/internal/infrastructure/fsys"
	"github.com/kihyun1998/hash_validator/internal/infrastructure/hashval"
	"github.com/kihyun1998/hash_validator/internal/service/validator"
)

func main() {
	// 명령줄 인자 파싱
	var rootPath string
	flag.StringVar(&rootPath, "path", ".", "검증할 디렉토리 경로")
	flag.Parse()

	// 의존성 초기화
	fileSystem := fsys.NewLocalFileSystem()
	hashValidator := hashval.NewSHA256Validator()

	// 서비스 초기화
	validationService := validator.NewValidationService(hashValidator, fileSystem)

	// 검증 실행
	results, err := validationService.ValidateDirectory(rootPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "오류 발생: %v\n", err)
		os.Exit(1)
	}

	// 결과 출력
	validCount, invalidCount := 0, 0
	for _, result := range results {
		if result.IsValid {
			fmt.Printf("✓ %s: 유효함\n", result.FilePath)
			validCount++
		} else {
			fmt.Printf("✗ %s: 유효하지 않음 - %s\n", result.FilePath, result.ErrorMessage)
			invalidCount++
		}
	}

	// 요약 출력
	totalFiles := len(results)
	fmt.Printf("\n검증 완료: 총 %d개 파일 중 %d개 유효, %d개 유효하지 않음\n",
		totalFiles, validCount, invalidCount)

	// 유효하지 않은 파일이 있으면 오류 코드로 종료
	if invalidCount > 0 {
		os.Exit(2)
	}
}

```
## internal/domain/model/file.go
```go
package model

// FileMetadata는 파일의 메타데이터를 나타내는 값 객체
type FileMetadata struct {
	// RelativePath는 기준 디렉토리로부터의 상대 경로
	RelativePath string

	// Size는 파일의 크기(바이트)
	Size int64

	// IsDirectory는 해당 항목이 디렉토리인지 여부
	IsDirectory bool
}

```
## internal/domain/model/validation.go
```go
package model

// ValidationResult는 파일 검증 결과를 나타내는 값 객체
type ValidationResult struct {
	// FilePath는 검증된 파일의 상대 경로
	FilePath string

	// IsValid는 파일이 유효한지 여부
	IsValid bool

	// ErrorMessage는 검증 실패 시 오류 메시지
	ErrorMessage string
}

// FileHash는 파일의 해시 정보를 나타내는 값 객체
type FileHash struct {
	// PathHash는 파일 경로의 해시
	PathHash string

	// DataHash는 파일 내용의 해시
	DataHash string

	// FileType는 파일 유형 (f: 일반 파일)
	FileType string
}

```
## internal/domain/repository/filesystem.go
```go
package repository

import "github.com/kihyun1998/hash_validator/internal/domain/model"

// IFileSystem은 파일 시스템 작업을 위한 인터페이스
type IFileSystem interface {
	// ReadFile은 지정된 경로의 파일 내용을 읽어옴
	ReadFile(path string) ([]byte, error)

	// WriteFile은 지정된 경로에 데이터를 파일로 저장
	WriteFile(path string, data []byte) error

	// WalkDirectory는 디렉토리를 재귀적으로 순회하며 각 파일에 콜백 함수를 적용
	WalkDirectory(root string, callback func(model.FileMetadata) error) error

	// GetFileInfo는 지정된 경로의 파일 정보를 조회
	GetFileInfo(path string) (model.FileMetadata, error)

	// FileExists는 파일이 존재하는지 확인
	FileExists(path string) bool
}

```
## internal/domain/repository/validator.go
```go
package repository

// IValidator는 해시 검증을 위한 인터페이스
type IValidator interface {
	// ValidateHash는 파일 경로와 데이터에 대한 해시가 기대값과 일치하는지 검증
	ValidateHash(path string, data []byte, expectedPathHash, expectedDataHash string) (bool, error)

	// GeneratePathHash는 파일 경로에 대한 해시를 생성
	GeneratePathHash(path string) (string, error)

	// GenerateDataHash는 파일 데이터에 대한 해시를 생성
	GenerateDataHash(data []byte) (string, error)
}

```
## internal/infrastructure/fsys/local_filesystem.go
```go
package fsys

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kihyun1998/hash_validator/internal/domain/model"
	"github.com/kihyun1998/hash_validator/internal/domain/repository"
)

// LocalFileSystem은 로컬 파일 시스템 구현체
type LocalFileSystem struct{}

// NewLocalFileSystem은 새로운 LocalFileSystem 인스턴스를 생성
func NewLocalFileSystem() repository.IFileSystem {
	return &LocalFileSystem{}
}

func (fs *LocalFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (fs *LocalFileSystem) WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func (fs *LocalFileSystem) WalkDirectory(root string, callback func(model.FileMetadata) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("디렉토리 순회 중 오류: %w", err)
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("상대 경로 계산 실패: %w", err)
		}

		metadata := model.FileMetadata{
			RelativePath: filepath.ToSlash(relPath),
			Size:         info.Size(),
			IsDirectory:  info.IsDir(),
		}

		return callback(metadata)
	})
}

func (fs *LocalFileSystem) GetFileInfo(path string) (model.FileMetadata, error) {
	info, err := os.Stat(path)
	if err != nil {
		return model.FileMetadata{}, fmt.Errorf("파일 정보 조회 실패: %w", err)
	}

	return model.FileMetadata{
		RelativePath: filepath.Base(path),
		Size:         info.Size(),
		IsDirectory:  info.IsDir(),
	}, nil
}

func (fs *LocalFileSystem) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
```
## internal/infrastructure/hashval/sha256_validator.go
```go
package hashval

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/kihyun1998/hash_validator/internal/domain/repository"
)

// SHA256Validator는 SHA-256 해시 검증기 구현체
type SHA256Validator struct{}

// NewSHA256Validator는 새로운 SHA256Validator 인스턴스를 생성
func NewSHA256Validator() repository.IValidator {
	return &SHA256Validator{}
}

// ValidateHash는 파일의 해시 무결성을 검증
func (v *SHA256Validator) ValidateHash(path string, data []byte, expectedPathHash, expectedDataHash string) (bool, error) {
	// 경로 해시 생성
	pathHash, err := v.GeneratePathHash(path)
	if err != nil {
		return false, fmt.Errorf("경로 해시 생성 실패: %w", err)
	}

	// 경로 해시 검증
	if pathHash != expectedPathHash {
		return false, nil
	}

	// 데이터 해시 생성
	dataHash, err := v.GenerateDataHash(data)
	if err != nil {
		return false, fmt.Errorf("데이터 해시 생성 실패: %w", err)
	}

	// 데이터 해시 검증
	return dataHash == expectedDataHash, nil
}

// GeneratePathHash는 경로에 대한 SHA-256 해시를 생성
func (v *SHA256Validator) GeneratePathHash(path string) (string, error) {
	hash := sha256.Sum256([]byte(path))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// GenerateDataHash는 데이터에 대한 SHA-256 해시를 생성
func (v *SHA256Validator) GenerateDataHash(data []byte) (string, error) {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		return "", fmt.Errorf("데이터 해시 생성 실패: %w", err)
	}
	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

```
## internal/service/validator/validation_service.go
```go
package validator

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kihyun1998/hash_validator/internal/domain/model"
	"github.com/kihyun1998/hash_validator/internal/domain/repository"
)

const (
	SumFileName = "hash_sum.txt" // 해시 검증에 사용할 파일 이름
)

// ValidationService는 파일 해시 검증을 담당하는 서비스
type ValidationService struct {
	validator  repository.IValidator
	fileSystem repository.IFileSystem
	hashMap    map[string]model.FileHash // 파일 경로 -> 해시 정보 매핑
}

// NewValidationService는 새로운 ValidationService 인스턴스를 생성
func NewValidationService(
	validator repository.IValidator,
	fs repository.IFileSystem,
) *ValidationService {
	return &ValidationService{
		validator:  validator,
		fileSystem: fs,
		hashMap:    make(map[string]model.FileHash),
	}
}

// ValidateDirectory는 디렉토리 내 파일들의 무결성을 검증
func (s *ValidationService) ValidateDirectory(rootPath string) ([]model.ValidationResult, error) {
	// 결과 저장용 슬라이스
	var results []model.ValidationResult

	// 해시 파일 경로
	sumFilePath := filepath.Join(rootPath, SumFileName)

	// 해시 파일 존재 확인
	if !s.fileSystem.FileExists(sumFilePath) {
		return nil, fmt.Errorf("해시 파일이 존재하지 않음: %s", sumFilePath)
	}

	// 해시 파일 읽기
	hashData, err := s.fileSystem.ReadFile(sumFilePath)
	if err != nil {
		return nil, fmt.Errorf("해시 파일 읽기 실패: %w", err)
	}

	// 해시 데이터 파싱
	if err := s.parseHashFile(string(hashData)); err != nil {
		return nil, err
	}

	// 디렉토리 재귀적 검증
	err = s.fileSystem.WalkDirectory(rootPath, func(metadata model.FileMetadata) error {
		// 해시 파일 자체는 검증 대상에서 제외
		if metadata.RelativePath == SumFileName || metadata.IsDirectory {
			return nil
		}

		// 파일 검증 수행
		result := s.validateFile(rootPath, metadata.RelativePath)
		results = append(results, result)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("디렉토리 검증 중 오류 발생: %w", err)
	}

	// 해시 파일에는 있지만 실제로 존재하지 않는 파일 확인
	for path := range s.hashMap {
		// 이미 검증한 파일은 건너뜀
		found := false
		for _, result := range results {
			if result.FilePath == path {
				found = true
				break
			}
		}

		if !found {
			results = append(results, model.ValidationResult{
				FilePath:     path,
				IsValid:      false,
				ErrorMessage: "파일이 존재하지 않음",
			})
		}
	}

	return results, nil
}

// validateFile은 단일 파일에 대한 해시 검증을 수행
func (s *ValidationService) validateFile(rootPath, relativePath string) model.ValidationResult {
	fullPath := filepath.Join(rootPath, relativePath)

	// 예상 해시 정보 가져오기
	expectedHash, exists := s.hashMap[relativePath]
	if !exists {
		return model.ValidationResult{
			FilePath:     relativePath,
			IsValid:      false,
			ErrorMessage: "해시 정보가 없음",
		}
	}

	// 파일 데이터 읽기
	data, err := s.fileSystem.ReadFile(fullPath)
	if err != nil {
		return model.ValidationResult{
			FilePath:     relativePath,
			IsValid:      false,
			ErrorMessage: fmt.Sprintf("파일 읽기 실패: %v", err),
		}
	}

	// 해시 검증
	isValid, err := s.validator.ValidateHash(relativePath, data, expectedHash.PathHash, expectedHash.DataHash)
	if err != nil {
		return model.ValidationResult{
			FilePath:     relativePath,
			IsValid:      false,
			ErrorMessage: fmt.Sprintf("해시 검증 실패: %v", err),
		}
	}

	if !isValid {
		return model.ValidationResult{
			FilePath:     relativePath,
			IsValid:      false,
			ErrorMessage: "해시가 일치하지 않음",
		}
	}

	return model.ValidationResult{
		FilePath:     relativePath,
		IsValid:      true,
		ErrorMessage: "",
	}
}

// parseHashFile은 해시 파일을 파싱하여 내부 맵에 저장
func (s *ValidationService) parseHashFile(content string) error {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ";")
		if len(parts) != 3 {
			return fmt.Errorf("잘못된 해시 파일 형식: %s", line)
		}

		fileType := parts[0]
		pathHash := parts[1]
		dataHash := parts[2]

		// 🔥 현재는 "." 기준 → 👇 반드시 rootPath 기준이어야 함
		err := s.fileSystem.WalkDirectory(s.rootPath, func(metadata model.FileMetadata) error {
			if metadata.IsDirectory {
				return nil
			}

			calcPathHash, err := s.validator.GeneratePathHash(metadata.RelativePath)
			if err != nil {
				return nil
			}

			if calcPathHash == pathHash {
				s.hashMap[metadata.RelativePath] = model.FileHash{
					FileType: fileType,
					PathHash: pathHash,
					DataHash: dataHash,
				}
			}
			return nil
		})

		if err != nil {
			return fmt.Errorf("파일 경로 매핑 중 오류: %w", err)
		}
	}

	return nil
}

```
## lib/main/validator.go
```go
package main

// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"encoding/json"
	"unsafe"

	"github.com/kihyun1998/hash_validator/internal/domain/model"
	"github.com/kihyun1998/hash_validator/internal/infrastructure/fsys"
	"github.com/kihyun1998/hash_validator/internal/infrastructure/hashval"
	"github.com/kihyun1998/hash_validator/internal/service/validator"
)

//export ValidateDirectory
func ValidateDirectory(dirPath *C.char) *C.char {
	path := C.GoString(dirPath)

	fileSystem := fsys.NewLocalFileSystem()
	hashValidator := hashval.NewSHA256Validator()
	validationService := validator.NewValidationService(hashValidator, fileSystem)

	results, err := validationService.ValidateDirectory(path)

	type Response struct {
		Success bool                     `json:"success"`
		Error   string                   `json:"error,omitempty"`
		Results []model.ValidationResult `json:"results,omitempty"`
	}

	// 전체 파일이 유효한지 체크
	allValid := true
	for _, result := range results {
		if !result.IsValid {
			allValid = false
			break
		}
	}

	var response Response
	if err != nil {
		response = Response{
			Success: false,
			Error:   err.Error(),
		}
	} else {
		response = Response{
			Success: allValid,
			Results: results,
		}
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		jsonData = []byte(`{"success":false,"error":"JSON 마샬링 실패"}`)
	}

	cResult := C.CString(string(jsonData))
	if cResult == nil {
		return C.CString(`{"success":false,"error":"메모리 할당 실패 (C.CString returned nil)"}`)
	}
	return cResult
}

//export FreeString
func FreeString(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export GetValidFiles
func GetValidFiles(dirPath *C.char) *C.char {
	path := C.GoString(dirPath)

	fileSystem := fsys.NewLocalFileSystem()
	hashValidator := hashval.NewSHA256Validator()
	validationService := validator.NewValidationService(hashValidator, fileSystem)

	results, err := validationService.ValidateDirectory(path)

	var validFiles []string
	if err == nil {
		for _, result := range results {
			if result.IsValid {
				validFiles = append(validFiles, result.FilePath)
			}
		}
	}

	type Response struct {
		Success bool     `json:"success"`
		Error   string   `json:"error,omitempty"`
		Files   []string `json:"files,omitempty"`
	}

	var response Response
	if err != nil {
		response = Response{
			Success: false,
			Error:   err.Error(),
		}
	} else {
		response = Response{
			Success: true,
			Files:   validFiles,
		}
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		jsonData = []byte(`{"success":false,"error":"JSON 마샬링 실패"}`)
	}

	cResult := C.CString(string(jsonData))
	if cResult == nil {
		return C.CString(`{"success":false,"error":"메모리 할당 실패 (C.CString returned nil)"}`)
	}
	return cResult
}

func main() {}

```
