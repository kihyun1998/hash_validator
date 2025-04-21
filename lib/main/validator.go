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

// ValidateDirectoryCGO는 디렉토리의 무결성을 검증하는 C 호환 함수
//
//export ValidateDirectory
func ValidateDirectory(dirPath *C.char) *C.char {
	path := C.GoString(dirPath)

	// 의존성 초기화
	fileSystem := fsys.NewLocalFileSystem()
	hashValidator := hashval.NewSHA256Validator()

	// 서비스 초기화
	validationService := validator.NewValidationService(hashValidator, fileSystem)

	// 검증 실행
	results, err := validationService.ValidateDirectory(path)

	// 결과를 JSON으로 변환
	type Response struct {
		Success bool                     `json:"success"`
		Error   string                   `json:"error,omitempty"`
		Results []model.ValidationResult `json:"results,omitempty"`
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
			Results: results,
		}
	}

	// JSON으로 마샬링
	jsonData, err := json.Marshal(response)
	if err != nil {
		jsonData = []byte(`{"success":false,"error":"JSON 마샬링 실패"}`)
	}

	// C 문자열로 변환
	cResult := C.CString(string(jsonData))
	return cResult
}

// FreeString은 C에서 할당된 문자열을 해제
//
//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

// GetValidResults는 유효한 파일 목록만 반환하는 C 호환 함수
//
//export GetValidFiles
func GetValidFiles(dirPath *C.char) *C.char {
	path := C.GoString(dirPath)

	// 의존성 초기화
	fileSystem := fsys.NewLocalFileSystem()
	hashValidator := hashval.NewSHA256Validator()

	// 서비스 초기화
	validationService := validator.NewValidationService(hashValidator, fileSystem)

	// 검증 실행
	results, err := validationService.ValidateDirectory(path)

	// 유효한 파일만 필터링
	var validFiles []string
	if err == nil {
		for _, result := range results {
			if result.IsValid {
				validFiles = append(validFiles, result.FilePath)
			}
		}
	}

	// JSON으로 마샬링
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

	// C 문자열로 변환
	cResult := C.CString(string(jsonData))
	return cResult
}

// main 함수는 cgo 요구사항
func main() {}
