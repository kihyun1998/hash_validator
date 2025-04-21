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

const (
	SumFileName = "hash_sum.txt" // 해시 검증에 사용할 파일 이름
)

//export ValidateDirectory
func ValidateDirectory(dirPath *C.char) *C.char {
	path := C.GoString(dirPath)

	fileSystem := fsys.NewLocalFileSystem()
	hashValidator := hashval.NewSHA256Validator()
	validationService := validator.NewValidationService(hashValidator, fileSystem)

	results, allValid, err := validationService.ValidateDirectory(path)

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
	} else if !allValid {
		response = Response{
			Success: false,
			Results: results,
		}
	} else {
		response = Response{
			Success: true,
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

	_, allValid, err := validationService.ValidateDirectory(path)

	var validFiles []string
	if err == nil && allValid {
		// 모든 파일이 유효할 경우 디렉토리 내 모든 파일 목록 반환
		fileSystem.WalkDirectory(path, func(metadata model.FileMetadata) error {
			if !metadata.IsDirectory && metadata.RelativePath != SumFileName {
				validFiles = append(validFiles, metadata.RelativePath)
			}
			return nil
		})
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
			Success: allValid,
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
