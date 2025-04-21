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
