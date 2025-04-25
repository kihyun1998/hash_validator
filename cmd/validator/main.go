package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kihyun1998/hash_validator/internal/infrastructure/fileutil"
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
	exclusion := fileutil.NewPatternExclusion("unins*.*")

	// 서비스 초기화
	validationService := validator.NewValidationService(hashValidator, fileSystem, exclusion)

	// 검증 실행
	results, allValid, err := validationService.ValidateDirectory(rootPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "오류 발생: %v\n", err)
		os.Exit(1)
	}

	// 결과 출력
	if allValid {
		fmt.Println("모든 파일이 유효합니다.")
	} else {
		fmt.Println("일부 파일이 유효하지 않습니다:")
		for _, result := range results {
			fmt.Printf("  - %s: %s\n", result.FilePath, result.ErrorMessage)
		}

		// 유효하지 않은 파일 개수 출력
		fmt.Printf("\n총 %d개의 유효하지 않은 파일이 발견되었습니다.\n", len(results))
		os.Exit(2)
	}
}
