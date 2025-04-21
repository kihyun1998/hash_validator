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
