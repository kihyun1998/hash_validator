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
	validator     repository.IValidator
	fileSystem    repository.IFileSystem
	fileExclusion repository.IFileExclusion
	hashMap       map[string]model.FileHash // 파일 경로 -> 해시 정보 매핑
}

// NewValidationService는 새로운 ValidationService 인스턴스를 생성
func NewValidationService(
	validator repository.IValidator,
	fs repository.IFileSystem,
	exclusion repository.IFileExclusion,
) *ValidationService {
	return &ValidationService{
		validator:     validator,
		fileSystem:    fs,
		fileExclusion: exclusion,
		hashMap:       make(map[string]model.FileHash),
		// rootPath는 ValidateDirectory 호출 시 설정됨
	}
}

// ValidateDirectory는 디렉토리 내 파일들의 무결성을 검증
// 성공 시에는 간단한 결과만, 실패 시에는 자세한 오류 정보를 반환
func (s *ValidationService) ValidateDirectory(rootPath string) ([]model.ValidationResult, bool, error) {
	// 결과 저장용 슬라이스
	var results []model.ValidationResult

	// 해시 파일 경로
	sumFilePath := filepath.Join(rootPath, SumFileName)

	// 해시 파일 존재 확인
	if !s.fileSystem.FileExists(sumFilePath) {
		return nil, false, fmt.Errorf("해시 파일이 존재하지 않음: %s", sumFilePath)
	}

	// 해시 파일 읽기
	hashData, err := s.fileSystem.ReadFile(sumFilePath)
	if err != nil {
		return nil, false, fmt.Errorf("해시 파일 읽기 실패: %w", err)
	}

	// 해시 데이터 파싱
	if err := s.parseHashFile(string(hashData), rootPath); err != nil {
		return nil, false, err
	}

	// 디렉토리 재귀적 검증
	err = s.fileSystem.WalkDirectory(rootPath, func(metadata model.FileMetadata) error {
		// 해시 파일 자체는 검증 대상에서 제외
		if metadata.RelativePath == SumFileName || metadata.IsDirectory {
			return nil
		}

		// 파일 검증 수행
		result := s.validateFile(rootPath, metadata.RelativePath)
		if !result.IsValid {
			results = append(results, result)
		}

		return nil
	})

	if err != nil {
		return nil, false, fmt.Errorf("디렉토리 검증 중 오류 발생: %w", err)
	}

	// 해시 파일에는 있지만, 실제로 존재하지 않는 파일 확인
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
			// 존재하지 않는 파일을 체크하기 위한 추가 검증
			fileFullPath := filepath.Join(rootPath, path)
			if !s.fileSystem.FileExists(fileFullPath) {
				results = append(results, model.ValidationResult{
					FilePath:     path,
					IsValid:      false,
					ErrorMessage: "파일이 존재하지 않음",
				})
			}
		}
	}

	// 결과가 없으면 모든 파일이 유효한 것임
	allValid := len(results) == 0
	return results, allValid, nil
}

// validateFile은 단일 파일에 대한 해시 검증을 수행
func (s *ValidationService) validateFile(rootPath, relativePath string) model.ValidationResult {
	if s.fileExclusion.IsExcluded(relativePath) {
		return model.ValidationResult{
			FilePath:     relativePath,
			IsValid:      true,
			ErrorMessage: "",
		}
	}

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
func (s *ValidationService) parseHashFile(content string, rootPath string) error {
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

		// 현재 rootPath 기준으로 파일을 검색
		err := s.fileSystem.WalkDirectory(rootPath, func(metadata model.FileMetadata) error {
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
