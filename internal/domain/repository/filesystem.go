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
