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