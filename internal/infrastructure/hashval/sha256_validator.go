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
