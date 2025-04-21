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
