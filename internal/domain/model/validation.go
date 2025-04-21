package model

// ValidationResult는 파일 검증 결과를 나타내는 값 객체
type ValidationResult struct {
	// FilePath는 검증된 파일의 상대 경로
	FilePath string

	// IsValid는 파일이 유효한지 여부
	IsValid bool

	// ErrorMessage는 검증 실패 시 오류 메시지
	ErrorMessage string
}

// FileHash는 파일의 해시 정보를 나타내는 값 객체
type FileHash struct {
	// PathHash는 파일 경로의 해시
	PathHash string

	// DataHash는 파일 내용의 해시
	DataHash string

	// FileType는 파일 유형 (f: 일반 파일)
	FileType string
}
