package model

// FileMetadata는 파일의 메타데이터를 나타내는 값 객체
type FileMetadata struct {
	// RelativePath는 기준 디렉토리로부터의 상대 경로
	RelativePath string

	// Size는 파일의 크기(바이트)
	Size int64

	// IsDirectory는 해당 항목이 디렉토리인지 여부
	IsDirectory bool
}
