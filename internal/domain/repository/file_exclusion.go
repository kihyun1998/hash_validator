package repository

// IFileExclusion은 파일 제외 패턴을 관리하는 인터페이스
type IFileExclusion interface {
	// IsExcluded는 주어진 파일 경로가 제외 패턴에 매칭되는지 확인
	IsExcluded(filePath string) bool

	// AddPattern은 새로운 제외 패턴을 추가
	AddPattern(pattern string)
}
