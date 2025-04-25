package fileutil

import (
	"path/filepath"
	"strings"
)

// PatternExclusion은 패턴 기반 파일 제외 구현체
type PatternExclusion struct {
	patterns []string
}

// NewPatternExclusion은 새로운 PatternExclusion 인스턴스를 생성
func NewPatternExclusion(defaultPatterns ...string) *PatternExclusion {
	return &PatternExclusion{
		patterns: defaultPatterns,
	}
}

// IsExcluded는 주어진 파일 경로가 제외 패턴에 매칭되는지 확인
func (p *PatternExclusion) IsExcluded(filePath string) bool {
	// 파일명만 추출 (경로 제외)
	baseFileName := filepath.Base(filePath)

	// 모든 패턴에 대해 매칭 검사
	for _, pattern := range p.patterns {
		matched, err := filepath.Match(pattern, baseFileName)
		if err == nil && matched {
			return true
		}

		// 경로 전체에 대한 매칭도 검사 (필요한 경우)
		if strings.Contains(pattern, "/") || strings.Contains(pattern, "\\") {
			matched, err = filepath.Match(pattern, filePath)
			if err == nil && matched {
				return true
			}
		}
	}

	return false
}

// AddPattern은 새로운 제외 패턴을 추가
func (p *PatternExclusion) AddPattern(pattern string) {
	p.patterns = append(p.patterns, pattern)
}
