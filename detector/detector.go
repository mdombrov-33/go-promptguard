package detector

import "context"

// Detector interface - every detector implements this interface
type Detector interface {
	Detect(ctx context.Context, input string) Result
}
