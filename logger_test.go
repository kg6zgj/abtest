package abtest

import (
	"testing"
)

func TestGetLogLevel(t *testing.T) {
	if getLogLevel("DEBUG") != LogLevelDebug {
		t.Failed()
	}
	if getLogLevel("ERROR") != LogLevelError {
		t.Failed()
	}
	if getLogLevel("INFO") != LogLevelInfo{
		t.Failed()
	}
}
