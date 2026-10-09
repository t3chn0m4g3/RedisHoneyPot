package main

import (
	"bytes"
	"testing"
)

func TestEventWriter(t *testing.T) {
	tests := []struct {
		name       string
		withFile   bool
		logStdout  bool
		wantStdout bool
		wantFile   bool
	}{
		{name: "stdout only", withFile: false, logStdout: true, wantStdout: true},
		{name: "file and stdout", withFile: true, logStdout: true, wantStdout: true, wantFile: true},
		{name: "file only", withFile: true, logStdout: false, wantFile: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, file bytes.Buffer
			var w = eventWriter(&stdout, nil, tt.logStdout)
			if tt.withFile {
				w = eventWriter(&stdout, &file, tt.logStdout)
			}
			if _, err := w.Write([]byte("event\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := stdout.Len() > 0; got != tt.wantStdout {
				t.Errorf("stdout written = %v, want %v", got, tt.wantStdout)
			}
			if got := file.Len() > 0; got != tt.wantFile {
				t.Errorf("file written = %v, want %v", got, tt.wantFile)
			}
		})
	}
}
