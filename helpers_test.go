package caddywaf

import (
	"os"
	"testing"
)

func TestFileExists(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty path",
			path: "",
			want: false,
		},
		{
			name: "non-existent file",
			path: "/path/to/nonexistent/file",
			want: false,
		},
		{
			name: "existing file",
			path: tmpFile.Name(),
			want: true,
		},
		{
			name: "directory",
			path: os.TempDir(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileExists(tt.path); got != tt.want {
				t.Errorf("fileExists() = %v, want %v", got, tt.want)
			}
		})
	}
}
