package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestIsMountedHandlesMountpointExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		mounted bool
		wantErr bool
	}{
		{name: "mounted", code: 0, mounted: true},
		{name: "not mounted util linux", code: 32},
		{name: "not mounted alternate", code: 1},
		{name: "unexpected failure", code: 2, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			binary := filepath.Join(directory, "nsenter")
			script := fmt.Sprintf("#!/bin/sh\nexit %d\n", test.code)
			if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			previous := nsenterCommand
			nsenterCommand = binary
			t.Cleanup(func() { nsenterCommand = previous })
			mounted, err := isMounted(context.Background(), "/workspace")
			if (err != nil) != test.wantErr || mounted != test.mounted {
				t.Fatalf("isMounted() = %v, %v; want %v, error=%v", mounted, err, test.mounted, test.wantErr)
			}
		})
	}
}

func TestHostPathExistsHandlesTestExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		exists  bool
		wantErr bool
	}{
		{name: "exists", code: 0, exists: true},
		{name: "missing", code: 1},
		{name: "unexpected failure", code: 2, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			binary := filepath.Join(directory, "nsenter")
			script := fmt.Sprintf("#!/bin/sh\nexit %d\n", test.code)
			if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			previous := nsenterCommand
			nsenterCommand = binary
			t.Cleanup(func() { nsenterCommand = previous })
			exists, err := hostPathExists(context.Background(), "/workspace/lost+found")
			if (err != nil) != test.wantErr || exists != test.exists {
				t.Fatalf("hostPathExists() = %v, %v; want %v, error=%v", exists, err, test.exists, test.wantErr)
			}
		})
	}
}
