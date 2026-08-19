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
			binary := filepath.Join(directory, "mountpoint")
			script := fmt.Sprintf("#!/bin/sh\nexit %d\n", test.code)
			if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory)
			mounted, err := isMounted(context.Background(), "/workspace")
			if (err != nil) != test.wantErr || mounted != test.mounted {
				t.Fatalf("isMounted() = %v, %v; want %v, error=%v", mounted, err, test.mounted, test.wantErr)
			}
		})
	}
}
