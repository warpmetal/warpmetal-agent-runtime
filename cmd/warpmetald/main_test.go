package main

import "testing"

func TestSupportedHostKeyAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm string
		supported bool
	}{
		{algorithm: "ssh-rsa", supported: true},
		{algorithm: "ssh-ed25519", supported: true},
		{algorithm: "ecdsa-sha2-nistp256", supported: true},
		{algorithm: "ecdsa-sha2-nistp384", supported: true},
		{algorithm: "ecdsa-sha2-nistp521", supported: true},
		{algorithm: "ssh-dss"},
		{algorithm: "sk-ssh-ed25519@openssh.com"},
		{algorithm: "unknown"},
	}
	for _, test := range tests {
		t.Run(test.algorithm, func(t *testing.T) {
			if got := supportedHostKeyAlgorithm(test.algorithm); got != test.supported {
				t.Fatalf("supportedHostKeyAlgorithm(%q) = %v, want %v", test.algorithm, got, test.supported)
			}
		})
	}
}
