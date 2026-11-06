package config

import (
	"strings"
	"testing"
)

func FuzzParseReader(f *testing.F) {
	f.Add("Port 22\nPasswordAuthentication yes\n")
	f.Add("Match User alice Address 192.0.2.0/24\n    ForceCommand \"echo hi\"\n")
	f.Add("Include missing.conf\n")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseReader(strings.NewReader(data), "fuzz")
	})
}
