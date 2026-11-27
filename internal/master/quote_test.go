package master

import (
	"os/exec"
	"strings"
	"testing"
)

// The one place this can go quietly wrong. ssh carries a single command string,
// so the arguments have to survive being joined and split again — including the
// ones with spaces, quotes and semicolons in them.
//
// Each case is run through a real /bin/sh, the same way the far side runs it.
func TestQuoteForShellSurvivesAShell(t *testing.T) {
	cases := []struct {
		name string
		argv []string
	}{
		{"simple", []string{"hello"}},
		{"spaces", []string{"two words"}},
		{"command with its own quoting", []string{"echo a b"}},
		{"single quotes", []string{"it's here"}},
		{"dollars and quotes", []string{`echo '$HOME' "x"`}},
		{"empty argument", []string{""}},
		{"semicolons", []string{"a; rm -rf /"}},
		{"glob", []string{"*"}},
		{"backslashes", []string{`a\b`}},
		{"newline in an argument", []string{"one\ntwo"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Print each argument the shell ends up with, NUL-separated, so the
			// test can see exactly how it was split — including arguments that
			// are empty or contain newlines.
			const script = `for a in "$@"; do printf '%s\0' "$a"; done`
			whole := append([]string{"sh", "-c", script, "sh"}, c.argv...)

			out, err := exec.Command("/bin/sh", "-c", quoteForShell(whole)).Output()
			if err != nil {
				t.Fatalf("running the quoted command: %v", err)
			}

			got := strings.Split(string(out), "\x00")
			if n := len(got); n > 0 && got[n-1] == "" {
				got = got[:n-1]
			}
			if len(got) != len(c.argv) {
				t.Fatalf("the shell saw %d arguments %q, want %d %q", len(got), got, len(c.argv), c.argv)
			}
			for i := range got {
				if got[i] != c.argv[i] {
					t.Fatalf("argument %d became %q, want %q", i, got[i], c.argv[i])
				}
			}
		})
	}
}
