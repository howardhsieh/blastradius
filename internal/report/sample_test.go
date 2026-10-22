package report

import (
	"os"
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// TestWriteSample dumps the fixture report when BLASTRADIUS_SAMPLE is set,
// so the README example comes from the real renderer.
func TestWriteSample(t *testing.T) {
	path := os.Getenv("BLASTRADIUS_SAMPLE")
	if path == "" {
		t.Skip("set BLASTRADIUS_SAMPLE=<file> to write the sample report")
	}
	_, res := fullScan(t)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Table(f, res, TableOptions{MinSeverity: cred.Low}); err != nil {
		t.Fatal(err)
	}
}
