package scan

import (
	"fmt"
	"testing"
)

var TestingScanner = &Scanner{
	Description: "Tests common scan functions",
	scan: func(host string) (Grade, Output, error) {
		switch host {
		case "bad.example.com:443":
			return Bad, outputString("bad.com"), nil
		case "Warning.example.com:443":
			return Warning, outputString("Warning.com"), nil
		case "good.example.com:443":
			return Good, outputString("good.com"), nil
		case "skipped.example.com:443/0":
			return Skipped, outputString("skipped"), nil
		default:
			return Grade(-1), outputString("invalid"), fmt.Errorf("scan: invalid grade")
		}
	},
}

var TestingFamily = &Family{
	Description: "Tests the scan_common",
	Scanners: map[string]*Scanner{
		"TestingScanner": TestingScanner,
	},
}

func TestCommon(t *testing.T) {
	if TestingFamily.Scanners["TestingScanner"] != TestingScanner {
		t.FailNow()
	}

	var grade Grade
	var output Output
	var err error

	grade, output, err = TestingScanner.Scan("bad.example.com:443")
	if grade != Bad || output.String() != "bad.com" || err != nil {
		t.FailNow()
	}

	grade, output, err = TestingScanner.Scan("Warning.example.com:443")
	if grade != Warning || output.String() != "Warning.com" || err != nil {
		t.FailNow()
	}

	grade, output, err = TestingScanner.Scan("good.example.com:443")
	if grade != Good || output.String() != "good.com" || err != nil {
		t.FailNow()
	}

	grade, output, err = TestingScanner.Scan("skipped.example.com:443/0")
	if grade != Skipped || output.String() != "skipped" || err != nil {
		t.FailNow()
	}

	_, _, err = TestingScanner.Scan("invalid")
	if err == nil {
		t.FailNow()
	}
}
