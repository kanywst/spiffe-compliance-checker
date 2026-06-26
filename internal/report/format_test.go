package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/report"
	"github.com/kanywst/spiffe-compliance-checker/internal/spec"
)

func sampleReport() *report.Report {
	r := &report.Report{Subject: "scc id  spiffe://Example.com/a"}
	r.Pass(spec.IDSchemeSpiffe, "")
	r.Fail(spec.IDTrustDomainLowercase, `trust_domain="Example.com"`)
	r.Fail(spec.IDLengthLimit, "len=9000") // SHOULD -> downgraded to warn
	return r
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"text", "json", "sarif"} {
		if _, err := report.ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q) returned error: %v", ok, err)
		}
	}
	if _, err := report.ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(\"yaml\") should have failed")
	}
}

func TestWriteJSON(t *testing.T) {
	var buf strings.Builder
	if err := sampleReport().WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Subject string `json:"subject"`
		Summary struct {
			Passed, Failed, Warnings int
		} `json:"summary"`
		Assertions []struct {
			Status, Spec, Section, Severity, Text, Detail string
		} `json:"assertions"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Summary.Passed != 1 || got.Summary.Failed != 1 || got.Summary.Warnings != 1 {
		t.Errorf("summary = %+v, want 1/1/1", got.Summary)
	}
	if len(got.Assertions) != 3 {
		t.Fatalf("got %d assertions, want 3", len(got.Assertions))
	}
	// The SHOULD clause must surface as warn, not fail, mirroring the exit code.
	if a := got.Assertions[2]; a.Status != "warn" || a.Severity != "SHOULD" {
		t.Errorf("warn assertion = %+v, want status=warn severity=SHOULD", a)
	}
	if a := got.Assertions[1]; a.Detail == "" {
		t.Errorf("failing assertion should carry a detail, got %+v", a)
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf strings.Builder
	if err := sampleReport().WriteSARIF(&buf); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", got.Version)
	}
	if got.Schema == "" {
		t.Error("$schema must be set")
	}
	if len(got.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(got.Runs))
	}
	run := got.Runs[0]
	if run.Tool.Driver.Name != "scc" {
		t.Errorf("driver name = %q, want scc", run.Tool.Driver.Name)
	}
	// Only the two violations (1 fail + 1 warn) become results; the pass does not.
	if len(run.Results) != 2 {
		t.Fatalf("got %d results, want 2 (pass must not emit a result)", len(run.Results))
	}
	levels := map[string]int{}
	for _, res := range run.Results {
		levels[res.Level]++
		if res.RuleID == "" {
			t.Error("result missing ruleId")
		}
	}
	if levels["error"] != 1 || levels["warning"] != 1 {
		t.Errorf("levels = %v, want one error and one warning", levels)
	}
	// Every result's ruleId must be resolvable against the declared rules.
	declared := map[string]bool{}
	for _, ru := range run.Tool.Driver.Rules {
		declared[ru.ID] = true
	}
	for _, res := range run.Results {
		if !declared[res.RuleID] {
			t.Errorf("result ruleId %q not present in driver.rules", res.RuleID)
		}
	}
}

func TestWriteSARIFLocations(t *testing.T) {
	// A file-backed input carries an Artifact; results must point at it so
	// GitHub Code Scanning can map findings to the file.
	r := sampleReport()
	r.Artifact = "certs/leaf.pem"
	var buf strings.Builder
	if err := r.WriteSARIF(&buf); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	for _, res := range got.Runs[0].Results {
		if len(res.Locations) != 1 {
			t.Fatalf("result has %d locations, want 1", len(res.Locations))
		}
		if uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "certs/leaf.pem" {
			t.Errorf("location uri = %q, want certs/leaf.pem", uri)
		}
	}

	// Without an Artifact, results must omit locations entirely (string/token
	// inputs have no file to point at).
	var noLoc strings.Builder
	if err := sampleReport().WriteSARIF(&noLoc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(noLoc.String(), "physicalLocation") {
		t.Error("a report without Artifact must not emit physicalLocation")
	}
}
