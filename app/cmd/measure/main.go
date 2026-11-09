// Command measure runs D1b's real-model experiment ONCE, as pre-registered.
//
//	make measure-dry-run    # free: print the three arms' requests, no key, no network
//	read -rs MODEL_API_KEY && export MODEL_API_KEY
//	MODEL_BASE_URL=https://api.anthropic.com make measure
//
// Reads MODEL_API_KEY and MODEL_BASE_URL (both required: the key goes
// only where someone named, D1b), optionally MODEL_NAME, and no
// vendor-named variable. Every design parameter comes from the
// experiment directory's preregistration.json. Refuses to run when:
//   - the experiment or the harness has uncommitted changes (the design
//     that ran must be the design that was committed -- TM D5);
//   - a run already exists in runs/ (the experiment runs once);
//   - MODEL_NAME is set and differs from the pre-registered model.
//
// Never in CI, never in attacks/ (D1b, D1c).
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/ddbatista/brokenbazaar/app/measure"
)

// Paths whose uncommitted changes would mean the run is not the
// pre-registered design: the harness, the assemblers the arms are built
// from, and -- added at run time -- the experiment's own directory.
var guarded = []string{"app/measure", "app/cmd/measure", "app/agent", "app/store", "app/go.mod", "app/go.sum", "Makefile",
	"experiments/03-injection-compliance/README.md"} // 03b's design is written there

func main() {
	dir := flag.String("dir", "../experiments/03-injection-compliance", "experiment directory")
	dry := flag.Bool("dry-run", false, "print each arm's request and exit (no key, no network)")
	flag.Parse()

	in, err := measure.LoadInputs(filepath.Join(*dir, "document.json"))
	check(err)
	p, err := measure.LoadPrereg(filepath.Join(*dir, "preregistration.json"))
	check(err)

	if *dry {
		for _, arm := range p.Arms {
			spans, err := measure.Spans(arm, in)
			check(err)
			req, err := measure.Render(spans, in, p)
			check(err)
			body, err := measure.WireBody(p, req)
			check(err)
			var out bytes.Buffer
			check(json.Indent(&out, body, "", "  "))
			fmt.Printf("== arm %s (%s)\n%s\n\n", arm, p.Protocol, out.String())
		}
		fmt.Printf("dry run: %d arms x %d trials = %d requests to %s would be sent\n",
			len(p.Arms), p.NPerArm, len(p.Arms)*p.NPerArm, p.Model)
		return
	}

	key := os.Getenv("MODEL_API_KEY")
	if name := os.Getenv("MODEL_NAME"); name != "" && name != p.Model {
		fail("MODEL_NAME=%s differs from the pre-registered model %s", name, p.Model)
	}
	base := os.Getenv("MODEL_BASE_URL")
	client, err := measure.NewClientFor(p, base, key) // refuses an unset base URL (D1b)
	check(err)

	root, err := filepath.Abs(filepath.Join(*dir, "..", ".."))
	check(err)
	expDir, err := filepath.Abs(*dir)
	check(err)
	expRel, err := filepath.Rel(root, expDir)
	check(err)
	if dirty := git(root, append([]string{"status", "--porcelain", "--", expRel}, guarded...)...); dirty != "" {
		fail("uncommitted changes to the experiment or harness -- commit the design before running it:\n%s", dirty)
	}
	runs := filepath.Join(*dir, "runs")
	if existing, _ := filepath.Glob(filepath.Join(runs, "*.jsonl")); len(existing) > 0 {
		fail("a run already exists (%s) -- the experiment runs once (preregistration.json, \"reruns\")", existing[0])
	}
	commit := git(root, "rev-parse", "HEAD")

	stamp := time.Now().UTC().Format("20060102T150405Z")
	runPath := filepath.Join(runs, stamp+".jsonl")
	f, err := os.OpenFile(runPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	check(err)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	total := len(p.Arms) * p.NPerArm
	fmt.Fprintf(os.Stderr, "measure: %s -- %d requests to %s over %s at %s (commit %.12s)\n",
		p.Experiment, total, p.Model, p.Protocol, base, commit)

	sum, runErr := measure.Run(ctx, client, in, p, &progress{w: f, total: total}, key)
	if err := f.Close(); err != nil && runErr == nil {
		runErr = fmt.Errorf("closing the run file: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	if info, _ := os.Stat(runPath); runErr != nil && info != nil && info.Size() == 0 {
		os.Remove(runPath) // aborted before any data: not a run
		fail("%v", runErr)
	}

	summary := map[string]any{
		"commit": commit, "run_file": filepath.Base(runPath), "experiment": p.Experiment, "protocol": p.Protocol,
		"model": p.Model, "effort": p.Effort, "temperature": p.Temperature,
		"anthropic_version": p.AnthropicVersion, "sampling": p.Sampling, "base_url": base,
		"n_per_arm": p.NPerArm, "summary": sum, "completed": runErr == nil,
	}
	if runErr != nil {
		summary["stopped"] = runErr.Error()
	}
	out, _ := json.MarshalIndent(summary, "", "  ")
	if measure.ContainsKey(out, key) { // the same exact-key check every run line gets
		fail("refusing to write the summary: it contains MODEL_API_KEY")
	}
	check(os.WriteFile(filepath.Join(runs, stamp+".summary.json"), append(out, '\n'), 0o644))

	fmt.Print(sum.Text())
	fmt.Printf("\nrun file: %s\n", runPath)
	if runErr != nil {
		fail("the run stopped early: %v (the partial run is kept and must be reported, not rerun)", runErr)
	}
}

// progress passes run lines through to the file and prints one mark per
// trial to stderr, so a 150-request run is visibly alive.
type progress struct {
	w     io.Writer
	total int
	done  int
}

func (p *progress) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		var rec struct {
			Arm     string `json:"arm"`
			Outcome struct {
				Kind string `json:"kind"`
			} `json:"outcome"`
		}
		json.Unmarshal(sc.Bytes(), &rec)
		p.done++
		fmt.Fprintf(os.Stderr, "\r  %3d/%d  last: %-8s %-12s", p.done, p.total, rec.Arm, rec.Outcome.Kind)
	}
	return n, err
}

func git(root string, args ...string) string {
	out, err := exec.Command("git", append([]string{"-C", root}, args...)...).Output()
	if err != nil {
		fail("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "measure: "+format+"\n", args...)
	os.Exit(2)
}
