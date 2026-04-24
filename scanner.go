package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func sseWrite(w http.ResponseWriter, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func apiScanStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	assetID := r.URL.Query().Get("asset_id")
	tests := r.URL.Query().Get("tests")
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	b, _ := json.Marshal(map[string]string{"run_id": runID, "asset_id": assetID})
	sseWrite(w, "start", string(b))

	// Resolve test script path — prefer TEST_DIR env, fall back to ./test
	testDir := os.Getenv("TEST_DIR")
	if testDir == "" {
		testDir = "test"
	}

	var script string
	switch tests {
	case "11", "injection":
		script = testDir + "/11_malicious_injection.py"
	case "quick":
		script = testDir + "/run_tests.py"
	default:
		script = testDir + "/run_tests.py"
	}

	env := append(os.Environ(),
		"RUN_ID="+runID,
		"ASSET_ID="+assetID,
	)
	// Pass through a subset selector when caller specifies a single test
	if tests != "" && tests != "all" && tests != "quick" && tests != "11" && tests != "injection" {
		env = append(env, "TEST_NUM="+tests)
	}

	cmd := exec.CommandContext(r.Context(), "python3", script)
	cmd.Env = env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		eb, _ := json.Marshal(map[string]string{"message": err.Error()})
		sseWrite(w, "error", string(eb))
		return
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		eb, _ := json.Marshal(map[string]string{"message": err.Error()})
		sseWrite(w, "error", string(eb))
		return
	}

	// Stream stdout line by line
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		lb, _ := json.Marshal(sc.Text())
		sseWrite(w, "log", string(lb))
	}

	// Drain stderr
	if stderr != nil {
		sc2 := bufio.NewScanner(stderr)
		for sc2.Scan() {
			lb, _ := json.Marshal("[stderr] " + sc2.Text())
			sseWrite(w, "log", string(lb))
		}
	}

	cmd.Wait()

	if assetID != "" {
		dbTouchAsset(assetID)
	}

	rb, _ := json.Marshal(map[string]string{"run_id": runID})
	sseWrite(w, "done", string(rb))
}

func apiRunTests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())
	writeJSON(w, map[string]string{
		"run_id": runID,
		"stream": "/api/scan/stream?run_id=" + runID,
	})
}
