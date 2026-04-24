package main

import (
	"embed"
	"log"
	"net/http"
	"os"
)

//go:embed index.html
var staticFS embed.FS

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "data/findings.db"
	}
	initDB(dbPath)

	mux := http.NewServeMux()

	mux.HandleFunc("/", serveIndex)

	// Summary, findings, runs, services
	mux.HandleFunc("/api/summary", apiSummary)
	mux.HandleFunc("/api/findings", apiFindings)
	mux.HandleFunc("/api/runs", apiRuns)
	mux.HandleFunc("/api/services", apiServices)

	// Assets CRUD
	mux.HandleFunc("/api/assets", apiAssets)
	mux.HandleFunc("/api/assets/", apiAssetByID)

	// Policies CRUD
	mux.HandleFunc("/api/policies", apiPolicies)
	mux.HandleFunc("/api/policies/", apiPolicyByID)

	// Audit log
	mux.HandleFunc("/api/audit", apiAudit)

	// MITRE
	mux.HandleFunc("/api/mitre-counts", apiMITRECounts)
	mux.HandleFunc("/api/mitre-catalog", apiMITRECatalog)

	// Scanner / SSE
	mux.HandleFunc("/api/scan/stream", apiScanStream)
	mux.HandleFunc("/api/run-tests", apiRunTests)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9002"
	}
	log.Printf("AI Security Platform listening on :%s  db=%s", port, dbPath)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	content, err := staticFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "index.html not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}
