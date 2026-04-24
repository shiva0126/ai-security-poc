package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(v)
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// ── Summary ───────────────────────────────────────────────────────────────

func apiSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dbGetSummary(r.URL.Query().Get("run_id")))
}

// ── Findings ──────────────────────────────────────────────────────────────

func apiFindings(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	findings, err := dbGetFindings(r.URL.Query().Get("run_id"), limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if findings == nil {
		findings = []Finding{}
	}
	writeJSON(w, findings)
}

// ── Runs ──────────────────────────────────────────────────────────────────

func apiRuns(w http.ResponseWriter, r *http.Request) {
	runs, _ := dbGetRuns(50)
	if runs == nil {
		runs = []ScanRun{}
	}
	writeJSON(w, runs)
}

// ── Services ──────────────────────────────────────────────────────────────

func apiServices(w http.ResponseWriter, r *http.Request) {
	svcs, _ := dbGetServices(r.URL.Query().Get("run_id"))
	if svcs == nil {
		svcs = []ServiceCheck{}
	}
	writeJSON(w, svcs)
}

// ── Assets ────────────────────────────────────────────────────────────────

func apiAssets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		assets, _ := dbListAssets()
		if assets == nil {
			assets = []Asset{}
		}
		writeJSON(w, assets)
	case http.MethodPost:
		var a Asset
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.ID = newID()
		if err := dbCreateAsset(a); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, a)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func apiAssetByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/assets/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a, err := dbGetAsset(id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, a)
	case http.MethodDelete:
		if err := dbDeleteAsset(id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ── Policies ──────────────────────────────────────────────────────────────

func apiPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies, _ := dbListPolicies()
		if policies == nil {
			policies = []Policy{}
		}
		writeJSON(w, policies)
	case http.MethodPost:
		var p Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		p.ID = newID()
		if err := dbCreatePolicy(p); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, p)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func apiPolicyByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/policies/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		if err := dbDeletePolicy(id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "method not allowed", 405)
	}
}

// ── Audit ─────────────────────────────────────────────────────────────────

func apiAudit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries, _ := dbGetAuditLog(200)
		if entries == nil {
			entries = []AuditEntry{}
		}
		writeJSON(w, entries)
	case http.MethodPost:
		var e AuditEntry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		dbLogAudit(e.AssetID, e.PolicyID, e.Action, e.ToolUsed, e.Payload, e.Result, e.Status)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ── MITRE ─────────────────────────────────────────────────────────────────

func apiMITRECounts(w http.ResponseWriter, r *http.Request) {
	counts := dbMITRECounts()
	if counts == nil {
		counts = map[string]int{}
	}
	writeJSON(w, counts)
}

func apiMITRECatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, mitreCatalog)
}
