package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

const schema = `
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id       TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    label        TEXT,
    asset_id     TEXT,
    total_tests  INTEGER DEFAULT 0,
    passed       INTEGER DEFAULT 0,
    failed       INTEGER DEFAULT 0,
    skipped      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS test_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    test_num    TEXT NOT NULL,
    test_name   TEXT NOT NULL,
    status      TEXT NOT NULL,
    duration_ms INTEGER,
    notes       TEXT,
    timestamp   TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL,
    test_num         TEXT,
    finding_name     TEXT NOT NULL,
    category         TEXT,
    owasp_id         TEXT,
    mitre_id         TEXT,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    severity         TEXT,
    status           TEXT,
    detail           TEXT,
    payload          TEXT,
    response_preview TEXT,
    framework        TEXT,
    remediation      TEXT,
    timestamp        TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS service_checks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    service_name TEXT NOT NULL,
    url          TEXT,
    status       TEXT,
    http_code    INTEGER,
    timestamp    TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE IF NOT EXISTS assets (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL DEFAULT 'llm_endpoint',
    endpoint       TEXT,
    model          TEXT,
    api_key        TEXT,
    vendor         TEXT,
    tags           TEXT DEFAULT '[]',
    description    TEXT,
    created_at     TEXT NOT NULL,
    last_scanned_at TEXT,
    active         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS scan_policies (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    allowed_tools   TEXT DEFAULT '[]',
    denied_tools    TEXT DEFAULT '[]',
    rate_limit_rpm  INTEGER DEFAULT 60,
    require_hitl    INTEGER DEFAULT 0,
    max_tokens      INTEGER DEFAULT 1000,
    session_isolation INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    active          INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS agent_audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    asset_id    TEXT,
    policy_id   TEXT,
    action      TEXT NOT NULL,
    tool_used   TEXT,
    payload     TEXT,
    result      TEXT,
    approved_by TEXT,
    status      TEXT DEFAULT 'completed'
);
`

// migrations adds columns to tables that existed before Go rewrite
var migrations = []string{
	`ALTER TABLE findings ADD COLUMN mitre_id TEXT`,
	`ALTER TABLE findings ADD COLUMN mitre_tactic TEXT`,
	`ALTER TABLE findings ADD COLUMN mitre_technique TEXT`,
	`ALTER TABLE scan_runs ADD COLUMN asset_id TEXT`,
}

func initDB(path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Fatal(err)
	}
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	if _, err = db.Exec(schema); err != nil {
		log.Fatalf("schema: %v", err)
	}
	for _, m := range migrations {
		db.Exec(m) // ignore errors (column already exists)
	}
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// ── Types ─────────────────────────────────────────────────────────────────────

type ScanRun struct {
	RunID       string `json:"run_id"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Label       string `json:"label"`
	AssetID     string `json:"asset_id"`
	TotalTests  int    `json:"total_tests"`
	Passed      int    `json:"passed"`
	Failed      int    `json:"failed"`
	Skipped     int    `json:"skipped"`
}

type Finding struct {
	ID              int    `json:"id"`
	RunID           string `json:"run_id"`
	TestNum         string `json:"test_num"`
	FindingName     string `json:"finding_name"`
	Category        string `json:"category"`
	OWASPID         string `json:"owasp_id"`
	MITREID         string `json:"mitre_id"`
	MITRETactic     string `json:"mitre_tactic"`
	MITRETechnique  string `json:"mitre_technique"`
	Severity        string `json:"severity"`
	Status          string `json:"status"`
	Detail          string `json:"detail"`
	Payload         string `json:"payload"`
	ResponsePreview string `json:"response_preview"`
	Framework       string `json:"framework"`
	Remediation     string `json:"remediation"`
	Timestamp       string `json:"timestamp"`
}

type ServiceCheck struct {
	ID          int    `json:"id"`
	RunID       string `json:"run_id"`
	ServiceName string `json:"service_name"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	HTTPCode    int    `json:"http_code"`
	Timestamp   string `json:"timestamp"`
}

type Asset struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Endpoint      string `json:"endpoint"`
	Model         string `json:"model"`
	APIKey        string `json:"api_key"`
	Vendor        string `json:"vendor"`
	Tags          string `json:"tags"`
	Description   string `json:"description"`
	CreatedAt     string `json:"created_at"`
	LastScannedAt string `json:"last_scanned_at"`
	Active        bool   `json:"active"`
}

type Policy struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	AllowedTools     string `json:"allowed_tools"`
	DeniedTools      string `json:"denied_tools"`
	RateLimitRPM     int    `json:"rate_limit_rpm"`
	RequireHITL      bool   `json:"require_hitl"`
	MaxTokens        int    `json:"max_tokens"`
	SessionIsolation bool   `json:"session_isolation"`
	CreatedAt        string `json:"created_at"`
	Active           bool   `json:"active"`
}

type AuditEntry struct {
	ID         int    `json:"id"`
	Timestamp  string `json:"timestamp"`
	AssetID    string `json:"asset_id"`
	PolicyID   string `json:"policy_id"`
	Action     string `json:"action"`
	ToolUsed   string `json:"tool_used"`
	Payload    string `json:"payload"`
	Result     string `json:"result"`
	ApprovedBy string `json:"approved_by"`
	Status     string `json:"status"`
}

type Summary struct {
	Total      int `json:"total"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Vulnerable int `json:"vulnerable"`
}

// ── Scan runs ─────────────────────────────────────────────────────────────────

func dbGetRuns(limit int) ([]ScanRun, error) {
	rows, err := db.Query(`SELECT run_id,started_at,COALESCE(completed_at,''),COALESCE(label,''),
		COALESCE(asset_id,''),total_tests,passed,failed,skipped
		FROM scan_runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRun
	for rows.Next() {
		var r ScanRun
		if err := rows.Scan(&r.RunID, &r.StartedAt, &r.CompletedAt, &r.Label,
			&r.AssetID, &r.TotalTests, &r.Passed, &r.Failed, &r.Skipped); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// ── Findings ──────────────────────────────────────────────────────────────────

func dbGetFindings(runID string, limit int) ([]Finding, error) {
	var (
		rows *sql.Rows
		err  error
	)
	q := `SELECT id,run_id,COALESCE(test_num,''),finding_name,COALESCE(category,''),
		COALESCE(owasp_id,''),COALESCE(mitre_id,''),COALESCE(mitre_tactic,''),COALESCE(mitre_technique,''),
		COALESCE(severity,''),COALESCE(status,''),COALESCE(detail,''),
		COALESCE(payload,''),COALESCE(response_preview,''),COALESCE(framework,''),COALESCE(remediation,''),timestamp
		FROM findings`
	if runID != "" {
		rows, err = db.Query(q+` WHERE run_id=? ORDER BY timestamp DESC`, runID)
	} else {
		rows, err = db.Query(q+` ORDER BY timestamp DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.RunID, &f.TestNum, &f.FindingName, &f.Category,
			&f.OWASPID, &f.MITREID, &f.MITRETactic, &f.MITRETechnique,
			&f.Severity, &f.Status, &f.Detail, &f.Payload, &f.ResponsePreview,
			&f.Framework, &f.Remediation, &f.Timestamp); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func dbGetSummary(runID string) Summary {
	base := `SELECT COUNT(*) FROM findings`
	cond := ""
	if runID != "" {
		cond = fmt.Sprintf(` WHERE run_id='%s'`, runID)
	}
	and := func(extra string) string {
		if runID != "" {
			return cond + " AND " + extra
		}
		return " WHERE " + extra
	}
	var s Summary
	db.QueryRow(base + cond).Scan(&s.Total)
	db.QueryRow(base + and("severity='Critical'")).Scan(&s.Critical)
	db.QueryRow(base + and("severity='High'")).Scan(&s.High)
	db.QueryRow(base + and("severity='Medium'")).Scan(&s.Medium)
	db.QueryRow(base + and("status='VULNERABLE'")).Scan(&s.Vulnerable)
	return s
}

// ── Service checks ────────────────────────────────────────────────────────────

func dbGetServices(runID string) ([]ServiceCheck, error) {
	var rows *sql.Rows
	var err error
	if runID != "" {
		rows, err = db.Query(`SELECT id,run_id,service_name,COALESCE(url,''),COALESCE(status,''),
			COALESCE(http_code,0),timestamp FROM service_checks WHERE run_id=? ORDER BY service_name`, runID)
	} else {
		rows, err = db.Query(`SELECT id,run_id,service_name,COALESCE(url,''),COALESCE(status,''),
			COALESCE(http_code,0),timestamp FROM service_checks ORDER BY timestamp DESC LIMIT 50`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceCheck
	for rows.Next() {
		var sc ServiceCheck
		if err := rows.Scan(&sc.ID, &sc.RunID, &sc.ServiceName, &sc.URL,
			&sc.Status, &sc.HTTPCode, &sc.Timestamp); err != nil {
			continue
		}
		out = append(out, sc)
	}
	return out, nil
}

// ── Assets ────────────────────────────────────────────────────────────────────

func dbListAssets() ([]Asset, error) {
	rows, err := db.Query(`SELECT id,name,type,COALESCE(endpoint,''),COALESCE(model,''),
		COALESCE(api_key,''),COALESCE(vendor,''),COALESCE(tags,'[]'),
		COALESCE(description,''),created_at,COALESCE(last_scanned_at,''),active
		FROM assets WHERE active=1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var active int
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Endpoint, &a.Model,
			&a.APIKey, &a.Vendor, &a.Tags, &a.Description,
			&a.CreatedAt, &a.LastScannedAt, &active); err != nil {
			continue
		}
		a.Active = active == 1
		out = append(out, a)
	}
	return out, nil
}

func dbGetAsset(id string) (Asset, error) {
	var a Asset
	var active int
	err := db.QueryRow(`SELECT id,name,type,COALESCE(endpoint,''),COALESCE(model,''),
		COALESCE(api_key,''),COALESCE(vendor,''),COALESCE(tags,'[]'),
		COALESCE(description,''),created_at,COALESCE(last_scanned_at,''),active
		FROM assets WHERE id=?`, id).Scan(
		&a.ID, &a.Name, &a.Type, &a.Endpoint, &a.Model,
		&a.APIKey, &a.Vendor, &a.Tags, &a.Description,
		&a.CreatedAt, &a.LastScannedAt, &active)
	a.Active = active == 1
	return a, err
}

func dbCreateAsset(a Asset) error {
	if a.Tags == "" {
		a.Tags = "[]"
	}
	_, err := db.Exec(`INSERT INTO assets (id,name,type,endpoint,model,api_key,vendor,tags,description,created_at,active)
		VALUES (?,?,?,?,?,?,?,?,?,?,1)`,
		a.ID, a.Name, a.Type, a.Endpoint, a.Model, a.APIKey, a.Vendor, a.Tags, a.Description, nowUTC())
	return err
}

func dbDeleteAsset(id string) error {
	_, err := db.Exec(`UPDATE assets SET active=0 WHERE id=?`, id)
	return err
}

func dbTouchAsset(id string) {
	db.Exec(`UPDATE assets SET last_scanned_at=? WHERE id=?`, nowUTC(), id)
}

// ── Policies ──────────────────────────────────────────────────────────────────

func dbListPolicies() ([]Policy, error) {
	rows, err := db.Query(`SELECT id,name,COALESCE(allowed_tools,'[]'),COALESCE(denied_tools,'[]'),
		rate_limit_rpm,require_hitl,max_tokens,session_isolation,created_at,active
		FROM scan_policies WHERE active=1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		var hitl, isolation, active int
		if err := rows.Scan(&p.ID, &p.Name, &p.AllowedTools, &p.DeniedTools,
			&p.RateLimitRPM, &hitl, &p.MaxTokens, &isolation, &p.CreatedAt, &active); err != nil {
			continue
		}
		p.RequireHITL = hitl == 1
		p.SessionIsolation = isolation == 1
		p.Active = active == 1
		out = append(out, p)
	}
	return out, nil
}

func dbCreatePolicy(p Policy) error {
	hitl, isolation := 0, 0
	if p.RequireHITL {
		hitl = 1
	}
	if p.SessionIsolation {
		isolation = 1
	}
	if p.AllowedTools == "" {
		p.AllowedTools = "[]"
	}
	if p.DeniedTools == "" {
		p.DeniedTools = "[]"
	}
	_, err := db.Exec(`INSERT OR REPLACE INTO scan_policies
		(id,name,allowed_tools,denied_tools,rate_limit_rpm,require_hitl,max_tokens,session_isolation,created_at,active)
		VALUES (?,?,?,?,?,?,?,?,?,1)`,
		p.ID, p.Name, p.AllowedTools, p.DeniedTools,
		p.RateLimitRPM, hitl, p.MaxTokens, isolation, nowUTC())
	return err
}

func dbDeletePolicy(id string) error {
	_, err := db.Exec(`UPDATE scan_policies SET active=0 WHERE id=?`, id)
	return err
}

// ── Audit log ─────────────────────────────────────────────────────────────────

func dbGetAuditLog(limit int) ([]AuditEntry, error) {
	rows, err := db.Query(`SELECT id,timestamp,COALESCE(asset_id,''),COALESCE(policy_id,''),
		action,COALESCE(tool_used,''),COALESCE(payload,''),COALESCE(result,''),
		COALESCE(approved_by,''),COALESCE(status,'completed')
		FROM agent_audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AssetID, &e.PolicyID,
			&e.Action, &e.ToolUsed, &e.Payload, &e.Result,
			&e.ApprovedBy, &e.Status); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func dbLogAudit(assetID, policyID, action, tool, payload, result, status string) {
	db.Exec(`INSERT INTO agent_audit_log (timestamp,asset_id,policy_id,action,tool_used,payload,result,status)
		VALUES (?,?,?,?,?,?,?,?)`,
		nowUTC(), assetID, policyID, action, tool, payload, result, status)
}

// ── MITRE counts ──────────────────────────────────────────────────────────────

func dbMITRECounts() map[string]int {
	rows, err := db.Query(`SELECT mitre_id, COUNT(*) FROM findings WHERE mitre_id!='' GROUP BY mitre_id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var cnt int
		if err := rows.Scan(&id, &cnt); err == nil {
			out[id] = cnt
		}
	}
	// Also tally owasp_id as fallback mapping
	owaspRows, _ := db.Query(`SELECT owasp_id, COUNT(*) FROM findings WHERE owasp_id!='' GROUP BY owasp_id`)
	if owaspRows != nil {
		defer owaspRows.Close()
		owaspToMITRE := map[string]string{
			"LLM01": "AML.T0051", "LLM03": "AML.T0020", "LLM06": "AML.T0056",
			"LLM07": "AML.T0051.002", "LLM08": "AML.T0048", "LLM10": "AML.T0025",
		}
		for owaspRows.Next() {
			var oid string
			var cnt int
			if err := owaspRows.Scan(&oid, &cnt); err == nil {
				if mid, ok := owaspToMITRE[oid]; ok {
					out[mid] += cnt
				}
			}
		}
	}
	return out
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
