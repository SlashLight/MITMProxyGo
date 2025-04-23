package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	if err := createTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	return db, nil
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			host TEXT,
			method TEXT,
			path TEXT,
			request_data TEXT,
			response_data TEXT
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create requests table: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sql_injection_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_id INTEGER,
			parameter_type TEXT,
			parameter_name TEXT,
			payload TEXT,
			original_code INTEGER,
			original_len INTEGER,
			test_code INTEGER,
			test_len INTEGER,
			is_vulnerable BOOLEAN,
			FOREIGN KEY (request_id) REFERENCES requests(id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create sql_injection_results table: %v", err)
	}

	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
		CREATE INDEX IF NOT EXISTS idx_requests_host ON requests(host);
		CREATE INDEX IF NOT EXISTS idx_requests_method ON requests(method);
		CREATE INDEX IF NOT EXISTS idx_requests_path ON requests(path);
		CREATE INDEX IF NOT EXISTS idx_sql_injection_request_id ON sql_injection_results(request_id);
		CREATE INDEX IF NOT EXISTS idx_sql_injection_vulnerable ON sql_injection_results(is_vulnerable);
	`)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %v", err)
	}

	return nil
}

func SaveRequest(db *sql.DB, req *Request, resp *Response) error {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	respJSON, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %v", err)
	}

	host := req.Headers["Host"]
	if host == "" {
		url, err := url.Parse("http://" + req.Path)
		if err == nil && url.Host != "" {
			host = url.Host
		} else {
			host = "unknown"
		}
	}

	_, err = db.Exec(`
		INSERT INTO requests (
			timestamp,
			host,
			method,
			path,
			request_data,
			response_data
		) VALUES (?, ?, ?, ?, ?, ?)
	`, time.Now(), host, req.Method, req.Path, string(reqJSON), string(respJSON))

	if err != nil {
		return fmt.Errorf("failed to insert request/response: %v", err)
	}

	return nil
}

func GetRequests(db *sql.DB, limit int, offset int, filters map[string]string) ([]Request, error) {
	query := `
		SELECT request_data 
		FROM requests 
		WHERE 1=1
	`
	args := []interface{}{}

	if host, ok := filters["host"]; ok {
		query += " AND host = ?"
		args = append(args, host)
	}
	if method, ok := filters["method"]; ok {
		query += " AND method = ?"
		args = append(args, method)
	}
	if path, ok := filters["path"]; ok {
		query += " AND path LIKE ?"
		args = append(args, "%"+path+"%")
	}

	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query requests: %v", err)
	}
	defer rows.Close()

	var requests []Request
	for rows.Next() {
		var reqData string
		if err := rows.Scan(&reqData); err != nil {
			return nil, fmt.Errorf("failed to scan request data: %v", err)
		}

		var req Request
		if err := json.Unmarshal([]byte(reqData), &req); err != nil {
			return nil, fmt.Errorf("failed to unmarshal request data: %v", err)
		}

		requests = append(requests, req)
	}

	return requests, nil
}

func GetRequestByID(db *sql.DB, id int) (*Request, *Response, error) {
	var reqData, respData string
	err := db.QueryRow(`
		SELECT request_data, response_data 
		FROM requests 
		WHERE id = ?
	`, id).Scan(&reqData, &respData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query request: %v", err)
	}

	var req Request
	if err := json.Unmarshal([]byte(reqData), &req); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal request data: %v", err)
	}

	var resp Response
	if err := json.Unmarshal([]byte(respData), &resp); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response data: %v", err)
	}

	return &req, &resp, nil
}

func DeleteOldRequests(db *sql.DB, olderThan time.Duration) error {
	_, err := db.Exec(`
		DELETE FROM requests 
		WHERE timestamp < ?
	`, time.Now().Add(-olderThan))
	if err != nil {
		return fmt.Errorf("failed to delete old requests: %v", err)
	}
	return nil
}

func SaveSQLInjectionResults(db *sql.DB, requestID int64, results []SQLInjectionResult) error {
	for _, result := range results {
		_, err := db.Exec(`
			INSERT INTO sql_injection_results (
				request_id,
				parameter_type,
				parameter_name,
				payload,
				original_code,
				original_len,
				test_code,
				test_len,
				is_vulnerable
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, requestID, result.ParameterType, result.ParameterName, result.Payload,
			result.OriginalCode, result.OriginalLen, result.TestCode, result.TestLen, result.IsVulnerable)
		if err != nil {
			return fmt.Errorf("failed to insert SQL injection result: %v", err)
		}
	}
	return nil
}
