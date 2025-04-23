package storage

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Request struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	GetParams  map[string]string `json:"get_params"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	PostParams map[string]string `json:"post_params"`
	Body       string            `json:"body"`
}

type Response struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

type SQLInjectionResult struct {
	ParameterType string
	ParameterName string
	Payload       string
	OriginalCode  int
	OriginalLen   int
	TestCode      int
	TestLen       int
	IsVulnerable  bool
}

type Storage struct {
	db *sql.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := InitDB(dbPath)
	if err != nil {
		return nil, err
	}
	return &Storage{db: db}, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) SaveRequestResponse(req *Request, resp *Response) error {
	return SaveRequest(s.db, req, resp)
}

func (s *Storage) GetRequests(limit int, offset int, filters map[string]string) ([]Request, error) {
	return GetRequests(s.db, limit, offset, filters)
}

func (s *Storage) GetRequestByID(id int) (*Request, *Response, error) {
	return GetRequestByID(s.db, id)
}

func (s *Storage) DeleteOldRequests(olderThan time.Duration) error {
	return DeleteOldRequests(s.db, olderThan)
}
