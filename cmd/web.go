package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
)

//go:embed webapp
var webAppFiles embed.FS

type algorithmResponse struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Tag   string `json:"tag"`
}

type encryptRequest struct {
	Algorithm string `json:"algorithm"`
	Text      string `json:"text"`
}

type encryptResponse struct {
	Algorithm  string `json:"algorithm"`
	Ciphertext string `json:"ciphertext"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func runWeb(stdout, stderr io.Writer, addr string) int {
	handler, err := newWebHandler()
	if err != nil {
		fmt.Fprintf(stderr, "error preparing web arcade: %v\n", err)
		return 1
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(stderr, "error starting web arcade: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "crypt4kids browser arcade")
	fmt.Fprintf(stdout, "Listening on http://%s\n", listener.Addr())
	fmt.Fprintln(stdout, "Press Ctrl-C to stop.")

	server := &http.Server{Handler: handler}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "error serving web arcade: %v\n", err)
		return 1
	}

	return 0
}

func newWebHandler() (http.Handler, error) {
	staticFiles, err := fs.Sub(webAppFiles, "webapp")
	if err != nil {
		return nil, fmt.Errorf("open embedded web app: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/algorithms", handleAlgorithms)
	mux.HandleFunc("/api/encrypt", handleEncrypt)
	mux.Handle("/", http.FileServer(http.FS(staticFiles)))

	return mux, nil
}

func handleAlgorithms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	algorithms := make([]algorithmResponse, 0, len(arcadeAlgorithms))
	for _, alg := range arcadeAlgorithms {
		algorithms = append(algorithms, algorithmResponse{
			Key:   alg.key,
			Title: alg.title,
			Tag:   alg.tag,
		})
	}

	writeJSON(w, http.StatusOK, algorithms)
}

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	defer r.Body.Close()

	var request encryptRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid encryption request"})
		return
	}

	algorithm := normalizeAlgorithm(request.Algorithm)
	writeJSON(w, http.StatusOK, encryptResponse{
		Algorithm:  algorithm,
		Ciphertext: encodeString(algorithm, request.Text),
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
