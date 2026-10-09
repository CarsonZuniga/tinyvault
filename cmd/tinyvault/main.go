package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/carsonzuniga/tinyvault/internal/auth"
	"github.com/carsonzuniga/tinyvault/internal/crypto"
	"github.com/carsonzuniga/tinyvault/internal/store"
	"github.com/carsonzuniga/tinyvault/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "genkey":
		fmt.Println(crypto.GenerateKey())
	case "hash-password":
		runHashPassword()
	case "serve":
		runServe()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: tinyvault <command>

Commands:
  genkey          print a new base64 master key
  hash-password   read a password and print its Argon2id hash
  serve           start the web server`)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tinyvault: "+format+"\n", args...)
	os.Exit(1)
}

func runHashPassword() {
	fd := int(os.Stdin.Fd())
	var pw string
	if term.IsTerminal(fd) {
		pw = promptPassword(fd, "Password: ")
		if promptPassword(fd, "Confirm:  ") != pw {
			fatal("passwords do not match")
		}
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fatal("no password on stdin")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Println(hash)
}

func promptPassword(fd int, label string) string {
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("reading password: %v", err)
	}
	return string(b)
}

type config struct {
	adminHash     string
	dbPath        string
	listen        string
	ipHeader      string
	secureCookies bool
}

func envOrFile(name string) (string, error) {
	if p := os.Getenv(name + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		return strings.TrimSpace(string(b)), err
	}
	return os.Getenv(name), nil
}

func getenv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	hash, err := envOrFile("TINYVAULT_ADMIN_HASH")
	if err != nil {
		fatal("reading admin hash: %v", err)
	}
	if hash == "" {
		fatal("TINYVAULT_ADMIN_HASH or TINYVAULT_ADMIN_HASH_FILE must be set")
	}
	if _, err := auth.VerifyPassword("probe", hash); err != nil {
		fatal("TINYVAULT_ADMIN_HASH is not a valid argon2id hash (generate one with: tinyvault hash-password)")
	}
	secure, err := strconv.ParseBool(getenv("TINYVAULT_SECURE_COOKIES", "false"))
	if err != nil {
		fatal("TINYVAULT_SECURE_COOKIES must be true or false")
	}
	return config{
		adminHash:     hash,
		dbPath:        getenv("TINYVAULT_DB", "/data/tinyvault.db"),
		listen:        getenv("TINYVAULT_LISTEN", ":8080"),
		ipHeader:      os.Getenv("TINYVAULT_IP_HEADER"),
		secureCookies: secure,
	}
}

func runServe() {
	key, err := crypto.LoadMasterKey()
	if err != nil {
		fatal("%v", err)
	}
	cfg := loadConfig()

	st, err := store.Open(cfg.dbPath, key)
	if errors.Is(err, store.ErrWrongKey) {
		fatal("master key does not match the database at %s", cfg.dbPath)
	}
	if err != nil {
		fatal("opening database: %v", err)
	}
	defer st.Close()

	if !cfg.secureCookies {
		log.Print("warning: TINYVAULT_SECURE_COOKIES is false; only use this over plain HTTP on a trusted network")
	}

	authCfg := auth.Config{PasswordHash: cfg.adminHash, SecureCookies: cfg.secureCookies}
	if cfg.ipHeader != "" {
		authCfg.ClientIP = auth.HeaderIP(cfg.ipHeader)
	}

	mux := http.NewServeMux()
	mux.Handle("/", web.New(st, auth.New(authCfg)).Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on %s (db: %s)", cfg.listen, cfg.dbPath)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		fatal("%v", err)
	}
	log.Print("shut down cleanly")
}
