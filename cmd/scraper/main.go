package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hacktivity-scraper/internal/config"
	"hacktivity-scraper/internal/hackerone"
	"hacktivity-scraper/internal/scraper"
	"hacktivity-scraper/internal/storage/sqlite"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
}

// run does the real work. It's separate from main so that deferred calls
// (closing the DB, etc.) still run before os.Exit.
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Cancelled when the user presses Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	h1 := hackerone.NewClient(cfg.Username, cfg.Token, cfg.RateLimit)
	s := scraper.New(h1, sqlite.NewReportStore(db), cfg.Workers)

	start := time.Now()
	stats, err := s.Run(ctx, cfg.FromDate, start)

	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("inserted: %d | skipped (already stored): %d | failed: %d | duration: %v\n",
		stats.Inserted, stats.Skipped, stats.Failed, time.Since(start).Round(time.Second))

	return err
}
