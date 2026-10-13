// Package scraper runs the fetch pipeline. It only depends on the Source and
// Store interfaces, so it knows nothing about HTTP or SQL.
package scraper

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"hacktivity-scraper/internal/report"
)

// Source is where reports come from (HackerOne).
type Source interface {
	// ListPage returns one page of reports (without markdown). It returns
	// ErrNoMorePages past the last page and ErrUnauthorized on bad credentials.
	ListPage(ctx context.Context, page int, from, to time.Time) ([]report.Report, error)
	// ReportMarkdown fetches the markdown body of a single report.
	ReportMarkdown(ctx context.Context, reportURL string) (string, error)
}

// Store is where reports are saved (SQLite).
type Store interface {
	Exists(ctx context.Context, id int) (bool, error)
	Insert(ctx context.Context, r report.Report) error
}

type Stats struct {
	Inserted int
	Skipped  int
	Failed   int
}

type Scraper struct {
	src     Source
	store   Store
	workers int
}

func New(src Source, store Store, workers int) *Scraper {
	return &Scraper{src: src, store: store, workers: workers}
}

// Run fetches pages concurrently, then saves each new report one at a time.
// It stops when the last page is reached, on an auth error, or when ctx is cancelled.
func (s *Scraper) Run(ctx context.Context, from, to time.Time) (Stats, error) {
	// pagingCtx only controls the page counter. Cancelling it stops us from
	// requesting new pages, but pages already in flight still finish.
	pagingCtx, stopPaging := context.WithCancel(ctx)
	defer stopPaging()

	var (
		fatalOnce sync.Once
		fatalErr  error
	)
	fail := func(err error) {
		fatalOnce.Do(func() { fatalErr = err })
		stopPaging()
	}

	// Producer: hands out page numbers 1, 2, 3, ... until told to stop.
	pages := make(chan int)
	go func() {
		defer close(pages)
		for p := 1; ; p++ {
			select {
			case pages <- p:
			case <-pagingCtx.Done():
				return
			}
		}
	}()

	// Workers: fetch pages and send the reports downstream.
	reports := make(chan report.Report)
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for page := range pages {
				var items []report.Report
				err := retry(ctx, func() (err error) {
					items, err = s.src.ListPage(ctx, page, from, to)
					return err
				})

				switch {
				case err == nil:
					for _, r := range items {
						select {
						case reports <- r:
						case <-ctx.Done():
							return
						}
					}
				case errors.Is(err, ErrUnauthorized):
					log.Println("[!] authentication/authorization issue.")
					fail(err)
				case errors.Is(err, ErrNoMorePages):
					stopPaging()
				case ctx.Err() != nil:
					return
				default:
					log.Printf("[!] page %d failed: %v", page, err)
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(reports)
	}()

	// Consumer: a single goroutine, so SQLite only ever has one writer.
	var stats Stats
	for r := range reports {
		if ctx.Err() != nil {
			continue // cancelled: just drain the channel so workers can exit
		}
		s.process(ctx, r, &stats)
	}

	if fatalErr != nil {
		return stats, fatalErr
	}
	return stats, ctx.Err()
}

func (s *Scraper) process(ctx context.Context, r report.Report, stats *Stats) {
	// Check the database first so we skip the markdown request for known reports.
	exists, err := s.store.Exists(ctx, r.ID)
	if err != nil {
		log.Printf("[!] checking report %d: %v", r.ID, err)
		stats.Failed++
		return
	}
	if exists {
		stats.Skipped++
		return
	}

	var markdown string
	err = retry(ctx, func() (err error) {
		markdown, err = s.src.ReportMarkdown(ctx, r.URL)
		return err
	})
	if err != nil {
		log.Printf("[!] failed to get content for %s: %v", r.URL, err)
		stats.Failed++
		return
	}
	r.Markdown = markdown

	if err := s.store.Insert(ctx, r); err != nil {
		log.Printf("[!] failed to insert report %d: %v", r.ID, err)
		stats.Failed++
		return
	}
	stats.Inserted++
}

const maxAttempts = 5

// retry calls fn, and if it fails with a RateLimitError, waits and tries again.
func retry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err = fn()

		var rl RateLimitError
		if !errors.As(err, &rl) {
			return err
		}

		log.Printf("[!] 429, sleeping %v", rl.RetryAfter)
		select {
		case <-time.After(rl.RetryAfter):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}
