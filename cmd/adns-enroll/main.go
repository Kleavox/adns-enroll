package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/pawl"
	"github.com/Kleavox/adns-enroll/internal/store"
	"github.com/Kleavox/adns-enroll/internal/web"
)

var version = "dev"

const (
	reconcileEvery = 10 * time.Minute
	retryAfter     = 30 * time.Second
	subjectsEvery  = 6 * time.Hour
	subjectsPerAsk = 1000
)

func pause(err error) time.Duration {
	if err != nil {
		return retryAfter
	}
	return reconcileEvery
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		os.Exit(health(os.Getenv("LISTEN")))
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func health(listen string) int {
	if listen == "" {
		listen = ":8080"
	}
	port := listen[strings.LastIndex(listen, ":")+1:]
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	c, missing := load(os.Getenv)
	if len(missing) > 0 {
		return fmt.Errorf("set %s", strings.Join(missing, ", "))
	}
	saved, err := store.Open(c.DataDir)
	if err != nil {
		return err
	}
	if _, err := saved.Read(); err != nil {
		return fmt.Errorf("read %s: %w", store.File, err)
	}
	dns := adguard.New(c.AdGuardURL, c.AdGuardUser, c.AdGuardPassword, nil)
	service := &enroll.Service{Store: saved, DNS: dns, Now: time.Now}
	if err := service.Migrate(); err != nil {
		return fmt.Errorf("move devices to accounts: %w", err)
	}
	for _, note := range c.Retired {
		log.Print(note)
	}
	server := &web.Server{Service: service, AdGuard: dns, Admins: c.Admins, Origin: c.Origin, Missing: c.signInMissing(), Log: log.Printf, Now: time.Now}
	var provider *pawl.Provider
	if server.Missing == "" {
		provider = pawl.New(c.Issuer, c.ClientID, c.ClientSecret, c.Origin+"/auth/callback")
		server.Pawl = provider
		server.Key = c.sessionKey()
	}
	httpServer := &http.Server{
		Addr:              c.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go reconcile(ctx, service)
	if provider != nil {
		go watchSubjects(ctx, service, provider.Live)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	log.Printf("adns-enroll %s listening on %s", version, c.Listen)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func reconcile(ctx context.Context, service *enroll.Service) {
	for {
		err := service.Reconcile(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("reconcile: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause(err)):
		}
	}
}

type liveSubjects func(ctx context.Context, subjects []string) ([]string, error)

func liveRound(ctx context.Context, service *enroll.Service, live liveSubjects) error {
	subjects, err := service.Subjects()
	if err != nil {
		return err
	}
	var still []string
	for chunk := range slices.Chunk(subjects, subjectsPerAsk) {
		known, err := live(ctx, chunk)
		if err != nil {
			return err
		}
		still = append(still, known...)
	}
	return service.EndMissing(ctx, subjects, still)
}

func watchSubjects(ctx context.Context, service *enroll.Service, live liveSubjects) {
	for {
		if err := liveRound(ctx, service, live); err != nil && ctx.Err() == nil {
			log.Printf("ask Pawl which accounts still exist: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(subjectsEvery):
		}
	}
}
