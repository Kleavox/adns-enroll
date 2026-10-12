package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/store"
	"github.com/Kleavox/adns-enroll/internal/web"
)

var version = "dev"

const reconcileEvery = 10 * time.Minute

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
	service := &enroll.Service{Store: saved, DNS: adguard.New(c.AdGuardURL, c.AdGuardUser, c.AdGuardPassword, nil), Now: time.Now}
	server := &web.Server{Service: service, Identity: c.identity(), Admins: c.Admins, DoHHost: c.DoHHost, Log: log.Printf}
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
	tick := time.NewTicker(reconcileEvery)
	defer tick.Stop()
	for {
		if err := service.Reconcile(ctx); err != nil && ctx.Err() == nil {
			log.Printf("reconcile: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
