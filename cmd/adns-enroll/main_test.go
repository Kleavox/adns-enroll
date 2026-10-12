package main

import (
	"errors"
	"testing"
	"time"
)

func TestAFailedReconcileIsTriedAgainSoon(t *testing.T) {
	if wait := pause(errors.New("adguard clients: timeout")); wait != 30*time.Second {
		t.Fatalf("after a failure: %v", wait)
	}
	if wait := pause(nil); wait != 10*time.Minute {
		t.Fatalf("after a success: %v", wait)
	}
}
