package pdsql

import (
	"testing"

	"github.com/coredns/caddy"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

func TestSetupPdsql(t *testing.T) {
	c := caddy.NewTestController("dns", `pdsql sqlite3 :memory:`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pdsql sqlite3 :memory: {
}`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pdsql sqlite3 :memory: {
debug db
}`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pdsql sqlite`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pdsql sqlite3 :memory: {
unknown
}`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pdsql sqlite3 :memory: {
debug
unknown
}`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `pdsql sqlite3 :memory: {
debug
} invalid`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}
}
