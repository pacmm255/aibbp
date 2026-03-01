package db

import (
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations applies all pending migrations.
func RunMigrations(dsn, migrationsDir string) error {
	source := fmt.Sprintf("file://%s", migrationsDir)
	m, err := migrate.New(source, dsn)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}

	version, dirty, _ := m.Version()
	if dirty {
		return fmt.Errorf("migration version %d is dirty", version)
	}

	return nil
}

// RollbackMigration rolls back the last migration.
func RollbackMigration(dsn, migrationsDir string) error {
	source := fmt.Sprintf("file://%s", migrationsDir)
	m, err := migrate.New(source, dsn)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("rollback migration: %w", err)
	}

	return nil
}
