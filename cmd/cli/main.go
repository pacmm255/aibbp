package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/db"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/queue"
)

var cfgFile string

func main() {
	rootCmd := &cobra.Command{
		Use:   "aibbp",
		Short: "AI Bug Bounty Platform - Orchestrate autonomous security testing",
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./configs/config.yaml)")

	rootCmd.AddCommand(
		initCmd(),
		scanCmd(),
		statusCmd(),
		findingsCmd(),
		costsCmd(),
		migrateCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() *config.Config {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}
	return cfg
}

// ── init command ──────────────────────────────────────────────────────

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [program-handle]",
		Short: "Initialize a new bug bounty program",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()
			ctx := context.Background()

			database, err := db.New(ctx, cfg.Database)
			if err != nil {
				log.Fatal().Err(err).Msg("connect to database")
			}
			defer database.Close()

			repo := db.NewRepository(database)

			program := &models.Program{
				Platform: "hackerone",
				Handle:   args[0],
				Name:     args[0],
				Status:   "active",
				ScopeRaw: json.RawMessage("{}"),
			}

			if err := repo.CreateProgram(ctx, program); err != nil {
				log.Fatal().Err(err).Msg("create program")
			}

			fmt.Printf("Program initialized: %s (ID: %s)\n", program.Handle, program.ID)
		},
	}
}

// ── scan command ─────────────────────────────────────────────────────

func scanCmd() *cobra.Command {
	var programID string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Start a scan for a program",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()
			ctx := context.Background()

			pID, err := uuid.Parse(programID)
			if err != nil {
				log.Fatal().Err(err).Msg("invalid program ID")
			}

			natsClient, err := queue.NewClient(ctx, cfg.NATS)
			if err != nil {
				log.Fatal().Err(err).Msg("connect to NATS")
			}
			defer natsClient.Close()

			publisher := queue.NewPublisher(natsClient)

			// Publish initial recon tasks
			scanners := []models.ScannerType{
				models.ScannerSubfinder,
				models.ScannerHTTPX,
				models.ScannerNuclei,
			}

			for _, st := range scanners {
				task := models.NewTaskMessage(pID, models.TaskTypeScan, "")
				task.Scanner = st

				if err := publisher.Publish(ctx, queue.TaskScanSubject(string(st)), task, task.ID.String()); err != nil {
					log.Error().Err(err).Str("scanner", string(st)).Msg("publish scan task")
					continue
				}
				fmt.Printf("Queued %s scan for program %s\n", st, pID)
			}
		},
	}

	cmd.Flags().StringVarP(&programID, "program", "p", "", "Program ID to scan")
	cmd.MarkFlagRequired("program")

	return cmd
}

// ── status command ───────────────────────────────────────────────────

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current scan status",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()

			natsClient, err := queue.NewClient(context.Background(), cfg.NATS)
			if err != nil {
				log.Fatal().Err(err).Msg("connect to NATS")
			}
			defer natsClient.Close()

			fmt.Println("NATS: connected")
			fmt.Println("Status: OK")
		},
	}
}

// ── findings command ─────────────────────────────────────────────────

func findingsCmd() *cobra.Command {
	var programID string

	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List vulnerabilities for a program",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()
			ctx := context.Background()

			pID, err := uuid.Parse(programID)
			if err != nil {
				log.Fatal().Err(err).Msg("invalid program ID")
			}

			database, err := db.New(ctx, cfg.Database)
			if err != nil {
				log.Fatal().Err(err).Msg("connect to database")
			}
			defer database.Close()

			repo := db.NewRepository(database)

			vulns, err := repo.GetVulnerabilities(ctx, pID, models.VulnStatusValidated)
			if err != nil {
				log.Fatal().Err(err).Msg("get vulnerabilities")
			}

			if len(vulns) == 0 {
				fmt.Println("No validated findings yet.")
				return
			}

			for _, v := range vulns {
				fmt.Printf("[%s] %s - %s (confidence: %d%%)\n",
					v.Severity, v.Type, v.Title, v.Confidence)
			}
		},
	}

	cmd.Flags().StringVarP(&programID, "program", "p", "", "Program ID")
	cmd.MarkFlagRequired("program")

	return cmd
}

// ── costs command ────────────────────────────────────────────────────

func costsCmd() *cobra.Command {
	var programID string

	cmd := &cobra.Command{
		Use:   "costs",
		Short: "Show API cost tracking for a program",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := loadConfig()
			ctx := context.Background()

			pID, err := uuid.Parse(programID)
			if err != nil {
				log.Fatal().Err(err).Msg("invalid program ID")
			}

			database, err := db.New(ctx, cfg.Database)
			if err != nil {
				log.Fatal().Err(err).Msg("connect to database")
			}
			defer database.Close()

			repo := db.NewRepository(database)

			total, err := repo.GetTotalCost(ctx, pID)
			if err != nil {
				log.Fatal().Err(err).Msg("get costs")
			}

			fmt.Printf("Total API cost: $%.4f / $%.2f budget\n", total, cfg.Budget.TotalDollars)
		},
	}

	cmd.Flags().StringVarP(&programID, "program", "p", "", "Program ID")
	cmd.MarkFlagRequired("program")

	return cmd
}

// ── migrate command ──────────────────────────────────────────────────

func migrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		Run: func(cmd *cobra.Command, args []string) {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			cfg := loadConfig()

			if err := db.RunMigrations(cfg.Database.DSN(), "migrations"); err != nil {
				log.Fatal().Err(err).Msg("migration failed")
			}
			fmt.Println("Migrations applied successfully.")
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "down",
		Short: "Rollback last migration",
		Run: func(cmd *cobra.Command, args []string) {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
			cfg := loadConfig()

			if err := db.RollbackMigration(cfg.Database.DSN(), "migrations"); err != nil {
				log.Fatal().Err(err).Msg("rollback failed")
			}
			fmt.Println("Migration rolled back.")
		},
	})

	return cmd
}
