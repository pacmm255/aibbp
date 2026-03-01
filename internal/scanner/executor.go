package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ExecResult holds the result of a subprocess execution.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// ExecCommand runs a command with context timeout and captures output.
func ExecCommand(ctx context.Context, name string, args ...string) (*ExecResult, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Debug().
		Str("cmd", name).
		Strs("args", args).
		Msg("executing scanner command")

	err := cmd.Run()
	duration := time.Since(start)

	result := &ExecResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: duration,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			// Some scanners use non-zero exit codes for valid results
			// (e.g., nmap returns 1 when host is down)
			log.Debug().
				Str("cmd", name).
				Int("exit_code", result.ExitCode).
				Str("stderr", truncate(string(stderr.Bytes()), 500)).
				Dur("duration", duration).
				Msg("command exited with non-zero code")
		} else if ctx.Err() != nil {
			return result, fmt.Errorf("command timed out after %s: %w", duration, ctx.Err())
		} else {
			return result, fmt.Errorf("exec %s: %w", name, err)
		}
	}

	log.Debug().
		Str("cmd", name).
		Int("stdout_bytes", len(result.Stdout)).
		Dur("duration", duration).
		Msg("command completed")

	return result, nil
}

// BinaryAvailable checks if a binary exists in PATH.
func BinaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// truncate shortens a string to max length.
func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
