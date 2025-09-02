package sloglogger

import (
    "fmt"
    "log/slog"
    "os"
    "strings"
)

// NewLogger creates a slog logger with level and format ("text" or "json").
func NewLogger(level, format string) (*slog.Logger, error) {
    var opts slog.HandlerOptions
    var handler slog.Handler
    var err error

    switch strings.ToLower(level) {
    case "debug":
        opts.Level = slog.LevelDebug
    case "info":
        opts.Level = slog.LevelInfo
    case "warn", "warning":
        opts.Level = slog.LevelWarn
    case "error":
        opts.Level = slog.LevelError
    default:
        opts.Level = slog.LevelInfo
        err = fmt.Errorf("log level not recognized, falling back to info")
    }

    switch strings.ToLower(format) {
    case "json":
        handler = slog.NewJSONHandler(os.Stdout, &opts)
    case "text":
        fallthrough
    default:
        handler = slog.NewTextHandler(os.Stdout, &opts)
        if strings.ToLower(format) != "text" {
            err = fmt.Errorf("log format not recognized, falling back to text")
        }
    }

    return slog.New(handler), err
}

