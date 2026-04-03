package logger

import (
	"log"
	"strings"
)

const (
	LevelDebug = 0
	LevelInfo  = 1
	LevelWarn  = 2
	LevelError = 3
)

var level = LevelInfo

func SetLevel(s string) {
	switch strings.ToLower(s) {
	case "debug":
		level = LevelDebug
	case "warn":
		level = LevelWarn
	case "error":
		level = LevelError
	default:
		level = LevelInfo
	}
}

func Debug(format string, args ...interface{}) {
	if level <= LevelDebug {
		log.Printf("DEBUG "+format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if level <= LevelInfo {
		log.Printf("INFO  "+format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if level <= LevelWarn {
		log.Printf("WARN  "+format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if level <= LevelError {
		log.Printf("ERROR "+format, args...)
	}
}
