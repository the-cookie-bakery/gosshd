package logging

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"strings"
	"sync"
)

type Level int

const (
	Debug Level = iota
	Info
	Warning
	Error
)

var (
	mu     sync.Mutex
	level  = Info
	logger = log.New(os.Stderr, "", log.LstdFlags)
	writer *syslog.Writer
)

func ParseLevel(name string) Level {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3":
		return Debug
	case "WARNING", "WARN":
		return Warning
	case "ERROR", "ERR":
		return Error
	default:
		return Info
	}
}

func Configure(levelName, facility string, forceStderr bool) {
	mu.Lock()
	defer mu.Unlock()
	level = ParseLevel(levelName)
	if writer != nil {
		_ = writer.Close()
		writer = nil
	}
	if forceStderr {
		logger.SetOutput(os.Stderr)
		return
	}
	w, err := syslog.New(syslogPriority(facility)|syslog.LOG_INFO, "gosshd")
	if err != nil {
		logger.SetOutput(os.Stderr)
		return
	}
	writer = w
}

func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if writer != nil {
		_ = writer.Close()
		writer = nil
	}
	logger.SetOutput(w)
}

func Debugf(format string, args ...any)   { output(Debug, format, args...) }
func Infof(format string, args ...any)    { output(Info, format, args...) }
func Warningf(format string, args ...any) { output(Warning, format, args...) }
func Errorf(format string, args ...any)   { output(Error, format, args...) }

func output(l Level, format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if l < level {
		return
	}
	message := fmt.Sprintf(format, args...)
	if writer != nil {
		switch l {
		case Debug:
			_ = writer.Debug(message)
		case Warning:
			_ = writer.Warning(message)
		case Error:
			_ = writer.Err(message)
		default:
			_ = writer.Info(message)
		}
		return
	}
	logger.Printf("%s: %s", levelName(l), message)
}

func levelName(l Level) string {
	switch l {
	case Debug:
		return "debug"
	case Warning:
		return "warning"
	case Error:
		return "error"
	default:
		return "info"
	}
}

func syslogPriority(facility string) syslog.Priority {
	switch strings.ToUpper(strings.TrimSpace(facility)) {
	case "AUTHPRIV":
		return syslog.LOG_AUTHPRIV
	case "DAEMON":
		return syslog.LOG_DAEMON
	case "USER":
		return syslog.LOG_USER
	case "LOCAL0":
		return syslog.LOG_LOCAL0
	case "LOCAL1":
		return syslog.LOG_LOCAL1
	case "LOCAL2":
		return syslog.LOG_LOCAL2
	case "LOCAL3":
		return syslog.LOG_LOCAL3
	case "LOCAL4":
		return syslog.LOG_LOCAL4
	case "LOCAL5":
		return syslog.LOG_LOCAL5
	case "LOCAL6":
		return syslog.LOG_LOCAL6
	case "LOCAL7":
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_AUTH
	}
}
