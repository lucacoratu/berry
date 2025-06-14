package logging

import (
	"log"
	"os"
)

// Data class that holds the variables necessary to log the data locally (either in a file or to stdout/stderr)
type Logger struct {
	InternalLogger *log.Logger
	InfoPrefix     string
	WarningPrefix  string
	ErrorPrefix    string
	FatalPrefix    string
	DebugEnabled   bool
	DebugPrefix    string
}

var (
	GreenColor  string = "\x1b[1;32m"
	RedColor    string = "\x1b[1;31m"
	YellowColor string = "\x1b[1;33m"
	ResetColor  string = "\x1b[0m"
)

func NewLogger(infoPrefix string, warningPrefix string, errorPrefix string, fatalPrefix string) *Logger {
	//Create a new logger that will output to stdout
	return &Logger{InternalLogger: log.New(os.Stdout, "[BLUEBERRY] - ", log.Ldate|log.Ltime), InfoPrefix: infoPrefix, WarningPrefix: warningPrefix, ErrorPrefix: errorPrefix, FatalPrefix: fatalPrefix, DebugEnabled: false, DebugPrefix: ""}
}

func NewDebugLogger(infoPrefix string, warningPrefix string, errorPrefix string, fatalPrefix string, debugPrefix string) *Logger {
	return &Logger{InternalLogger: log.New(os.Stdout, "[BLUEBERRY] - ", log.Ldate|log.Ltime), InfoPrefix: infoPrefix, WarningPrefix: warningPrefix, ErrorPrefix: errorPrefix, FatalPrefix: fatalPrefix, DebugEnabled: true, DebugPrefix: debugPrefix}
}

func NewDefaultLogger() *Logger {
	return &Logger{
		InternalLogger: log.New(os.Stdout, "[BLUEBERRY] - ", log.Ldate|log.Ltime),
		InfoPrefix:     GreenColor + "[INFO]" + ResetColor + " -",
		WarningPrefix:  YellowColor + "[WARNING]" + ResetColor + " -",
		ErrorPrefix:    RedColor + "[ERROR]" + ResetColor + " -",
		FatalPrefix:    RedColor + "[FATAL]" + ResetColor + " -",
		DebugEnabled:   false,
		DebugPrefix:    ""}
}

func NewDefaultDebugLogger() *Logger {
	return &Logger{
		InternalLogger: log.New(os.Stdout, "[BLUEBERRY] - ", log.Ldate|log.Ltime),
		InfoPrefix:     GreenColor + "[INFO]" + ResetColor + " -",
		WarningPrefix:  YellowColor + "[WARNING]" + ResetColor + " -",
		ErrorPrefix:    RedColor + "[ERROR]" + ResetColor + "-",
		FatalPrefix:    RedColor + "[FATAL]" + ResetColor + "-",
		DebugEnabled:   true,
		DebugPrefix:    "[DEBUG] -"}
}

func (logger *Logger) Info(args ...any) {
	logger.InternalLogger.Println(logger.InfoPrefix, args)
}

func (logger *Logger) Warning(args ...any) {
	logger.InternalLogger.Println(logger.WarningPrefix, args)
}

func (logger *Logger) Error(args ...any) {
	logger.InternalLogger.Println(logger.ErrorPrefix, args)
}

func (logger *Logger) Fatal(args ...any) {
	logger.InternalLogger.Fatalln(logger.FatalPrefix, args)
}

func (logger *Logger) Debug(args ...any) {
	if logger.DebugEnabled {
		logger.InternalLogger.Println(logger.DebugPrefix, args)
	}
}
