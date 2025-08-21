package logging

// Interface that holds all the neccessary functions for the logger throughout the application
type ILogger interface {
	Info(args ...any)
	Warning(args ...any)
	Error(args ...any)
	Fatal(args ...any)
	Debug(args ...any)
}
