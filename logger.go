package abtest

import (
	"log"
	"os"
	"sync"
)

// Logger
// 插件禁用了unsafe和syscall，导致很多logger库用不了。
// Ref https://github.com/tomMoulard/fail2ban/blob/main/fail2ban.go#L35-L38 实现了个简单的logger
type Logger struct {
	loggerInfo  *log.Logger
	loggerDebug *log.Logger
	loggerError *log.Logger
}

func (l *Logger) Info(args ...interface{}) {
	l.loggerInfo.Println(args...)
}

func (l *Logger) Debug(args ...interface{}) {
	l.loggerDebug.Println(args...)
}

func (l *Logger) Error(args ...interface{}) {
	l.loggerError.Println(args...)
}

func NewLogger() *Logger {
	return &Logger{
		loggerInfo:  log.New(os.Stdout, "INFO: [AB_TEST] ", log.Ldate|log.Ltime|log.Lshortfile),
		loggerDebug: log.New(os.Stdout, "DEBU: [AB_TEST] ", log.Ldate|log.Ltime|log.Lshortfile),
		loggerError: log.New(os.Stdout, "ERRO: [AB_TEST] ", log.Ldate|log.Ltime|log.Lshortfile),
	}
}

var (
	logger     *Logger
	onceLogger sync.Once
)

func initLogger() {
	onceLogger.Do(func() {
		logger = NewLogger()
	})
}
