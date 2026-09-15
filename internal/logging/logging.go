package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type writer struct{ output io.Writer }

func Configure() {
	log.SetFlags(0)
	log.SetOutput(writer{output: os.Stderr})
}

func (w writer) Write(data []byte) (int, error) {
	message := strings.TrimSuffix(string(data), "\n")
	marker := "*"
	if len(message) >= 3 && message[0] == '[' && message[2] == ']' {
		marker, message = message[1:2], strings.TrimSpace(message[3:])
	}
	_, err := fmt.Fprintf(w.output, "[%s] [%s] %s\n", time.Now().Format("1/2 15:04:05"), marker, message)
	return len(data), err
}

func Event(marker, format string, args ...any) {
	log.Printf("[%s] %s", marker, fmt.Sprintf(format, args...))
}
