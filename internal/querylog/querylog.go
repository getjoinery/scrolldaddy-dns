package querylog

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"scrolldaddy-dns/internal/logger"
)

// TODO(perf): If profiling shows GC pressure from Entry allocations at high
// query rates, two optimizations to consider:
// 1. Use sync.Pool for Entry structs to avoid per-query heap allocation
// 2. Format the log line on the caller side into a pooled []byte buffer,
//    send pre-formatted bytes through the channel, and have the writer
//    just do file.Write — eliminates both struct allocation and writer-side
//    fmt.Fprintf. See BenchmarkRecord to measure.

// Entry represents a single DNS query log record.
type Entry struct {
	ResolverUID string
	Time        time.Time
	Domain      string
	QType       string
	Result      string
	Reason      string
	Category    string
	Cached      bool
}

// openFile tracks an open file handle and its current size.
type openFile struct {
	f    *os.File
	size int64
}

// Logger writes per-device DNS query logs to flat files.
// Record() is non-blocking; a background goroutine performs the actual writes.
type Logger struct {
	dir         string
	maxFileSize int64
	ch          chan *Entry
	mu          sync.Mutex
	files       map[string]*openFile
	done        chan struct{}
}

// New creates a Logger that writes per-device log files to dir.
// bufferSize is the channel capacity; entries are dropped if full.
// maxFileSize is the per-file rotation threshold in bytes (0 = no limit).
// Creates dir if it doesn't exist. Starts the background writer goroutine.
func New(dir string, bufferSize int, maxFileSize int64) *Logger {
	if bufferSize <= 0 {
		bufferSize = 4096
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Error("querylog: failed to create directory %s: %v", dir, err)
	}
	l := &Logger{
		dir:         dir,
		maxFileSize: maxFileSize,
		ch:          make(chan *Entry, bufferSize),
		files:       make(map[string]*openFile),
		done:        make(chan struct{}),
	}
	go l.writer()
	return l
}

// Record sends an entry to the background writer. Non-blocking: if the
// channel buffer is full, the entry is silently dropped.
func (l *Logger) Record(entry *Entry) {
	if l == nil {
		return
	}
	select {
	case l.ch <- entry:
	default:
		// Buffer full — drop entry rather than block DNS resolution
	}
}

// Close drains the channel, closes all open file handles, and stops the
// background writer goroutine.
func (l *Logger) Close() {
	if l == nil {
		return
	}
	close(l.ch)
	<-l.done // wait for writer to finish
}

// ReadTail returns the last n lines from a device's log file.
// Returns an empty slice (no error) if the file doesn't exist or is empty.
func (l *Logger) ReadTail(resolverUID string, n int) ([]string, error) {
	if l == nil || n <= 0 {
		return nil, nil
	}
	path := l.filePath(resolverUID)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	return tailFile(f, n)
}

// Purge truncates a device's log file. If the file is currently open by
// the writer, it is closed first so the truncated file is clean.
func (l *Logger) Purge(resolverUID string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if of, ok := l.files[resolverUID]; ok {
		of.f.Close()
		delete(l.files, resolverUID)
	}
	l.mu.Unlock()

	path := l.filePath(resolverUID)
	if err := os.Truncate(path, 0); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (l *Logger) filePath(resolverUID string) string {
	return filepath.Join(l.dir, resolverUID+".log")
}

func (l *Logger) backupPath(resolverUID string) string {
	return filepath.Join(l.dir, resolverUID+".log.1")
}

// writer is the background goroutine that drains the channel and writes to files.
func (l *Logger) writer() {
	defer func() {
		// Close all open file handles
		l.mu.Lock()
		for _, of := range l.files {
			of.f.Close()
		}
		l.files = nil
		l.mu.Unlock()
		close(l.done)
	}()

	for entry := range l.ch {
		of := l.getOrOpenFile(entry.ResolverUID)
		if of == nil {
			continue
		}
		cached := "no"
		if entry.Cached {
			cached = "yes"
		}
		n, err := fmt.Fprintf(of.f, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			entry.Time.UTC().Format(time.RFC3339),
			entry.Domain,
			entry.QType,
			entry.Result,
			entry.Reason,
			entry.Category,
			cached,
		)
		if err != nil {
			logger.Warn("querylog: write error for %s: %v", entry.ResolverUID, err)
			continue
		}
		of.size += int64(n)
		if l.maxFileSize > 0 && of.size >= l.maxFileSize {
			l.rotateFile(entry.ResolverUID)
		}
	}
}

// getOrOpenFile returns the open file handle for a device, opening it if needed.
func (l *Logger) getOrOpenFile(uid string) *openFile {
	l.mu.Lock()
	defer l.mu.Unlock()

	if of, ok := l.files[uid]; ok {
		return of
	}

	path := l.filePath(uid)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Warn("querylog: failed to open %s: %v", path, err)
		return nil
	}

	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}

	of := &openFile{f: f, size: size}
	l.files[uid] = of
	return of
}

// rotateFile closes the current log, renames it to .log.1, and removes
// the handle from the map so the next write opens a fresh file.
func (l *Logger) rotateFile(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if of, ok := l.files[uid]; ok {
		of.f.Close()
		delete(l.files, uid)
	}

	src := l.filePath(uid)
	dst := l.backupPath(uid)
	if err := os.Rename(src, dst); err != nil {
		logger.Warn("querylog: rotate failed for %s: %v", uid, err)
	}
}

// tailFile reads the last n lines from an open file by seeking backward
// in chunks from the end.
func tailFile(f *os.File, n int) ([]string, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := info.Size()
	if fileSize == 0 {
		return nil, nil
	}

	const chunkSize = 4096
	buf := make([]byte, 0, chunkSize)
	newlineCount := 0
	offset := fileSize

	// Read backward in chunks until we have enough newlines
	for offset > 0 && newlineCount <= n {
		readSize := int64(chunkSize)
		if readSize > offset {
			readSize = offset
		}
		offset -= readSize

		chunk := make([]byte, readSize)
		_, err := f.ReadAt(chunk, offset)
		if err != nil && err != io.EOF {
			return nil, err
		}

		// Prepend chunk to buf
		buf = append(chunk, buf...)

		// Count newlines in the chunk
		for _, b := range chunk {
			if b == '\n' {
				newlineCount++
			}
		}
	}

	// Parse lines from the buffer
	scanner := bufio.NewScanner(bytesReader(buf))
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Return only the last n lines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// bytesReader wraps a byte slice to implement io.Reader for bufio.Scanner.
type bytesReaderImpl struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) io.Reader {
	return &bytesReaderImpl{data: data}
}

func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
