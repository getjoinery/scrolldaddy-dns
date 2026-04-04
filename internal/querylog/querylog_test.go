package querylog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tmpDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

func makeEntry(uid, domain string) *Entry {
	return &Entry{
		ResolverUID: uid,
		Time:        time.Date(2026, 4, 4, 19, 23, 45, 0, time.UTC),
		Domain:      domain,
		QType:       "A",
		Result:      "FORWARDED",
		Reason:      "not_blocked",
		Category:    "",
		Cached:      false,
	}
}

// waitForDrain waits until the channel is empty, ensuring all prior entries
// have been written to disk.
func waitForDrain(t *testing.T, l *Logger, uid string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(l.ch) == 0 {
			// Give the writer goroutine a moment to finish writing the last entry
			time.Sleep(10 * time.Millisecond)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for channel to drain")
}

func TestRecordWritesLine(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)
	defer l.Close()

	l.Record(makeEntry("aaa", "google.com"))
	waitForDrain(t, l, "aaa")

	lines, err := l.ReadTail("aaa", 10)
	if err != nil {
		t.Fatal(err)
	}
	// Should have our entry + the drain sentinel
	found := false
	for _, line := range lines {
		if strings.Contains(line, "google.com") && strings.Contains(line, "FORWARDED") {
			found = true
			parts := strings.Split(line, "\t")
			if len(parts) != 7 {
				t.Errorf("expected 7 tab-separated fields, got %d: %q", len(parts), line)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected to find google.com entry in log, got: %v", lines)
	}
}

func TestMultipleDevices(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)
	defer l.Close()

	l.Record(makeEntry("dev1", "site-a.com"))
	l.Record(makeEntry("dev2", "site-b.com"))
	waitForDrain(t, l, "dev1")
	waitForDrain(t, l, "dev2")

	// Check files exist
	if _, err := os.Stat(filepath.Join(dir, "dev1.log")); err != nil {
		t.Error("dev1.log should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "dev2.log")); err != nil {
		t.Error("dev2.log should exist")
	}

	lines1, _ := l.ReadTail("dev1", 10)
	lines2, _ := l.ReadTail("dev2", 10)

	foundA := false
	for _, line := range lines1 {
		if strings.Contains(line, "site-a.com") {
			foundA = true
		}
		if strings.Contains(line, "site-b.com") {
			t.Error("dev1 log should not contain site-b.com")
		}
	}
	if !foundA {
		t.Error("dev1 log should contain site-a.com")
	}

	foundB := false
	for _, line := range lines2 {
		if strings.Contains(line, "site-b.com") {
			foundB = true
		}
	}
	if !foundB {
		t.Error("dev2 log should contain site-b.com")
	}
}

func TestFileReuse(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)
	defer l.Close()

	l.Record(makeEntry("uid1", "first.com"))
	l.Record(makeEntry("uid1", "second.com"))
	waitForDrain(t, l, "uid1")

	l.mu.Lock()
	count := len(l.files)
	l.mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 open file handle, got %d", count)
	}
}

func TestBufferFullDrops(t *testing.T) {
	dir := tmpDir(t)
	// Buffer size of 1 — second send should be dropped without blocking
	l := New(dir, 1, 0)

	// Fill the buffer
	l.ch <- makeEntry("uid1", "fill.com")

	// This should not block
	done := make(chan struct{})
	go func() {
		l.Record(makeEntry("uid1", "dropped.com"))
		close(done)
	}()

	select {
	case <-done:
		// Good — Record returned without blocking
	case <-time.After(1 * time.Second):
		t.Fatal("Record blocked when channel was full")
	}

	l.Close()
}

func TestRotation(t *testing.T) {
	dir := tmpDir(t)
	// Tiny max file size to force rotation
	l := New(dir, 100, 200)
	defer l.Close()

	// Write enough entries to exceed 200 bytes
	for i := 0; i < 10; i++ {
		l.Record(makeEntry("rot1", "example.com"))
	}
	waitForDrain(t, l, "rot1")

	// Check that backup file exists
	backupPath := filepath.Join(dir, "rot1.log.1")
	if _, err := os.Stat(backupPath); err != nil {
		t.Error("rot1.log.1 backup should exist after rotation")
	}

	// Active log should be smaller than maxFileSize
	activePath := filepath.Join(dir, "rot1.log")
	info, err := os.Stat(activePath)
	if err != nil {
		t.Fatal("rot1.log should exist")
	}
	if info.Size() > 200 {
		t.Errorf("active log should be smaller than max after rotation, got %d bytes", info.Size())
	}
}

func TestRotationOverwritesBackup(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 150)
	defer l.Close()

	// Write enough to trigger rotation multiple times
	for i := 0; i < 20; i++ {
		l.Record(makeEntry("rot2", "example.com"))
	}
	waitForDrain(t, l, "rot2")

	// .log.1 should exist, .log.2 should not
	if _, err := os.Stat(filepath.Join(dir, "rot2.log.1")); err != nil {
		t.Error("rot2.log.1 should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "rot2.log.2")); err == nil {
		t.Error("rot2.log.2 should NOT exist — only one backup")
	}
}

func TestSizeTrackingAcrossRestart(t *testing.T) {
	dir := tmpDir(t)

	// Write some entries, close
	l1 := New(dir, 100, 0)
	for i := 0; i < 5; i++ {
		l1.Record(makeEntry("uid1", "test.com"))
	}
	waitForDrain(t, l1, "uid1")
	l1.Close()

	// Get actual file size
	info, _ := os.Stat(filepath.Join(dir, "uid1.log"))
	actualSize := info.Size()

	// Create new logger — it should pick up the existing file size via Stat
	l2 := New(dir, 100, 0)
	l2.Record(makeEntry("uid1", "after-restart.com"))
	waitForDrain(t, l2, "uid1")
	l2.Close() // close first to ensure writer is done

	// Now check the file grew beyond the pre-restart size
	info2, _ := os.Stat(filepath.Join(dir, "uid1.log"))
	if info2.Size() <= actualSize {
		t.Errorf("file size after restart (%d) should be greater than pre-restart size (%d)", info2.Size(), actualSize)
	}
}

func TestZeroMaxSizeDisablesRotation(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0) // maxFileSize=0 means no limit
	defer l.Close()

	for i := 0; i < 20; i++ {
		l.Record(makeEntry("uid1", "example.com"))
	}
	waitForDrain(t, l, "uid1")

	// No backup should exist
	if _, err := os.Stat(filepath.Join(dir, "uid1.log.1")); err == nil {
		t.Error("backup should not exist when maxFileSize=0")
	}
}

func TestReadTail(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)
	defer l.Close()

	for i := 0; i < 20; i++ {
		l.Record(makeEntry("uid1", "test.com"))
	}
	waitForDrain(t, l, "uid1")

	lines, err := l.ReadTail("uid1", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 {
		t.Errorf("expected 5 lines, got %d", len(lines))
	}
}

func TestReadTailEmpty(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)
	defer l.Close()

	lines, err := l.ReadTail("nonexistent", 10)
	if err != nil {
		t.Errorf("expected no error for nonexistent file, got %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("expected empty slice, got %v", lines)
	}
}

func TestPurge(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)
	defer l.Close()

	for i := 0; i < 5; i++ {
		l.Record(makeEntry("uid1", "test.com"))
	}
	waitForDrain(t, l, "uid1")

	if err := l.Purge("uid1"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "uid1.log"))
	if err != nil {
		t.Fatal("file should still exist after purge")
	}
	if info.Size() != 0 {
		t.Errorf("file should be empty after purge, got %d bytes", info.Size())
	}

	// File handle should have been removed so a fresh one is opened on next write
	l.mu.Lock()
	_, exists := l.files["uid1"]
	l.mu.Unlock()
	if exists {
		t.Error("file handle should have been removed from map after purge")
	}
}

func TestClose(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 100, 0)

	l.Record(makeEntry("uid1", "test.com"))
	l.Close()

	// File handles should be cleaned up
	l.mu.Lock()
	files := l.files
	l.mu.Unlock()
	if files != nil {
		t.Error("files map should be nil after Close")
	}
}

func TestNilLoggerSafe(t *testing.T) {
	var l *Logger
	// None of these should panic
	l.Record(makeEntry("uid1", "test.com"))
	l.Close()
	lines, err := l.ReadTail("uid1", 10)
	if err != nil || lines != nil {
		t.Error("nil logger should return nil, nil")
	}
	if err := l.Purge("uid1"); err != nil {
		t.Error("nil logger Purge should return nil")
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := tmpDir(t)
	l := New(dir, 1000, 0)
	defer l.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			uid := "uid1"
			if i%2 == 0 {
				uid = "uid2"
			}
			l.Record(makeEntry(uid, "concurrent.com"))
		}(i)
	}
	wg.Wait()
}

func BenchmarkRecord(b *testing.B) {
	dir := b.TempDir()
	l := New(dir, 8192, 0)
	defer l.Close()

	entry := makeEntry("bench", "example.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Record(entry)
	}
}
