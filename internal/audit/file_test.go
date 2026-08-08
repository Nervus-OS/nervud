package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestRecorder(t *testing.T, maxBytes int64) (*FileRecorder, string) {
	t.Helper()
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	r, err := NewFileRecorder(FileConfig{
		Dir:      dir,
		MaxBytes: maxBytes,
		MaxFiles: 2,
		Log:      discardLog(),
		now:      func() time.Time { return at },
	})
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func recordN(r *FileRecorder, n int) {
	for i := 0; i < n; i++ {
		r.Record(context.Background(), Event{
			Action:  "test.Action",
			Subject: "pkg:com.example uid:20001",
			Detail:  "i",
		})
	}
}

func readCurrent(t *testing.T, dir string) []Record {
	t.Helper()
	records, skipped, err := ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("unexpected audit result; value = %d", skipped)
	}
	return records
}

func TestFileRecorder_ChainVerifies(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 5)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records := readCurrent(t, dir)

	if len(records) != 7 {
		t.Fatalf("unexpected audit result; value = %d, want 7 ChainStarted + 5 + Closed", len(records))
	}
	if records[0].Action != ActionChainStarted {
		t.Fatalf("unexpected audit result; action = %q, want %q", records[0].Action, ActionChainStarted)
	}
	if last := records[len(records)-1]; last.Action != ActionClosed {
		t.Fatalf("unexpected audit result; action = %q, want %q", last.Action, ActionClosed)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}
}

//

func TestFileRecorder_DetectsModifiedRecord(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	r.Record(context.Background(), Event{Action: "a", Subject: "s", Denied: true})
	recordN(r, 2)
	_ = r.Close()

	records := readCurrent(t, dir)

	if records[1].Action != "a" {
		t.Fatalf("unexpected audit result; action = %q, want a", records[1].Action)
	}
	records[1].Denied = false

	idx, err := VerifyChain(records, "", 1)
	if err == nil {
		t.Fatal("unexpected audit result")
	}
	if idx != 1 {
		t.Fatalf("unexpected audit result; value = %d, want 1", idx)
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("unexpected audit result; err = %v; expected rejection", err)
	}
}

func TestFileRecorder_DetectsDeletedRecords(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 5)
	_ = r.Close()

	records := readCurrent(t, dir)

	tampered := append([]Record{records[0]}, records[3:]...)

	idx, err := VerifyChain(tampered, "", 1)
	if err == nil {
		t.Fatal("unexpected audit result")
	}
	if idx != 1 {
		t.Fatalf("unexpected audit result; value = %d, want 1", idx)
	}
	if !strings.Contains(err.Error(), "removed or inserted") {
		t.Fatalf("unexpected audit result; err = %v; expected rejection", err)
	}
}

func TestFileRecorder_DetectsReordering(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 4)
	_ = r.Close()

	records := readCurrent(t, dir)
	records[1], records[2] = records[2], records[1]

	if _, err := VerifyChain(records, "", 1); err == nil {
		t.Fatal("unexpected audit result")
	}
}

//

func TestFileRecorder_ResumesChainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	newAt := func() *FileRecorder {
		r, err := NewFileRecorder(FileConfig{
			Dir: dir, MaxFiles: 2, Log: discardLog(),
			now: func() time.Time { return at },
		})
		if err != nil {
			t.Fatalf("NewFileRecorder: %v", err)
		}
		return r
	}

	first := newAt()
	recordN(first, 3)
	_ = first.Close()

	second := newAt()
	recordN(second, 2)
	_ = second.Close()

	records := readCurrent(t, dir)

	if len(records) != 8 {
		t.Fatalf("unexpected audit result; value = %d, want 8", len(records))
	}
	starts, unclean := 0, 0
	for _, rec := range records {
		switch rec.Action {
		case ActionChainStarted:
			starts++
		case ActionUncleanShutdown:
			unclean++
		}
	}
	if starts != 1 {
		t.Fatalf("unexpected audit result; ChainStarted %d want 1", starts)
	}
	if unclean != 0 {
		t.Fatalf("unexpected audit result; value = %d UncleanShutdown", unclean)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}
	if last := records[len(records)-1]; last.Seq != 8 {
		t.Fatalf("unexpected audit result; seq = %d, want 8", last.Seq)
	}
}

//

func TestFileRecorder_MarksNewChainWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 3)
	_ = first.Close()

	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(second, 1)
	_ = second.Close()

	records := readCurrent(t, dir)
	if len(records) != 3 {
		t.Fatalf("unexpected audit result; value = %d, want 3 ChainStarted + 1 + Closed", len(records))
	}
	if records[0].Action != ActionChainStarted {
		t.Fatalf("unexpected audit result; action = %q, want %q", records[0].Action, ActionChainStarted)
	}
	if records[0].Detail == "" {
		t.Fatal("unexpected audit result; ChainStarted")
	}

	if records[0].Seq != 1 || records[0].Prev != "" {
		t.Fatalf("unexpected audit result; seq=%d prev=%q, want 1", records[0].Seq, records[0].Prev)
	}
}

//

func TestFileRecorder_RotationCarriesChain(t *testing.T) {

	r, dir := newTestRecorder(t, 400)
	recordN(r, 12)
	_ = r.Close()

	if _, statErr := os.Stat(filepath.Join(dir, FileName+".1")); statErr != nil {
		t.Fatalf("unexpected audit result; value = %v", statErr)
	}
	current := readCurrent(t, dir)
	if len(current) == 0 {
		t.Fatal("unexpected audit result")
	}

	if current[0].Action != ActionRotated {
		t.Fatalf("unexpected audit result; action = %q, want %q", current[0].Action, ActionRotated)
	}

	if current[0].Seq <= 1 {
		t.Fatalf("unexpected audit result; seq = %d", current[0].Seq)
	}
	if current[0].Prev == "" {
		t.Fatal("unexpected audit result; prev")
	}

	if idx, err := VerifyChain(current, current[0].Prev, current[0].Seq); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}

	if !strings.Contains(current[0].Detail, "carried_hash=") {
		t.Fatalf("unexpected audit result; Rotated: %q", current[0].Detail)
	}
}

//

func truncateLastLine(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := trimNewline(data)
	start := len(trimmed)
	for start > 0 && trimmed[start-1] != '\n' {
		start--
	}
	if start == 0 {
		t.Fatal("unexpected audit result")
	}

	keep := start + (len(trimmed)-start)/2
	if err := os.WriteFile(path, data[:keep], filePerm); err != nil {
		t.Fatal(err)
	}
}

func TestReadFile_TolerantOfTruncatedTail(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 3)
	_ = r.Close()

	path := filepath.Join(dir, FileName)
	truncateLastLine(t, path)

	records, skipped, err := ReadFile(path)
	if err != nil {
		t.Fatalf("unexpected audit result; value = %v", err)
	}

	if len(records) != 4 {
		t.Fatalf("unexpected audit result; value = %d, want 4", len(records))
	}

	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}
}

func TestFileRecorder_ResumesAfterTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 3)
	_ = first.Close()

	path := filepath.Join(dir, FileName)
	truncateLastLine(t, path)

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(second, 1)
	_ = second.Close()

	records, skipped, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}

	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}
	starts := 0
	for _, rec := range records {
		if rec.Action == ActionChainStarted {
			starts++
		}
	}

	if starts != 1 {
		t.Fatalf("unexpected audit result; ChainStarted %d want 1", starts)
	}
}

func TestFileRecorder_CarriesError(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	r.Record(context.Background(), Event{
		Action:  "perm.Denied",
		Subject: "pkg:com.example",
		Denied:  true,
		Err:     errors.New("permission not granted"),
	})
	_ = r.Close()

	records := readCurrent(t, dir)
	if len(records) != 3 {
		t.Fatalf("unexpected audit result; value = %d, want 3 ChainStarted + 1 + Closed", len(records))
	}
	if records[1].Err != "permission not granted" {
		t.Fatalf("err = %q", records[1].Err)
	}
	if !records[1].Denied {
		t.Fatal("unexpected audit result; denied")
	}
}

func TestFileRecorder_FileIsOwnerOnly(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 1)
	_ = r.Close()

	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Fatalf("unexpected audit result; value = %o, want %o", perm, filePerm)
	}
}

//

//

//

//

func simulatePowerLoss(t *testing.T, dir string, lose int) {
	t.Helper()
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	end := len(bytesTrimNewline(data))
	for i := 0; i < lose; i++ {
		start := end
		for start > 0 && data[start-1] != '\n' {
			start--
		}
		if start == 0 {
			t.Fatal("unexpected audit result")
		}
		end = start
	}
	if err := os.WriteFile(path, data[:end], filePerm); err != nil {
		t.Fatal(err)
	}
}

func bytesTrimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func countAction(records []Record, action string) int {
	n := 0
	for _, rec := range records {
		if rec.Action == action {
			n++
		}
	}
	return n
}

func TestFileRecorder_CleanCloseWritesTerminator(t *testing.T) {
	r, dir := newTestRecorder(t, DefaultMaxBytes)
	recordN(r, 2)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	records := readCurrent(t, dir)
	last := records[len(records)-1]
	if last.Action != ActionClosed {
		t.Fatalf("unexpected audit result; action = %q, want %q", last.Action, ActionClosed)
	}

	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}
}

func TestFileRecorder_MarksUncleanShutdown(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 3)
	_ = first.Close()

	simulatePowerLoss(t, dir, 2)

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(second, 1)
	_ = second.Close()

	records := readCurrent(t, dir)
	if n := countAction(records, ActionUncleanShutdown); n != 1 {
		t.Fatalf("unexpected audit result; UncleanShutdown %d, want 1", n)
	}

	if n := countAction(records, ActionChainStarted); n != 1 {
		t.Fatalf("unexpected audit result; ChainStarted %d, want 1", n)
	}
	if idx, err := VerifyChain(records, "", 1); err != nil {
		t.Fatalf("unexpected audit result; value = %d: %v", idx, err)
	}

	for i, rec := range records {
		if rec.Action == ActionUncleanShutdown {
			if records[i-1].Action == ActionClosed {
				t.Fatal("unexpected audit result")
			}
			if !rec.Denied {
				t.Fatal("unexpected audit result; UncleanShutdown Denied")
			}
			return
		}
	}
	t.Fatal("unexpected audit result; UncleanShutdown")
}

func TestFileRecorder_NoFalseUncleanAfterCleanClose(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	for i := 0; i < 3; i++ {
		r, err := NewFileRecorder(cfg)
		if err != nil {
			t.Fatal(err)
		}
		recordN(r, 1)
		_ = r.Close()
	}

	records := readCurrent(t, dir)
	if n := countAction(records, ActionUncleanShutdown); n != 0 {
		t.Fatalf("unexpected audit result; 3 %d UncleanShutdown", n)
	}
}

func TestFileRecorder_MissingFileIsNewChainNotUnclean(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	cfg := FileConfig{Dir: dir, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at }}

	first, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recordN(first, 2)
	_ = first.Close()
	simulatePowerLoss(t, dir, 1)

	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}

	second, err := NewFileRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()

	records := readCurrent(t, dir)
	if n := countAction(records, ActionChainStarted); n != 1 {
		t.Fatalf("unexpected audit result; ChainStarted %d, want 1", n)
	}
	if n := countAction(records, ActionUncleanShutdown); n != 0 {
		t.Fatalf("unexpected audit result; ChainStarted %d UncleanShutdown", n)
	}
}

//

//

func waitRecords(t *testing.T, r *FileRecorder, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := r.Stats(); got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	got, _ := r.Stats()
	t.Fatalf("unexpected audit result; value = %d %d", n, got)
}

func newClockedRecorder(t *testing.T) (*FileRecorder, *time.Time) {
	t.Helper()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	clock := &at
	r, err := NewFileRecorder(FileConfig{
		Dir: t.TempDir(), Log: discardLog(),
		now: func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, clock
}

func TestFileRecorder_DeniedSyncsImmediately(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	_, before := r.Stats()

	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 2)

	if _, after := r.Stats(); after != before+1 {
		t.Fatalf("unexpected audit result; fsync %d -> %d, want +1", before, after)
	}
}

//

func TestFileRecorder_DeniedIsThrottled(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)

	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 2)
	_, afterFirst := r.Stats()

	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 3)

	if _, after := r.Stats(); after != afterFirst {
		t.Fatalf("unexpected audit result; fsync %d %d", afterFirst, after)
	}
}

func TestFileRecorder_ThrottleReopensAfterInterval(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 2)
	_, base := r.Stats()

	*clock = clock.Add(minSyncInterval)
	r.Record(context.Background(), Event{Action: "perm.Denied", Denied: true})
	waitRecords(t, r, 3)

	if _, after := r.Stats(); after != base+1 {
		t.Fatalf("unexpected audit result; fsync %d -> %d", base, after)
	}
}

func TestFileRecorder_PlainRecordDoesNotSync(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	_, before := r.Stats()

	recordN(r, 3)
	waitRecords(t, r, 4)

	if _, after := r.Stats(); after != before {
		t.Fatalf("unexpected audit result; fsync %d %d", before, after)
	}
}

func TestFileRecorder_CloseSyncs(t *testing.T) {
	r, clock := newClockedRecorder(t)

	waitRecords(t, r, 1)
	*clock = clock.Add(2 * minSyncInterval)
	recordN(r, 2)
	waitRecords(t, r, 3)
	_, before := r.Stats()

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, after := r.Stats(); after <= before {
		t.Fatalf("unexpected audit result; Close fsync %d -> %d", before, after)
	}
}

//

func TestFileRecorder_RotationSyncs(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	r, err := NewFileRecorder(FileConfig{
		Dir: dir, MaxBytes: 400, MaxFiles: 2, Log: discardLog(),
		now: func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	waitRecords(t, r, 1)
	_, before := r.Stats()

	recordN(r, 12)
	waitRecords(t, r, 13)

	if _, statErr := os.Stat(filepath.Join(dir, FileName+".1")); statErr != nil {
		t.Fatalf("unexpected audit result; value = %v", statErr)
	}
	if _, after := r.Stats(); after <= before {
		t.Fatalf("unexpected audit result; fsync %d -> %d", before, after)
	}
}

//

func TestFileRecorder_IdleDoesNotSync(t *testing.T) {
	r, _ := newClockedRecorder(t)

	waitRecords(t, r, 1)

	time.Sleep(2*minSyncInterval + 200*time.Millisecond)
	_, first := r.Stats()

	time.Sleep(2*minSyncInterval + 200*time.Millisecond)
	if _, second := r.Stats(); second != first {
		t.Fatalf("unexpected audit result; fsync %d %d dirty", first, second)
	}
}
