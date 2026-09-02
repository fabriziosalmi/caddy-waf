package caddywaf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phemmer/go-iptrie"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// writeAtomic performs the standard atomic-update dance: write a temp file in
// the same directory, then os.Rename it over the target. The rename replaces
// the target's inode, which is precisely what a file-inode watch cannot follow.
func writeAtomic(t *testing.T, dir, target, content string) {
	t.Helper()
	tmp := filepath.Join(dir, ".tmp-"+filepath.Base(target))
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0o644))
	require.NoError(t, os.Rename(tmp, target))
}

// TestFileWatcherReloadsOnAtomicRename pins the hot-reload path against atomic
// file updates.
//
// startFileWatcher used to call watcher.Add on the file path and react only to
// fsnotify.Write. An atomic update (write temp + os.Rename over the target)
// swaps the file's inode: fsnotify fires Rename/Remove on the old, now-dead
// inode, no Write ever arrives, and the watch is left permanently deaf. So a
// blocklist refreshed the standard way silently stopped hot-reloading.
//
// The fix watches the parent directory and treats Create/Rename/Write on the
// target basename as reload triggers. This test replaces a watched IP blacklist
// via rename and asserts the new entry is actually enforced, then writes the
// file in place to prove the watch survived the rename (the old code left it
// dead) and the original Write behaviour still works.
//
// The reload is asynchronous, so both assertions poll with Eventually rather
// than a fixed sleep.
func TestFileWatcherReloadsOnAtomicRename(t *testing.T) {
	logger := zap.NewNop()
	dir := t.TempDir()
	blFile := filepath.Join(dir, "ip_blacklist.txt")
	require.NoError(t, os.WriteFile(blFile, []byte("203.0.113.1\n"), 0o644))

	m := &Middleware{
		logger:          logger,
		blacklistLoader: NewBlacklistLoader(logger),
		IPBlacklistFile: blFile,
		ipBlacklist:     iptrie.NewTrie(),
	}
	require.NoError(t, m.loadIPBlacklist(blFile, m.ipBlacklist))
	require.True(t, m.isIPBlacklisted("203.0.113.1:1"), "seed entry must be enforced")
	require.False(t, m.isIPBlacklisted("198.51.100.9:1"))

	m.startFileWatcher([]string{blFile})
	// Give the goroutine a moment to arm its directory watch before we mutate.
	time.Sleep(150 * time.Millisecond)

	// 1) Atomic update: temp write + rename over the target (replaces the inode).
	writeAtomic(t, dir, blFile, "203.0.113.1\n198.51.100.9\n")
	require.Eventually(t, func() bool { return m.isIPBlacklisted("198.51.100.9:1") },
		3*time.Second, 25*time.Millisecond,
		"an atomic rename over the watched file must trigger a reload")

	// 2) The watch must still be alive after the rename: a subsequent in-place
	//    write is also picked up. This is the regression guard -- the old
	//    file-inode watch was left dead by the rename.
	require.NoError(t, os.WriteFile(blFile, []byte("203.0.113.1\n198.51.100.9\n192.0.2.5\n"), 0o644))
	require.Eventually(t, func() bool { return m.isIPBlacklisted("192.0.2.5:1") },
		3*time.Second, 25*time.Millisecond,
		"an in-place write after an atomic rename must still trigger a reload")
}
