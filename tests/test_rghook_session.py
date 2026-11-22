"""Route lifetime: the real decoder and watcher, with QNX spawnle mapped to posix_spawn on the Mac.
Killing mm-ipod must retire its route without deleting a later session's route. No car connection is used.
"""
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    from test_rgkombi import maneuver, update
except ImportError:
    from tests.test_rgkombi import maneuver, update

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <spawn.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#define read rg_read_hook
#define write rg_write_hook
#define symlink test_symlink
#include "rghook.c"
#undef read
#undef write
#undef symlink
static int watcher, spawn_attempts, short_write, fault;
void rgk_kick(void) {}  /* variant senders are covered separately; here only their watcher is exercised */
void rgh_kick(void) {}
int spawnle(int mode, const char *path, const char *arg, ...) {
  if (getenv("TEST_SPAWN_FAIL_ONCE") && ++spawn_attempts == 1) return -1;
  char *args[16]; unsigned n = 0;
  args[n++] = (char *)arg;
  va_list ap; va_start(ap, arg);
  while (n < 15 && (args[n] = va_arg(ap, char *))) n++;
  args[n] = 0;
  char **env = va_arg(ap, char **);
  va_end(ap);
  int pid;
  if (posix_spawn(&pid, path, 0, 0, args, env)) return -1;
  watcher = pid;
  return pid;
}
static int mac_open(const char *p, int f, ...) {
  if (fault == 1 && f) { errno = EACCES; return -1; }
  return open(p, f ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY, 0644);
}
static long mac_write(int fd, const void *b, size_t n) {
  if (fd != logfd && fault == 2) { errno = EIO; return -1; }
  return write(fd, b, short_write && fd != logfd && n ? n - 1 : n);
}
static int mac_close(int fd) {
  int rc = close(fd);
  if (fault == 3) { errno = EIO; return -1; }
  if (fault == 2) errno = EBADF; /* cleanup must not overwrite the original write errno in the diagnostic */
  return rc;
}
static int mac_rename(const char *a, const char *b) {
  if (fault == 4) { errno = EIO; return -1; }
  struct stat st;
  if (!lstat(a, &st) && !S_ISLNK(st.st_mode)) { errno = EXDEV; return -1; } /* actual QNX /dev/shmem behavior */
  return rename(a, b);
}
int test_symlink(const char *a, const char *b) {
  if (fault == 5) { errno = EPERM; return -1; }
  if (getenv("TEST_PUBLIC_LINK_FAIL_ONCE") && !strcmp(b, getenv("RGHOOK_PPS"))) {
    unsetenv("TEST_PUBLIC_LINK_FAIL_ONCE"); errno = EACCES; return -1;
  }
  return symlink(a, b);
}
static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10; }
int main(void) {
  r_open = mac_open; r_write = mac_write; r_read = read; r_close = mac_close; r_unlink = unlink; r_rename = mac_rename;
  inited = 1; logfd = getenv("RGHOOK_LOG") ? open(getenv("RGHOOK_LOG"), O_WRONLY | O_CREAT | O_TRUNC, 0644) : -1;
  rg_clear();
  char line[8192];
  while (fgets(line, sizeof line, stdin)) {
    if (!strncmp(line, "short", 5)) short_write = 1;
    else if (!strncmp(line, "fault ", 6)) { fault = atoi(line + 6); short_write = 0; }
    else if (!strncmp(line, "msg ", 4)) {
      char *e; u32 mid = (u32)strtoul(line + 4, &e, 16); while (*e == ' ') e++;
      u8 b[4096]; u32 n = 0;
      while (e[0] > ' ' && e[1] > ' ' && n < sizeof b) { b[n++] = (u8)(hexv(e[0]) << 4 | hexv(e[1])); e += 2; }
      on_rg(mid, b, n);
    }
    printf("ok %d %d\n", getpid(), watcher); fflush(stdout);
  }
  return 0;
}
'''


@unittest.skipUnless(shutil.which('clang') and Path('/bin/ksh').exists(), 'clang and /bin/ksh required')
class RouteSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='rghook-session-build-')
        d = Path(cls.build.name)
        (d / 'h.c').write_text(HARNESS)
        cls.variants = {}
        for name, defs in [('plain', []), ('kombi', ['-DRGHOOK_KOMBI']), ('most', ['-DRGHOOK_MOST']),
                           ('both', ['-DRGHOOK_KOMBI', '-DRGHOOK_MOST'])]:
            cls.variants[name] = d / name
            subprocess.run(['clang', '-w', '-D_FORTIFY_SOURCE=0', *defs, '-I', str(ROOT / 'src'), '-o', str(cls.variants[name]),
                            str(d / 'h.c')], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='rghook-session-')
        self.addCleanup(self.tmp.cleanup)
        # These are literal path characters, never a shell program in the watcher.
        self.pps = Path(self.tmp.name) / "route ' $(literal)"
        self.log = Path(self.tmp.name) / 'publication.log'
        self.processes = []
        self.watchers = set()
        self.addCleanup(self.stop_all)

    def stop_all(self):
        for p in self.processes:
            if p.poll() is None:
                p.kill()
            p.wait()
            p.stdin.close()
            p.stdout.close()
        for pid in self.watchers:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def start(self, variant='plain', **extra_env):
        env = dict(os.environ, RGHOOK_PPS=str(self.pps), RGHOOK_LOG=str(self.log), **extra_env)
        env.pop('RGHOOK_NO_WATCH', None)
        p = subprocess.Popen([str(self.variants[variant])], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.processes.append(p)
        self.msg(p, 0x5202, maneuver(1, 1, 'Test Road'))
        self.msg(p, 0x5201, update(idx=1, metres=60, text='60 m'))
        return p

    def msg(self, p, mid, payload):
        self.command(p, 'msg %x %s' % (mid, payload.hex()))

    def command(self, p, line):
        p.stdin.write(line + '\n')
        p.stdin.flush()
        reply = p.stdout.readline().split()
        self.assertEqual(reply[:2], ['ok', str(p.pid)])
        watcher = int(reply[2])
        if watcher > 0:
            self.watchers.add(watcher)

    def wait_removed(self, path):
        deadline = time.monotonic() + 20
        while path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(path.exists(), 'route survived the end of its mm-ipod session')

    def test_disconnect_clears_route_even_after_sigkill(self):
        p = self.start()
        self.assertIn('dist_to_maneuver:n:60', self.pps.read_text())
        p.kill()
        p.wait()
        self.wait_removed(self.pps)

    def test_qnx_ram_rename_is_not_required(self):
        self.start()
        self.assertTrue(self.pps.exists(), 'a QNX EXDEV on regular RAM rename must not prevent publication')
        self.assertIn('dist_to_maneuver:n:60', self.pps.read_text())
        session = self.pps.parent / os.readlink(self.pps)
        self.assertTrue(session.is_symlink())
        self.assertIn('RG publish ready:', self.log.read_text())
        self.assertNotIn('Test Road', self.log.read_text())

    def test_failed_publications_preserve_route_and_report_errno(self):
        p = self.start()
        cases = [(1, 'open', 13), (2, 'write', 5), (3, 'close', 5), (4, 'rename session', 5), (5, 'symlink session', 1)]
        for number, op, error in cases:
            with self.subTest(op=op):
                before = self.pps.read_bytes()
                self.command(p, 'fault %d' % number)
                self.msg(p, 0x5201, update(idx=1, metres=30, text='30 m'))
                self.msg(p, 0x5201, update(idx=1, metres=20, text='20 m'))
                self.assertEqual(self.pps.read_bytes(), before)
                diagnostic = 'RG publish %s failed:' % op
                log = self.log.read_text()
                self.assertEqual(log.count(diagnostic), 1, log)
                self.assertIn('errno=%d ' % error, log.split(diagnostic)[-1])
                self.command(p, 'fault 0')
                self.msg(p, 0x5201, update(idx=1, metres=10, text='10 m'))
                self.assertIn('dist_to_maneuver:n:10', self.pps.read_text())
        self.assertEqual(self.log.read_text().count('RG publish recovered:'), len(cases))

    def test_public_link_failure_retries(self):
        self.start(TEST_PUBLIC_LINK_FAIL_ONCE='1')
        log = self.log.read_text()
        self.assertIn('RG publish symlink public failed:', log)
        self.assertIn('errno=13 ', log)
        self.assertIn('RG publish recovered:', log)
        self.assertIn('route_state:n:1', self.pps.read_text())

    def test_reader_keeps_complete_previous_snapshot(self):
        p = self.start()
        before = self.pps.read_bytes()
        with self.pps.open('rb') as reader:
            self.msg(p, 0x5201, update(idx=1, metres=30, text='30 m'))
            self.assertEqual(reader.read(), before)
        self.assertIn('dist_to_maneuver:n:30', self.pps.read_text())

    def test_idle_connected_route_has_no_expiry(self):
        p = self.start()
        before = self.pps.read_bytes()
        time.sleep(10.2)  # one watcher poll without a new navigation message
        self.assertEqual(self.pps.read_bytes(), before)
        self.assertEqual(len(self.watchers), 1)
        p.stdin.close()  # normal exit, unlike the SIGKILL test
        p.wait(timeout=5)
        self.wait_removed(self.pps)

    def test_old_watcher_preserves_new_session(self):
        old = self.start()
        self.assertTrue(self.pps.is_symlink())
        old_session = Path(os.readlink(self.pps))
        old_file = self.pps.resolve()
        new = self.start()
        new_file = self.pps.resolve()
        self.assertNotEqual(old_file, new_file)
        self.msg(old, 0x5201, update(idx=1, metres=999, text='999 m'))
        self.assertEqual(self.pps.resolve(), new_file)
        self.assertIn('dist_to_maneuver:n:60', self.pps.read_text())
        old_file = old_session.resolve()
        old.kill()
        old.wait()
        self.wait_removed(old_file)
        self.assertEqual(self.pps.resolve(), new_file)
        self.assertIn('route_state:n:1', self.pps.read_text())
        self.assertIsNone(new.poll())

    def test_lost_ram_route_cannot_be_read_after_reboot(self):
        self.start()
        self.assertTrue(self.pps.is_symlink())
        self.pps.resolve().unlink()  # reboot loses the RAM target, while /var retains the link
        self.assertTrue(self.pps.is_symlink())
        with self.assertRaises(FileNotFoundError):
            self.pps.read_bytes()

    def test_watcher_retries_failed_spawn(self):
        p = self.start(TEST_SPAWN_FAIL_ONCE='1')
        self.assertEqual(len(self.watchers), 1)
        p.kill()
        p.wait()
        self.wait_removed(self.pps)

    def test_partial_write_keeps_previous_route(self):
        p = self.start()
        before = self.pps.read_bytes()
        self.command(p, 'short')
        self.msg(p, 0x5201, update(idx=1, metres=30, text='30 m'))
        self.assertEqual(self.pps.read_bytes(), before)
        self.assertEqual([f.resolve() for f in self.pps.parent.glob(self.pps.name + '.%d.*' % p.pid)], [self.pps.resolve()])
        self.assertIn('RG publish write failed:', self.log.read_text())
        self.assertIn('errno=0 ', self.log.read_text())

    def test_drawing_variants_also_retire_their_route(self):
        for variant in ('kombi', 'most', 'both'):
            with self.subTest(variant=variant):
                p = self.start(variant=variant)
                self.assertTrue(self.pps.exists())
                p.kill()
                p.wait()
                self.wait_removed(self.pps)


if __name__ == '__main__':
    unittest.main()
