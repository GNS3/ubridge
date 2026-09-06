#include <criterion/criterion.h>
#include <glob.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ubridge.h"

static int wait_for_file(const char *path)
{
  for (int i = 0; i < 200; i++) {
    if (access(path, F_OK) == 0)
      return TRUE;
    usleep(10000);
  }
  return FALSE;
}

static size_t thread_count(pid_t pid)
{
  char   pattern[64];
  glob_t tasks = {0};

  snprintf(pattern, sizeof(pattern), "/proc/%ld/task/*", (long)pid);
  glob(pattern, GLOB_NOSORT, NULL, &tasks);
  size_t count = tasks.gl_pathc;
  globfree(&tasks);
  return count;
}

Test(mem, config_reload, .timeout = 5)
{
  const char       *capture_path = "tests/unit/fixtures/reload.pcap";
  int               status;
  ubridge_options_t opts = {
    .mode = UBRIDGE_MODE_CONFIG_FILE,
    .config.path = "tests/unit/fixtures/test.ini",
  };
  unlink(capture_path);

  pid_t pid = fork();
  cr_assert_neq(pid, -1);

  if (pid == 0) {
    run_ubridge(opts);
    _exit(EXIT_SUCCESS);
  }

  cr_assert(wait_for_file(capture_path));
  usleep(250000); // 250ms
  cr_assert_eq(thread_count(pid), 3);
  cr_assert_eq(unlink(capture_path), 0);
  cr_assert_eq(kill(pid, SIGHUP), 0);

  cr_assert(wait_for_file(capture_path));
  usleep(250000); // 250ms
  cr_assert_eq(thread_count(pid), 3,
               "reload left old bridge listener threads running");
  cr_assert_eq(kill(pid, SIGTERM), 0);

  cr_assert_eq(waitpid(pid, &status, 0), pid);
  unlink(capture_path);

  cr_assert(WIFEXITED(status));
  cr_assert_eq(WEXITSTATUS(status), EXIT_SUCCESS);
}
