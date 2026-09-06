#ifndef UBRIDGE_OPTS_H
#define UBRIDGE_OPTS_H

typedef enum {
  UBRIDGE_MODE_CONFIG_FILE,
  UBRIDGE_MODE_HYPERVISOR_TCP,
  UBRIDGE_MODE_HYPERVISOR_UNIX,
} ubridge_mode_t;

typedef struct {
  int            debug_level;
  ubridge_mode_t mode;

  union {
    struct {
      char *path;
    } config;

    struct {
      char *ip;
      int   port;
    } tcp;

    struct {
      char *path;
    } unix_socket;
  };
} ubridge_options_t;

ubridge_options_t parse_cli_args(int argc, char **argv);
#endif
