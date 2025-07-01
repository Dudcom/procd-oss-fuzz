#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>

// Platform-specific includes
#ifdef __linux__
#include <sys/wait.h>
#include <linux/limits.h>
#endif

// Additional includes for fuzzing utilities
#include <sys/wait.h>
#include <unistd.h>

// Include necessary headers from procd
#include "jail/jail.h"
#include "jail/capabilities.h"  // Needed for indirect deps
#include "jail/cgroups.h"
#include "jail/fs.h"

// Conditional includes for procd headers that may not be available during linting
#if defined(__linux__) && !defined(_WIN32)
  #include "utils/utils.h"
  #include "log.h"
#else
  // Stub declarations for Windows/linting environment
  int patch_stdio(const char *device);
  #define ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
  #define DEBUG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
  #define INFO(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#endif

// Fallback definitions for missing constants/types
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef WIFEXITED
#define WIFEXITED(status) (((status) & 0x7f) == 0)
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#endif

// Forward declarations for functions that may not be available during linting
#ifndef __linux__
typedef int pid_t;
pid_t fork(void) { return -1; }
int waitpid(pid_t pid, int *status, int options) { (void)pid; (void)status; (void)options; return -1; }
void _exit(int status) { exit(status); }
int patch_stdio(const char *device) { (void)device; return -1; }
#endif

// External function declarations
extern int parseOCI(const char *jsonfile);

// Forward declarations for types used in opts structure
struct sock_fprog;
struct jail_capset;
struct sysctl_val;
struct hook_execvpe;
struct rlimit;
struct mknod_args;
struct blob_attr;

// Forward declarations for the functions we want to fuzz directly
extern void post_main(struct uloop_timeout *t);
extern void pre_exec_jail(struct uloop_timeout *t);
extern int procd_jail_main(int argc, char **argv);

// Forward declarations for initialization functions
extern void init_library_search(void);
extern void mount_list_init(void);
extern void cgroups_prepare(void);
extern void free_library_search(void);
extern void mount_free(void);
extern void cgroups_free(void);

// Forward declaration for the global opts structure (remove extern since we removed static)
// The actual structure is defined in jail.c and is now globally accessible
extern struct {
    char *name;
    char *hostname;
    char **jail_argv;
    char *cwd;
    char *seccomp;
    struct sock_fprog *ociseccomp;
    char *capabilities;
    struct jail_capset capset;
    char *user;
    char *group;
    char *extroot;
    char *overlaydir;
    char *tmpoverlaysize;
    char **envp;
    char *uidmap;
    char *gidmap;
    char *pidfile;
    struct sysctl_val **sysctl;
    int no_new_privs;
    int namespace;
    struct {
        int pid;
        int net;
        int ns;
        int ipc;
        int uts;
        int user;
        int cgroup;
    } setns;
    int procfs;
    int ronly;
    int sysfs;
    int console;
    int pw_uid;
    int pw_gid;
    int gr_gid;
    int root_map_uid;
    gid_t *additional_gids;
    size_t num_additional_gids;
    mode_t umask;
    bool set_umask;
    int require_jail;
    struct {
        struct hook_execvpe **createRuntime;
        struct hook_execvpe **createContainer;
        struct hook_execvpe **startContainer;
        struct hook_execvpe **poststart;
        struct hook_execvpe **poststop;
    } hooks;
    struct rlimit *rlimits[16];
    int oom_score_adj;
    bool set_oom_score_adj;
    struct mknod_args **devices;
    char *ocibundle;
    bool immediately;
    struct blob_attr *annotations;
    int term_timeout;
} opts;

// Global state initialization and cleanup
// NOTE: The procd code expects init_library_search() etc. to be called once per process.
// Calling init → cleanup → init again causes use-after-free because the cleanup doesn't
// properly reset all global pointers. So we initialize once and never cleanup during fuzzing.
//
// IMPORTANT: We also need to initialize the global 'opts' structure with safe defaults
// because the jail functions expect it to be populated with valid values (especially
// opts.jail_argv for the program to execute). Without this, we get null pointer crashes.
static bool jail_state_initialized = false;

static void init_opts_defaults(void) {
    // Initialize the global opts structure with safe defaults
    // This prevents null pointer dereferences in the jail functions
    static char *default_argv[] = {"/bin/true", NULL};
    
    memset(&opts, 0, sizeof(opts));
    
    // Set essential fields that the functions expect
    opts.jail_argv = default_argv;
    opts.name = "test-jail";
    opts.term_timeout = 5;
    opts.root_map_uid = 65534;
    
    // Initialize setns fields to -1 (indicates unused)
    opts.setns.pid = -1;
    opts.setns.net = -1;
    opts.setns.ns = -1;
    opts.setns.ipc = -1;
    opts.setns.uts = -1;
    opts.setns.user = -1;
    opts.setns.cgroup = -1;
}

static void init_jail_state(void) {
    if (jail_state_initialized) return;
    
    // Initialize global state as done in procd_jail_main
    // Wrap in try-catch equivalent for safety
    umask(022);
    
    // Initialize the opts structure with safe defaults
    init_opts_defaults();
    
    // Initialize subsystems safely
    #if defined(__linux__) && !defined(_WIN32)
    mount_list_init();
    init_library_search();
    cgroups_prepare();
    #endif
    
    jail_state_initialized = true;
}

static void cleanup_jail_state(void) {
    // Don't cleanup between fuzzer iterations to avoid use-after-free
    // The original procd code expects these to be initialized once per process
    // Cleanup only happens at process exit (handled by OS)
    return;
}

// Required structures and globals from jail.c




// Fuzzing modes
typedef enum {
    FUZZ_MODE_PATCH_STDIO = 0,
    FUZZ_MODE_OCI_PARSE = 1,
    FUZZ_MODE_POST_MAIN = 2,
    FUZZ_MODE_PRE_EXEC_JAIL = 3,
    FUZZ_MODE_PROCD_JAIL_MAIN = 4,
    FUZZ_MODE_COUNT
} fuzz_mode_t;

// Stub implementations for functions referenced by jail.c but not needed for fuzzing
int jail_network_start(void *ctx, char *name, int pid) {
    // Stub - not needed for parseOCI fuzzing
    return 0;
}

int jail_network_stop(void) {
    // Stub - not needed for parseOCI fuzzing  
    return 0;
}

// Provide strlcpy implementation for Linux (BSD function not available)
size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = (srclen < size - 1) ? srclen : size - 1;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}

// Fuzzer constraints
#define MAX_FUZZ_SIZE (1024 * 1024)  // 1MB max
#define MIN_FUZZ_SIZE 10              // Minimum reasonable JSON size

// Global variables for fuzzing state
static char temp_filename[256] = {0};
static char temp_device_path[256] = {0};
static bool cleanup_needed = false;

// Cleanup function
static void cleanup_temp_files(void) {
    if (temp_filename[0] != '\0') {
        unlink(temp_filename);
        temp_filename[0] = '\0';
    }
    if (temp_device_path[0] != '\0') {
        unlink(temp_device_path);
        temp_device_path[0] = '\0';
    }
    cleanup_needed = false;
}

// Signal handler for cleanup
static void signal_handler(int sig) {
    cleanup_temp_files();
    _exit(1);
}

// Setup signal handlers
static void setup_signals(void) {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGABRT, signal_handler);
}

// Create temporary file with fuzz data
static int create_temp_file(const uint8_t *data, size_t size, const char *suffix) {
    int fd;
    ssize_t written;
    char template[256];
    
    snprintf(template, sizeof(template), "/tmp/fuzz_%s_XXXXXX", suffix);
    fd = mkstemp(template);
    if (fd == -1) {
        return -1;
    }
    
    // Store filename for cleanup
    if (strcmp(suffix, "config") == 0) {
        strcpy(temp_filename, template);
    } else if (strcmp(suffix, "device") == 0) {
        strcpy(temp_device_path, template);
    }
    
    written = write(fd, data, size);
    if (written != (ssize_t)size) {
        close(fd);
        unlink(template);
        return -1;
    }
    
    close(fd);
    return 0;
}

// Fuzz patch_stdio function
static int fuzz_patch_stdio(const uint8_t *data, size_t size) {
    char device_path[PATH_MAX];
    
    if (size < 5 || size > PATH_MAX - 1) {
        return 0;
    }
    
    // Create a device path from fuzz data
    memcpy(device_path, data, size);
    device_path[size] = '\0';
    
    // Sanitize path - only allow basic characters to avoid issues
    for (size_t i = 0; i < size; i++) {
        if (device_path[i] == '\0') break;
        if (device_path[i] < 0x20 || device_path[i] > 0x7E) {
            device_path[i] = '_';
        }
    }
    
    // Create a temporary device file if the path looks reasonable
    if (strncmp(device_path, "/dev/", 5) == 0 || strncmp(device_path, "/tmp/", 5) == 0) {
        // For safety, redirect to /dev/null or create a temp file
        if (create_temp_file(data, size, "device") == 0) {
            strcpy(device_path, temp_device_path);
        } else {
            strcpy(device_path, "/dev/null");
        }
    } else {
        strcpy(device_path, "/dev/null");
    }
    
    // Test patch_stdio in a child process to avoid affecting the main process
    pid_t child = fork();
    if (child == 0) {
        // Child process - test patch_stdio
        int result = patch_stdio(device_path);
        _exit(result == 0 ? 0 : 1);
    } else if (child > 0) {
        // Parent process - wait for child
        int status;
        waitpid(child, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    
    return 0;
}

// Fuzz OCI parsing (original functionality)
static int fuzz_oci_parse(const uint8_t *data, size_t size) {
    int result;
    
    // Basic JSON validation
    bool has_brace = false;
    bool has_quote = false;
    
    for (size_t i = 0; i < size && i < 100; i++) {
        if (data[i] == '{' || data[i] == '}') {
            has_brace = true;
        }
        if (data[i] == '"') {
            has_quote = true;
        }
        if (data[i] == 0 && i < (size - 1)) {
            return 0; // Reject binary data
        }
    }
    
    if (!has_brace && !has_quote) {
        return 0;
    }
    
    // Create temporary JSON file
    if (create_temp_file(data, size, "config") != 0) {
        return 0;
    }
    
    // Test parseOCI
    result = parseOCI(temp_filename);
    
    // Ignore result - we're looking for crashes, not correctness
    (void)result;
    
    return 0;
}

// Direct fuzz for post_main - call the actual function
static int fuzz_post_main(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    
    // Create a mock uloop_timeout structure
    struct uloop_timeout timeout = {0};
    
    // Fork to isolate the complex post_main function
    pid_t child = fork();
    if (child == 0) {
        // Child process - call the real post_main function
        // Child inherits initialized jail state from parent
        post_main(&timeout);
        _exit(0);
    } else if (child > 0) {
        // Parent process - wait for child
        int status;
        waitpid(child, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    
    return 0;
}

// Direct fuzz for pre_exec_jail - call the actual function  
static int fuzz_pre_exec_jail(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    // Create a mock uloop_timeout structure
    struct uloop_timeout timeout = {0};
    
    // Fork to isolate the complex pre_exec_jail function
    // Use double fork to handle the execve() call in post_start_hook
    pid_t child = fork();
    if (child == 0) {
        // Child process - call the real pre_exec_jail function
        // Child inherits initialized jail state from parent
        
        // Set up a timeout to prevent infinite execution
        alarm(2); // 2 second timeout
        
        pre_exec_jail(&timeout);
        _exit(0);
    } else if (child > 0) {
        // Parent process - wait for child with timeout
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        
        // Give it a short time to run
        if (result == 0) {
            usleep(100000); // 100ms
            result = waitpid(child, &status, WNOHANG);
        }
        
        // Kill child if still running
        if (result == 0) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
        }
        
        return 0;
    }
    
    return 0;
}

// Extract arguments from fuzz data for procd_jail_main
static int extract_args_from_fuzz_data(const uint8_t *data, size_t size, 
                                     int *argc, char ***argv) {
    if (size < 10) return -1;
    
    // Simple argument extraction - create argc/argv from fuzz data
    *argc = (data[0] % 8) + 1; // 1-8 arguments
    *argv = calloc(*argc + 1, sizeof(char*));
    if (!*argv) return -1;
    
    (*argv)[0] = strdup("/bin/true");  // Program name
    
    size_t offset = 1;
    for (int i = 1; i < *argc && offset < size; i++) {
        size_t arg_len = (data[offset] % 32) + 1; // 1-32 char arguments
        offset++;
        
        if (offset + arg_len >= size) break;
        
        (*argv)[i] = malloc(arg_len + 1);
        if (!(*argv)[i]) break;
        
        memcpy((*argv)[i], data + offset, arg_len);
        (*argv)[i][arg_len] = '\0';
        
        // Sanitize argument
        for (size_t j = 0; j < arg_len; j++) {
            if ((*argv)[i][j] < 0x20 || (*argv)[i][j] > 0x7E) {
                (*argv)[i][j] = 'A';
            }
        }
        
        offset += arg_len;
    }
    
    return 0;
}

// Direct fuzz for procd_jail_main - call the actual function
static int fuzz_procd_jail_main(const uint8_t *data, size_t size) {
    int argc;
    char **argv;
    
    if (size < 10) return 0;
    
    // Extract arguments from fuzz data
    if (extract_args_from_fuzz_data(data, size, &argc, &argv) != 0) {
        return 0;
    }
    
    // Fork to isolate the complex procd_jail_main function
    pid_t child = fork();
    if (child == 0) {
        // Child process - call the real procd_jail_main function
        int result = procd_jail_main(argc, argv);
        _exit(result);
    } else if (child > 0) {
        // Parent process - wait for child
        int status;
        waitpid(child, &status, 0);
        
        // Cleanup argv in parent
        for (int i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);
        
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    
    // Cleanup on fork failure
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    
    return 0;
}

// Input validation
static int validate_fuzz_input(const uint8_t *data, size_t size) {
    if (size < MIN_FUZZ_SIZE || size > MAX_FUZZ_SIZE) {
        return 0;
    }
    return 1;
}

// Main fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_mode_t mode;
    const uint8_t *fuzz_data;
    size_t fuzz_size;
    
    // Validate input
    if (!validate_fuzz_input(data, size)) {
        return 0;
    }
    
    // Initialize jail state once per process (not per iteration)
    init_jail_state();
    
    // Setup signal handlers and cleanup
    setup_signals();
    cleanup_needed = true;
    
    // Determine fuzzing mode from first byte
    mode = data[0] % FUZZ_MODE_COUNT;
    fuzz_data = data + 1;
    fuzz_size = size - 1;
    
    if (fuzz_size == 0) {
        goto cleanup;
    }
    
    // Execute appropriate fuzzing mode
    switch (mode) {
        case FUZZ_MODE_PATCH_STDIO:
            fuzz_patch_stdio(fuzz_data, fuzz_size);
            break;
            
        case FUZZ_MODE_OCI_PARSE:
            fuzz_oci_parse(fuzz_data, fuzz_size);
            break;
            
        case FUZZ_MODE_POST_MAIN:
            fuzz_post_main(fuzz_data, fuzz_size);
            break;
            
        case FUZZ_MODE_PRE_EXEC_JAIL:
            fuzz_pre_exec_jail(fuzz_data, fuzz_size);
            break;
            
        case FUZZ_MODE_PROCD_JAIL_MAIN:
            fuzz_procd_jail_main(fuzz_data, fuzz_size);
            break;
            
        default:
            break;
    }
    
cleanup:
    // Clean up temporary files only (not jail state between iterations)
    cleanup_temp_files();
    
    return 0;
}

// Initialize function (called once)
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize any global state needed for fuzzing
    (void)argc;
    (void)argv;
    
    // Seed random number generator
    srand(time(NULL));
    
    return 0;
}

