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

// Include necessary headers from procd
#include "jail/jail.h"
#include "jail/capabilities.h"  // Needed for indirect deps
#include "jail/cgroups.h"
#include "jail/fs.h"

// External function declarations that parseOCI depends on
extern int parseOCI(const char *jsonfile);

// Fuzzer constraints
#define MAX_FUZZ_SIZE (1024 * 1024)  // 1MB max
#define MIN_FUZZ_SIZE 10              // Minimum reasonable JSON size

// Temporary file cleanup tracking
static char temp_filename[256] = {0};

static void cleanup_temp_file(void) {
    if (temp_filename[0] != '\0') {
        unlink(temp_filename);
        temp_filename[0] = '\0';
    }
}

static int create_temp_json_file(const uint8_t *data, size_t size) {
    int fd;
    ssize_t written;
    
    // Create temporary file
    strcpy(temp_filename, "/tmp/fuzz_config_XXXXXX");
    fd = mkstemp(temp_filename);
    if (fd == -1) {
        return -1;
    }
    
    // Write fuzz data to file
    written = write(fd, data, size);
    if (written != (ssize_t)size) {
        close(fd);
        cleanup_temp_file();
        return -1;
    }
    
    close(fd);
    return 0;
}

static int validate_fuzz_input(const uint8_t *data, size_t size) {
    // Size validation
    if (size < MIN_FUZZ_SIZE || size > MAX_FUZZ_SIZE) {
        return 0;
    }
    
    // Basic content validation - ensure it contains some JSON-like characters
    bool has_brace = false;
    bool has_quote = false;
    
    for (size_t i = 0; i < size && i < 100; i++) {  // Check first 100 bytes
        if (data[i] == '{' || data[i] == '}') {
            has_brace = true;
        }
        if (data[i] == '"') {
            has_quote = true;
        }
        // Reject obviously binary data
        if (data[i] == 0 && i < (size - 1)) {
            return 0;
        }
    }
    
    // Require at least some JSON-like structure
    if (!has_brace && !has_quote) {
        return 0;
    }
    
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int result;
    
    // Validate input before processing
    if (!validate_fuzz_input(data, size)) {
        return 0;
    }
    
    // Create temporary JSON file with fuzz data
    if (create_temp_json_file(data, size) != 0) {
        goto cleanup;
    }
    
    // Call parseOCI with the temporary file
    // This is the main fuzzing target
    result = parseOCI(temp_filename);
    
    // Note: We ignore the result intentionally - we're looking for crashes,
    // not correctness. parseOCI is expected to fail on invalid input.
    (void)result;
    
cleanup:
    // Clean up temporary file
    cleanup_temp_file();
    
    return 0;
}

// Initialize function called once at startup
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Suppress error messages to avoid spam during fuzzing
    // You might want to comment this out during development
    freopen("/dev/null", "w", stderr);
    
    return 0;
}