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


#include "jail/jail.h"
#include "jail/capabilities.h" 
#include "jail/cgroups.h"
#include "jail/fs.h"

extern int parseOCI(const char *jsonfile);

int jail_network_start(void *ctx, char *name, int pid) {
    return 0;
}

int jail_network_stop(void) {
    return 0;
}

size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = (srclen < size - 1) ? srclen : size - 1;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}



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
    
    strcpy(temp_filename, "/tmp/fuzz_config_XXXXXX");
    fd = mkstemp(temp_filename);
    if (fd == -1) {
        return -1;
    }
    
    written = write(fd, data, size);
    if (written != (ssize_t)size) {
        close(fd);
        cleanup_temp_file();
        return -1;
    }
    
    close(fd);
    return 0;
}



int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {    
    if (size < 10) {
        return 0;
    }

    if (create_temp_json_file(data, size) != 0) {
        return 0;
    }
    parseOCI(temp_filename);
    cleanup_temp_file();

    return 0;
}

