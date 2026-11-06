#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char title[64];
    char author[32];
} Manifest;

/* FIXED: Explicit length check + bounded snprintf (CWE-120 mitigated) */
int parse_header(const char *raw_title, size_t len, Manifest *m) {
    if (raw_title == NULL || m == NULL || len >= sizeof(m->title)) {
        return -1;
    }
    snprintf(m->author, sizeof(m->author), "%s", "default_author");
    int n = snprintf(m->title, sizeof(m->title), "%s", raw_title);
    if (n < 0 || (size_t)n >= sizeof(m->title)) {
        return -1;
    }
    return 0;
}

#ifdef STANDALONE_POC
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    Manifest m;
    int rc = parse_header(argv[1], strlen(argv[1]), &m);
    if (rc != 0) {
        printf("[SECURE] Error: Input rejected cleanly (len=%zu >= 64). rc=%d\n", strlen(argv[1]), rc);
        return 0;
    }
    printf("Parsed Title: %s | Author: %s\n", m.title, m.author);
    return 0;
}
#endif
