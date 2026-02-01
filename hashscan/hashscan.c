/*
 * HASHSCAN v6.0 - Superman Hash Artifact Scanner
 * ================================================
 * Cross-platform (Linux/Windows) comprehensive hash finder.
 * 
 * Features:
 *   - Binary detection (skips binaries)
 *   - UTF-16 detection & conversion
 *   - Deduplication (FNV-1a fingerprint)
 *   - Context lines
 *   - Proper JSON escaping
 *   - Windows owner via path heuristic
 *   - 45+ hash patterns
 *   - Smart hex false-positive filtering
 *   - Symlink loop detection (inode tracking)
 *   - Dynamic memory (no fixed limits)
 *   - Timeout support
 *
 * Compile:
 *   Linux:   gcc -O2 -o hashscan hashscan.c
 *   Windows: x86_64-w64-mingw32-gcc -O2 -o hashscan.exe hashscan.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <math.h>
#include <errno.h>

#ifdef _WIN32
    #include <windows.h>
    #define PATH_SEP '\\'
    #define IS_WINDOWS 1
    #define stat _stat
    #define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
    #define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
    #define S_ISLNK(m) 0
#else
    #include <unistd.h>
    #include <pwd.h>
    #define PATH_SEP '/'
    #define IS_WINDOWS 0
#endif

#define VERSION "10.0"
#define MAX_LINE 16384
#define MAX_PATH_LEN 4096
#define MAX_CONTEXT 512
#define HASH_TABLE_SIZE 65536
#define TEMP_DIR "/tmp/hashscan_extract"

#ifdef _WIN32
#define TEMP_DIR_WIN "C:\\Windows\\Temp\\hashscan_extract"
#endif

/* Tool availability flags */
static int has_tar = 0;
static int has_unzip = 0;
static int has_sqlite3 = 0;
static int has_git = 0;
static int has_strings = 0;
static int opt_collectors = 1;  /* Enable collectors by default */

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

typedef enum { CAT_PASSWORD_HASH, CAT_POSSIBLE_HASH, CAT_PLAINTEXT, CAT_TOKEN, CAT_PRIVATE_KEY } Category;
typedef enum { CONF_HIGH, CONF_MEDIUM, CONF_LOW } Confidence;

/* Forward declarations (after type definitions) */
static void add_finding(Category cat, const char* type, Confidence conf, const char* path,
                       int line, long off, const char* val, int hc, const char* reason,
                       const char* cb, const char* ca);

typedef struct {
    Category category;
    char hash_type[64];
    Confidence confidence;
    char file_path[MAX_PATH_LEN];
    int line_number;
    long byte_offset;
    char value_preview[256];
    char value_full[512];
    int value_length;
    int hashcat_mode;
    char owner[64];
    char reason[256];
    char context_before[MAX_CONTEXT];
    char context_after[MAX_CONTEXT];
    uint32_t value_hash;
    int occurrence_count;
} Finding;

typedef struct {
    Finding* findings;
    int count;
    int capacity;
    int files_scanned;
    int files_skipped_binary;
    int files_skipped_size;
    int duplicates_suppressed;
    int errors;
    time_t start_time;
} ScanResult;

typedef struct DedupeEntry { uint32_t hash; int idx; struct DedupeEntry* next; } DedupeEntry;
typedef struct InodeEntry { uint64_t inode; uint64_t dev; struct InodeEntry* next; } InodeEntry;

/* Globals */
static ScanResult result;
static DedupeEntry* dedup_table[HASH_TABLE_SIZE];
static InodeEntry* inode_table[HASH_TABLE_SIZE];
static int opt_wide = 0, opt_show_values = 0, opt_json = 0, opt_verbose = 0, opt_context_lines = 1;
static int opt_max_files = 50000, opt_max_runtime = 0;
static long opt_max_file_size = 20 * 1024 * 1024;
static FILE* json_file = NULL;
static char* line_buffer[5];
static int line_buffer_idx = 0;

/* ============================================================================
 * USER-HASH CORRELATION & REUSE DETECTION
 * ============================================================================ */

typedef struct UserHashEntry {
    char username[64];
    char hash_types[256];
    int hash_count;
    char sources[512];
    int source_count;
    struct UserHashEntry* next;
} UserHashEntry;

typedef struct ReuseEntry {
    uint32_t value_hash;
    char value_preview[64];
    char users[256];
    int user_count;
    char files[512];
    int file_count;
    struct ReuseEntry* next;
} ReuseEntry;

#define USER_HASH_SIZE 256
#define REUSE_HASH_SIZE 1024

static UserHashEntry* user_hash_table[USER_HASH_SIZE];
static ReuseEntry* reuse_table[REUSE_HASH_SIZE];
static int opt_hashcat_mode = 0;
static int opt_correlation = 1;  /* Enable by default */

/* ============================================================================
 * HASH PATTERNS
 * ============================================================================ */

typedef struct { const char* name; const char* prefix; int plen; int minl; int maxl; int hc; Confidence c; } HashPattern;

static const HashPattern PATTERNS[] = {
    /* Unix crypt */
    {"sha512crypt", "$6$", 3, 90, 130, 1800, CONF_HIGH},
    {"sha256crypt", "$5$", 3, 55, 80, 7400, CONF_HIGH},
    {"md5crypt", "$1$", 3, 30, 45, 500, CONF_HIGH},
    {"bcrypt_2a", "$2a$", 4, 59, 61, 3200, CONF_HIGH},
    {"bcrypt_2b", "$2b$", 4, 59, 61, 3200, CONF_HIGH},
    {"bcrypt_2y", "$2y$", 4, 59, 61, 3200, CONF_HIGH},
    {"bcrypt_2x", "$2x$", 4, 59, 61, 3200, CONF_HIGH},
    {"yescrypt", "$y$", 3, 40, 200, -1, CONF_HIGH},
    {"gost_yescrypt", "$gy$", 4, 40, 200, -1, CONF_HIGH},
    {"scrypt", "$7$", 3, 50, 200, -1, CONF_HIGH},
    /* Argon2 */
    {"argon2i", "$argon2i$", 9, 60, 250, -1, CONF_HIGH},
    {"argon2d", "$argon2d$", 9, 60, 250, -1, CONF_HIGH},
    {"argon2id", "$argon2id$", 10, 60, 250, -1, CONF_HIGH},
    /* PHP/CMS */
    {"phpass_P", "$P$", 3, 34, 35, 400, CONF_HIGH},
    {"phpass_H", "$H$", 3, 34, 35, 400, CONF_HIGH},
    {"drupal7", "$S$", 3, 52, 54, 7900, CONF_HIGH},
    {"mediawiki_B", "$B$", 3, 31, 32, 3711, CONF_HIGH},
    /* Django */
    {"django_pbkdf2_256", "pbkdf2_sha256$", 14, 70, 200, 10000, CONF_HIGH},
    {"django_pbkdf2_1", "pbkdf2_sha1$", 12, 60, 150, -1, CONF_HIGH},
    {"pbkdf2_generic", "pbkdf2$", 7, 50, 200, -1, CONF_HIGH},
    /* Apache/LDAP */
    {"apr1", "$apr1$", 6, 30, 45, 1600, CONF_HIGH},
    {"sha_apache", "{SHA}", 5, 28, 32, 101, CONF_HIGH},
    {"ssha", "{SSHA}", 6, 32, 80, 111, CONF_HIGH},
    {"ssha256", "{SSHA256}", 9, 48, 100, -1, CONF_HIGH},
    {"ssha512", "{SSHA512}", 9, 96, 150, -1, CONF_HIGH},
    /* Spring */
    {"bcrypt_spring", "{bcrypt}", 8, 67, 70, 3200, CONF_HIGH},
    {"scrypt_spring", "{scrypt}", 8, 80, 200, -1, CONF_HIGH},
    /* Database */
    {"postgres_md5", "md5", 3, 35, 35, 0, CONF_HIGH},
    {"mssql2005", "0x0100", 6, 54, 54, 132, CONF_HIGH},
    {"mssql2012", "0x0200", 6, 132, 140, 1731, CONF_HIGH},
    /* SCRAM */
    {"scram_sha256", "SCRAM-SHA-256$", 14, 80, 200, -1, CONF_HIGH},
    {"mongodb_scram", "SCRAM-SHA-1$", 12, 70, 150, -1, CONF_HIGH},
    /* Windows */
    {"dcc2", "$DCC2$", 6, 50, 100, 2100, CONF_HIGH},
    /* Cisco */
    {"cisco_type8", "$8$", 3, 55, 60, 9200, CONF_HIGH},
    {"cisco_type9", "$9$", 3, 55, 60, 9300, CONF_HIGH},
    /* Kerberos */
    {"krb5tgs", "$krb5tgs$", 9, 50, 500, 13100, CONF_HIGH},
    {"krb5asrep", "$krb5asrep$", 11, 50, 500, 18200, CONF_HIGH},
    {NULL, NULL, 0, 0, 0, 0, 0}
};

static const char* CONTEXT_KEYWORDS[] = {
    "hash", "password", "passwd", "pwd", "pass", "secret", "credential",
    "auth", "login", "user", "salt", "md5", "sha1", "sha256", "ntlm",
    "INSERT", "UPDATE", "VALUES", "password_hash", "crypt(", NULL
};

/* Cloud/API Key Patterns */
typedef struct { const char* name; const char* prefix; int plen; int min; int max; } TokenPattern;

static const TokenPattern TOKEN_PATTERNS[] = {
    /* AWS */
    {"aws_access_key", "AKIA", 4, 20, 20},
    {"aws_access_key", "ABIA", 4, 20, 20},
    {"aws_access_key", "ACCA", 4, 20, 20},
    {"aws_access_key", "ASIA", 4, 20, 20},
    /* Google */
    {"gcp_api_key", "AIza", 4, 39, 39},
    /* GitHub */
    {"github_pat", "ghp_", 4, 40, 40},
    {"github_oauth", "gho_", 4, 40, 40},
    {"github_app", "ghu_", 4, 40, 40},
    {"github_refresh", "ghr_", 4, 40, 40},
    /* GitLab */
    {"gitlab_pat", "glpat-", 6, 26, 26},
    /* Slack */
    {"slack_token", "xoxb-", 5, 50, 80},
    {"slack_token", "xoxp-", 5, 50, 80},
    {"slack_token", "xoxa-", 5, 50, 80},
    {"slack_token", "xoxr-", 5, 50, 80},
    /* Stripe */
    {"stripe_live", "sk_live_", 8, 30, 50},
    {"stripe_test", "sk_test_", 8, 30, 50},
    /* Twilio */
    {"twilio_key", "SK", 2, 32, 32},
    /* SendGrid */
    {"sendgrid_key", "SG.", 3, 69, 69},
    /* npm */
    {"npm_token", "npm_", 4, 36, 36},
    /* PyPI */
    {"pypi_token", "pypi-", 5, 50, 200},
    /* Heroku */
    {"heroku_api", "heroku_", 7, 30, 50},
    /* DigitalOcean */
    {"digitalocean", "dop_v1_", 7, 64, 64},
    {"digitalocean", "doo_v1_", 7, 64, 64},
    /* Discord */
    {"discord_token", "NDc", 3, 59, 70},  /* Base64 starts */
    {"discord_token", "MTA", 3, 59, 70},
    /* Telegram */
    {"telegram_bot", "bot", 3, 45, 50},  /* Needs :AAF pattern */
    /* OpenAI */
    {"openai_key", "sk-", 3, 48, 60},
    /* Anthropic */
    {"anthropic_key", "sk-ant-", 7, 90, 120},
    /* Azure */
    {"azure_sas", "sig=", 4, 40, 100},
    /* Firebase */
    {"firebase_key", "AAAA", 4, 140, 200},  /* FCM server key */
    {NULL, NULL, 0, 0, 0}
};

/* Base64 secret indicators */
static const char* BASE64_SECRET_CONTEXTS[] = {
    "secret", "password", "key", "token", "credential", "auth",
    "private", "api_key", "apikey", "access_key", "secret_key",
    "encryption_key", "signing_key", "master_key", "app_key",
    NULL
};

/* Kubernetes secret patterns */
static const char* K8S_SECRET_KEYS[] = {
    "password:", "token:", "secret:", "api-key:", "apikey:",
    "credentials:", "private-key:", "ca.crt:", "tls.crt:", "tls.key:",
    NULL
};

/* ============================================================================
 * URL SCHEMES - for embedded credential detection
 * ============================================================================ */

/* ============================================================================
 * CREDENTIAL PATTERNS - Comprehensive plaintext detection
 * ============================================================================ */

/* Variable assignment patterns (comprehensive list) */
static const char* CRED_VAR_PATTERNS[] = {
    /* Generic */
    "password", "passwd", "pwd", "pass", "secret", "credential", "auth",
    /* Database - all variants */
    "db_password", "db_pass", "db_passwd", "database_password", "dbpassword", "dbpass",
    "mysql_password", "mysql_pwd", "mysql_pass", "mysql_root_password",
    "postgres_password", "pg_password", "pgpassword", "postgresql_password",
    "oracle_password", "mssql_password", "sql_password", "sqlpassword",
    "mongo_password", "mongodb_password", "mongo_pass",
    "redis_password", "redis_pass", "redis_auth",
    "mariadb_password", "mariadb_root_password",
    /* Web/App secrets */
    "app_secret", "app_key", "application_secret", "secret_key", "secret_key_base",
    "api_key", "apikey", "api_secret", "api_token",
    "access_key", "access_secret", "access_token",
    "auth_token", "auth_key", "auth_secret",
    "jwt_secret", "jwt_key", "session_secret", "session_key",
    "cookie_secret", "cookie_key",
    "encryption_key", "encrypt_key", "cipher_key", "crypto_key",
    "signing_key", "sign_key", "private_key", "priv_key",
    "master_key", "master_secret",
    /* Email/SMTP */
    "smtp_password", "smtp_pass", "smtp_pwd", "smtppassword",
    "mail_password", "mailpassword", "email_password",
    "imap_password", "pop3_password",
    /* Admin/Root */
    "admin_password", "admin_pass", "admin_pwd", "adminpassword",
    "root_password", "root_pass", "rootpassword",
    "user_password", "userpassword", "user_pass",
    "login_password", "loginpassword",
    "sudo_pass", "sudo_password",
    /* Cloud/Services */
    "aws_secret", "aws_secret_access_key", "aws_access_key_id",
    "azure_password", "azure_secret", "azure_key",
    "gcp_key", "google_api_key", "google_secret",
    "digitalocean_token", "do_token",
    "heroku_api_key", "heroku_key",
    /* Protocols */
    "ftp_password", "ftp_pass", "ftppassword",
    "ssh_password", "ssh_pass", "sshpassword", "ssh_key_passphrase",
    "vnc_password", "vnc_pass",
    "rdp_password", "rdp_pass",
    "telnet_password",
    /* LDAP/Directory */
    "ldap_password", "ldap_pass", "ldappassword",
    "bind_password", "bindpassword", "bind_pw",
    "ad_password", "active_directory_password",
    /* Tokens */
    "token", "bearer_token", "refresh_token", "oauth_token",
    "github_token", "gitlab_token", "bitbucket_password",
    "slack_token", "discord_token", "telegram_token",
    "stripe_secret", "stripe_key", "paypal_secret",
    "twilio_auth_token", "sendgrid_api_key",
    /* Framework specific */
    "django_secret_key", "rails_secret_key_base", "rails_master_key",
    "laravel_key", "symfony_secret", "flask_secret_key",
    "wp_password", "wordpress_db_password",
    "drupal_hash_salt",
    /* Connection strings often use these */
    "conn_password", "connection_password", "connectionstring",
    NULL
};

/* URL schemes that may contain credentials */
static const char* URL_SCHEMES[] = {
    "mysql://", "mysqli://", "postgres://", "postgresql://",
    "mongodb://", "mongo://", "redis://", "rediss://",
    "amqp://", "amqps://",  /* RabbitMQ */
    "ftp://", "ftps://", "sftp://",
    "ssh://", "scp://",
    "http://", "https://",  /* Basic auth embedded */
    "ldap://", "ldaps://",
    "smtp://", "smtps://",
    "oracle://", "sqlserver://", "mssql://",
    NULL
};

/* SQL patterns for INSERT/UPDATE with passwords */
static const char* SQL_PASSWORD_COLUMNS[] = {
    "password", "passwd", "pwd", "pass", "user_pass",
    "user_password", "hashed_password", "encrypted_password",
    "secret", "token", "auth_token", "api_key",
    NULL
};

/* ============================================================================
 * UTILITIES
 * ============================================================================ */

static uint32_t fnv1a(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

/* Calculate Shannon entropy (bits per character) */
static double calc_entropy(const char* s) {
    int freq[256] = {0};
    int len = 0;
    
    for (const char* p = s; *p; p++) {
        freq[(unsigned char)*p]++;
        len++;
    }
    
    if (len == 0) return 0.0;
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* Track user-hash correlation */
static void track_user_hash(const char* username, const char* hash_type, const char* source) {
    if (!opt_correlation || !username || !username[0]) return;
    
    uint32_t h = fnv1a(username) % USER_HASH_SIZE;
    UserHashEntry* e = user_hash_table[h];
    
    while (e) {
        if (strcmp(e->username, username) == 0) {
            /* Update existing entry */
            if (!strstr(e->hash_types, hash_type)) {
                if (e->hash_types[0]) strncat(e->hash_types, ", ", sizeof(e->hash_types) - strlen(e->hash_types) - 1);
                strncat(e->hash_types, hash_type, sizeof(e->hash_types) - strlen(e->hash_types) - 1);
                e->hash_count++;
            }
            /* Extract filename from path */
            const char* fname = strrchr(source, '/');
            if (!fname) fname = strrchr(source, '\\');
            fname = fname ? fname + 1 : source;
            if (!strstr(e->sources, fname)) {
                if (e->sources[0]) strncat(e->sources, ", ", sizeof(e->sources) - strlen(e->sources) - 1);
                strncat(e->sources, fname, sizeof(e->sources) - strlen(e->sources) - 1);
                e->source_count++;
            }
            return;
        }
        e = e->next;
    }
    
    /* New entry */
    e = calloc(1, sizeof(UserHashEntry));
    if (!e) return;
    strncpy(e->username, username, sizeof(e->username) - 1);
    strncpy(e->hash_types, hash_type, sizeof(e->hash_types) - 1);
    e->hash_count = 1;
    const char* fname = strrchr(source, '/');
    if (!fname) fname = strrchr(source, '\\');
    fname = fname ? fname + 1 : source;
    strncpy(e->sources, fname, sizeof(e->sources) - 1);
    e->source_count = 1;
    e->next = user_hash_table[h];
    user_hash_table[h] = e;
}

/* Track value reuse (passwords/hashes appearing multiple times) */
static void track_reuse(const char* value, const char* username, const char* filepath) {
    if (!opt_correlation || !value || strlen(value) < 4) return;
    
    uint32_t vh = fnv1a(value);
    uint32_t idx = vh % REUSE_HASH_SIZE;
    ReuseEntry* e = reuse_table[idx];
    
    while (e) {
        if (e->value_hash == vh) {
            /* Update existing */
            if (username && username[0] && !strstr(e->users, username)) {
                if (e->users[0]) strncat(e->users, ", ", sizeof(e->users) - strlen(e->users) - 1);
                strncat(e->users, username, sizeof(e->users) - strlen(e->users) - 1);
                e->user_count++;
            }
            const char* fname = strrchr(filepath, '/');
            if (!fname) fname = strrchr(filepath, '\\');
            fname = fname ? fname + 1 : filepath;
            if (!strstr(e->files, fname)) {
                if (e->files[0]) strncat(e->files, ", ", sizeof(e->files) - strlen(e->files) - 1);
                strncat(e->files, fname, sizeof(e->files) - strlen(e->files) - 1);
                e->file_count++;
            }
            return;
        }
        e = e->next;
    }
    
    /* New entry */
    e = calloc(1, sizeof(ReuseEntry));
    if (!e) return;
    e->value_hash = vh;
    strncpy(e->value_preview, value, sizeof(e->value_preview) - 1);
    if (username && username[0]) {
        strncpy(e->users, username, sizeof(e->users) - 1);
        e->user_count = 1;
    }
    const char* fname = strrchr(filepath, '/');
    if (!fname) fname = strrchr(filepath, '\\');
    fname = fname ? fname + 1 : filepath;
    strncpy(e->files, fname, sizeof(e->files) - 1);
    e->file_count = 1;
    e->next = reuse_table[idx];
    reuse_table[idx] = e;
}

#ifdef _WIN32
/* Windows doesn't have strncasecmp */
static int strncasecmp(const char* s1, const char* s2, size_t n) {
    while (n-- && *s1 && *s2) {
        int c1 = tolower((unsigned char)*s1++);
        int c2 = tolower((unsigned char)*s2++);
        if (c1 != c2) return c1 - c2;
    }
    return 0;
}
#endif

/* Case-insensitive strstr */
static const char* strcasestr_local(const char* haystack, const char* needle) {
    if (!*needle) return haystack;
    size_t nlen = strlen(needle);
    while (*haystack) {
        if (strncasecmp(haystack, needle, nlen) == 0) return haystack;
        haystack++;
    }
    return NULL;
}

static int is_hex(char c) { return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'); }
static void str_lower(char* s) { while (*s) { *s = tolower(*s); s++; } }

static void json_escape(const char* src, char* dst, int sz) {
    int di = 0;
    for (int si = 0; src[si] && di < sz - 6; si++) {
        unsigned char c = src[si];
        switch (c) {
            case '"': dst[di++]='\\'; dst[di++]='"'; break;
            case '\\': dst[di++]='\\'; dst[di++]='\\'; break;
            case '\n': dst[di++]='\\'; dst[di++]='n'; break;
            case '\r': dst[di++]='\\'; dst[di++]='r'; break;
            case '\t': dst[di++]='\\'; dst[di++]='t'; break;
            default: if (c<32) di+=snprintf(dst+di,sz-di,"\\u%04x",c); else dst[di++]=c;
        }
    }
    dst[di] = '\0';
}

static char* redact(const char* v, char* buf, int sz) {
    int l = strlen(v);
    if (l <= 16) snprintf(buf, sz, "****");
    else snprintf(buf, sz, "%.8s...%.8s", v, v + l - 8);
    return buf;
}

static int has_context(const char* line) {
    char lower[MAX_LINE];
    strncpy(lower, line, sizeof(lower)-1);
    str_lower(lower);
    for (int i = 0; CONTEXT_KEYWORDS[i]; i++)
        if (strstr(lower, CONTEXT_KEYWORDS[i])) return 1;
    return 0;
}

static int is_fp_hex(const char* hex, int len, const char* line) {
    /* Same char */
    int same = 1;
    for (int i = 1; i < len && same; i++) if (tolower(hex[i]) != tolower(hex[0])) same = 0;
    if (same) return 1;
    
    /* UUID check */
    if (len == 32) {
        const char* p = strstr(line, hex);
        if (p && ((p > line && *(p-1) == '-') || p[len] == '-')) return 1;
    }
    
    /* Git commit */
    if (len == 40 && (strstr(line, "commit ") || strstr(line, "tree ") || strstr(line, "parent "))) return 1;
    
    /* Docker sha256: */
    if (len == 64 && strstr(line, "sha256:")) return 1;
    
    /* Empty string hashes */
    char lower[256];
    for (int i = 0; i < len && i < 255; i++) lower[i] = tolower(hex[i]);
    lower[len < 255 ? len : 255] = '\0';
    if (len == 32 && strcmp(lower, "d41d8cd98f00b204e9800998ecf8427e") == 0) return 1;
    if (len == 40 && strcmp(lower, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0) return 1;
    
    /* Checksum context */
    if (strstr(line, "checksum") || strstr(line, "md5sum") || strstr(line, "sha256sum") || strstr(line, "integrity")) return 1;
    
    return 0;
}

static int is_binary(const unsigned char* buf, size_t len) {
    if (len == 0) return 0;
    int nulls = 0, nontext = 0;
    size_t check = len > 8192 ? 8192 : len;
    for (size_t i = 0; i < check; i++) {
        if (buf[i] == 0) nulls++;
        else if (buf[i] < 7 || (buf[i] > 14 && buf[i] < 32 && buf[i] != 27)) nontext++;
    }
    return (nulls > (int)(check * 0.1)) || (nontext > (int)(check * 0.3));
}

static int is_utf16(const unsigned char* buf, size_t len) {
    if (len < 2) return 0;
    if (buf[0] == 0xFF && buf[1] == 0xFE) return 1;
    if (buf[0] == 0xFE && buf[1] == 0xFF) return 2;
    return 0;
}

static size_t utf16_to_ascii(const unsigned char* src, size_t slen, char* dst, size_t dsize) {
    size_t di = 0, si = (src[0]==0xFF && src[1]==0xFE) ? 2 : 0;
    while (si + 1 < slen && di < dsize - 1) {
        unsigned char lo = src[si], hi = src[si+1];
        if (hi == 0 && lo >= 32 && lo < 127) dst[di++] = lo;
        else if (hi == 0 && (lo == '\n' || lo == '\r' || lo == '\t')) dst[di++] = lo;
        si += 2;
    }
    dst[di] = '\0';
    return di;
}

static void get_owner(const char* path, char* owner, int sz) {
#ifdef _WIN32
    const char* u = strstr(path, "\\Users\\");
    if (!u) u = strstr(path, "/Users/");
    if (u) {
        u += 7;
        const char* e = u;
        while (*e && *e != '\\' && *e != '/') e++;
        int l = e - u;
        if (l > 0 && l < sz - 1) { strncpy(owner, u, l); owner[l] = '\0'; return; }
    }
    owner[0] = '\0';
#else
    struct stat st;
    if (stat(path, &st) == 0) {
        struct passwd* pw = getpwuid(st.st_uid);
        if (pw) { strncpy(owner, pw->pw_name, sz-1); owner[sz-1] = '\0'; return; }
        snprintf(owner, sz, "%d", st.st_uid);
        return;
    }
    const char* h = strstr(path, "/home/");
    if (h) {
        h += 6;
        const char* e = strchr(h, '/');
        if (e) { int l = e - h; if (l > 0 && l < sz-1) { strncpy(owner, h, l); owner[l] = '\0'; return; } }
    }
    if (strncmp(path, "/root", 5) == 0) { strncpy(owner, "root", sz); return; }
    owner[0] = '\0';
#endif
}

/* ============================================================================
 * TOOL DETECTION - Check for system tools
 * ============================================================================ */

static int check_tool(const char* tool) {
#ifdef _WIN32
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "where %s >nul 2>&1", tool);
    return system(cmd) == 0;
#else
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "which %s >/dev/null 2>&1", tool);
    return system(cmd) == 0;
#endif
}

static void detect_tools(void) {
    has_tar = check_tool("tar");
    has_unzip = check_tool("unzip");
    has_sqlite3 = check_tool("sqlite3");
    has_git = check_tool("git");
    has_strings = check_tool("strings");
    
    if (opt_verbose) {
        fprintf(stderr, "[*] Tools: tar=%d unzip=%d sqlite3=%d git=%d strings=%d\n",
                has_tar, has_unzip, has_sqlite3, has_git, has_strings);
    }
}

/* ============================================================================
 * ARCHIVE COLLECTOR - Extract and scan ZIP/TAR archives
 * ============================================================================ */

static void scan_file(const char* path);  /* Forward declaration */
static void scan_dir(const char* path, int depth);

static void cleanup_temp_dir(void) {
#ifdef _WIN32
    system("rmdir /s /q " TEMP_DIR_WIN " 2>nul");
#else
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s 2>/dev/null", TEMP_DIR);
    system(cmd);
#endif
}

static void create_temp_dir(void) {
    cleanup_temp_dir();
#ifdef _WIN32
    system("mkdir " TEMP_DIR_WIN " 2>nul");
#else
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s 2>/dev/null", TEMP_DIR);
    system(cmd);
#endif
}

static int extract_archive(const char* archive_path) {
    char cmd[2048];
    const char* ext = strrchr(archive_path, '.');
    if (!ext) return 0;
    
    create_temp_dir();
    
#ifdef _WIN32
    const char* temp = TEMP_DIR_WIN;
#else
    const char* temp = TEMP_DIR;
#endif
    
    int success = 0;
    
    /* ZIP */
    if (has_unzip && (strcasecmp(ext, ".zip") == 0)) {
#ifdef _WIN32
        snprintf(cmd, sizeof(cmd), "powershell -Command \"Expand-Archive -Force '%s' '%s'\" 2>nul", archive_path, temp);
#else
        snprintf(cmd, sizeof(cmd), "unzip -o -q '%s' -d '%s' 2>/dev/null", archive_path, temp);
#endif
        success = (system(cmd) == 0);
    }
    /* TAR.GZ / TGZ */
    else if (has_tar && (strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".tgz") == 0)) {
        snprintf(cmd, sizeof(cmd), "tar -xzf '%s' -C '%s' 2>/dev/null", archive_path, temp);
        success = (system(cmd) == 0);
    }
    /* TAR.BZ2 */
    else if (has_tar && strcasecmp(ext, ".bz2") == 0) {
        snprintf(cmd, sizeof(cmd), "tar -xjf '%s' -C '%s' 2>/dev/null", archive_path, temp);
        success = (system(cmd) == 0);
    }
    /* Plain TAR */
    else if (has_tar && strcasecmp(ext, ".tar") == 0) {
        snprintf(cmd, sizeof(cmd), "tar -xf '%s' -C '%s' 2>/dev/null", archive_path, temp);
        success = (system(cmd) == 0);
    }
    
    return success;
}

static void collect_archive(const char* archive_path) {
    if (!opt_collectors) return;
    if (!has_tar && !has_unzip) return;
    
    /* Check file size (max 50MB for archives) */
    struct stat st;
    if (stat(archive_path, &st) != 0) return;
    if (st.st_size > 50 * 1024 * 1024) {
        if (opt_verbose) fprintf(stderr, "[!] Archive too large: %s\n", archive_path);
        return;
    }
    
    if (opt_verbose) fprintf(stderr, "[*] Extracting archive: %s\n", archive_path);
    
    if (extract_archive(archive_path)) {
#ifdef _WIN32
        scan_dir(TEMP_DIR_WIN, 0);
#else
        scan_dir(TEMP_DIR, 0);
#endif
        cleanup_temp_dir();
    }
}

/* ============================================================================
 * SQLITE COLLECTOR - Dump and scan SQLite databases
 * ============================================================================ */

static void collect_sqlite(const char* db_path) {
    if (!opt_collectors) return;
    
    /* Check file size */
    struct stat st;
    if (stat(db_path, &st) != 0) return;
    if (st.st_size > 100 * 1024 * 1024) return;  /* Max 100MB */
    
    if (has_sqlite3) {
        /* Use sqlite3 CLI to dump */
        char cmd[2048];
        char dump_path[MAX_PATH_LEN];
        
#ifdef _WIN32
        snprintf(dump_path, sizeof(dump_path), "%s\\sqlite_dump.txt", TEMP_DIR_WIN);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "sqlite3 \"%s\" .dump > \"%s\" 2>nul", db_path, dump_path);
#else
        snprintf(dump_path, sizeof(dump_path), "%s/sqlite_dump.txt", TEMP_DIR);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "sqlite3 '%s' .dump > '%s' 2>/dev/null", db_path, dump_path);
#endif
        
        if (opt_verbose) fprintf(stderr, "[*] Dumping SQLite: %s\n", db_path);
        
        if (system(cmd) == 0) {
            scan_file(dump_path);
        }
        cleanup_temp_dir();
    }
    else if (has_strings) {
        /* Fallback: strings extraction */
        char cmd[2048];
        char strings_path[MAX_PATH_LEN];
        
#ifdef _WIN32
        snprintf(strings_path, sizeof(strings_path), "%s\\strings_out.txt", TEMP_DIR_WIN);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "strings \"%s\" > \"%s\" 2>nul", db_path, strings_path);
#else
        snprintf(strings_path, sizeof(strings_path), "%s/strings_out.txt", TEMP_DIR);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "strings '%s' > '%s' 2>/dev/null", db_path, strings_path);
#endif
        
        if (opt_verbose) fprintf(stderr, "[*] Strings from SQLite: %s\n", db_path);
        
        if (system(cmd) == 0) {
            scan_file(strings_path);
        }
        cleanup_temp_dir();
    }
}

/* ============================================================================
 * GIT COLLECTOR - Scan git history for secrets
 * ============================================================================ */

static void collect_git(const char* git_dir) {
    if (!opt_collectors) return;
    if (!has_git) return;
    
    /* git_dir should be the .git directory, get parent */
    char repo_path[MAX_PATH_LEN];
    strncpy(repo_path, git_dir, sizeof(repo_path) - 1);
    
    /* Remove .git suffix */
    char* git_suffix = strstr(repo_path, "/.git");
    if (!git_suffix) git_suffix = strstr(repo_path, "\\.git");
    if (git_suffix) *git_suffix = '\0';
    else return;
    
    if (opt_verbose) fprintf(stderr, "[*] Scanning git history: %s\n", repo_path);
    
    char cmd[2048];
    char log_path[MAX_PATH_LEN];
    
#ifdef _WIN32
    snprintf(log_path, sizeof(log_path), "%s\\git_history.txt", TEMP_DIR_WIN);
    create_temp_dir();
    /* Get last 100 commits with diffs */
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" log -p -100 --all > \"%s\" 2>nul", repo_path, log_path);
#else
    snprintf(log_path, sizeof(log_path), "%s/git_history.txt", TEMP_DIR);
    create_temp_dir();
    snprintf(cmd, sizeof(cmd), "git -C '%s' log -p -100 --all > '%s' 2>/dev/null", repo_path, log_path);
#endif
    
    if (system(cmd) == 0) {
        scan_file(log_path);
    }
    
    /* Also scan git config for credentials */
    char config_path[MAX_PATH_LEN];
    snprintf(config_path, sizeof(config_path), "%s/.git/config", repo_path);
    struct stat st;
    if (stat(config_path, &st) == 0) {
        scan_file(config_path);
    }
    
    cleanup_temp_dir();
}

/* ============================================================================
 * WINDOWS ARTIFACT DISCOVERY - Report sensitive files
 * ============================================================================ */

static void check_windows_artifacts(const char* path) {
#ifdef _WIN32
    /* Check for SAM/SYSTEM/SECURITY hives */
    const char* artifacts[] = {
        "SAM", "SYSTEM", "SECURITY", "NTDS.dit", "ntds.dit",
        NULL
    };
    
    const char* fname = strrchr(path, '\\');
    if (!fname) fname = strrchr(path, '/');
    if (!fname) fname = path;
    else fname++;
    
    for (int i = 0; artifacts[i]; i++) {
        if (strcasecmp(fname, artifacts[i]) == 0) {
            /* Report as artifact discovery */
            char reason[256];
            snprintf(reason, sizeof(reason), "Windows credential artifact: %s", artifacts[i]);
            add_finding(CAT_TOKEN, "windows_artifact", CONF_HIGH, path, 0, 0, 
                       "[CREDENTIAL ARTIFACT]", -1, reason, NULL, NULL);
            break;
        }
    }
#else
    (void)path;
#endif
}

/* ============================================================================
 * DEDUP & INODE
 * ============================================================================ */

static void init_tables(void) { memset(dedup_table, 0, sizeof(dedup_table)); memset(inode_table, 0, sizeof(inode_table)); }

static void free_tables(void) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        DedupeEntry* d = dedup_table[i];
        while (d) { DedupeEntry* n = d->next; free(d); d = n; }
        InodeEntry* e = inode_table[i];
        while (e) { InodeEntry* n = e->next; free(e); e = n; }
    }
}

static int check_dup(uint32_t h) {
    int idx = h % HASH_TABLE_SIZE;
    for (DedupeEntry* e = dedup_table[idx]; e; e = e->next)
        if (e->hash == h) return e->idx;
    return -1;
}

static void add_dup(uint32_t h, int fidx) {
    int idx = h % HASH_TABLE_SIZE;
    DedupeEntry* e = malloc(sizeof(DedupeEntry));
    if (e) { e->hash = h; e->idx = fidx; e->next = dedup_table[idx]; dedup_table[idx] = e; }
}

#ifndef _WIN32
static int check_inode(uint64_t inode, uint64_t dev) {
    uint32_t h = (uint32_t)(inode ^ dev);
    int idx = h % HASH_TABLE_SIZE;
    for (InodeEntry* e = inode_table[idx]; e; e = e->next)
        if (e->inode == inode && e->dev == dev) return 1;
    InodeEntry* e = malloc(sizeof(InodeEntry));
    if (e) { e->inode = inode; e->dev = dev; e->next = inode_table[idx]; inode_table[idx] = e; }
    return 0;
}
#endif

/* ============================================================================
 * FINDINGS
 * ============================================================================ */

static int ensure_cap(void) {
    if (result.count >= result.capacity) {
        int nc = result.capacity * 2;
        Finding* nf = realloc(result.findings, nc * sizeof(Finding));
        if (!nf) { fprintf(stderr, "[!] Out of memory\n"); return 0; }
        result.findings = nf;
        result.capacity = nc;
    }
    return 1;
}

static void add_finding(Category cat, const char* type, Confidence conf, const char* path,
                       int line, long off, const char* val, int hc, const char* reason,
                       const char* ctx_b, const char* ctx_a) {
    uint32_t vh = fnv1a(val);
    int dup = check_dup(vh);
    if (dup >= 0) { result.findings[dup].occurrence_count++; result.duplicates_suppressed++; return; }
    if (!ensure_cap()) return;
    
    Finding* f = &result.findings[result.count];
    memset(f, 0, sizeof(Finding));
    f->category = cat;
    strncpy(f->hash_type, type, sizeof(f->hash_type)-1);
    f->confidence = conf;
    strncpy(f->file_path, path, sizeof(f->file_path)-1);
    f->line_number = line;
    f->byte_offset = off;
    f->value_length = strlen(val);
    f->hashcat_mode = hc;
    strncpy(f->reason, reason, sizeof(f->reason)-1);
    f->value_hash = vh;
    f->occurrence_count = 1;
    strncpy(f->value_full, val, sizeof(f->value_full)-1);
    if (opt_show_values) strncpy(f->value_preview, val, sizeof(f->value_preview)-1);
    else redact(val, f->value_preview, sizeof(f->value_preview));
    get_owner(path, f->owner, sizeof(f->owner));
    if (ctx_b) strncpy(f->context_before, ctx_b, sizeof(f->context_before)-1);
    if (ctx_a) strncpy(f->context_after, ctx_a, sizeof(f->context_after)-1);
    
    /* Calculate entropy for tokens/credentials */
    if (cat == CAT_TOKEN || cat == CAT_PLAINTEXT) {
        double ent = calc_entropy(val);
        if (ent < 2.0 && f->value_length > 8) {
            /* Low entropy - likely placeholder */
            f->confidence = CONF_LOW;
            strncat(f->reason, " [LOW ENTROPY]", sizeof(f->reason) - strlen(f->reason) - 1);
        }
    }
    
    /* Track user-hash correlation */
    if (cat == CAT_PASSWORD_HASH || cat == CAT_POSSIBLE_HASH) {
        track_user_hash(f->owner, type, path);
    }
    
    /* Track value reuse */
    track_reuse(val, f->owner, path);
    
    add_dup(vh, result.count);
    result.count++;
    
    if (opt_verbose) fprintf(stderr, "[+] %s: %s in %s:%d\n",
        cat==CAT_PASSWORD_HASH?"HASH":cat==CAT_POSSIBLE_HASH?"POSSIBLE":"FOUND", type, path, line);
}

/* ============================================================================
 * SCANNING
 * ============================================================================ */

static void scan_line(const char* line, const char* path, int lnum, long off, const char* cb, const char* ca) {
    int len = strlen(line);
    if (len < 8 || len > MAX_LINE) return;
    
    /* Pattern matching */
    for (int i = 0; PATTERNS[i].name; i++) {
        const HashPattern* p = &PATTERNS[i];
        if (p->plen == 0) continue;
        const char* pos = line;
        while ((pos = strstr(pos, p->prefix)) != NULL) {
            int hl = 0;
            const char* st = pos;
            while (st[hl] && !isspace(st[hl]) && st[hl]!='"' && st[hl]!='\'' && 
                   st[hl]!=',' && st[hl]!=';' && st[hl]!='<' && st[hl]!='>' && 
                   st[hl]!=')' && st[hl]!=']' && hl < 300) hl++;
            if (hl >= p->minl && hl <= p->maxl) {
                char hv[512];
                strncpy(hv, st, hl < 511 ? hl : 511);
                hv[hl < 511 ? hl : 511] = '\0';
                add_finding(CAT_PASSWORD_HASH, p->name, p->c, path, lnum, off, hv, p->hc, "Matched pattern", cb, ca);
            }
            pos++;
        }
    }
    
    /* MySQL5 *HASH */
    const char* mp = line;
    while ((mp = strchr(mp, '*')) != NULL) {
        int hc = 0;
        while (is_hex(mp[1+hc]) && hc < 50) hc++;
        if (hc == 40) {
            char hv[50];
            strncpy(hv, mp, 41);
            hv[41] = '\0';
            add_finding(CAT_PASSWORD_HASH, "mysql5", CONF_HIGH, path, lnum, off, hv, 300, "MySQL5 hash", cb, ca);
        }
        mp++;
    }
    
    /* Hex patterns */
    int has_ctx = has_context(line);
    if (opt_wide || has_ctx) {
        const char* hp = line;
        while (*hp) {
            while (*hp && !is_hex(*hp)) hp++;
            if (!*hp) break;
            const char* st = hp;
            int hl = 0;
            while (is_hex(*hp)) { hl++; hp++; }
            if (hl == 32 || hl == 40 || hl == 64 || hl == 128) {
                char hv[256];
                strncpy(hv, st, hl < 255 ? hl : 255);
                hv[hl < 255 ? hl : 255] = '\0';
                if (!is_fp_hex(hv, hl, line)) {
                    const char* t = hl==32?"hex32_md5_ntlm":hl==40?"hex40_sha1":hl==64?"hex64_sha256":"hex128_sha512";
                    int hc = hl==32?0:hl==40?100:hl==64?1400:1700;
                    Confidence c = has_ctx ? CONF_MEDIUM : CONF_LOW;
                    add_finding(CAT_POSSIBLE_HASH, t, c, path, lnum, off, hv, hc, 
                               has_ctx ? "Hex with context" : "Hex (wide)", cb, ca);
                }
            }
        }
    }
    
    /* ========================================================================
     * CREDENTIAL DISCOVERY ENGINE - Comprehensive plaintext detection
     * ======================================================================== */
    
    /* 1. Variable assignments: password=xxx, password: xxx, password => xxx */
    for (int i = 0; CRED_VAR_PATTERNS[i]; i++) {
        const char* pattern = CRED_VAR_PATTERNS[i];
        const char* pos = line;
        
        while ((pos = strcasestr_local(pos, pattern)) != NULL) {
            /* Make sure it's a word boundary (not part of larger word) */
            if (pos > line && (isalnum(*(pos-1)) || *(pos-1) == '_')) {
                pos++;
                continue;
            }
            
            /* Skip to end of keyword */
            const char* after = pos + strlen(pattern);
            
            /* Skip optional characters: _key, _value, etc */
            while (*after && (isalnum(*after) || *after == '_' || *after == '-')) after++;
            
            /* Skip whitespace */
            while (*after == ' ' || *after == '\t') after++;
            
            /* Check for assignment operators: = : => */
            int is_assign = 0;
            if (*after == '=') { after++; is_assign = 1; }
            else if (*after == ':') { after++; is_assign = 1; }
            else if (after[0] == '=' && after[1] == '>') { after += 2; is_assign = 1; }
            
            if (!is_assign) { pos++; continue; }
            
            /* Skip whitespace and quotes */
            while (*after == ' ' || *after == '\t') after++;
            char quote = 0;
            if (*after == '"' || *after == '\'') { quote = *after; after++; }
            
            /* Extract value */
            int vlen = 0;
            while (after[vlen] && vlen < 200) {
                if (quote && after[vlen] == quote) break;
                if (!quote && (isspace(after[vlen]) || after[vlen] == ';' || 
                    after[vlen] == ',' || after[vlen] == '"' || after[vlen] == '\'' ||
                    after[vlen] == '<' || after[vlen] == '>')) break;
                vlen++;
            }
            
            if (vlen >= 3 && vlen <= 200) {
                char val[256];
                strncpy(val, after, vlen);
                val[vlen] = '\0';
                
                /* Skip common placeholders */
                char vlow[256];
                strncpy(vlow, val, sizeof(vlow)-1);
                str_lower(vlow);
                
                if (strcmp(vlow, "xxx") == 0 || strcmp(vlow, "changeme") == 0 ||
                    strcmp(vlow, "password") == 0 || strcmp(vlow, "secret") == 0 ||
                    strcmp(vlow, "your_password") == 0 || strcmp(vlow, "none") == 0 ||
                    strcmp(vlow, "null") == 0 || strcmp(vlow, "undefined") == 0 ||
                    strcmp(vlow, "todo") == 0 || strcmp(vlow, "fixme") == 0 ||
                    strcmp(vlow, "example") == 0 || strcmp(vlow, "test") == 0 ||
                    strcmp(vlow, "false") == 0 || strcmp(vlow, "true") == 0 ||
                    strstr(vlow, "placeholder") || strstr(vlow, "change_me") ||
                    strstr(vlow, "your-") || strstr(vlow, "your_") ||
                    strstr(vlow, "insert") || strstr(vlow, "enter") ||
                    val[0] == '$' || val[0] == '%' || val[0] == '{' || 
                    val[0] == '<' || val[0] == '(' || val[0] == '[') {
                    pos++;
                    continue;
                }
                
                /* Skip if it looks like a path or URL without creds */
                if (val[0] == '/' || strncmp(val, "http", 4) == 0 || 
                    strncmp(val, "file:", 5) == 0) {
                    pos++;
                    continue;
                }
                
                Confidence conf = (vlen >= 8) ? CONF_HIGH : CONF_MEDIUM;
                char reason[128];
                snprintf(reason, sizeof(reason), "Credential: %s=...", pattern);
                add_finding(CAT_PLAINTEXT, "plaintext_credential", conf, path, lnum, off, val, -1, reason, cb, ca);
            }
            pos++;
        }
    }
    
    /* 2. URL embedded credentials: mysql://user:pass@host */
    for (int i = 0; URL_SCHEMES[i]; i++) {
        const char* scheme = URL_SCHEMES[i];
        const char* pos = line;
        
        while ((pos = strcasestr_local(pos, scheme)) != NULL) {
            const char* after_scheme = pos + strlen(scheme);
            
            /* Look for user:pass@host pattern */
            const char* at = strchr(after_scheme, '@');
            if (at && at - after_scheme < 100) {
                /* Check if there's a colon before @ (indicates password) */
                const char* colon = strchr(after_scheme, ':');
                if (colon && colon < at) {
                    /* Extract user:pass */
                    int cred_len = at - after_scheme;
                    if (cred_len >= 3 && cred_len < 100) {
                        char cred[128];
                        strncpy(cred, after_scheme, cred_len);
                        cred[cred_len] = '\0';
                        
                        /* Skip if looks like port number only */
                        const char* pass_start = colon + 1;
                        int pass_len = at - pass_start;
                        if (pass_len > 0) {
                            int all_digits = 1;
                            for (int j = 0; j < pass_len; j++) {
                                if (!isdigit(pass_start[j])) { all_digits = 0; break; }
                            }
                            if (!all_digits) {
                                add_finding(CAT_PLAINTEXT, "url_credential", CONF_HIGH, path, lnum, off, cred, -1, "URL embedded credential", cb, ca);
                            }
                        }
                    }
                }
            }
            pos++;
        }
    }
    
    /* 3. HTTP Basic Auth: Authorization: Basic <base64> */
    const char* auth_basic = strcasestr_local(line, "authorization");
    if (auth_basic) {
        const char* basic = strcasestr_local(auth_basic, "basic ");
        if (basic) {
            basic += 6;
            while (*basic == ' ') basic++;
            
            int b64len = 0;
            while (basic[b64len] && (isalnum(basic[b64len]) || basic[b64len] == '+' || 
                   basic[b64len] == '/' || basic[b64len] == '=') && b64len < 100) {
                b64len++;
            }
            
            if (b64len >= 8 && b64len <= 100) {
                char b64[128];
                strncpy(b64, basic, b64len);
                b64[b64len] = '\0';
                add_finding(CAT_PLAINTEXT, "http_basic_auth", CONF_HIGH, path, lnum, off, b64, -1, "HTTP Basic Auth (base64)", cb, ca);
            }
        }
    }
    
    /* 4. SQL INSERT/UPDATE with password columns */
    const char* sql = strcasestr_local(line, "INSERT");
    if (!sql) sql = strcasestr_local(line, "UPDATE");
    if (sql) {
        int has_pwd_col = 0;
        for (int i = 0; SQL_PASSWORD_COLUMNS[i]; i++) {
            if (strcasestr_local(line, SQL_PASSWORD_COLUMNS[i])) {
                has_pwd_col = 1;
                break;
            }
        }
        
        if (has_pwd_col) {
            const char* values = strcasestr_local(line, "VALUES");
            if (values) {
                const char* paren = strchr(values, '(');
                if (paren) {
                    const char* p = paren + 1;
                    while (*p && *p != ')') {
                        if (*p == '\'' || *p == '"') {
                            char quote = *p;
                            p++;
                            int vlen = 0;
                            while (p[vlen] && p[vlen] != quote && vlen < 100) vlen++;
                            if (vlen >= 4 && vlen <= 100) {
                                char val[128];
                                strncpy(val, p, vlen);
                                val[vlen] = '\0';
                                int has_letter = 0;
                                for (int j = 0; j < vlen; j++) if (isalpha(val[j])) has_letter = 1;
                                if (has_letter && !strchr(val, '@')) {
                                    add_finding(CAT_PLAINTEXT, "sql_value", CONF_MEDIUM, path, lnum, off, val, -1, "SQL INSERT/UPDATE value", cb, ca);
                                }
                            }
                            p += vlen;
                        }
                        p++;
                    }
                }
            }
        }
    }
    
    /* 5. JSON "key": "value" with password-related keys */
    if (strchr(line, '"')) {
        const char* check_keys[] = {"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", NULL};
        for (int i = 0; check_keys[i]; i++) {
            char json_pat[64];
            snprintf(json_pat, sizeof(json_pat), "\"%s\"", check_keys[i]);
            
            const char* pos = strcasestr_local(line, json_pat);
            if (pos) {
                pos += strlen(json_pat);
                while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
                
                if (*pos == '"') {
                    pos++;
                    int vlen = 0;
                    while (pos[vlen] && pos[vlen] != '"' && vlen < 200) vlen++;
                    
                    if (vlen >= 3 && vlen <= 200) {
                        char val[256];
                        strncpy(val, pos, vlen);
                        val[vlen] = '\0';
                        
                        char vlow[256];
                        strncpy(vlow, val, sizeof(vlow)-1);
                        str_lower(vlow);
                        if (strcmp(vlow, "xxx") != 0 && strcmp(vlow, "changeme") != 0 &&
                            strcmp(vlow, "null") != 0 && strcmp(vlow, "none") != 0 &&
                            strcmp(vlow, "false") != 0 && strcmp(vlow, "true") != 0 &&
                            val[0] != '$' && val[0] != '{') {
                            add_finding(CAT_PLAINTEXT, "json_credential", CONF_HIGH, path, lnum, off, val, -1, "JSON credential value", cb, ca);
                        }
                    }
                }
            }
        }
    }
    
    /* 6. XML/HTML password elements: <password>value</password> */
    const char* xml_tags[] = {"<password>", "<passwd>", "<pwd>", "<secret>", "<token>", "<apikey>", NULL};
    for (int i = 0; xml_tags[i]; i++) {
        const char* tag = strcasestr_local(line, xml_tags[i]);
        if (tag) {
            const char* val_start = tag + strlen(xml_tags[i]);
            const char* val_end = strchr(val_start, '<');
            if (val_end && val_end - val_start >= 3 && val_end - val_start < 100) {
                int vlen = val_end - val_start;
                char val[128];
                strncpy(val, val_start, vlen);
                val[vlen] = '\0';
                add_finding(CAT_PLAINTEXT, "xml_credential", CONF_HIGH, path, lnum, off, val, -1, "XML credential value", cb, ca);
            }
        }
    }
    
    /* Private keys */
    if (strstr(line, "-----BEGIN") && strstr(line, "PRIVATE KEY-----"))
        add_finding(CAT_PRIVATE_KEY, "private_key", CONF_HIGH, path, lnum, off, "[PRIVATE KEY]", -1, "Private key", cb, ca);
    
    /* JWT */
    const char* jwt = line;
    while ((jwt = strstr(jwt, "eyJ")) != NULL) {
        int jl = 0, dots = 0;
        while (jwt[jl] && (isalnum(jwt[jl]) || jwt[jl]=='_' || jwt[jl]=='-' || jwt[jl]=='.')) {
            if (jwt[jl] == '.') dots++;
            jl++;
        }
        if (dots == 2 && jl > 50) {
            char jv[512];
            strncpy(jv, jwt, jl < 500 ? jl : 500);
            jv[jl < 500 ? jl : 500] = '\0';
            add_finding(CAT_TOKEN, "jwt_token", CONF_HIGH, path, lnum, off, jv, -1, "JWT token", cb, ca);
        }
        jwt++;
    }
    
    /* Cloud/API Tokens */
    for (int i = 0; TOKEN_PATTERNS[i].name; i++) {
        const TokenPattern* tp = &TOKEN_PATTERNS[i];
        const char* pos = line;
        while ((pos = strstr(pos, tp->prefix)) != NULL) {
            /* Check if it's a valid token (alphanumeric + some special chars) */
            int tlen = 0;
            const char* start = pos;
            while (start[tlen] && (isalnum(start[tlen]) || start[tlen]=='_' || start[tlen]=='-' || start[tlen]=='.' || start[tlen]==':')) {
                tlen++;
            }
            if (tlen >= tp->min && tlen <= tp->max) {
                char tv[256];
                strncpy(tv, start, tlen < 255 ? tlen : 255);
                tv[tlen < 255 ? tlen : 255] = '\0';
                add_finding(CAT_TOKEN, tp->name, CONF_HIGH, path, lnum, off, tv, -1, "API/Cloud token", cb, ca);
            }
            pos++;
        }
    }
    
    /* AWS Secret Key (40 char base64 after aws_secret) */
    const char* aws_sec = line;
    while ((aws_sec = strcasestr_local(aws_sec, "aws_secret")) != NULL) {
        /* Find = or : */
        const char* eq = aws_sec + 10;
        while (*eq && (*eq == ' ' || *eq == '_' || *eq == 'a' || *eq == 'c' || *eq == 'e' || *eq == 's' || *eq == 'k' || *eq == 'y')) eq++;
        if (*eq == '=' || *eq == ':') {
            eq++;
            while (*eq == ' ' || *eq == '"' || *eq == '\'') eq++;
            int klen = 0;
            while (eq[klen] && (isalnum(eq[klen]) || eq[klen]=='+' || eq[klen]=='/' || eq[klen]=='=') && klen < 50) klen++;
            if (klen >= 38 && klen <= 45) {
                char kv[64];
                strncpy(kv, eq, klen);
                kv[klen] = '\0';
                add_finding(CAT_TOKEN, "aws_secret_key", CONF_HIGH, path, lnum, off, kv, -1, "AWS Secret Key", cb, ca);
            }
        }
        aws_sec++;
    }
    
    /* NetNTLMv2 (user::domain:challenge:response format) */
    const char* ntlm = line;
    while ((ntlm = strstr(ntlm, "::")) != NULL) {
        /* Look backwards for username */
        const char* user_start = ntlm;
        while (user_start > line && *(user_start-1) != ' ' && *(user_start-1) != '\t' && *(user_start-1) != ':') user_start--;
        if (ntlm - user_start >= 1) {
            /* Look forward for domain:challenge:response */
            const char* rest = ntlm + 2;
            int colons = 0;
            int rlen = 0;
            while (rest[rlen] && rest[rlen] != ' ' && rest[rlen] != '\t' && rlen < 500) {
                if (rest[rlen] == ':') colons++;
                rlen++;
            }
            /* NetNTLMv2 has format: user::domain:challenge:NTProofStr:response */
            if (colons >= 2 && rlen > 50) {
                int total_len = (ntlm - user_start) + 2 + rlen;
                if (total_len > 60 && total_len < 600) {
                    char nv[600];
                    strncpy(nv, user_start, total_len < 599 ? total_len : 599);
                    nv[total_len < 599 ? total_len : 599] = '\0';
                    /* Verify it looks like NetNTLM (has hex in response) */
                    int hex_count = 0;
                    for (int i = 0; i < rlen; i++) if (is_hex(rest[i])) hex_count++;
                    if (hex_count > 30) {
                        /* Determine v1 vs v2 by response length */
                        /* v1: 48 hex chars, v2: much longer */
                        if (hex_count >= 32 && hex_count <= 52) {
                            add_finding(CAT_PASSWORD_HASH, "netntlmv1", CONF_HIGH, path, lnum, off, nv, 5500, "NetNTLMv1 capture", cb, ca);
                        } else {
                            add_finding(CAT_PASSWORD_HASH, "netntlmv2", CONF_HIGH, path, lnum, off, nv, 5600, "NetNTLMv2 capture", cb, ca);
                        }
                    }
                }
            }
        }
        ntlm++;
    }
    
    /* Base64 encoded secrets (look for base64 after secret keywords) */
    for (int i = 0; BASE64_SECRET_CONTEXTS[i]; i++) {
        const char* ctx = line;
        char ctx_lower[32];
        strncpy(ctx_lower, BASE64_SECRET_CONTEXTS[i], sizeof(ctx_lower)-1);
        while ((ctx = strcasestr_local(ctx, BASE64_SECRET_CONTEXTS[i])) != NULL) {
            /* Find = or : after keyword */
            const char* eq = ctx + strlen(BASE64_SECRET_CONTEXTS[i]);
            while (*eq && (*eq == ' ' || *eq == '_' || *eq == '-' || isalpha(*eq))) eq++;
            if (*eq == '=' || *eq == ':') {
                eq++;
                while (*eq == ' ' || *eq == '"' || *eq == '\'') eq++;
                /* Check for base64 content */
                int b64len = 0;
                int has_letter = 0, has_digit = 0, has_special = 0;
                while (eq[b64len] && (isalnum(eq[b64len]) || eq[b64len]=='+' || eq[b64len]=='/' || eq[b64len]=='=') && b64len < 200) {
                    if (isalpha(eq[b64len])) has_letter = 1;
                    if (isdigit(eq[b64len])) has_digit = 1;
                    if (eq[b64len]=='+' || eq[b64len]=='/') has_special = 1;
                    b64len++;
                }
                /* Valid base64 secret: 20+ chars, mixed content, ends with = or has +/ */
                if (b64len >= 20 && b64len <= 200 && has_letter && has_digit && 
                    (has_special || (eq[b64len-1] == '=' || eq[b64len-2] == '='))) {
                    char bv[256];
                    strncpy(bv, eq, b64len);
                    bv[b64len] = '\0';
                    add_finding(CAT_TOKEN, "base64_secret", CONF_MEDIUM, path, lnum, off, bv, -1, "Base64 encoded secret", cb, ca);
                }
            }
            ctx++;
        }
    }
    
    /* Kubernetes secrets (YAML format) */
    for (int i = 0; K8S_SECRET_KEYS[i]; i++) {
        const char* k8s = strcasestr_local(line, K8S_SECRET_KEYS[i]);
        if (k8s) {
            const char* val = k8s + strlen(K8S_SECRET_KEYS[i]);
            while (*val == ' ') val++;
            int vlen = 0;
            while (val[vlen] && val[vlen] != '\n' && val[vlen] != '\r' && val[vlen] != '#' && vlen < 200) vlen++;
            /* Trim trailing spaces */
            while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '"' || val[vlen-1] == '\'')) vlen--;
            /* Skip leading quotes */
            if (*val == '"' || *val == '\'') { val++; vlen--; }
            if (vlen >= 8 && vlen <= 200) {
                char kv[256];
                strncpy(kv, val, vlen);
                kv[vlen] = '\0';
                /* Skip placeholders */
                char kvlow[256];
                strncpy(kvlow, kv, sizeof(kvlow)-1);
                str_lower(kvlow);
                if (strstr(kvlow, "changeme") || strstr(kvlow, "placeholder") || strstr(kvlow, "example")) continue;
                add_finding(CAT_TOKEN, "k8s_secret", CONF_MEDIUM, path, lnum, off, kv, -1, "Kubernetes secret", cb, ca);
            }
        }
    }
    
    /* SSH Private Key content (after BEGIN marker, look for key data) */
    if (strstr(line, "PRIVATE KEY")) {
        /* Already handled above, but mark for multi-line capture */
    }
    
    /* .NET Machine Key */
    const char* machkey = strcasestr_local(line, "machineKey");
    if (machkey) {
        /* Look for validationKey= or decryptionKey= */
        const char* vkey = strcasestr_local(line, "validationKey");
        const char* dkey = strcasestr_local(line, "decryptionKey");
        if (vkey) {
            const char* eq = strchr(vkey, '=');
            if (eq) {
                eq++;
                while (*eq == '"' || *eq == ' ') eq++;
                int klen = 0;
                while (is_hex(eq[klen]) && klen < 150) klen++;
                if (klen >= 40) {
                    char mv[200];
                    strncpy(mv, eq, klen);
                    mv[klen] = '\0';
                    add_finding(CAT_TOKEN, "dotnet_machinekey_validation", CONF_HIGH, path, lnum, off, mv, -1, ".NET MachineKey validationKey", cb, ca);
                }
            }
        }
        if (dkey) {
            const char* eq = strchr(dkey, '=');
            if (eq) {
                eq++;
                while (*eq == '"' || *eq == ' ') eq++;
                int klen = 0;
                while (is_hex(eq[klen]) && klen < 100) klen++;
                if (klen >= 32) {
                    char mv[128];
                    strncpy(mv, eq, klen);
                    mv[klen] = '\0';
                    add_finding(CAT_TOKEN, "dotnet_machinekey_decryption", CONF_HIGH, path, lnum, off, mv, -1, ".NET MachineKey decryptionKey", cb, ca);
                }
            }
        }
    }
    
    /* Connection strings (SQL Server, MySQL, etc.) */
    const char* connstr = strcasestr_local(line, "connectionstring");
    if (!connstr) connstr = strcasestr_local(line, "connection_string");
    if (!connstr) connstr = strcasestr_local(line, "connstr");
    if (connstr) {
        /* Look for password in connection string */
        const char* pwd = strcasestr_local(line, "password=");
        if (!pwd) pwd = strcasestr_local(line, "pwd=");
        if (pwd) {
            pwd = strchr(pwd, '=') + 1;
            int plen = 0;
            while (pwd[plen] && pwd[plen] != ';' && pwd[plen] != '"' && pwd[plen] != '\'' && plen < 100) plen++;
            if (plen >= 4) {
                char pv[128];
                strncpy(pv, pwd, plen);
                pv[plen] = '\0';
                add_finding(CAT_PLAINTEXT, "connection_string_password", CONF_HIGH, path, lnum, off, pv, -1, "Connection string password", cb, ca);
            }
        }
    }
}

static int should_scan(const char* fn) {
    const char* names[] = {
        "shadow", "passwd", ".env", "htpasswd", "credentials", 
        "wp-config.php", "config.php", "database.php",
        /* Cloud/K8s */
        "credentials", "config", "secrets", ".npmrc", ".pypirc",
        ".docker", "kubeconfig", ".kube", ".aws", 
        "terraform.tfvars", "variables.tf", 
        "docker-compose.yml", "docker-compose.yaml",
        "values.yaml", "secrets.yaml", "secrets.yml",
        /* Git */
        ".git-credentials", ".netrc",
        /* Web config */
        "web.config", "appsettings.json", "app.config",
        "settings.py", "local_settings.py",
        NULL
    };
    for (int i = 0; names[i]; i++) if (strcasecmp(fn, names[i])==0 || strstr(fn, names[i])) return 1;
    const char* ext = strrchr(fn, '.');
    if (!ext) return 0;
    const char* exts[] = {
        ".php", ".inc", ".env", ".ini", ".conf", ".yml", ".yaml", ".json", ".xml", ".sql", ".dump",
        ".bak", ".old", ".log", ".txt", ".py", ".sh", ".htpasswd", ".swp",
        /* Additional */
        ".tf", ".tfvars", ".hcl",  /* Terraform */
        ".properties",  /* Java */
        ".toml",  /* Rust/Python */
        ".pem", ".key", ".crt", ".p12", ".pfx",  /* Certs/Keys */
        NULL
    };
    for (int i = 0; exts[i]; i++) if (strcasecmp(ext, exts[i])==0) return 1;
    int l = strlen(fn);
    if (l > 0 && fn[l-1] == '~') return 1;
    return 0;
}

static int should_skip(const char* dn) {
    const char* skip[] = {"node_modules","__pycache__",".git","vendor","venv","proc","sys","dev","Windows","Program Files",NULL};
    for (int i = 0; skip[i]; i++) if (strcmp(dn, skip[i])==0) return 1;
    return 0;
}

static void scan_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { result.errors++; return; }
    
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsz > opt_max_file_size) { result.files_skipped_size++; fclose(f); return; }
    
    unsigned char* buf = malloc(fsz + 1);
    if (!buf) { fclose(f); return; }
    size_t rd = fread(buf, 1, fsz, f);
    buf[rd] = '\0';
    fclose(f);
    
    if (is_binary(buf, rd)) { result.files_skipped_binary++; free(buf); return; }
    
    char* content; size_t clen; char* utf8 = NULL;
    if (is_utf16(buf, rd)) {
        utf8 = malloc(rd);
        if (!utf8) { free(buf); return; }
        clen = utf16_to_ascii(buf, rd, utf8, rd);
        content = utf8;
    } else {
        content = (char*)buf;
        clen = rd;
    }
    
    result.files_scanned++;
    
    for (int i = 0; i < 5; i++) { if (!line_buffer[i]) line_buffer[i] = malloc(MAX_LINE); if (line_buffer[i]) line_buffer[i][0]='\0'; }
    
    char* ls = content;
    int lnum = 0;
    long boff = 0;
    
    while (ls < content + clen) {
        lnum++;
        char* le = ls;
        while (le < content + clen && *le != '\n' && *le != '\r') le++;
        int ll = le - ls;
        if (ll >= MAX_LINE) ll = MAX_LINE - 1;
        
        char ln[MAX_LINE];
        strncpy(ln, ls, ll);
        ln[ll] = '\0';
        
        char* ctx_b = line_buffer[(line_buffer_idx + 4) % 5];
        strncpy(line_buffer[line_buffer_idx], ln, MAX_LINE - 1);
        line_buffer_idx = (line_buffer_idx + 1) % 5;
        
        char ctx_a[MAX_CONTEXT] = "";
        if (le < content + clen) {
            char* ns = le;
            while (ns < content + clen && (*ns=='\n' || *ns=='\r')) ns++;
            if (ns < content + clen) {
                char* ne = ns;
                while (ne < content + clen && *ne != '\n' && *ne != '\r' && ne - ns < MAX_CONTEXT - 1) ne++;
                strncpy(ctx_a, ns, ne - ns);
                ctx_a[ne - ns] = '\0';
            }
        }
        
        scan_line(ln, path, lnum, boff, opt_context_lines ? ctx_b : NULL, opt_context_lines ? ctx_a : NULL);
        
        boff += (le - ls);
        while (le < content + clen && (*le == '\n' || *le == '\r')) { boff++; le++; }
        ls = le;
    }
    
    free(buf);
    if (utf8) free(utf8);
}

static void scan_dir(const char* path, int depth) {
    if (depth > 30 || result.files_scanned >= opt_max_files) return;
    if (opt_max_runtime > 0 && difftime(time(NULL), result.start_time) > opt_max_runtime) return;
    
    DIR* dir = opendir(path);
    if (!dir) return;
    
#ifndef _WIN32
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) { if (stat(path, &st) == 0 && check_inode(st.st_ino, st.st_dev)) { closedir(dir); return; } }
        else if (check_inode(st.st_ino, st.st_dev)) { closedir(dir); return; }
    }
#endif
    
    struct dirent* e;
    while ((e = readdir(dir)) != NULL) {
        if (result.files_scanned >= opt_max_files) break;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        
        char fp[MAX_PATH_LEN];
        snprintf(fp, sizeof(fp), "%s%c%s", path, PATH_SEP, e->d_name);
        
        struct stat st;
        if (stat(fp, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            /* Check for .git directory */
            if (strcmp(e->d_name, ".git") == 0 && has_git && opt_collectors) {
                collect_git(fp);
            }
            else if (!should_skip(e->d_name)) {
                scan_dir(fp, depth + 1);
            }
        }
        else if (S_ISREG(st.st_mode)) {
            const char* ext = strrchr(e->d_name, '.');
            
            /* Check for archives */
            if (ext && opt_collectors) {
                if (strcasecmp(ext, ".zip") == 0 || strcasecmp(ext, ".tar") == 0 ||
                    strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".tgz") == 0 ||
                    strcasecmp(ext, ".bz2") == 0) {
                    collect_archive(fp);
                }
                /* Check for SQLite databases */
                else if (strcasecmp(ext, ".db") == 0 || strcasecmp(ext, ".sqlite") == 0 ||
                         strcasecmp(ext, ".sqlite3") == 0) {
                    collect_sqlite(fp);
                }
            }
            
            /* Check for Windows artifacts */
            check_windows_artifacts(fp);
            
            /* Normal file scan */
            if (should_scan(e->d_name)) {
                scan_file(fp);
            }
        }
    }
    closedir(dir);
}

#ifndef _WIN32
static void collect_shadow(void) {
    FILE* f = fopen("/etc/shadow", "r");
    if (!f) return;
    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        char* c1 = strchr(ln, ':');
        if (!c1) continue;
        char user[64];
        int ul = c1 - ln;
        if (ul >= 64) continue;
        strncpy(user, ln, ul);
        user[ul] = '\0';
        char* hs = c1 + 1;
        char* c2 = strchr(hs, ':');
        if (!c2) continue;
        int hl = c2 - hs;
        if (hl < 3 || hs[0]=='*' || hs[0]=='x') continue;
        int locked = (hs[0] == '!');
        if (locked) { hs++; hl--; }
        if (hl < 10) continue;
        char hash[512];
        strncpy(hash, hs, hl);
        hash[hl] = '\0';
        const char* t = "unknown";
        int hc = -1;
        if (strncmp(hash,"$6$",3)==0) { t="sha512crypt"; hc=1800; }
        else if (strncmp(hash,"$5$",3)==0) { t="sha256crypt"; hc=7400; }
        else if (strncmp(hash,"$y$",3)==0) { t="yescrypt"; }
        else if (strncmp(hash,"$2",2)==0) { t="bcrypt"; hc=3200; }
        else if (strncmp(hash,"$1$",3)==0) { t="md5crypt"; hc=500; }
        char reason[128];
        snprintf(reason, sizeof(reason), "Shadow: %s%s", user, locked?" [LOCKED]":"");
        add_finding(CAT_PASSWORD_HASH, t, CONF_HIGH, "/etc/shadow", lnum, 0, hash, hc, reason, NULL, NULL);
    }
    fclose(f);
}
#endif

/* ============================================================================
 * OUTPUT
 * ============================================================================ */

static const char* cat_str(Category c) {
    switch (c) { case CAT_PASSWORD_HASH: return "PASSWORD_HASH"; case CAT_POSSIBLE_HASH: return "POSSIBLE_HASH";
                 case CAT_PLAINTEXT: return "PLAINTEXT"; case CAT_TOKEN: return "TOKEN";
                 case CAT_PRIVATE_KEY: return "PRIVATE_KEY"; default: return "UNKNOWN"; }
}

static const char* conf_str(Confidence c) {
    switch (c) { case CONF_HIGH: return "high"; case CONF_MEDIUM: return "medium"; case CONF_LOW: return "low"; default: return "?"; }
}

static void print_report(void) {
    double dur = difftime(time(NULL), result.start_time);
    printf("\n══════════════════════════════════════════════════════════════════════\n");
    printf("  HASHSCAN v%s - RESULTS\n", VERSION);
    printf("══════════════════════════════════════════════════════════════════════\n\n");
    printf("  Files scanned    : %d\n", result.files_scanned);
    printf("  Skipped (binary) : %d\n", result.files_skipped_binary);
    printf("  Skipped (size)   : %d\n", result.files_skipped_size);
    printf("  Duplicates merged: %d\n", result.duplicates_suppressed);
    printf("  Duration         : %.1fs\n", dur);
    printf("  Unique findings  : %d\n\n", result.count);
    
    if (result.count == 0) { printf("  [!] No findings\n"); return; }
    
    int cc[5] = {0};
    for (int i = 0; i < result.count; i++) cc[result.findings[i].category]++;
    Category cats[] = {CAT_PASSWORD_HASH, CAT_POSSIBLE_HASH, CAT_PLAINTEXT, CAT_TOKEN, CAT_PRIVATE_KEY};
    
    for (int c = 0; c < 5; c++) {
        if (cc[cats[c]] == 0) continue;
        printf("══════════════════════════════════════════════════════════════════════\n");
        printf("  [%s] - %d\n", cat_str(cats[c]), cc[cats[c]]);
        printf("══════════════════════════════════════════════════════════════════════\n");
        int n = 1;
        for (int i = 0; i < result.count; i++) {
            Finding* f = &result.findings[i];
            if (f->category != cats[c]) continue;
            printf("\n  [%d] %s (%s)\n", n++, f->hash_type, conf_str(f->confidence));
            printf("      File   : %s:%d\n", f->file_path, f->line_number);
            printf("      Reason : %s\n", f->reason);
            if (f->owner[0]) printf("      Owner  : %s\n", f->owner);
            printf("      Value  : %s (len:%d)\n", f->value_preview, f->value_length);
            if (f->occurrence_count > 1) printf("      Seen   : %d times\n", f->occurrence_count);
            if (f->hashcat_mode >= 0) printf("      Hashcat: -m %d\n", f->hashcat_mode);
            if (f->context_before[0] && opt_context_lines) printf("      Context: ...%s\n              > [MATCH]\n", f->context_before);
        }
        printf("\n");
    }
    
    /* ===== INTELLIGENCE REPORTS ===== */
    
    /* User-Hash Correlation Map */
    int user_count = 0;
    for (int i = 0; i < USER_HASH_SIZE; i++) {
        UserHashEntry* e = user_hash_table[i];
        while (e) { user_count++; e = e->next; }
    }
    
    if (user_count > 0 && opt_correlation) {
        printf("══════════════════════════════════════════════════════════════════════\n");
        printf("  [USER-HASH CORRELATION]\n");
        printf("══════════════════════════════════════════════════════════════════════\n\n");
        printf("  %-16s %-30s %s\n", "User", "Hash Types", "Sources");
        printf("  %-16s %-30s %s\n", "────────────────", "──────────────────────────────", "───────────────────");
        
        for (int i = 0; i < USER_HASH_SIZE; i++) {
            UserHashEntry* e = user_hash_table[i];
            while (e) {
                printf("  %-16s %-30s %s\n", 
                       e->username[0] ? e->username : "(unknown)",
                       e->hash_types,
                       e->sources);
                e = e->next;
            }
        }
        printf("\n");
    }
    
    /* Password Reuse Detection */
    int reuse_count = 0;
    for (int i = 0; i < REUSE_HASH_SIZE; i++) {
        ReuseEntry* e = reuse_table[i];
        while (e) {
            if (e->user_count > 1 || e->file_count > 1) reuse_count++;
            e = e->next;
        }
    }
    
    if (reuse_count > 0) {
        printf("══════════════════════════════════════════════════════════════════════\n");
        printf("  [!] PASSWORD REUSE DETECTED\n");
        printf("══════════════════════════════════════════════════════════════════════\n\n");
        
        for (int i = 0; i < REUSE_HASH_SIZE; i++) {
            ReuseEntry* e = reuse_table[i];
            while (e) {
                if (e->user_count > 1 || e->file_count > 1) {
                    printf("  Value: %s\n", e->value_preview);
                    if (e->user_count > 1) printf("    → Users: %s\n", e->users);
                    if (e->file_count > 1) printf("    → Files: %s\n", e->files);
                    printf("\n");
                }
                e = e->next;
            }
        }
    }
    
    /* Hashcat Command Generator */
    if (opt_hashcat_mode) {
        printf("══════════════════════════════════════════════════════════════════════\n");
        printf("  [HASHCAT COMMANDS]\n");
        printf("══════════════════════════════════════════════════════════════════════\n\n");
        
        /* Group by hashcat mode */
        int modes_seen[20000] = {0};
        for (int i = 0; i < result.count; i++) {
            Finding* f = &result.findings[i];
            if (f->hashcat_mode > 0 && f->hashcat_mode < 20000 && !modes_seen[f->hashcat_mode]) {
                modes_seen[f->hashcat_mode] = 1;
                
                const char* mode_name = f->hash_type;
                printf("  # %s (mode %d)\n", mode_name, f->hashcat_mode);
                printf("  hashcat -m %d -a 0 hashes_%s.txt wordlist.txt\n", f->hashcat_mode, f->hash_type);
                
                /* Print hashes for this mode */
                printf("  # Hashes:\n");
                for (int j = 0; j < result.count; j++) {
                    if (result.findings[j].hashcat_mode == f->hashcat_mode) {
                        printf("  # echo '%s' >> hashes_%s.txt\n", 
                               opt_show_values ? result.findings[j].value_full : result.findings[j].value_preview,
                               f->hash_type);
                    }
                }
                printf("\n");
            }
        }
        
        /* Lateral movement hints for NetNTLM */
        for (int i = 0; i < result.count; i++) {
            Finding* f = &result.findings[i];
            if (strstr(f->hash_type, "netntlm")) {
                printf("  # [PIVOT] %s found - Lateral Movement Options:\n", f->hash_type);
                printf("  # evil-winrm -i <target> -u <user> -H <hash>\n");
                printf("  # psexec.py <domain>/<user>@<target> -hashes :<hash>\n");
                printf("  # wmiexec.py <domain>/<user>@<target> -hashes :<hash>\n\n");
                break;
            }
        }
    }
    
    printf("══════════════════════════════════════════════════════════════════════\n");
    printf("  SUMMARY: ");
    int h=0,m=0,l=0;
    for (int i=0;i<result.count;i++) { switch(result.findings[i].confidence){case CONF_HIGH:h++;break;case CONF_MEDIUM:m++;break;case CONF_LOW:l++;break;} }
    printf("HIGH=%d  MEDIUM=%d  LOW=%d\n", h, m, l);
}

static void print_json(void) {
    FILE* out = json_file ? json_file : stdout;
    fprintf(out, "{\n  \"tool\": \"HASHSCAN\",\n  \"version\": \"%s\",\n", VERSION);
    fprintf(out, "  \"files_scanned\": %d,\n  \"duplicates_suppressed\": %d,\n  \"total_findings\": %d,\n  \"findings\": [\n", 
            result.files_scanned, result.duplicates_suppressed, result.count);
    for (int i = 0; i < result.count; i++) {
        Finding* f = &result.findings[i];
        char ep[MAX_PATH_LEN*2], ev[1024], er[512], ecb[MAX_CONTEXT*2], eca[MAX_CONTEXT*2];
        json_escape(f->file_path, ep, sizeof(ep));
        json_escape(opt_show_values ? f->value_full : f->value_preview, ev, sizeof(ev));
        json_escape(f->reason, er, sizeof(er));
        json_escape(f->context_before, ecb, sizeof(ecb));
        json_escape(f->context_after, eca, sizeof(eca));
        fprintf(out, "    {\"category\":\"%s\",\"hash_type\":\"%s\",\"confidence\":\"%s\",", cat_str(f->category), f->hash_type, conf_str(f->confidence));
        fprintf(out, "\"file_path\":\"%s\",\"line\":%d,\"value\":\"%s\",\"len\":%d,", ep, f->line_number, ev, f->value_length);
        fprintf(out, "\"occurrences\":%d,\"hashcat\":%d,\"owner\":\"%s\",\"reason\":\"%s\",", f->occurrence_count, f->hashcat_mode, f->owner, er);
        fprintf(out, "\"context_before\":\"%s\",\"context_after\":\"%s\"}", ecb, eca);
        fprintf(out, "%s\n", i < result.count - 1 ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
}

/* ============================================================================
 * PROFILES
 * ============================================================================ */

static void run_profile(const char* p) {
#ifndef _WIN32
    collect_shadow();
#endif
    const char* web[] = {
#ifdef _WIN32
        "C:\\inetpub\\wwwroot","C:\\xampp\\htdocs","C:\\wamp\\www",NULL
#else
        "/var/www","/srv/www","/srv","/opt",NULL
#endif
    };
    if (strcmp(p,"quick")==0||strcmp(p,"htb")==0||strcmp(p,"web")==0)
        for (int i=0;web[i];i++) { struct stat st; if (stat(web[i],&st)==0) { if(opt_verbose)fprintf(stderr,"[*] %s\n",web[i]); scan_dir(web[i],0); } }
    if (strcmp(p,"quick")==0||strcmp(p,"htb")==0) {
#ifdef _WIN32
        char* up=getenv("USERPROFILE"); if(up){if(opt_verbose)fprintf(stderr,"[*] %s\n",up);scan_dir(up,0);}
#else
        char* h=getenv("HOME"); if(h){if(opt_verbose)fprintf(stderr,"[*] %s\n",h);scan_dir(h,0);}
        scan_dir("/home",0); scan_dir("/root",0);
        /* Cloud config locations */
        scan_dir("/root/.aws",0);
        scan_dir("/root/.kube",0);
        scan_dir("/root/.docker",0);
#endif
    }
    if (strcmp(p,"htb")==0||strcmp(p,"full")==0) {
#ifndef _WIN32
        const char* ex[]={"/etc","/var/backups","/var/log","/tmp",NULL};
        for(int i=0;ex[i];i++){if(opt_verbose)fprintf(stderr,"[*] %s\n",ex[i]);scan_dir(ex[i],0);}
#endif
    }
    if (strcmp(p,"full")==0) {
#ifdef _WIN32
        scan_dir("C:\\",0);
#else
        scan_dir("/",0);
#endif
    }
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void banner(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, "██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗\n");
    fprintf(stderr, "██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║\n");
    fprintf(stderr, "███████║███████║███████╗███████║███████╗██║     ███████║██╔██╗ ██║\n");
    fprintf(stderr, "██╔══██║██╔══██║╚════██║██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║\n");
    fprintf(stderr, "██║  ██║██║  ██║███████║██║  ██║███████║╚██████╗██║  ██║██║ ╚████║\n");
    fprintf(stderr, "╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n");
    fprintf(stderr, "Superman Hash Artifact Scanner v%s\n", VERSION);
    fprintf(stderr, "════════════════════════════════════════════════════════════════════\n\n");
}

static void usage(const char* p) {
    printf("Usage: %s [options] [paths...]\n\n", p);
    printf("Options:\n");
    printf("  --profile <p>     quick, htb, web, full\n");
    printf("  --wide            Include low-confidence patterns\n");
    printf("  --show-values     Show actual values\n");
    printf("  --context <n>     Context lines (default: 1)\n");
    printf("  --json            JSON output\n");
    printf("  -o <file>         Output file\n");
    printf("  -v, --verbose     Verbose mode\n");
    printf("  --max-files <n>   Max files (default: 50000)\n");
    printf("  --timeout <s>     Max runtime seconds\n");
    printf("  --no-collectors   Disable archive/sqlite/git collectors\n");
    printf("\nIntelligence:\n");
    printf("  --hashcat         Generate hashcat commands\n");
    printf("  --no-correlation  Disable user-hash correlation\n");
    printf("\nCollectors (auto-detected tools):\n");
    printf("  - Archive: unzip, tar (extracts ZIP/TAR/GZ/BZ2)\n");
    printf("  - SQLite:  sqlite3 or strings fallback\n");
    printf("  - Git:     git log -p for history secrets\n");
}

int main(int argc, char* argv[]) {
    memset(&result, 0, sizeof(result));
    result.start_time = time(NULL);
    result.capacity = 1000;
    result.findings = malloc(result.capacity * sizeof(Finding));
    if (!result.findings) { fprintf(stderr, "Error: Out of memory\n"); return 1; }
    init_tables();
    for (int i = 0; i < 5; i++) { line_buffer[i] = malloc(MAX_LINE); if (line_buffer[i]) line_buffer[i][0] = '\0'; }
    
    const char* profile = NULL;
    const char* outfile = NULL;
    char* paths[100];
    int pathc = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"--help")==0||strcmp(argv[i],"-h")==0) { usage(argv[0]); return 0; }
        if (strcmp(argv[i],"--version")==0) { printf("HASHSCAN %s\n", VERSION); return 0; }
        if (strcmp(argv[i],"--wide")==0) opt_wide=1;
        else if (strcmp(argv[i],"--show-values")==0) opt_show_values=1;
        else if (strcmp(argv[i],"--json")==0) opt_json=1;
        else if (strcmp(argv[i],"-v")==0||strcmp(argv[i],"--verbose")==0) opt_verbose=1;
        else if (strcmp(argv[i],"--no-collectors")==0) opt_collectors=0;
        else if (strcmp(argv[i],"--hashcat")==0) opt_hashcat_mode=1;
        else if (strcmp(argv[i],"--no-correlation")==0) opt_correlation=0;
        else if (strcmp(argv[i],"--profile")==0&&i+1<argc) profile=argv[++i];
        else if (strcmp(argv[i],"-o")==0&&i+1<argc) outfile=argv[++i];
        else if (strcmp(argv[i],"--max-files")==0&&i+1<argc) opt_max_files=atoi(argv[++i]);
        else if (strcmp(argv[i],"--timeout")==0&&i+1<argc) opt_max_runtime=atoi(argv[++i]);
        else if (strcmp(argv[i],"--context")==0&&i+1<argc) opt_context_lines=atoi(argv[++i]);
        else if (argv[i][0]!='-'&&pathc<100) paths[pathc++]=argv[i];
    }
    
    if (outfile) { json_file = fopen(outfile, "w"); if (!json_file) { fprintf(stderr, "Error: %s\n", outfile); return 1; } opt_json = 1; }
    
    banner();
    
    /* Detect available tools */
    if (opt_collectors) {
        detect_tools();
        fprintf(stderr, "[*] Collectors: archive=%s sqlite=%s git=%s\n",
                (has_tar || has_unzip) ? "yes" : "no",
                (has_sqlite3 || has_strings) ? "yes" : "no",
                has_git ? "yes" : "no");
    } else {
        fprintf(stderr, "[*] Collectors: disabled\n");
    }
    
    fprintf(stderr, "[*] Mode: %s | Context: %d | Max: %d files\n", opt_wide?"wide":"strict", opt_context_lines, opt_max_files);
    if (profile) fprintf(stderr, "[*] Profile: %s\n", profile);
    fprintf(stderr, "\n");
    
    if (profile) run_profile(profile);
    else if (pathc > 0) {
#ifndef _WIN32
        collect_shadow();
#endif
        for (int i = 0; i < pathc; i++) { fprintf(stderr, "[*] %s\n", paths[i]); scan_dir(paths[i], 0); }
    } else {
#ifndef _WIN32
        collect_shadow();
#endif
#ifdef _WIN32
        char* up = getenv("USERPROFILE"); if (up) { fprintf(stderr, "[*] %s\n", up); scan_dir(up, 0); }
#else
        char* h = getenv("HOME"); if (h) { fprintf(stderr, "[*] %s\n", h); scan_dir(h, 0); }
#endif
    }
    
    if (opt_json) print_json(); else print_report();
    if (json_file) { fclose(json_file); fprintf(stderr, "\n[+] Saved: %s\n", outfile); }
    
    free(result.findings);
    free_tables();
    for (int i = 0; i < 5; i++) if (line_buffer[i]) free(line_buffer[i]);
    return 0;
}
