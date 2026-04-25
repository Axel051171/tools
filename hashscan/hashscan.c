/*
 * HASHSCAN v11.0 - Superman Hash Artifact Scanner
 * =================================================
 * Cross-platform (Linux/Windows) comprehensive hash & credential finder.
 *
 * Features:
 *   - 60+ hash patterns (Unix crypt, bcrypt, Argon2, NetNTLM, Kerberos, ...)
 *   - 70+ credential patterns (ENV, YAML, JSON, XML, PHP, Python, ...)
 *   - 25+ cloud token patterns (AWS, GitHub, Slack, OpenAI, Stripe, ...)
 *   - Pwdump/hashdump format (user:RID:LM:NT:::)
 *   - GPP cpassword extraction
 *   - BitLocker recovery key detection
 *   - WPA PMKID hashcat format
 *   - User registry from /etc/passwd with credential correlation
 *   - Shell/SQL history scanning for passwords in commands
 *   - WiFi PSK extraction (NetworkManager + Windows profiles)
 *   - /proc/*/environ secret scanning
 *   - Crontab credential scanning
 *   - htpasswd user:hash inline parsing
 *   - Windows: Unattend.xml, GPP, PowerShell history, WiFi, DPAPI
 *   - Windows: SAM/SYSTEM/NTDS.dit artifact detection
 *   - KeePass .kdbx / RDP password detection
 *   - Archive/SQLite/Git collectors
 *   - Binary/UTF-16 detection, dedup, context lines, JSON output
 *   - Symlink loop detection, dynamic memory, timeout support
 *
 * Compile:
 *   Linux:   gcc -O2 -o hashscan hashscan.c -lm
 *   Windows: x86_64-w64-mingw32-gcc -O2 -o hashscan.exe hashscan.c -lm
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
#include <signal.h>

#ifdef _WIN32
    #include <windows.h>
    #define PATH_SEP '\\'
    #define IS_WINDOWS 1
    #define stat _stat
    #ifndef S_ISDIR
        #define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
    #endif
    #ifndef S_ISREG
        #define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
    #endif
    #ifndef S_ISLNK
        #define S_ISLNK(m) 0
    #endif
#else
    #include <unistd.h>
    #include <pwd.h>
    #define PATH_SEP '/'
    #define IS_WINDOWS 0
#endif

#define VERSION "11.0"
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

typedef enum { CAT_PASSWORD_HASH, CAT_POSSIBLE_HASH, CAT_PLAINTEXT, CAT_TOKEN, CAT_PRIVATE_KEY, CAT_NETWORK_AUTH } Category;
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
static int opt_wide = 0, opt_show_values = 0, opt_json = 0, opt_verbose = 0, opt_quiet = 0, opt_context_lines = 1;
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
static const char* opt_pcredz_file = NULL;  /* Pcredz direct parsing */

/* ============================================================================
 * USER REGISTRY - Track known system users
 * ============================================================================ */

#define USER_REGISTRY_SIZE 512

typedef struct UserRegEntry {
    char username[64];
    int uid;
    char home_dir[MAX_PATH_LEN];
    char shell[128];
    int has_password;       /* 1 if found in shadow with real hash */
    int credential_count;   /* number of credentials found for this user */
    struct UserRegEntry* next;
} UserRegEntry;

static UserRegEntry* user_registry[USER_REGISTRY_SIZE];

static void user_registry_add(const char* username, int uid, const char* home, const char* shell) {
    if (!username || !username[0]) return;
    uint32_t h = 2166136261u;
    for (const char* p = username; *p; p++) { h ^= (unsigned char)*p; h *= 16777619u; }
    int idx = h % USER_REGISTRY_SIZE;
    /* Check if already exists */
    for (UserRegEntry* e = user_registry[idx]; e; e = e->next)
        if (strcmp(e->username, username) == 0) return;
    UserRegEntry* e = calloc(1, sizeof(UserRegEntry));
    if (!e) return;
    strncpy(e->username, username, sizeof(e->username) - 1);
    e->uid = uid;
    if (home) strncpy(e->home_dir, home, sizeof(e->home_dir) - 1);
    if (shell) strncpy(e->shell, shell, sizeof(e->shell) - 1);
    e->next = user_registry[idx];
    user_registry[idx] = e;
}

static UserRegEntry* user_registry_find(const char* username) {
    if (!username || !username[0]) return NULL;
    uint32_t h = 2166136261u;
    for (const char* p = username; *p; p++) { h ^= (unsigned char)*p; h *= 16777619u; }
    int idx = h % USER_REGISTRY_SIZE;
    for (UserRegEntry* e = user_registry[idx]; e; e = e->next)
        if (strcmp(e->username, username) == 0) return e;
    return NULL;
}

static void user_registry_free(void) {
    for (int i = 0; i < USER_REGISTRY_SIZE; i++) {
        UserRegEntry* e = user_registry[i];
        while (e) { UserRegEntry* n = e->next; free(e); e = n; }
        user_registry[i] = NULL;
    }
}

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
    {"mssql2012", "0x0200", 6, 50, 140, 1731, CONF_HIGH},
    /* SCRAM */
    {"scram_sha256", "SCRAM-SHA-256$", 14, 80, 200, 28600, CONF_HIGH},
    {"mongodb_scram", "SCRAM-SHA-1$", 12, 70, 150, -1, CONF_HIGH},
    /* Windows */
    {"dcc2", "$DCC2$", 6, 50, 100, 2100, CONF_HIGH},
    /* Cisco */
    {"cisco_type8", "$8$", 3, 55, 60, 9200, CONF_HIGH},
    {"cisco_type9", "$9$", 3, 55, 60, 9300, CONF_HIGH},
    /* Kerberos */
    {"krb5tgs", "$krb5tgs$", 9, 50, 5000, 13100, CONF_HIGH},
    {"krb5asrep", "$krb5asrep$", 11, 50, 5000, 18200, CONF_HIGH},
    {"krb5pa", "$krb5pa$", 8, 50, 500, 7500, CONF_HIGH},
    /* Network Auth - Pcredz compatible */
    {"mysql_native", "$mysqlna$", 9, 40, 100, 11200, CONF_HIGH},
    {"vnc_challenge", "$vnc$", 5, 40, 80, 10000, CONF_HIGH},
    /* postgres_scram and mssql_2012 merged into scram_sha256 and mssql2012 above */
    /* SNMP */
    {"snmpv3", "$SNMPv3$", 8, 50, 300, 25000, CONF_HIGH},
    /* RADIUS */
    {"tacacs_plus", "$tacacs-plus$", 13, 30, 100, 16100, CONF_HIGH},
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

/* Sanitize a path for safe use in shell commands.
 * Escapes single quotes by replacing ' with '\'' */
static void shell_escape(const char* src, char* dst, size_t dsz) {
    size_t di = 0;
    dst[0] = '\0';
    for (size_t si = 0; src[si] && di < dsz - 5; si++) {
        if (src[si] == '\'') {
            dst[di++] = '\'';
            dst[di++] = '\\';
            dst[di++] = '\'';
            dst[di++] = '\'';
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = '\0';
}

/* Validate that a path contains no dangerous shell metacharacters.
 * Returns 1 if safe, 0 if suspicious. */
static int path_is_safe(const char* path) {
    for (const char* p = path; *p; p++) {
        switch (*p) {
            case ';': case '|': case '&': case '`':
            case '$': case '(': case ')': case '{':
            case '}': case '\n': case '\r':
                return 0;
        }
    }
    return 1;
}

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
    while (n--) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        if (c1 != c2) return c1 - c2;
        if (c1 == 0) return 0;
        s1++;
        s2++;
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

    /* HTTP / cache / version context */
    if (strstr(line, "ETag") || strstr(line, "etag:") ||
        strstr(line, "If-None-Match") || strstr(line, "X-Request-ID") ||
        strstr(line, "trace_id") || strstr(line, "request-id") ||
        strstr(line, "version:") || strstr(line, "Version:")) return 1;

    /* All-numeric hex (no a-f) — almost never a real hash, usually an ID/serial */
    int has_alpha = 0;
    for (int i = 0; i < len && !has_alpha; i++) {
        char c = tolower(hex[i]);
        if (c >= 'a' && c <= 'f') has_alpha = 1;
    }
    if (!has_alpha) return 1;

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
    /* Check common paths directly instead of spawning a shell */
    const char* search_paths[] = {
        "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/bin/", "/sbin/", NULL
    };
    char path[512];
    for (int i = 0; search_paths[i]; i++) {
        snprintf(path, sizeof(path), "%s%s", search_paths[i], tool);
        if (access(path, X_OK) == 0) return 1;
    }
    return 0;
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
    char cmd[4096];
    const char* ext = strrchr(archive_path, '.');
    if (!ext) return 0;

    if (!path_is_safe(archive_path)) {
        if (opt_verbose) fprintf(stderr, "[!] Skipping archive with unsafe path: %s\n", archive_path);
        return 0;
    }

    char safe_path[MAX_PATH_LEN * 2];
    shell_escape(archive_path, safe_path, sizeof(safe_path));

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
        snprintf(cmd, sizeof(cmd), "powershell -Command \"Expand-Archive -Force '%s' '%s'\" 2>nul", safe_path, temp);
#else
        snprintf(cmd, sizeof(cmd), "unzip -o -q '%s' -d '%s' 2>/dev/null", safe_path, temp);
#endif
        success = (system(cmd) == 0);
    }
    /* TAR.GZ / TGZ */
    else if (has_tar && (strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".tgz") == 0)) {
        snprintf(cmd, sizeof(cmd), "tar -xzf '%s' -C '%s' 2>/dev/null", safe_path, temp);
        success = (system(cmd) == 0);
    }
    /* TAR.BZ2 */
    else if (has_tar && strcasecmp(ext, ".bz2") == 0) {
        snprintf(cmd, sizeof(cmd), "tar -xjf '%s' -C '%s' 2>/dev/null", safe_path, temp);
        success = (system(cmd) == 0);
    }
    /* Plain TAR */
    else if (has_tar && strcasecmp(ext, ".tar") == 0) {
        snprintf(cmd, sizeof(cmd), "tar -xf '%s' -C '%s' 2>/dev/null", safe_path, temp);
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

    if (!path_is_safe(db_path)) {
        if (opt_verbose) fprintf(stderr, "[!] Skipping SQLite with unsafe path: %s\n", db_path);
        return;
    }

    char safe_path[MAX_PATH_LEN * 2];
    shell_escape(db_path, safe_path, sizeof(safe_path));

    if (has_sqlite3) {
        char cmd[4096];
        char dump_path[MAX_PATH_LEN];

#ifdef _WIN32
        snprintf(dump_path, sizeof(dump_path), "%s\\sqlite_dump.txt", TEMP_DIR_WIN);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "sqlite3 \"%s\" .dump > \"%s\" 2>nul", safe_path, dump_path);
#else
        snprintf(dump_path, sizeof(dump_path), "%s/sqlite_dump.txt", TEMP_DIR);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "sqlite3 '%s' .dump > '%s' 2>/dev/null", safe_path, dump_path);
#endif

        if (opt_verbose) fprintf(stderr, "[*] Dumping SQLite: %s\n", db_path);

        if (system(cmd) == 0) {
            scan_file(dump_path);
        }
        cleanup_temp_dir();
    }
    else if (has_strings) {
        char cmd[4096];
        char strings_path[MAX_PATH_LEN];

#ifdef _WIN32
        snprintf(strings_path, sizeof(strings_path), "%s\\strings_out.txt", TEMP_DIR_WIN);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "strings \"%s\" > \"%s\" 2>nul", safe_path, strings_path);
#else
        snprintf(strings_path, sizeof(strings_path), "%s/strings_out.txt", TEMP_DIR);
        create_temp_dir();
        snprintf(cmd, sizeof(cmd), "strings '%s' > '%s' 2>/dev/null", safe_path, strings_path);
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
    repo_path[sizeof(repo_path) - 1] = '\0';

    /* Remove .git suffix */
    char* git_suffix = strstr(repo_path, "/.git");
    if (!git_suffix) git_suffix = strstr(repo_path, "\\.git");
    if (git_suffix) *git_suffix = '\0';
    else return;

    if (!path_is_safe(repo_path)) {
        if (opt_verbose) fprintf(stderr, "[!] Skipping git repo with unsafe path: %s\n", repo_path);
        return;
    }

    char safe_repo[MAX_PATH_LEN * 2];
    shell_escape(repo_path, safe_repo, sizeof(safe_repo));

    if (opt_verbose) fprintf(stderr, "[*] Scanning git history: %s\n", repo_path);

    char cmd[4096];
    char log_path[MAX_PATH_LEN];

#ifdef _WIN32
    snprintf(log_path, sizeof(log_path), "%s\\git_history.txt", TEMP_DIR_WIN);
    create_temp_dir();
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" log -p -100 --all > \"%s\" 2>nul", safe_repo, log_path);
#else
    snprintf(log_path, sizeof(log_path), "%s/git_history.txt", TEMP_DIR);
    create_temp_dir();
    snprintf(cmd, sizeof(cmd), "git -C '%s' log -p -100 --all > '%s' 2>/dev/null", safe_repo, log_path);
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

static void init_tables(void) {
    memset(dedup_table, 0, sizeof(dedup_table));
    memset(inode_table, 0, sizeof(inode_table));
    memset(user_hash_table, 0, sizeof(user_hash_table));
    memset(reuse_table, 0, sizeof(reuse_table));
    memset(user_registry, 0, sizeof(user_registry));
}

static void free_tables(void) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        DedupeEntry* d = dedup_table[i];
        while (d) { DedupeEntry* n = d->next; free(d); d = n; }
        InodeEntry* e = inode_table[i];
        while (e) { InodeEntry* n = e->next; free(e); e = n; }
    }
    for (int i = 0; i < USER_HASH_SIZE; i++) {
        UserHashEntry* e = user_hash_table[i];
        while (e) { UserHashEntry* n = e->next; free(e); e = n; }
    }
    for (int i = 0; i < REUSE_HASH_SIZE; i++) {
        ReuseEntry* e = reuse_table[i];
        while (e) { ReuseEntry* n = e->next; free(e); e = n; }
    }
    user_registry_free();
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
    /* Increment credential count in user registry */
    if (f->owner[0]) {
        UserRegEntry* ure = user_registry_find(f->owner);
        if (ure) ure->credential_count++;
    }
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
    if (cat == CAT_PASSWORD_HASH || cat == CAT_POSSIBLE_HASH || cat == CAT_NETWORK_AUTH) {
        track_user_hash(f->owner, type, path);
    }
    
    /* Track value reuse */
    track_reuse(val, f->owner, path);
    
    add_dup(vh, result.count);
    result.count++;
    
    if (opt_verbose) fprintf(stderr, "[+] %s: %s in %s:%d\n",
        cat==CAT_PASSWORD_HASH?"HASH":cat==CAT_POSSIBLE_HASH?"POSSIBLE":cat==CAT_NETWORK_AUTH?"NETAUTH":"FOUND", type, path, line);
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
    /* Early exit: skip expensive pattern loop if line has no assignment operators */
    int has_assign = (strchr(line, '=') || strchr(line, ':'));
    if (!has_assign) goto skip_cred_vars;
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
    skip_cred_vars:

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
    
    /* NetNTLMv1/v2 (user::domain:challenge:response format) - Pcredz compatible */
    const char* ntlm = line;
    while ((ntlm = strstr(ntlm, "::")) != NULL) {
        /* Look backwards for username */
        const char* user_start = ntlm;
        while (user_start > line && *(user_start-1) != ' ' && *(user_start-1) != '\t' && *(user_start-1) != ':' && *(user_start-1) != '\n') user_start--;
        int user_len = ntlm - user_start;
        if (user_len >= 1 && user_len <= 64) {
            /* Look forward for domain:challenge:response */
            const char* rest = ntlm + 2;
            int colons = 0;
            int rlen = 0;
            int challenge_start = -1, challenge_end = -1;
            
            while (rest[rlen] && rest[rlen] != ' ' && rest[rlen] != '\t' && rest[rlen] != '\n' && rlen < 600) {
                if (rest[rlen] == ':') {
                    colons++;
                    if (colons == 2) challenge_start = rlen + 1;
                    if (colons == 3) challenge_end = rlen;
                }
                rlen++;
            }
            
            /* Validate: NetNTLMv1: user::domain:challenge:lm:nt (colons=4, challenge=16 hex) */
            /* Validate: NetNTLMv2: user::domain:challenge:ntproof:blob (colons>=3, longer) */
            if (colons >= 3 && rlen > 50) {
                /* Check if challenge is 16 hex chars (8 bytes) */
                int valid_challenge = 0;
                if (challenge_start > 0 && challenge_end > challenge_start) {
                    int clen = challenge_end - challenge_start;
                    if (clen == 16) {
                        valid_challenge = 1;
                        for (int i = challenge_start; i < challenge_end && valid_challenge; i++) {
                            if (!is_hex(rest[i])) valid_challenge = 0;
                        }
                    }
                }
                
                if (valid_challenge || colons >= 4) {
                    int total_len = user_len + 2 + rlen;
                    if (total_len > 50 && total_len < 700) {
                        char nv[700];
                        strncpy(nv, user_start, total_len < 699 ? total_len : 699);
                        nv[total_len < 699 ? total_len : 699] = '\0';
                        
                        /* Count hex chars in response portion */
                        int hex_count = 0;
                        for (int i = 0; i < rlen; i++) if (is_hex(rest[i])) hex_count++;
                        
                        if (hex_count > 30) {
                            /* Determine v1 vs v2 by structure */
                            /* v1: colons=4, response ~48 hex */
                            /* v2: colons=3+, response much longer (ntproof=32 + blob) */
                            char* username = malloc(user_len + 1);
                            if (username) {
                                strncpy(username, user_start, user_len);
                                username[user_len] = '\0';
                                track_user_hash(username, colons == 4 ? "netntlmv1" : "netntlmv2", path);
                                free(username);
                            }
                            
                            if (colons == 4 && hex_count < 100) {
                                add_finding(CAT_NETWORK_AUTH, "netntlmv1", CONF_HIGH, path, lnum, off, nv, 5500, "NetNTLMv1 capture (Pcredz/Responder)", cb, ca);
                            } else {
                                add_finding(CAT_NETWORK_AUTH, "netntlmv2", CONF_HIGH, path, lnum, off, nv, 5600, "NetNTLMv2 capture (Pcredz/Responder)", cb, ca);
                            }
                        }
                    }
                }
            }
        }
        ntlm++;
    }
    
    /* HTTP NTLM (Type 3 message in Authorization header) */
    const char* http_ntlm = strcasestr_local(line, "Authorization: NTLM ");
    if (http_ntlm) {
        const char* b64 = http_ntlm + 20;
        while (*b64 == ' ') b64++;
        int b64len = 0;
        while (b64[b64len] && (isalnum(b64[b64len]) || b64[b64len] == '+' || b64[b64len] == '/' || b64[b64len] == '=')) b64len++;
        if (b64len >= 50 && b64len <= 2000) {
            char token[2048];
            strncpy(token, b64, b64len < 2047 ? b64len : 2047);
            token[b64len < 2047 ? b64len : 2047] = '\0';
            add_finding(CAT_NETWORK_AUTH, "http_ntlm", CONF_HIGH, path, lnum, off, token, -1, "HTTP NTLM Auth (Type 3)", cb, ca);
        }
    }
    
    /* SMB/CIFS credential patterns */
    if (strcasestr_local(line, "\\\\") && (strcasestr_local(line, "pass") || strcasestr_local(line, "pwd"))) {
        /* Check for net use or SMB credential line */
        if (strcasestr_local(line, "net use") || strcasestr_local(line, "/user:")) {
            add_finding(CAT_NETWORK_AUTH, "smb_credential", CONF_MEDIUM, path, lnum, off, "[SMB credential line]", -1, "SMB/CIFS credential reference", cb, ca);
        }
    }
    
    /* Base64 encoded secrets (look for base64 after secret keywords) */
    for (int i = 0; BASE64_SECRET_CONTEXTS[i]; i++) {
        const char* ctx = line;
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

    /* ========================================================================
     * PWDUMP FORMAT: user:RID:LMhash:NThash:::
     * ======================================================================== */
    {
        const char* p = line;
        while (*p) {
            /* Find pattern: word:number:32hex:32hex::: */
            const char* start = p;
            /* Skip to first colon (username) */
            while (*p && *p != ':' && *p != '\n') p++;
            if (*p != ':') break;
            int ulen = p - start;
            if (ulen < 1 || ulen > 64) { p++; continue; }
            p++; /* skip colon */

            /* RID field - must be numeric */
            const char* rid_start = p;
            while (*p && isdigit(*p)) p++;
            if (*p != ':' || p == rid_start) { p = start + ulen + 1; continue; }
            p++; /* skip colon */

            /* LM hash - exactly 32 hex chars */
            int lm_ok = 1;
            for (int i = 0; i < 32 && lm_ok; i++) {
                if (!is_hex(p[i])) lm_ok = 0;
            }
            if (!lm_ok || p[32] != ':') { p = start + ulen + 1; continue; }
            char lm_hash[33];
            strncpy(lm_hash, p, 32); lm_hash[32] = '\0';
            p += 33; /* 32 hex + colon */

            /* NT hash - exactly 32 hex chars */
            int nt_ok = 1;
            for (int i = 0; i < 32 && nt_ok; i++) {
                if (!is_hex(p[i])) nt_ok = 0;
            }
            if (!nt_ok) { p = start + ulen + 1; continue; }
            char nt_hash[33];
            strncpy(nt_hash, p, 32); nt_hash[32] = '\0';
            p += 32;

            /* Should end with ::: (or end of line) */
            if (p[0] == ':' && p[1] == ':' && p[2] == ':') {
                char user[65];
                strncpy(user, start, ulen); user[ulen] = '\0';

                /* Full pwdump line */
                int total = strlen(start);
                char pwdump_val[512];
                strncpy(pwdump_val, start, total < 511 ? total : 511);
                pwdump_val[total < 511 ? total : 511] = '\0';

                /* NT hash */
                char nt_lower[33];
                strncpy(nt_lower, nt_hash, 33);
                str_lower(nt_lower);
                track_user_hash(user, "ntlm", path);

                if (strcmp(nt_lower, "31d6cfe0d16ae931b73c59d7e0c089c0") != 0) { /* not empty NTLM */
                    char reason[128];
                    snprintf(reason, sizeof(reason), "NTLM hash for user: %s", user);
                    add_finding(CAT_PASSWORD_HASH, "ntlm_pwdump", CONF_HIGH, path, lnum, off,
                               nt_hash, 1000, reason, cb, ca);
                }

                /* LM hash - only if not empty */
                char lm_lower[33];
                strncpy(lm_lower, lm_hash, 33);
                str_lower(lm_lower);
                if (strcmp(lm_lower, "aad3b435b51404eeaad3b435b51404ee") != 0) {
                    char reason[128];
                    snprintf(reason, sizeof(reason), "LM hash for user: %s", user);
                    add_finding(CAT_PASSWORD_HASH, "lm_hash", CONF_HIGH, path, lnum, off,
                               lm_hash, 3000, reason, cb, ca);
                }
            }
            break; /* pwdump is one per line */
        }
    }

    /* ========================================================================
     * GPP CPASSWORD: cpassword="..." in XML
     * ======================================================================== */
    {
        const char* cp = strcasestr_local(line, "cpassword=\"");
        if (cp) {
            cp += 11;
            int vlen = 0;
            while (cp[vlen] && cp[vlen] != '"' && vlen < 500) vlen++;
            if (vlen > 2) {
                char val[512];
                strncpy(val, cp, vlen); val[vlen] = '\0';

                char user[64] = "";
                const char* un = strcasestr_local(line, "userName=\"");
                if (un) {
                    un += 10;
                    int ulen = 0;
                    while (un[ulen] && un[ulen] != '"' && ulen < 63) ulen++;
                    strncpy(user, un, ulen); user[ulen] = '\0';
                }

                char reason[256];
                snprintf(reason, sizeof(reason), "GPP cpassword%s%s (trivially decryptable)",
                        user[0] ? " for user: " : "", user);
                if (user[0]) track_user_hash(user, "gpp_cpassword", path);
                add_finding(CAT_PLAINTEXT, "gpp_cpassword", CONF_HIGH, path, lnum, off,
                           val, -1, reason, cb, ca);
            }
        }
    }

    /* ========================================================================
     * BITLOCKER RECOVERY KEY: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
     * ======================================================================== */
    {
        const char* p = line;
        while (*p) {
            /* Look for 6-digit group */
            if (isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) &&
                isdigit(p[3]) && isdigit(p[4]) && isdigit(p[5]) && p[6] == '-') {
                /* Verify full 8 groups of 6 digits */
                const char* start = p;
                int valid = 1;
                for (int g = 0; g < 8 && valid; g++) {
                    for (int d = 0; d < 6 && valid; d++) {
                        if (!isdigit(p[d])) valid = 0;
                    }
                    p += 6;
                    if (g < 7) {
                        if (*p != '-') valid = 0;
                        else p++;
                    }
                }
                /* Total length: 8*6 + 7 dashes = 55 chars */
                if (valid && (p - start) == 55) {
                    /* Verify not all zeros */
                    int all_zero = 1;
                    for (int i = 0; i < 55 && all_zero; i++) {
                        if (start[i] != '0' && start[i] != '-') all_zero = 0;
                    }
                    /* BitLocker constraint: every 6-digit group is divisible by 11.
                     * Cuts FPs from random ID strings to near-zero. */
                    int mod11_ok = 1;
                    for (int g = 0; g < 8 && mod11_ok; g++) {
                        const char* gp = start + g * 7;  /* 6 digits + 1 dash stride */
                        long v = 0;
                        for (int d = 0; d < 6; d++) v = v * 10 + (gp[d] - '0');
                        if (v % 11 != 0 || v > 720885) mod11_ok = 0;
                    }
                    if (!all_zero && mod11_ok) {
                        char key[56];
                        strncpy(key, start, 55); key[55] = '\0';
                        add_finding(CAT_TOKEN, "bitlocker_recovery_key", CONF_HIGH, path, lnum, off,
                                   key, -1, "BitLocker recovery key", cb, ca);
                    }
                }
                continue;
            }
            p++;
        }
    }

    /* ========================================================================
     * WPA PMKID / hashcat 22000 format
     * ======================================================================== */
    if (strncmp(line, "WPA*", 4) == 0 || strstr(line, "*PMKID*") || strncmp(line, "PMKID*", 6) == 0) {
        add_finding(CAT_NETWORK_AUTH, "wpa_pmkid", CONF_HIGH, path, lnum, off,
                   line, 22000, "WPA PMKID hash", cb, ca);
    }

    /* ========================================================================
     * HTPASSWD INLINE: user:$hash... format (when file is htpasswd)
     * ======================================================================== */
    if (strcasestr_local(path, "htpasswd")) {
        const char* colon = strchr(line, ':');
        if (colon && colon > line && colon - line < 64) {
            const char* hash = colon + 1;
            int hlen = strlen(hash);
            while (hlen > 0 && isspace(hash[hlen-1])) hlen--;
            if (hlen > 10 && (hash[0] == '$' || hash[0] == '{' || hash[0] == '*')) {
                char user[64];
                int ulen = colon - line;
                strncpy(user, line, ulen); user[ulen] = '\0';
                /* Don't add_finding here - scan_line() will already match the hash.
                 * Just track the user correlation. */
                const char* htype = "htpasswd";
                if (strncmp(hash, "$apr1$", 6) == 0) htype = "apr1";
                else if (strncmp(hash, "{SHA}", 5) == 0) htype = "sha_apache";
                else if (strncmp(hash, "$2", 2) == 0) htype = "bcrypt";
                track_user_hash(user, htype, path);
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
        /* Shell/SQL history */
        ".bash_history", ".zsh_history", ".sh_history",
        ".mysql_history", ".psql_history", ".python_history",
        /* Windows artifacts */
        "ConsoleHost_history.txt", "Unattend.xml", "autounattend.xml",
        "sysprep.inf", "Groups.xml", "Services.xml",
        "ScheduledTasks.xml", "DataSources.xml", "Drives.xml",
        "Printers.xml", "applicationHost.config",
        /* Linux security */
        "opasswd", "krb5.keytab",
        /* Credential files */
        "hashes", "hashdump", "secretsdump", "pwdump",
        "loot", "ntlm", "capture",
        NULL
    };
    for (int i = 0; names[i]; i++) if (strcasecmp(fn, names[i])==0 || strstr(fn, names[i])) return 1;
    const char* ext = strrchr(fn, '.');
    if (!ext) return 0;
    const char* exts[] = {
        ".php", ".inc", ".env", ".ini", ".conf", ".yml", ".yaml", ".json", ".xml", ".sql", ".dump",
        ".bak", ".old", ".log", ".txt", ".py", ".sh", ".htpasswd", ".swp",
        /* Terraform */
        ".tf", ".tfvars", ".hcl",
        /* Java */
        ".properties",
        /* Rust/Python */
        ".toml",
        /* Certs/Keys */
        ".pem", ".key", ".crt", ".p12", ".pfx",
        /* History */
        ".history",
        /* Windows */
        ".reg", ".rdp", ".rdg",
        /* Databases/Crypto */
        ".kdbx", ".keytab",
        /* PowerShell */
        ".ps1", ".psm1", ".psd1",
        /* Config */
        ".cfg", ".config", ".cnf",
        NULL
    };
    for (int i = 0; exts[i]; i++) if (strcasecmp(ext, exts[i])==0) return 1;
    int l = strlen(fn);
    if (l > 0 && fn[l-1] == '~') return 1;
    return 0;
}

static int should_skip(const char* dn) {
    const char* skip[] = {
        "node_modules", "__pycache__", ".git", "vendor", "venv",
        "sys", "dev", "Windows", "Program Files", "Program Files (x86)",
        NULL
    };
    /* Note: "proc" removed - handled selectively in scan_dir() */
    for (int i = 0; skip[i]; i++) if (strcmp(dn, skip[i])==0) return 1;
    return 0;
}

/* Pcredz/Responder output file detection */
static int is_pcredz_output(const char* path) {
    const char* fname = strrchr(path, '/');
    if (!fname) fname = strrchr(path, '\\');
    fname = fname ? fname + 1 : path;
    
    /* Common Pcredz/Responder output patterns */
    if (strcasestr_local(fname, "hashes") ||
        strcasestr_local(fname, "credentials") ||
        strcasestr_local(fname, "pcredz") ||
        strcasestr_local(fname, "responder") ||
        strcasestr_local(fname, "ntlm") ||
        strcasestr_local(fname, "capture") ||
        strcasestr_local(fname, "loot")) {
        return 1;
    }
    return 0;
}

/* Special scanner for Pcredz-style output files */
static void scan_pcredz_line(const char* line, const char* path, int lnum) {
    /* FTP credentials: FTP User:pass@host */
    if (strncasecmp(line, "FTP", 3) == 0 || strcasestr_local(line, "ftp://")) {
        const char* at = strchr(line, '@');
        const char* colon = strchr(line, ':');
        if (at && colon && colon < at) {
            add_finding(CAT_NETWORK_AUTH, "ftp_credential", CONF_HIGH, path, lnum, 0, 
                       line, -1, "FTP credential (Pcredz)", NULL, NULL);
        }
    }
    
    /* Telnet credentials */
    if (strncasecmp(line, "Telnet", 6) == 0) {
        add_finding(CAT_NETWORK_AUTH, "telnet_credential", CONF_HIGH, path, lnum, 0,
                   line, -1, "Telnet credential (Pcredz)", NULL, NULL);
    }
    
    /* HTTP Basic */
    if (strcasestr_local(line, "HTTP") && strcasestr_local(line, "Basic")) {
        add_finding(CAT_NETWORK_AUTH, "http_basic", CONF_HIGH, path, lnum, 0,
                   line, -1, "HTTP Basic Auth (Pcredz)", NULL, NULL);
    }
    
    /* SMTP credentials */
    if (strncasecmp(line, "SMTP", 4) == 0 || strcasestr_local(line, "smtp://")) {
        add_finding(CAT_NETWORK_AUTH, "smtp_credential", CONF_HIGH, path, lnum, 0,
                   line, -1, "SMTP credential (Pcredz)", NULL, NULL);
    }
    
    /* POP3 credentials */
    if (strncasecmp(line, "POP3", 4) == 0 || strcasestr_local(line, "pop3://")) {
        add_finding(CAT_NETWORK_AUTH, "pop3_credential", CONF_HIGH, path, lnum, 0,
                   line, -1, "POP3 credential (Pcredz)", NULL, NULL);
    }
    
    /* IMAP credentials */
    if (strncasecmp(line, "IMAP", 4) == 0 || strcasestr_local(line, "imap://")) {
        add_finding(CAT_NETWORK_AUTH, "imap_credential", CONF_HIGH, path, lnum, 0,
                   line, -1, "IMAP credential (Pcredz)", NULL, NULL);
    }
    
    /* LDAP credentials */
    if (strncasecmp(line, "LDAP", 4) == 0 || strcasestr_local(line, "ldap://")) {
        add_finding(CAT_NETWORK_AUTH, "ldap_credential", CONF_HIGH, path, lnum, 0,
                   line, -1, "LDAP credential (Pcredz)", NULL, NULL);
    }
    
    /* SNMPv1/v2 community strings */
    if (strcasestr_local(line, "SNMP") && strcasestr_local(line, "community")) {
        add_finding(CAT_NETWORK_AUTH, "snmp_community", CONF_HIGH, path, lnum, 0,
                   line, -1, "SNMP community string", NULL, NULL);
    }
    
    /* Kerberos (raw format) */
    if (strcasestr_local(line, "Kerberos") || strcasestr_local(line, "TGS") || strcasestr_local(line, "AS-REP")) {
        add_finding(CAT_NETWORK_AUTH, "kerberos_ticket", CONF_HIGH, path, lnum, 0,
                   line, -1, "Kerberos ticket data (Pcredz)", NULL, NULL);
    }
    
    /* WPA/WPA2 handshake reference - tightened to avoid FPs.
     * Bare "WPA" matches wpa_supplicant config, log lines, docs.
     * Skip if scan_line() already produced a wpa_pmkid finding for this line. */
    if (strncmp(line, "WPA*", 4) != 0 && strncmp(line, "PMKID*", 6) != 0) {
        int hit = 0;
        if (strstr(line, "PMKID:") || strstr(line, "[PMKID]")) hit = 1;
        else if (strstr(line, "EAPOL ") || strstr(line, "EAPOL-")) hit = 1;
        else if (strstr(line, "[WPA-") || strstr(line, "WPA-PSK") ||
                 strstr(line, "WPA2-PSK") || strstr(line, "[WPA]")) hit = 1;
        if (hit) {
            add_finding(CAT_NETWORK_AUTH, "wifi_handshake", CONF_MEDIUM, path, lnum, 0,
                       line, -1, "WiFi handshake/PMKID reference", NULL, NULL);
        }
    }
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
    
    /* Check if this is a Pcredz/Responder output file for special handling */
    int pcredz_mode = is_pcredz_output(path);
    
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
        
        /* Additional Pcredz-specific scanning for network capture files */
        if (pcredz_mode) {
            scan_pcredz_line(ln, path, lnum);
        }
        
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
#ifndef _WIN32
            /* Selective /proc scanning - only environ files */
            else if (strcmp(e->d_name, "proc") == 0 && depth == 0 && strcmp(path, "/") == 0) {
                if (opt_collectors) collect_proc_environ();
            }
#endif
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

            /* Special file type handlers */
            if (ext) {
                if (strcasecmp(ext, ".kdbx") == 0) {
                    detect_keepass_db(fp);
                }
                else if (strcasecmp(ext, ".rdp") == 0 || strcasecmp(ext, ".rdg") == 0) {
                    detect_rdp_file(fp);
                }
#ifdef _WIN32
                else if (strcasecmp(ext, ".reg") == 0) {
                    scan_reg_file(fp);
                }
#endif
            }

#ifndef _WIN32
            /* Shell/SQL history files get specialized scanning */
            if (strcasestr_local(e->d_name, "_history") || strcasestr_local(e->d_name, ".history")) {
                if (strcasestr_local(e->d_name, "mysql") || strcasestr_local(e->d_name, "psql"))
                    collect_sql_history(fp);
                else
                    collect_shell_history(fp);
            }
            /* htpasswd files get specialized parsing */
            if (strcasestr_local(e->d_name, "htpasswd")) {
                collect_htpasswd(fp);
            }
#endif

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
        track_user_hash(user, t, "/etc/shadow");
        /* Mark user in registry as having a password hash */
        UserRegEntry* ure = user_registry_find(user);
        if (ure) { ure->has_password = 1; ure->credential_count++; }
        add_finding(CAT_PASSWORD_HASH, t, CONF_HIGH, "/etc/shadow", lnum, 0, hash, hc, reason, NULL, NULL);
    }
    fclose(f);
}

/* ============================================================================
 * LINUX COLLECTOR: /etc/passwd - User Registry
 * ============================================================================ */

static void collect_passwd(void) {
    FILE* f = fopen("/etc/passwd", "r");
    if (!f) return;
    char ln[MAX_LINE];
    while (fgets(ln, sizeof(ln), f)) {
        /* format: user:x:uid:gid:gecos:home:shell */
        char* fields[7] = {0};
        int fc = 0;
        char* p = ln;
        for (int i = 0; i < 7 && p; i++) {
            fields[i] = p;
            char* sep = strchr(p, ':');
            if (sep) { *sep = '\0'; p = sep + 1; }
            else { /* strip newline */ char* nl = strchr(p, '\n'); if (nl) *nl = '\0'; p = NULL; }
            fc++;
        }
        if (fc >= 7 && fields[0][0]) {
            int uid = atoi(fields[2] ? fields[2] : "0");
            user_registry_add(fields[0], uid, fields[5], fields[6]);
            /* Flag UID 0 accounts that are not root */
            if (uid == 0 && strcmp(fields[0], "root") != 0) {
                char reason[128];
                snprintf(reason, sizeof(reason), "UID 0 non-root account: %s", fields[0]);
                add_finding(CAT_TOKEN, "uid0_account", CONF_HIGH, "/etc/passwd", 0, 0,
                           fields[0], -1, reason, NULL, NULL);
            }
        }
    }
    fclose(f);
}

/* ============================================================================
 * LINUX COLLECTOR: Shell History - Passwords in commands
 * ============================================================================ */

typedef struct { const char* pattern; const char* name; } HistoryPattern;

static const HistoryPattern HISTORY_PATTERNS[] = {
    {"mysql -p", "mysql_password"},
    {"mysql --password", "mysql_password"},
    {"mysqldump -p", "mysql_password"},
    {"sshpass -p", "sshpass_password"},
    {"sshpass -P", "sshpass_password"},
    {"curl -u ", "curl_credential"},
    {"curl --user ", "curl_credential"},
    {"wget --password", "wget_password"},
    {"wget --ftp-password", "wget_password"},
    {"htpasswd ", "htpasswd_cmd"},
    {"openssl passwd", "openssl_password"},
    {"net use ", "net_use_credential"},
    {"mount -o password", "mount_password"},
    {"mount.cifs", "cifs_credential"},
    {"psql -W", "psql_password"},
    {"pgpassword=", "postgres_env"},
    {"PGPASSWORD=", "postgres_env"},
    {"MYSQL_PWD=", "mysql_env"},
    {"ldapsearch -w ", "ldap_password"},
    {"ldapsearch -W", "ldap_password"},
    {"kinit ", "kerberos_cmd"},
    {"runas /user:", "runas_credential"},
    {"cmdkey /add:", "cmdkey_credential"},
    {NULL, NULL}
};

static void collect_shell_history(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;

    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        int len = strlen(ln);
        while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';
        if (len < 8) continue;

        for (int i = 0; HISTORY_PATTERNS[i].pattern; i++) {
            if (strcasestr_local(ln, HISTORY_PATTERNS[i].pattern)) {
                add_finding(CAT_PLAINTEXT, HISTORY_PATTERNS[i].name, CONF_HIGH, path, lnum, 0,
                           ln, -1, "Password in shell history", NULL, NULL);
                break;
            }
        }
        /* Also check generic password assignments in history */
        if (strcasestr_local(ln, "password=") || strcasestr_local(ln, "passwd=") ||
            strcasestr_local(ln, "SECRET_KEY=") || strcasestr_local(ln, "API_KEY=")) {
            add_finding(CAT_PLAINTEXT, "history_credential", CONF_MEDIUM, path, lnum, 0,
                       ln, -1, "Credential in shell history", NULL, NULL);
        }
    }
    fclose(f);
}

/* ============================================================================
 * LINUX COLLECTOR: SQL History
 * ============================================================================ */

static void collect_sql_history(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;

    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        int len = strlen(ln);
        while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';
        if (len < 10) continue;

        if (strcasestr_local(ln, "IDENTIFIED BY") ||
            strcasestr_local(ln, "SET PASSWORD") ||
            strcasestr_local(ln, "GRANT ") ||
            strcasestr_local(ln, "CREATE USER") ||
            strcasestr_local(ln, "ALTER USER") ||
            strcasestr_local(ln, "PASSWORD(")) {
            add_finding(CAT_PLAINTEXT, "sql_history_credential", CONF_HIGH, path, lnum, 0,
                       ln, -1, "SQL password in history", NULL, NULL);
        }
    }
    fclose(f);
}

/* ============================================================================
 * LINUX COLLECTOR: NetworkManager WiFi PSK
 * ============================================================================ */

static void collect_networkmanager(void) {
    const char* nm_dir = "/etc/NetworkManager/system-connections";
    DIR* dir = opendir(nm_dir);
    if (!dir) return;

    struct dirent* e;
    while ((e = readdir(dir)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char fp[MAX_PATH_LEN];
        snprintf(fp, sizeof(fp), "%s/%s", nm_dir, e->d_name);

        FILE* f = fopen(fp, "r");
        if (!f) continue;

        char ln[MAX_LINE];
        int lnum = 0;
        char ssid[128] = "";
        while (fgets(ln, sizeof(ln), f)) {
            lnum++;
            int len = strlen(ln);
            while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';

            if (strncmp(ln, "ssid=", 5) == 0) {
                strncpy(ssid, ln + 5, sizeof(ssid) - 1);
            }
            if (strncmp(ln, "psk=", 4) == 0 && len > 4) {
                char reason[256];
                snprintf(reason, sizeof(reason), "WiFi PSK for SSID: %s", ssid[0] ? ssid : "(unknown)");
                add_finding(CAT_PLAINTEXT, "wifi_psk", CONF_HIGH, fp, lnum, 0,
                           ln + 4, -1, reason, NULL, NULL);
            }
        }
        fclose(f);
    }
    closedir(dir);
}

/* ============================================================================
 * LINUX COLLECTOR: /etc/security/opasswd
 * ============================================================================ */

static void collect_opasswd(void) {
    FILE* f = fopen("/etc/security/opasswd", "r");
    if (!f) return;

    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        int len = strlen(ln);
        while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';
        if (len < 5) continue;

        /* Format: user:count:hash1,hash2,... */
        char* c1 = strchr(ln, ':');
        if (!c1) continue;
        char user[64];
        int ul = c1 - ln;
        if (ul >= 64 || ul <= 0) continue;
        strncpy(user, ln, ul); user[ul] = '\0';

        char* c2 = strchr(c1 + 1, ':');
        if (!c2) continue;
        char* hashes = c2 + 1;
        if (strlen(hashes) < 3) continue;

        char reason[128];
        snprintf(reason, sizeof(reason), "Old password for user: %s", user);
        /* Scan each comma-separated hash */
        char* tok = hashes;
        while (tok && *tok) {
            char* comma = strchr(tok, ',');
            if (comma) *comma = '\0';
            if (strlen(tok) > 5) {
                track_user_hash(user, "opasswd", "/etc/security/opasswd");
                add_finding(CAT_PASSWORD_HASH, "opasswd", CONF_HIGH,
                           "/etc/security/opasswd", lnum, 0, tok, -1, reason, NULL, NULL);
            }
            if (comma) tok = comma + 1; else break;
        }
    }
    fclose(f);
}

/* ============================================================================
 * LINUX COLLECTOR: /proc/*/environ - Secrets in process environment
 * ============================================================================ */

static void collect_proc_environ(void) {
    DIR* proc = opendir("/proc");
    if (!proc) return;

    struct dirent* e;
    int count = 0;
    while ((e = readdir(proc)) != NULL && count < 200) {
        /* Only numeric PID directories */
        if (!isdigit(e->d_name[0])) continue;

        char envpath[256];
        snprintf(envpath, sizeof(envpath), "/proc/%s/environ", e->d_name);

        FILE* f = fopen(envpath, "r");
        if (!f) continue;
        count++;

        /* environ is NUL-delimited */
        char buf[32768];
        size_t rd = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[rd] = '\0';

        size_t pos = 0;
        while (pos < rd) {
            const char* entry = buf + pos;
            size_t elen = strlen(entry);
            if (elen == 0) { pos++; continue; }
            pos += elen + 1;

            /* Check if key matches credential patterns */
            const char* eq = strchr(entry, '=');
            if (!eq || eq == entry) continue;
            int klen = eq - entry;
            const char* val = eq + 1;
            int vlen = strlen(val);

            if (vlen < 4 || vlen > 500) continue;

            /* Check key against known secret env var names */
            char key_lower[128];
            if (klen >= (int)sizeof(key_lower)) continue;
            for (int i = 0; i < klen; i++) key_lower[i] = tolower((unsigned char)entry[i]);
            key_lower[klen] = '\0';

            int is_secret = 0;
            const char* secret_keys[] = {
                "password", "passwd", "secret", "api_key", "apikey",
                "access_key", "token", "auth", "private_key", "credential",
                "db_pass", "mysql_pwd", "pgpassword", "redis_pass",
                NULL
            };
            for (int i = 0; secret_keys[i]; i++) {
                if (strstr(key_lower, secret_keys[i])) { is_secret = 1; break; }
            }

            if (is_secret) {
                char reason[256];
                snprintf(reason, sizeof(reason), "PID %s env: %.*s=...", e->d_name, klen, entry);
                add_finding(CAT_PLAINTEXT, "process_env_secret", CONF_HIGH,
                           envpath, 0, 0, val, -1, reason, NULL, NULL);
            }
        }
    }
    closedir(proc);
}

/* ============================================================================
 * LINUX COLLECTOR: Crontabs
 * ============================================================================ */

static void collect_crontabs(void) {
    const char* cron_dirs[] = {
        "/var/spool/cron", "/var/spool/cron/crontabs",
        "/etc/cron.d", NULL
    };
    for (int d = 0; cron_dirs[d]; d++) {
        DIR* dir = opendir(cron_dirs[d]);
        if (!dir) continue;
        struct dirent* e;
        while ((e = readdir(dir)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char fp[MAX_PATH_LEN];
            snprintf(fp, sizeof(fp), "%s/%s", cron_dirs[d], e->d_name);
            struct stat st;
            if (stat(fp, &st) == 0 && S_ISREG(st.st_mode))
                scan_file(fp);
        }
        closedir(dir);
    }
    /* Also scan /etc/crontab */
    struct stat st;
    if (stat("/etc/crontab", &st) == 0) scan_file("/etc/crontab");
}

/* ============================================================================
 * LINUX COLLECTOR: htpasswd file parser
 * ============================================================================ */

static void collect_htpasswd(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        int len = strlen(ln);
        while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';
        if (len < 3) continue;

        /* Format: user:hash */
        char* colon = strchr(ln, ':');
        if (!colon || colon == ln) continue;
        int ulen = colon - ln;
        if (ulen >= 64) continue;

        char user[64];
        strncpy(user, ln, ulen); user[ulen] = '\0';
        const char* hash = colon + 1;
        int hlen = strlen(hash);
        if (hlen < 4) continue;

        /* Determine hash type */
        const char* htype = "unknown_htpasswd";
        int hc = -1;
        if (strncmp(hash, "$apr1$", 6) == 0) { htype = "apr1"; hc = 1600; }
        else if (strncmp(hash, "{SHA}", 5) == 0) { htype = "sha_apache"; hc = 101; }
        else if (strncmp(hash, "$2y$", 4) == 0 || strncmp(hash, "$2a$", 4) == 0 || strncmp(hash, "$2b$", 4) == 0)
            { htype = "bcrypt"; hc = 3200; }
        else if (strncmp(hash, "$5$", 3) == 0) { htype = "sha256crypt"; hc = 7400; }
        else if (strncmp(hash, "$6$", 3) == 0) { htype = "sha512crypt"; hc = 1800; }

        char reason[128];
        snprintf(reason, sizeof(reason), "htpasswd user: %s", user);
        track_user_hash(user, htype, path);
        add_finding(CAT_PASSWORD_HASH, htype, CONF_HIGH, path, lnum, 0,
                   hash, hc, reason, NULL, NULL);
    }
    fclose(f);
}

#endif /* !_WIN32 */

/* ============================================================================
 * WINDOWS COLLECTORS
 * ============================================================================ */

#ifdef _WIN32

/* ============================================================================
 * WINDOWS COLLECTOR: Unattend.xml / sysprep.inf
 * ============================================================================ */

static void collect_unattend_xml(void) {
    const char* paths[] = {
        "C:\\Windows\\Panther\\Unattend.xml",
        "C:\\Windows\\Panther\\unattend.xml",
        "C:\\Windows\\Panther\\autounattend.xml",
        "C:\\Windows\\System32\\sysprep\\Unattend.xml",
        "C:\\Windows\\System32\\sysprep\\unattend.xml",
        "C:\\Windows\\System32\\sysprep\\sysprep.inf",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        FILE* f = fopen(paths[i], "r");
        if (!f) continue;

        if (opt_verbose) fprintf(stderr, "[*] Scanning Unattend: %s\n", paths[i]);

        char ln[MAX_LINE];
        int lnum = 0;
        int in_password_block = 0;
        while (fgets(ln, sizeof(ln), f)) {
            lnum++;
            int len = strlen(ln);
            while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';

            if (strcasestr_local(ln, "<Password>") || strcasestr_local(ln, "<AdministratorPassword>") ||
                strcasestr_local(ln, "<AutoLogon>"))
                in_password_block = 1;
            if (strcasestr_local(ln, "</Password>") || strcasestr_local(ln, "</AdministratorPassword>") ||
                strcasestr_local(ln, "</AutoLogon>"))
                in_password_block = 0;

            /* Extract <Value>base64</Value> */
            const char* val_tag = strcasestr_local(ln, "<Value>");
            if (val_tag && in_password_block) {
                const char* val_start = val_tag + 7;
                const char* val_end = strcasestr_local(val_start, "</Value>");
                if (val_end && val_end > val_start) {
                    int vlen = val_end - val_start;
                    if (vlen > 2 && vlen < 500) {
                        char val[512];
                        strncpy(val, val_start, vlen); val[vlen] = '\0';
                        add_finding(CAT_PLAINTEXT, "unattend_password", CONF_HIGH, paths[i], lnum, 0,
                                   val, -1, "Unattend.xml password (base64)", NULL, NULL);
                    }
                }
            }
            /* Also check for plaintext password fields */
            if (strcasestr_local(ln, "Password=") && !strcasestr_local(ln, "<!--")) {
                const char* eq = strcasestr_local(ln, "Password=");
                eq += 9;
                while (*eq == ' ' || *eq == '"') eq++;
                int vlen = 0;
                while (eq[vlen] && eq[vlen] != '"' && eq[vlen] != '\r' && eq[vlen] != '\n' && vlen < 200) vlen++;
                if (vlen > 2) {
                    char val[256];
                    strncpy(val, eq, vlen); val[vlen] = '\0';
                    add_finding(CAT_PLAINTEXT, "unattend_password", CONF_HIGH, paths[i], lnum, 0,
                               val, -1, "sysprep.inf password", NULL, NULL);
                }
            }
        }
        fclose(f);
    }
}

/* ============================================================================
 * WINDOWS COLLECTOR: GPP cpassword (Group Policy Preferences)
 * ============================================================================ */

static void scan_gpp_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;

    if (opt_verbose) fprintf(stderr, "[*] Scanning GPP: %s\n", path);

    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        const char* cp = strcasestr_local(ln, "cpassword=\"");
        if (!cp) continue;
        cp += 11;
        int vlen = 0;
        while (cp[vlen] && cp[vlen] != '"' && vlen < 500) vlen++;
        if (vlen > 2) {
            char val[512];
            strncpy(val, cp, vlen); val[vlen] = '\0';

            /* Also extract userName if present */
            char user[64] = "";
            const char* un = strcasestr_local(ln, "userName=\"");
            if (un) {
                un += 10;
                int ulen = 0;
                while (un[ulen] && un[ulen] != '"' && ulen < 63) ulen++;
                strncpy(user, un, ulen); user[ulen] = '\0';
            }

            char reason[256];
            if (user[0])
                snprintf(reason, sizeof(reason), "GPP cpassword for user: %s (AES key is public - trivially decryptable)", user);
            else
                snprintf(reason, sizeof(reason), "GPP cpassword (AES key is public - trivially decryptable)");

            if (user[0]) track_user_hash(user, "gpp_cpassword", path);
            add_finding(CAT_PLAINTEXT, "gpp_cpassword", CONF_HIGH, path, lnum, 0,
                       val, -1, reason, NULL, NULL);
        }
    }
    fclose(f);
}

static void collect_gpp_xml(void) {
    /* Search SYSVOL and common GPO paths */
    const char* gpp_bases[] = {
        "C:\\Windows\\SYSVOL",
        "C:\\Windows\\SYSVOL\\domain\\Policies",
        NULL
    };
    const char* gpp_files[] = {
        "Groups.xml", "Services.xml", "ScheduledTasks.xml",
        "DataSources.xml", "Drives.xml", "Printers.xml",
        NULL
    };

    for (int b = 0; gpp_bases[b]; b++) {
        for (int f = 0; gpp_files[f]; f++) {
            char search_path[MAX_PATH_LEN];
            snprintf(search_path, sizeof(search_path), "%s\\%s", gpp_bases[b], gpp_files[f]);
            struct stat st;
            if (stat(search_path, &st) == 0)
                scan_gpp_file(search_path);
        }
    }
}

/* ============================================================================
 * WINDOWS COLLECTOR: PowerShell History
 * ============================================================================ */

static void collect_powershell_history(void) {
    char* appdata = getenv("APPDATA");
    if (!appdata) return;

    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", appdata);

    FILE* f = fopen(path, "r");
    if (!f) return;

    if (opt_verbose) fprintf(stderr, "[*] Scanning PS history: %s\n", path);

    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        int len = strlen(ln);
        while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';
        if (len < 8) continue;

        int found = 0;
        /* PowerShell-specific credential patterns */
        if (strcasestr_local(ln, "ConvertTo-SecureString")) found = 1;
        else if (strcasestr_local(ln, "-Credential")) found = 1;
        else if (strcasestr_local(ln, "Net.NetworkCredential")) found = 1;
        else if (strcasestr_local(ln, "SecureString")) found = 1;
        else if (strcasestr_local(ln, "password") && (strchr(ln, '=') || strchr(ln, ':'))) found = 1;
        /* Also check generic history patterns */
        for (int i = 0; !found && HISTORY_PATTERNS[i].pattern; i++) {
            if (strcasestr_local(ln, HISTORY_PATTERNS[i].pattern)) found = 1;
        }

        if (found) {
            add_finding(CAT_PLAINTEXT, "powershell_history", CONF_HIGH, path, lnum, 0,
                       ln, -1, "Credential in PowerShell history", NULL, NULL);
        }
    }
    fclose(f);
}

/* ============================================================================
 * WINDOWS COLLECTOR: WiFi Profiles (keyMaterial)
 * ============================================================================ */

static void scan_wifi_profile(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;

    char ln[MAX_LINE];
    int lnum = 0;
    char ssid[128] = "";
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        int len = strlen(ln);
        while (len > 0 && (ln[len-1] == '\n' || ln[len-1] == '\r')) ln[--len] = '\0';

        /* Extract SSID name */
        const char* name_tag = strcasestr_local(ln, "<name>");
        if (name_tag && !ssid[0]) {
            const char* start = name_tag + 6;
            const char* end = strcasestr_local(start, "</name>");
            if (end && end > start && end - start < 127) {
                strncpy(ssid, start, end - start);
                ssid[end - start] = '\0';
            }
        }

        const char* key_tag = strcasestr_local(ln, "<keyMaterial>");
        if (key_tag) {
            const char* start = key_tag + 13;
            const char* end = strcasestr_local(start, "</keyMaterial>");
            if (end && end > start) {
                int vlen = end - start;
                if (vlen > 2 && vlen < 200) {
                    char val[256];
                    strncpy(val, start, vlen); val[vlen] = '\0';
                    char reason[256];
                    snprintf(reason, sizeof(reason), "WiFi key for SSID: %s", ssid[0] ? ssid : "(unknown)");
                    add_finding(CAT_PLAINTEXT, "wifi_key", CONF_HIGH, path, lnum, 0,
                               val, -1, reason, NULL, NULL);
                }
            }
        }
    }
    fclose(f);
}

static void collect_wifi_profiles(void) {
    char* programdata = getenv("ProgramData");
    if (!programdata) return;

    char base[MAX_PATH_LEN];
    snprintf(base, sizeof(base), "%s\\Microsoft\\Wlansvc\\Profiles\\Interfaces", programdata);

    DIR* ifaces = opendir(base);
    if (!ifaces) return;

    struct dirent* iface_e;
    while ((iface_e = readdir(ifaces)) != NULL) {
        if (iface_e->d_name[0] == '.') continue;
        char iface_dir[MAX_PATH_LEN];
        snprintf(iface_dir, sizeof(iface_dir), "%s\\%s", base, iface_e->d_name);

        DIR* profiles = opendir(iface_dir);
        if (!profiles) continue;
        struct dirent* prof_e;
        while ((prof_e = readdir(profiles)) != NULL) {
            if (prof_e->d_name[0] == '.') continue;
            const char* ext = strrchr(prof_e->d_name, '.');
            if (!ext || strcasecmp(ext, ".xml") != 0) continue;
            char prof_path[MAX_PATH_LEN];
            snprintf(prof_path, sizeof(prof_path), "%s\\%s", iface_dir, prof_e->d_name);
            scan_wifi_profile(prof_path);
        }
        closedir(profiles);
    }
    closedir(ifaces);
}

/* ============================================================================
 * WINDOWS COLLECTOR: Credential Manager & DPAPI artifacts
 * ============================================================================ */

static void collect_credential_manager(void) {
    const char* env_vars[] = {"APPDATA", "LOCALAPPDATA", NULL};
    for (int e = 0; env_vars[e]; e++) {
        char* base = getenv(env_vars[e]);
        if (!base) continue;
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s\\Microsoft\\Credentials", base);

        DIR* dir = opendir(path);
        if (!dir) continue;

        struct dirent* de;
        int count = 0;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] == '.') continue;
            count++;
        }
        closedir(dir);

        if (count > 0) {
            char reason[256];
            snprintf(reason, sizeof(reason), "%d DPAPI credential blob(s) found", count);
            add_finding(CAT_TOKEN, "dpapi_credential", CONF_MEDIUM, path, 0, 0,
                       "[DPAPI Protected Credentials]", -1, reason, NULL, NULL);
        }
    }

    /* Check for DPAPI master keys */
    char* appdata = getenv("APPDATA");
    if (appdata) {
        char mk_path[MAX_PATH_LEN];
        snprintf(mk_path, sizeof(mk_path), "%s\\Microsoft\\Protect", appdata);
        struct stat st;
        if (stat(mk_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            add_finding(CAT_TOKEN, "dpapi_masterkey", CONF_MEDIUM, mk_path, 0, 0,
                       "[DPAPI Master Keys]", -1, "DPAPI master key directory", NULL, NULL);
        }
    }
}

/* ============================================================================
 * WINDOWS COLLECTOR: Registry AutoLogon (.reg file scanner)
 * ============================================================================ */

static void scan_reg_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        if (strcasestr_local(ln, "DefaultPassword") || strcasestr_local(ln, "AutoAdminLogon")) {
            add_finding(CAT_PLAINTEXT, "registry_autologon", CONF_HIGH, path, lnum, 0,
                       ln, -1, "Windows AutoLogon credential", NULL, NULL);
        }
        if (strcasestr_local(ln, "VNCPassword") || strcasestr_local(ln, "Password") ||
            strcasestr_local(ln, "ProxyPassword")) {
            if (strchr(ln, '=') || strchr(ln, ':')) {
                add_finding(CAT_PLAINTEXT, "registry_password", CONF_MEDIUM, path, lnum, 0,
                           ln, -1, "Registry password entry", NULL, NULL);
            }
        }
    }
    fclose(f);
}

#endif /* _WIN32 */

/* ============================================================================
 * CROSS-PLATFORM: KeePass / RDP / Bitlocker detection
 * ============================================================================ */

static void detect_keepass_db(const char* path) {
    add_finding(CAT_TOKEN, "keepass_database", CONF_HIGH, path, 0, 0,
               "[KeePass Database]", 13400, "KeePass .kdbx (hashcat -m 13400)", NULL, NULL);
}

static void detect_rdp_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char ln[MAX_LINE];
    int lnum = 0;
    while (fgets(ln, sizeof(ln), f)) {
        lnum++;
        /* RDP password format: password 51:b:base64data */
        if (strncasecmp(ln, "password 51:b:", 14) == 0) {
            const char* b64 = ln + 14;
            int blen = strlen(b64);
            while (blen > 0 && (b64[blen-1] == '\n' || b64[blen-1] == '\r')) blen--;
            if (blen > 4) {
                char val[512];
                strncpy(val, b64, blen < 511 ? blen : 511);
                val[blen < 511 ? blen : 511] = '\0';
                add_finding(CAT_PLAINTEXT, "rdp_password", CONF_HIGH, path, lnum, 0,
                           val, -1, "RDP saved password (DPAPI encrypted)", NULL, NULL);
            }
        }
    }
    fclose(f);
}

/* ============================================================================
 * OUTPUT
 * ============================================================================ */

static const char* cat_str(Category c) {
    switch (c) { case CAT_PASSWORD_HASH: return "PASSWORD_HASH"; case CAT_POSSIBLE_HASH: return "POSSIBLE_HASH";
                 case CAT_PLAINTEXT: return "PLAINTEXT"; case CAT_TOKEN: return "TOKEN";
                 case CAT_PRIVATE_KEY: return "PRIVATE_KEY"; case CAT_NETWORK_AUTH: return "NETWORK_AUTH"; default: return "UNKNOWN"; }
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
    
    int cc[6] = {0};
    for (int i = 0; i < result.count; i++) cc[result.findings[i].category]++;
    Category cats[] = {CAT_PASSWORD_HASH, CAT_NETWORK_AUTH, CAT_POSSIBLE_HASH, CAT_PLAINTEXT, CAT_TOKEN, CAT_PRIVATE_KEY};

    for (int c = 0; c < 6; c++) {
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
        #define MAX_HASHCAT_MODE 30000
        int* modes_seen = calloc(MAX_HASHCAT_MODE, sizeof(int));
        if (!modes_seen) { fprintf(stderr, "[!] Out of memory for hashcat report\n"); return; }
        for (int i = 0; i < result.count; i++) {
            Finding* f = &result.findings[i];
            if (f->hashcat_mode > 0 && f->hashcat_mode < MAX_HASHCAT_MODE && !modes_seen[f->hashcat_mode]) {
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
        free(modes_seen);
    }

    /* User Registry Report */
    int reg_count = 0;
    for (int i = 0; i < USER_REGISTRY_SIZE; i++)
        for (UserRegEntry* e = user_registry[i]; e; e = e->next)
            if (e->has_password || e->credential_count > 0) reg_count++;

    if (reg_count > 0) {
        printf("══════════════════════════════════════════════════════════════════════\n");
        printf("  [USER REGISTRY] - %d users with credentials\n", reg_count);
        printf("══════════════════════════════════════════════════════════════════════\n\n");
        printf("  %-16s %-6s %-24s %-16s %s\n", "User", "UID", "Home", "Shell", "Creds");
        printf("  %-16s %-6s %-24s %-16s %s\n", "────────────────", "──────", "────────────────────────", "────────────────", "─────");
        for (int i = 0; i < USER_REGISTRY_SIZE; i++) {
            for (UserRegEntry* e = user_registry[i]; e; e = e->next) {
                if (e->has_password || e->credential_count > 0) {
                    printf("  %-16s %-6d %-24.24s %-16.16s %d\n",
                           e->username, e->uid,
                           e->home_dir[0] ? e->home_dir : "-",
                           e->shell[0] ? e->shell : "-",
                           e->credential_count);
                }
            }
        }
        printf("\n");
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
        char ep[MAX_PATH_LEN*2], ev[1024], er[512], eo[128], eht[128], ecb[MAX_CONTEXT*2], eca[MAX_CONTEXT*2];
        json_escape(f->file_path, ep, sizeof(ep));
        json_escape(opt_show_values ? f->value_full : f->value_preview, ev, sizeof(ev));
        json_escape(f->reason, er, sizeof(er));
        json_escape(f->owner, eo, sizeof(eo));
        json_escape(f->hash_type, eht, sizeof(eht));
        json_escape(f->context_before, ecb, sizeof(ecb));
        json_escape(f->context_after, eca, sizeof(eca));
        fprintf(out, "    {\"category\":\"%s\",\"hash_type\":\"%s\",\"confidence\":\"%s\",", cat_str(f->category), eht, conf_str(f->confidence));
        fprintf(out, "\"file_path\":\"%s\",\"line\":%d,\"value\":\"%s\",\"len\":%d,", ep, f->line_number, ev, f->value_length);
        fprintf(out, "\"occurrences\":%d,\"hashcat\":%d,\"owner\":\"%s\",\"reason\":\"%s\",", f->occurrence_count, f->hashcat_mode, eo, er);
        fprintf(out, "\"context_before\":\"%s\",\"context_after\":\"%s\"}", ecb, eca);
        fprintf(out, "%s\n", i < result.count - 1 ? "," : "");
    }
    fprintf(out, "  ]\n}\n");
}

/* ============================================================================
 * PROFILES
 * ============================================================================ */

static void run_profile(const char* p) {
    /* ---- Platform-specific collectors (run once before scanning) ---- */
#ifndef _WIN32
    collect_shadow();
    collect_passwd();
#endif
#ifdef _WIN32
    collect_unattend_xml();
    collect_gpp_xml();
    collect_powershell_history();
    collect_wifi_profiles();
    collect_credential_manager();
#endif

    /* ---- Web directories ---- */
    const char* web[] = {
#ifdef _WIN32
        "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs", "C:\\wamp\\www", NULL
#else
        "/var/www", "/srv/www", "/srv", "/opt", NULL
#endif
    };
    if (strcmp(p, "quick") == 0 || strcmp(p, "htb") == 0 || strcmp(p, "web") == 0)
        for (int i = 0; web[i]; i++) { struct stat st; if (stat(web[i], &st) == 0) { if (opt_verbose) fprintf(stderr, "[*] %s\n", web[i]); scan_dir(web[i], 0); } }

    /* ---- Home/User directories ---- */
    if (strcmp(p, "quick") == 0 || strcmp(p, "htb") == 0) {
#ifdef _WIN32
        char* up = getenv("USERPROFILE");
        if (up) { if (opt_verbose) fprintf(stderr, "[*] %s\n", up); scan_dir(up, 0); }
        /* Windows-specific paths */
        char* appdata = getenv("APPDATA");
        char* programdata = getenv("ProgramData");
        if (appdata) scan_dir(appdata, 0);
        /* IIS config */
        { struct stat st; if (stat("C:\\Windows\\System32\\inetsrv\\config", &st) == 0) scan_dir("C:\\Windows\\System32\\inetsrv\\config", 0); }
        /* Scheduled tasks */
        { struct stat st; if (stat("C:\\Windows\\System32\\Tasks", &st) == 0) scan_dir("C:\\Windows\\System32\\Tasks", 0); }
        /* Panther (unattend files) */
        { struct stat st; if (stat("C:\\Windows\\Panther", &st) == 0) scan_dir("C:\\Windows\\Panther", 0); }
        { struct stat st; if (stat("C:\\Windows\\System32\\sysprep", &st) == 0) scan_dir("C:\\Windows\\System32\\sysprep", 0); }
#else
        char* h = getenv("HOME");
        if (h) { if (opt_verbose) fprintf(stderr, "[*] %s\n", h); scan_dir(h, 0); }
        scan_dir("/home", 0);
        scan_dir("/root", 0);
        /* Cloud config locations */
        scan_dir("/root/.aws", 0);
        scan_dir("/root/.kube", 0);
        scan_dir("/root/.docker", 0);
#endif
    }

    /* ---- Extended paths for htb/full ---- */
    if (strcmp(p, "htb") == 0 || strcmp(p, "full") == 0) {
#ifndef _WIN32
        const char* ex[] = {
            "/etc", "/var/backups", "/var/log", "/tmp",
            /* Additional Linux paths */
            "/var/spool/cron", "/var/spool/cron/crontabs",
            "/etc/NetworkManager/system-connections",
            "/etc/security",
            NULL
        };
        for (int i = 0; ex[i]; i++) {
            struct stat st;
            if (stat(ex[i], &st) == 0) {
                if (opt_verbose) fprintf(stderr, "[*] %s\n", ex[i]);
                scan_dir(ex[i], 0);
            }
        }
        /* Linux-specific collectors */
        collect_networkmanager();
        collect_opasswd();
        collect_crontabs();
        collect_proc_environ();
#endif
    }

    /* ---- Full filesystem scan ---- */
    if (strcmp(p, "full") == 0) {
#ifdef _WIN32
        scan_dir("C:\\", 0);
#else
        scan_dir("/", 0);
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

/* ============================================================================
 * PCREDZ DIRECT PARSER - Parse Pcredz/Responder output files
 * ============================================================================ */

static void parse_pcredz_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[!] Cannot open Pcredz file: %s\n", path);
        return;
    }
    
    fprintf(stderr, "[*] Parsing Pcredz file: %s\n", path);
    
    char line[MAX_LINE];
    int lnum = 0;
    int found = 0;
    
    while (fgets(line, sizeof(line), f)) {
        lnum++;
        
        /* Remove trailing newline */
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }
        
        if (len < 5) continue;
        
        /* Skip comments but check for PLAINTEXT markers */
        if (line[0] == '#') {
            /* Pcredz plaintext format: # PLAINTEXT [protocol] user:pass */
            if (strstr(line, "PLAINTEXT")) {
                const char* proto_start = strchr(line, '[');
                const char* proto_end = proto_start ? strchr(proto_start, ']') : NULL;
                if (proto_start && proto_end) {
                    char proto[32] = {0};
                    int plen = proto_end - proto_start - 1;
                    if (plen > 0 && plen < 31) {
                        strncpy(proto, proto_start + 1, plen);
                    }
                    const char* cred = proto_end + 1;
                    while (*cred == ' ') cred++;
                    if (strlen(cred) > 3) {
                        char reason[128];
                        snprintf(reason, sizeof(reason), "Pcredz PLAINTEXT [%s]", proto);
                        add_finding(CAT_NETWORK_AUTH, "pcredz_plaintext", CONF_HIGH, path, lnum, 0,
                                   cred, -1, reason, NULL, NULL);
                        found++;
                    }
                }
            }
            continue;
        }
        
        /* NetNTLMv1: user::domain:lmhash:nthash:challenge (5 colons total) */
        /* NetNTLMv2: user::domain:challenge:ntproof:blob */
        if (strstr(line, "::")) {
            int colons = 0;
            for (int i = 0; line[i]; i++) if (line[i] == ':') colons++;
            
            if (colons >= 4) {
                /* Extract username for tracking */
                char* dcolon = strstr(line, "::");
                if (dcolon) {
                    char user[64] = {0};
                    int ulen = dcolon - line;
                    if (ulen > 0 && ulen < 63) {
                        strncpy(user, line, ulen);
                        track_user_hash(user, colons == 5 ? "netntlmv1" : "netntlmv2", path);
                    }
                }
                
                /* Determine v1 vs v2 by colon count and structure */
                if (colons == 5) {
                    add_finding(CAT_NETWORK_AUTH, "netntlmv1", CONF_HIGH, path, lnum, 0,
                               line, 5500, "Pcredz NetNTLMv1", NULL, NULL);
                } else {
                    add_finding(CAT_NETWORK_AUTH, "netntlmv2", CONF_HIGH, path, lnum, 0,
                               line, 5600, "Pcredz NetNTLMv2", NULL, NULL);
                }
                found++;
                continue;
            }
        }
        
        /* Kerberos AS-REP: $krb5asrep$23$user@REALM:... */
        if (strncmp(line, "$krb5asrep$", 11) == 0) {
            add_finding(CAT_PASSWORD_HASH, "krb5asrep", CONF_HIGH, path, lnum, 0,
                       line, 18200, "Pcredz Kerberos AS-REP", NULL, NULL);
            found++;
            continue;
        }
        
        /* Kerberos TGS: $krb5tgs$23$*user$realm$spn*$... */
        if (strncmp(line, "$krb5tgs$", 9) == 0) {
            add_finding(CAT_PASSWORD_HASH, "krb5tgs", CONF_HIGH, path, lnum, 0,
                       line, 13100, "Pcredz Kerberos TGS", NULL, NULL);
            found++;
            continue;
        }
        
        /* MySQL Native: $mysqlna$challenge$response */
        if (strncmp(line, "$mysqlna$", 9) == 0) {
            add_finding(CAT_PASSWORD_HASH, "mysql_native", CONF_HIGH, path, lnum, 0,
                       line, 11200, "Pcredz MySQL Native Auth", NULL, NULL);
            found++;
            continue;
        }
        
        /* PostgreSQL MD5: md5 + 32hex */
        if (strncmp(line, "md5", 3) == 0 && len >= 35) {
            int is_md5 = 1;
            for (int i = 3; i < 35 && is_md5; i++) {
                if (!is_hex(line[i])) is_md5 = 0;
            }
            if (is_md5) {
                add_finding(CAT_PASSWORD_HASH, "postgres_md5", CONF_HIGH, path, lnum, 0,
                           line, 0, "Pcredz PostgreSQL MD5", NULL, NULL);
                found++;
                continue;
            }
        }
        
        /* VNC: $vnc$*challenge*response */
        if (strncmp(line, "$vnc$", 5) == 0) {
            add_finding(CAT_PASSWORD_HASH, "vnc_challenge", CONF_HIGH, path, lnum, 0,
                       line, 10000, "Pcredz VNC Challenge", NULL, NULL);
            found++;
            continue;
        }
        
        /* SNMPv3: $SNMPv3$... */
        if (strncmp(line, "$SNMPv3$", 8) == 0) {
            add_finding(CAT_NETWORK_AUTH, "snmpv3", CONF_HIGH, path, lnum, 0,
                       line, 25000, "Pcredz SNMPv3", NULL, NULL);
            found++;
            continue;
        }
        
        /* MSSQL: 0x0100... or 0x0200... */
        if (strncmp(line, "0x0100", 6) == 0 || strncmp(line, "0x0200", 6) == 0) {
            int mode = (line[4] == '1') ? 132 : 1731;
            const char* type = (line[4] == '1') ? "mssql_2005" : "mssql_2012";
            add_finding(CAT_PASSWORD_HASH, type, CONF_HIGH, path, lnum, 0,
                       line, mode, "Pcredz MSSQL", NULL, NULL);
            found++;
            continue;
        }
        
        /* HTTP Basic: base64 after "Basic " */
        if (strcasestr_local(line, "Basic ")) {
            const char* b64 = strcasestr_local(line, "Basic ") + 6;
            while (*b64 == ' ') b64++;
            if (strlen(b64) > 4) {
                add_finding(CAT_NETWORK_AUTH, "http_basic", CONF_HIGH, path, lnum, 0,
                           b64, -1, "Pcredz HTTP Basic Auth", NULL, NULL);
                found++;
            }
            continue;
        }
        
        /* NTLM SSP (raw hex capture) */
        if (strcasestr_local(line, "NTLMSSP") || strcasestr_local(line, "NTLMv")) {
            add_finding(CAT_NETWORK_AUTH, "ntlm_ssp", CONF_HIGH, path, lnum, 0,
                       line, -1, "Pcredz NTLM SSP", NULL, NULL);
            found++;
            continue;
        }
        
        /* Generic protocol:user:pass or user:pass@host format */
        if (strchr(line, ':') && strchr(line, '@')) {
            /* FTP, SMTP, POP3, IMAP, etc. */
            const char* protocols[] = {"ftp", "smtp", "pop3", "imap", "telnet", "ldap", "http", "https", NULL};
            for (int i = 0; protocols[i]; i++) {
                if (strncasecmp(line, protocols[i], strlen(protocols[i])) == 0) {
                    char reason[64];
                    snprintf(reason, sizeof(reason), "Pcredz %s credential", protocols[i]);
                    add_finding(CAT_NETWORK_AUTH, "protocol_credential", CONF_HIGH, path, lnum, 0,
                               line, -1, reason, NULL, NULL);
                    found++;
                    break;
                }
            }
        }
    }
    
    fclose(f);
    fprintf(stderr, "[+] Pcredz parsing complete: %d findings\n\n", found);
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
    printf("  -q, --quiet       Suppress banner and status output\n");
    printf("  --max-files <n>   Max files (default: 50000)\n");
    printf("  --timeout <s>     Max runtime seconds\n");
    printf("  --no-collectors   Disable archive/sqlite/git collectors\n");
    printf("\nIntelligence:\n");
    printf("  --hashcat         Generate hashcat commands\n");
    printf("  --no-correlation  Disable user-hash correlation\n");
    printf("\nPcredz Integration:\n");
    printf("  --pcredz <file>   Parse Pcredz/Responder hashes.txt directly\n");
    printf("\nCollectors (auto-detected tools):\n");
    printf("  - Archive: unzip, tar (extracts ZIP/TAR/GZ/BZ2)\n");
    printf("  - SQLite:  sqlite3 or strings fallback\n");
    printf("  - Git:     git log -p for history secrets\n");
    printf("\nLinux collectors:\n");
    printf("  /etc/passwd, /etc/shadow, htpasswd, shell history,\n");
    printf("  NetworkManager WiFi, opasswd, /proc/environ, crontabs\n");
    printf("\nWindows collectors:\n");
    printf("  Unattend.xml, GPP cpassword, PowerShell history,\n");
    printf("  WiFi profiles, Credential Manager, .rdp/.kdbx detection\n");
    printf("\nPatterns: 60+ hashes, 70+ credentials, 25+ tokens, pwdump,\n");
    printf("  GPP, BitLocker, WPA PMKID, LM/NTLM standalone\n");
}

static void signal_handler(int sig) {
    cleanup_temp_dir();
    _exit(128 + sig);
}

int main(int argc, char* argv[]) {
    /* Register cleanup for temp files on exit/signal */
    atexit(cleanup_temp_dir);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGHUP, signal_handler);
#endif

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
        else if (strcmp(argv[i],"-q")==0||strcmp(argv[i],"--quiet")==0) opt_quiet=1;
        else if (strcmp(argv[i],"--no-collectors")==0) opt_collectors=0;
        else if (strcmp(argv[i],"--hashcat")==0) opt_hashcat_mode=1;
        else if (strcmp(argv[i],"--no-correlation")==0) opt_correlation=0;
        else if (strcmp(argv[i],"--pcredz")==0&&i+1<argc) opt_pcredz_file=argv[++i];
        else if (strcmp(argv[i],"--profile")==0&&i+1<argc) profile=argv[++i];
        else if (strcmp(argv[i],"-o")==0&&i+1<argc) outfile=argv[++i];
        else if (strcmp(argv[i],"--max-files")==0&&i+1<argc) opt_max_files=atoi(argv[++i]);
        else if (strcmp(argv[i],"--timeout")==0&&i+1<argc) opt_max_runtime=atoi(argv[++i]);
        else if (strcmp(argv[i],"--context")==0&&i+1<argc) opt_context_lines=atoi(argv[++i]);
        else if (argv[i][0]!='-'&&pathc<100) paths[pathc++]=argv[i];
    }
    
    if (outfile) { json_file = fopen(outfile, "w"); if (!json_file) { fprintf(stderr, "Error: %s\n", outfile); return 1; } opt_json = 1; }
    
    if (!opt_quiet) banner();

    /* Detect available tools */
    if (opt_collectors) {
        detect_tools();
        if (!opt_quiet)
            fprintf(stderr, "[*] Collectors: archive=%s sqlite=%s git=%s\n",
                    (has_tar || has_unzip) ? "yes" : "no",
                    (has_sqlite3 || has_strings) ? "yes" : "no",
                    has_git ? "yes" : "no");
    } else {
        if (!opt_quiet) fprintf(stderr, "[*] Collectors: disabled\n");
    }

    if (!opt_quiet) {
        fprintf(stderr, "[*] Mode: %s | Context: %d | Max: %d files\n", opt_wide?"wide":"strict", opt_context_lines, opt_max_files);
        if (profile) fprintf(stderr, "[*] Profile: %s\n", profile);
        if (opt_pcredz_file) fprintf(stderr, "[*] Pcredz mode: %s\n", opt_pcredz_file);
        fprintf(stderr, "\n");
    }
    
    /* Pcredz direct parsing mode - skip normal scanning */
    if (opt_pcredz_file) {
        parse_pcredz_file(opt_pcredz_file);
        if (opt_json) print_json(); else print_report();
        if (json_file) { fclose(json_file); fprintf(stderr, "\n[+] Saved: %s\n", outfile); }
        free(result.findings);
        free_tables();
        for (int i = 0; i < 5; i++) if (line_buffer[i]) free(line_buffer[i]);
        return 0;
    }
    
    if (profile) run_profile(profile);
    else if (pathc > 0) {
#ifndef _WIN32
        collect_shadow();
        collect_passwd();
#endif
#ifdef _WIN32
        collect_unattend_xml();
        collect_gpp_xml();
        collect_powershell_history();
        collect_wifi_profiles();
        collect_credential_manager();
#endif
        for (int i = 0; i < pathc; i++) {
            struct stat st;
            if (stat(paths[i], &st) == 0) {
                if (!opt_quiet) fprintf(stderr, "[*] %s\n", paths[i]);
                if (S_ISDIR(st.st_mode)) {
                    scan_dir(paths[i], 0);
                } else if (S_ISREG(st.st_mode)) {
                    scan_file(paths[i]);
                }
            } else {
                fprintf(stderr, "[!] Cannot access: %s\n", paths[i]);
            }
        }
    } else {
#ifndef _WIN32
        collect_shadow();
        collect_passwd();
#endif
#ifdef _WIN32
        collect_unattend_xml();
        collect_gpp_xml();
        collect_powershell_history();
        collect_wifi_profiles();
        collect_credential_manager();
        char* up = getenv("USERPROFILE"); if (up) { if (!opt_quiet) fprintf(stderr, "[*] %s\n", up); scan_dir(up, 0); }
#else
        char* h = getenv("HOME"); if (h) { if (!opt_quiet) fprintf(stderr, "[*] %s\n", h); scan_dir(h, 0); }
#endif
    }
    
    if (opt_json) print_json(); else print_report();
    if (json_file) { fclose(json_file); fprintf(stderr, "\n[+] Saved: %s\n", outfile); }
    
    free(result.findings);
    free_tables();
    for (int i = 0; i < 5; i++) if (line_buffer[i]) free(line_buffer[i]);
    return 0;
}
