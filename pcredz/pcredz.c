/*
 * pcredz.c v4.0 - Network Credential Extraction Tool
 * 
 * High-performance credential sniffer with proper TCP reassembly,
 * multi-threading, and comprehensive protocol support.
 *
 * Original Pcredz: Laurent Gaffie
 * C Rewrite: Axel
 *
 * Compile: gcc -O3 -o pcredz pcredz.c -lpcap -lpthread -lsqlite3
 * Usage:   ./pcredz -f capture.pcap -o results/
 *
 * Supported Protocols (22):
 *   Plaintext: FTP, Telnet, SMTP, POP3, IMAP, HTTP, LDAP, SNMP, Redis, MQTT
 *   Challenge: MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, VNC
 *   NTLM: SMB, HTTP, LDAP, RDP, MSSQL
 *   Kerberos: AS-REQ, AS-REP, TGS-REP
 *   Other: RDP/CredSSP, SMB2/3, TLS SNI
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <sqlite3.h>

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

#define VERSION "5.0.0"
#define MAX_STREAMS 65536
#define MAX_CREDENTIALS 131072
#define STREAM_BUFFER_SIZE 131072      /* 128KB per direction */
#define STREAM_TIMEOUT 300             /* 5 minutes */
#define HASH_TABLE_SIZE 16384
#define MAX_WORKERS 16

/* Size limits */
#define MAX_USERNAME 256
#define MAX_PASSWORD 512
#define MAX_HASH 2048
#define MAX_DOMAIN 128
#define MAX_HOSTNAME 256

/* ============================================================================
 * TYPE DEFINITIONS
 * ============================================================================ */

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_FTP, PROTO_TELNET, PROTO_SMTP, PROTO_POP3, PROTO_IMAP,
    PROTO_HTTP, PROTO_LDAP, PROTO_SNMP,
    PROTO_MYSQL, PROTO_POSTGRESQL, PROTO_MSSQL, PROTO_ORACLE,
    PROTO_MONGODB, PROTO_REDIS, PROTO_MQTT,
    PROTO_VNC, PROTO_RDP,
    PROTO_SMB, PROTO_NTLM, PROTO_KERBEROS,
    PROTO_TLS,
    PROTO_SAM, PROTO_NTDS, PROTO_DCC2, PROTO_LSA,
    PROTO_RADIUS, PROTO_SIP, PROTO_SOCKS, PROTO_WPA,
    PROTO_COUNT
} protocol_t;

typedef enum {
    CRED_PLAINTEXT = 0,
    CRED_HASH,
    CRED_CHALLENGE_RESPONSE,
    CRED_TICKET,
    CRED_CERTIFICATE
} cred_type_t;

typedef enum {
    AUTH_UNKNOWN = 0,
    AUTH_SUCCESS,
    AUTH_FAILURE
} auth_result_t;

typedef enum {
    STATE_INIT = 0,
    STATE_GREETING,
    STATE_AUTH_START,
    STATE_USER_SENT,
    STATE_CHALLENGE_SENT,
    STATE_RESPONSE_SENT,
    STATE_AUTH_COMPLETE,
    STATE_CLOSED
} stream_state_t;

/* Protocol name lookup */
static const char *proto_names[] = {
    "unknown", "ftp", "telnet", "smtp", "pop3", "imap",
    "http", "ldap", "snmp",
    "mysql", "postgresql", "mssql", "oracle",
    "mongodb", "redis", "mqtt",
    "vnc", "rdp",
    "smb", "ntlm", "kerberos",
    "tls",
    "sam", "ntds", "dcc2", "lsa",
    "radius", "sip", "socks", "wpa"
};

/* Hashcat modes */
static const int hashcat_modes[] = {
    0, 0, 0, 0, 0, 0,           /* unknown, ftp, telnet, smtp, pop3, imap */
    0, 0, 0,                     /* http, ldap, snmp */
    11200, 0, 1433, 0,          /* mysql, postgresql, mssql, oracle */
    0, 0, 0,                     /* mongodb, redis, mqtt */
    0, 5600,                     /* vnc, rdp */
    5600, 5600, 18200,          /* smb, ntlm, kerberos */
    0,                           /* tls */
    1000, 1000, 2100, 0,        /* sam, ntds, dcc2, lsa */
    0, 11400, 0, 22000          /* radius, sip, socks, wpa */
};

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/* TCP Segment for reassembly */
typedef struct tcp_segment {
    uint32_t seq;
    uint32_t len;
    uint8_t *data;
    struct tcp_segment *next;
} tcp_segment_t;

/* TCP Stream with full reassembly */
typedef struct tcp_stream {
    /* Connection tuple */
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    
    /* Sequence tracking */
    uint32_t client_isn;        /* Initial sequence number */
    uint32_t server_isn;
    uint32_t client_next_seq;   /* Expected next seq */
    uint32_t server_next_seq;
    
    /* Reassembly buffers */
    uint8_t *client_buffer;
    uint8_t *server_buffer;
    size_t client_len;
    size_t server_len;
    
    /* Out-of-order segments */
    tcp_segment_t *client_ooo;
    tcp_segment_t *server_ooo;
    
    /* Protocol state machine */
    protocol_t protocol;
    stream_state_t state;
    time_t last_activity;
    time_t created;
    
    /* Protocol-specific context */
    union {
        struct {
            char username[MAX_USERNAME];
            uint8_t auth_method;    /* 0=USER/PASS, 1=AUTH LOGIN, 2=AUTH PLAIN */
        } mail;  /* FTP, POP3, SMTP, IMAP */
        
        struct {
            uint8_t challenge[8];
            uint32_t flags;
            int version;            /* 1 or 2 */
        } ntlm;
        
        struct {
            uint8_t salt[20];
            uint8_t auth_plugin;
            char username[MAX_USERNAME];
        } mysql;
        
        struct {
            uint8_t salt[4];
            char username[MAX_USERNAME];
            uint8_t auth_type;      /* 0=clear, 3=md5, 5=md5+salt, 10=scram */
        } postgresql;
        
        struct {
            uint8_t challenge[16];
            uint8_t response[16];
        } vnc;
        
        struct {
            uint8_t dialect;        /* SMB1=1, SMB2=2, SMB3=3 */
            uint64_t session_id;
            uint8_t signing;
        } smb;
        
        struct {
            uint8_t version;        /* 4 or 5 */
            char realm[MAX_DOMAIN];
            char cname[MAX_USERNAME];
        } kerberos;
        
        struct {
            char server_name[MAX_HOSTNAME];  /* SNI */
        } tls;
        
        struct {
            char client_id[128];
        } mqtt;
        
    } ctx;
    
    /* Hash chain */
    struct tcp_stream *next;
    
} tcp_stream_t;

/* Extracted credential */
typedef struct credential {
    uint32_t id;
    protocol_t protocol;
    cred_type_t type;
    auth_result_t result;
    
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char hash[MAX_HASH];
    char domain[MAX_DOMAIN];
    char hostname[MAX_HOSTNAME];
    
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    
    int hashcat_mode;
    float confidence;
    time_t timestamp;
    uint32_t count;
    
    struct credential *next;
} credential_t;

/* Statistics */
typedef struct {
    uint64_t packets_total;
    uint64_t packets_tcp;
    uint64_t packets_udp;
    uint64_t bytes_total;
    uint64_t tcp_sessions;
    uint64_t tcp_reassembled;
    uint64_t credentials_total;
    uint64_t credentials_unique;
    uint64_t proto_counts[PROTO_COUNT];
    time_t start_time;
    time_t end_time;
} stats_t;

/* Global state */
typedef struct {
    tcp_stream_t *streams[HASH_TABLE_SIZE];
    credential_t *creds[HASH_TABLE_SIZE];
    
    pthread_mutex_t stream_lock;
    pthread_mutex_t cred_lock;
    pthread_mutex_t stats_lock;
    
    stats_t stats;
    uint32_t next_cred_id;
    uint32_t stream_count;
    uint32_t cred_count;
    
    sqlite3 *db;
    pcap_t *pcap_handle;
    volatile sig_atomic_t stop;
    
} global_state_t;

static global_state_t G = {0};

/* Options */
static struct {
    char *input_file;
    char *interface;
    char *output_dir;
    char *bpf_filter;
    char *responder_dir;
    char *secretsdump_file;
    
    float min_confidence;
    int capture_timeout;
    int num_workers;
    
    bool verbose;
    bool json_output;
    bool csv_output;
    bool hashcat_output;
    bool hashscan_output;
    bool sqlite_output;
    bool no_banner;
    bool no_progress;
    
} opts = {
    .output_dir = "./output",
    .min_confidence = 0.3f,
    .num_workers = 4,
    .json_output = true,
    .csv_output = true,
    .hashcat_output = true,
    .hashscan_output = true,
    .sqlite_output = true
};

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/* FNV-1a hash */
static inline uint32_t fnv1a(const void *data, size_t len) {
    uint32_t hash = 2166136261u;
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= 16777619u;
    }
    return hash;
}

/* Stream hash */
static inline uint32_t stream_hash(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp) {
    uint32_t data[4] = {sip, dip, sp, dp};
    return fnv1a(data, sizeof(data)) % HASH_TABLE_SIZE;
}

/* Credential hash for dedup */
static inline uint32_t cred_hash(protocol_t p, const char *u, const char *pw, const char *h) {
    uint32_t hash = fnv1a(&p, sizeof(p));
    if (u && *u) hash ^= fnv1a(u, strlen(u));
    if (pw && *pw) hash ^= fnv1a(pw, strlen(pw));
    if (h && *h) hash ^= fnv1a(h, strlen(h));
    return hash % HASH_TABLE_SIZE;
}

/* IP to string */
static void ip4_str(uint32_t ip, char *buf, size_t len) {
    struct in_addr a = {.s_addr = ip};
    inet_ntop(AF_INET, &a, buf, len);
}

/* Hex encode */
static void hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2] = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[len*2] = '\0';
}

/* Safe string copy */
static void safe_strcpy(char *dst, const char *src, size_t max) {
    if (!src) { dst[0] = '\0'; return; }
    size_t len = strlen(src);
    if (len >= max) len = max - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* JSON escape */
static void json_escape(const char *src, char *dst, size_t max) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < max - 6; i++) {
        switch (src[i]) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
            default:
                if ((unsigned char)src[i] < 32)
                    j += snprintf(dst+j, max-j, "\\u%04x", (unsigned char)src[i]);
                else
                    dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

/* Trim whitespace */
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) e--;
    e[1] = '\0';
    return s;
}

/* Create directory */
static void mkdir_p(const char *path) {
    char tmp[512];
    safe_strcpy(tmp, path, sizeof(tmp));
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* Base64 decode */
static const uint8_t b64_table[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
    ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
    ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
    ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
};

static size_t b64_decode(const char *in, size_t len, uint8_t *out, size_t max) {
    size_t out_len = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len && out_len < max; i++) {
        char c = in[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        acc = (acc << 6) | b64_table[(uint8_t)c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_len++] = (acc >> bits) & 0xff;
        }
    }
    return out_len;
}

/* ============================================================================
 * SIGNAL HANDLING
 * ============================================================================ */

static void signal_handler(int sig) {
    (void)sig;
    G.stop = 1;
    if (G.pcap_handle) pcap_breakloop(G.pcap_handle);
    fprintf(stderr, "\n[!] Stopping...\n");
}

/* ============================================================================
 * TCP STREAM MANAGEMENT
 * ============================================================================ */

static tcp_stream_t *stream_find(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp) {
    uint32_t h = stream_hash(sip, dip, sp, dp);
    
    for (tcp_stream_t *s = G.streams[h]; s; s = s->next) {
        if ((s->src_ip == sip && s->dst_ip == dip && s->src_port == sp && s->dst_port == dp) ||
            (s->src_ip == dip && s->dst_ip == sip && s->src_port == dp && s->dst_port == sp)) {
            return s;
        }
    }
    return NULL;
}

static protocol_t detect_protocol(uint16_t port) {
    switch (port) {
        case 21: return PROTO_FTP;
        case 23: return PROTO_TELNET;
        case 25: case 587: case 465: return PROTO_SMTP;
        case 110: case 995: return PROTO_POP3;
        case 143: case 993: return PROTO_IMAP;
        case 80: case 8080: case 8000: case 8888: return PROTO_HTTP;
        case 443: case 8443: return PROTO_TLS;
        case 389: case 636: return PROTO_LDAP;
        case 161: case 162: return PROTO_SNMP;
        case 3306: return PROTO_MYSQL;
        case 5432: return PROTO_POSTGRESQL;
        case 1433: case 1434: return PROTO_MSSQL;
        case 1521: return PROTO_ORACLE;
        case 27017: case 27018: return PROTO_MONGODB;
        case 6379: return PROTO_REDIS;
        case 1883: case 8883: return PROTO_MQTT;
        case 3389: return PROTO_RDP;
        case 445: case 139: return PROTO_SMB;
        case 88: case 464: return PROTO_KERBEROS;
        case 1812: case 1813: return PROTO_RADIUS;
        case 5060: case 5061: return PROTO_SIP;
        case 1080: return PROTO_SOCKS;
        default:
            if (port >= 5900 && port <= 5999) return PROTO_VNC;
            return PROTO_UNKNOWN;
    }
}

static tcp_stream_t *stream_create(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                                    uint32_t seq, protocol_t proto) {
    tcp_stream_t *s = calloc(1, sizeof(tcp_stream_t));
    if (!s) return NULL;
    
    s->src_ip = sip;
    s->dst_ip = dip;
    s->src_port = sp;
    s->dst_port = dp;
    s->client_isn = seq;
    s->client_next_seq = seq + 1;
    s->protocol = proto;
    s->state = STATE_INIT;
    s->created = s->last_activity = time(NULL);
    
    /* Allocate buffers */
    s->client_buffer = malloc(STREAM_BUFFER_SIZE);
    s->server_buffer = malloc(STREAM_BUFFER_SIZE);
    if (!s->client_buffer || !s->server_buffer) {
        free(s->client_buffer);
        free(s->server_buffer);
        free(s);
        return NULL;
    }
    
    /* Insert into hash table */
    uint32_t h = stream_hash(sip, dip, sp, dp);
    pthread_mutex_lock(&G.stream_lock);
    s->next = G.streams[h];
    G.streams[h] = s;
    G.stream_count++;
    G.stats.tcp_sessions++;
    pthread_mutex_unlock(&G.stream_lock);
    
    return s;
}

static void stream_free(tcp_stream_t *s) {
    /* Free OOO segments */
    tcp_segment_t *seg = s->client_ooo;
    while (seg) {
        tcp_segment_t *next = seg->next;
        free(seg->data);
        free(seg);
        seg = next;
    }
    seg = s->server_ooo;
    while (seg) {
        tcp_segment_t *next = seg->next;
        free(seg->data);
        free(seg);
        seg = next;
    }
    
    free(s->client_buffer);
    free(s->server_buffer);
    free(s);
}

/* Insert segment in order */
static void insert_ooo_segment(tcp_segment_t **head, uint32_t seq, const uint8_t *data, size_t len) {
    tcp_segment_t *seg = malloc(sizeof(tcp_segment_t));
    if (!seg) return;
    
    seg->seq = seq;
    seg->len = len;
    seg->data = malloc(len);
    if (!seg->data) { free(seg); return; }
    memcpy(seg->data, data, len);
    
    /* Insert sorted by seq */
    tcp_segment_t **pp = head;
    while (*pp && (*pp)->seq < seq) {
        pp = &(*pp)->next;
    }
    seg->next = *pp;
    *pp = seg;
}

/* Try to reassemble from OOO queue */
static void try_reassemble(tcp_stream_t *s, bool is_client) {
    tcp_segment_t **head = is_client ? &s->client_ooo : &s->server_ooo;
    uint32_t *next_seq = is_client ? &s->client_next_seq : &s->server_next_seq;
    uint8_t *buffer = is_client ? s->client_buffer : s->server_buffer;
    size_t *buf_len = is_client ? &s->client_len : &s->server_len;
    
    while (*head) {
        tcp_segment_t *seg = *head;
        
        if (seg->seq == *next_seq) {
            /* This segment is next in order */
            size_t space = STREAM_BUFFER_SIZE - *buf_len;
            size_t copy = seg->len < space ? seg->len : space;
            
            if (copy > 0) {
                memcpy(buffer + *buf_len, seg->data, copy);
                *buf_len += copy;
                *next_seq += copy;
                G.stats.tcp_reassembled++;
            }
            
            *head = seg->next;
            free(seg->data);
            free(seg);
        }
        else if ((int32_t)(seg->seq - *next_seq) < 0) {
            /* Already have this data (retransmit), skip */
            *head = seg->next;
            free(seg->data);
            free(seg);
        }
        else {
            /* Gap in sequence, stop */
            break;
        }
    }
}

/* ============================================================================
 * CREDENTIAL MANAGEMENT
 * ============================================================================ */

static credential_t *cred_add(protocol_t proto, cred_type_t type,
                              const char *user, const char *pass, const char *hash,
                              float confidence, tcp_stream_t *s) {
    if (confidence < opts.min_confidence) return NULL;
    
    /* Check for duplicate */
    uint32_t h = cred_hash(proto, user, pass, hash);
    
    pthread_mutex_lock(&G.cred_lock);
    
    for (credential_t *c = G.creds[h]; c; c = c->next) {
        if (c->protocol == proto &&
            strcmp(c->username, user ? user : "") == 0 &&
            strcmp(c->password, pass ? pass : "") == 0 &&
            strcmp(c->hash, hash ? hash : "") == 0) {
            c->count++;
            c->timestamp = time(NULL);
            pthread_mutex_unlock(&G.cred_lock);
            return c;
        }
    }
    
    /* Create new */
    credential_t *c = calloc(1, sizeof(credential_t));
    if (!c) {
        pthread_mutex_unlock(&G.cred_lock);
        return NULL;
    }
    
    c->id = ++G.next_cred_id;
    c->protocol = proto;
    c->type = type;
    c->hashcat_mode = hashcat_modes[proto];
    c->confidence = confidence;
    c->timestamp = time(NULL);
    c->count = 1;
    
    safe_strcpy(c->username, user ? user : "", MAX_USERNAME);
    safe_strcpy(c->password, pass ? pass : "", MAX_PASSWORD);
    safe_strcpy(c->hash, hash ? hash : "", MAX_HASH);
    
    if (s) {
        c->src_ip = s->src_ip;
        c->dst_ip = s->dst_ip;
        c->src_port = s->src_port;
        c->dst_port = s->dst_port;
    }
    
    c->next = G.creds[h];
    G.creds[h] = c;
    G.cred_count++;
    G.stats.credentials_total++;
    G.stats.credentials_unique++;
    G.stats.proto_counts[proto]++;
    
    pthread_mutex_unlock(&G.cred_lock);
    
    if (opts.verbose) {
        printf("[+] %s: %s", proto_names[proto], user ? user : "(empty)");
        if (pass && *pass) printf(":%s", pass);
        if (hash && *hash) printf(" [hash]");
        printf("\n");
    }
    
    return c;
}

/* ============================================================================
 * PROTOCOL PARSERS
 * ============================================================================ */

/* FTP: USER xxx / PASS xxx */
static void parse_ftp(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 5) return;
    
    char line[512];
    size_t ll = len < 511 ? len : 511;
    memcpy(line, data, ll);
    line[ll] = '\0';
    char *t = trim(line);
    
    if (is_client) {
        if (strncasecmp(t, "USER ", 5) == 0) {
            safe_strcpy(s->ctx.mail.username, t + 5, MAX_USERNAME);
            s->state = STATE_USER_SENT;
        }
        else if (strncasecmp(t, "PASS ", 5) == 0 && s->state == STATE_USER_SENT) {
            cred_add(PROTO_FTP, CRED_PLAINTEXT, s->ctx.mail.username, t + 5, NULL, 0.95f, s);
            s->state = STATE_AUTH_COMPLETE;
        }
    }
    else {
        if (strncmp(t, "230 ", 4) == 0) {
            /* Login OK - could update auth result */
        }
    }
}

/* Telnet: login/password prompts */
static void parse_telnet(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    /* Skip IAC sequences */
    size_t start = 0;
    while (start < len && data[start] == 0xFF && start + 2 < len) {
        start += 3;
    }
    if (start >= len) return;
    
    const char *text = (const char*)(data + start);
    size_t text_len = len - start;
    
    if (!is_client) {
        if (memmem(text, text_len, "login:", 6) || memmem(text, text_len, "Login:", 6) ||
            memmem(text, text_len, "Username:", 9)) {
            s->state = STATE_AUTH_START;
        }
        else if (memmem(text, text_len, "Password:", 9) || memmem(text, text_len, "password:", 9)) {
            s->state = STATE_USER_SENT;
        }
    }
    else {
        char input[256];
        size_t il = text_len < 255 ? text_len : 255;
        memcpy(input, text, il);
        input[il] = '\0';
        char *nl = strpbrk(input, "\r\n");
        if (nl) *nl = '\0';
        
        if (s->state == STATE_AUTH_START && input[0]) {
            safe_strcpy(s->ctx.mail.username, input, MAX_USERNAME);
            s->state = STATE_USER_SENT;
        }
        else if (s->state == STATE_USER_SENT && input[0] && s->ctx.mail.username[0]) {
            cred_add(PROTO_TELNET, CRED_PLAINTEXT, s->ctx.mail.username, input, NULL, 0.85f, s);
            s->state = STATE_AUTH_COMPLETE;
        }
    }
}

/* POP3: USER/PASS or APOP */
static void parse_pop3(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 5) return;
    
    char line[512];
    size_t ll = len < 511 ? len : 511;
    memcpy(line, data, ll);
    line[ll] = '\0';
    char *t = trim(line);
    
    if (is_client) {
        if (strncasecmp(t, "USER ", 5) == 0) {
            safe_strcpy(s->ctx.mail.username, t + 5, MAX_USERNAME);
            s->state = STATE_USER_SENT;
        }
        else if (strncasecmp(t, "PASS ", 5) == 0 && s->state == STATE_USER_SENT) {
            cred_add(PROTO_POP3, CRED_PLAINTEXT, s->ctx.mail.username, t + 5, NULL, 0.95f, s);
            s->state = STATE_AUTH_COMPLETE;
        }
        else if (strncasecmp(t, "APOP ", 5) == 0) {
            char *sp = strchr(t + 5, ' ');
            if (sp) {
                *sp = '\0';
                char hash[256];
                snprintf(hash, sizeof(hash), "APOP:%s", sp + 1);
                cred_add(PROTO_POP3, CRED_HASH, t + 5, NULL, hash, 0.9f, s);
            }
        }
    }
}

/* SMTP: AUTH LOGIN / AUTH PLAIN */
static void parse_smtp(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 4) return;
    
    char line[512];
    size_t ll = len < 511 ? len : 511;
    memcpy(line, data, ll);
    line[ll] = '\0';
    char *t = trim(line);
    
    if (is_client) {
        if (strncasecmp(t, "AUTH LOGIN", 10) == 0) {
            s->ctx.mail.auth_method = 1;
            s->state = STATE_AUTH_START;
        }
        else if (strncasecmp(t, "AUTH PLAIN ", 11) == 0) {
            uint8_t dec[256];
            size_t dl = b64_decode(t + 11, strlen(t + 11), dec, sizeof(dec) - 1);
            dec[dl] = '\0';
            /* Format: \0user\0pass */
            char *user = NULL, *pass = NULL;
            for (size_t i = 0; i < dl; i++) {
                if (dec[i] == '\0') {
                    if (!user && i + 1 < dl) user = (char*)dec + i + 1;
                    else if (user && !pass && i + 1 < dl) pass = (char*)dec + i + 1;
                }
            }
            if (user && pass) {
                cred_add(PROTO_SMTP, CRED_PLAINTEXT, user, pass, NULL, 0.95f, s);
            }
        }
        else if (s->state == STATE_AUTH_START) {
            uint8_t dec[256];
            size_t dl = b64_decode(t, strlen(t), dec, sizeof(dec) - 1);
            if (dl > 0) {
                dec[dl] = '\0';
                safe_strcpy(s->ctx.mail.username, (char*)dec, MAX_USERNAME);
                s->state = STATE_USER_SENT;
            }
        }
        else if (s->state == STATE_USER_SENT) {
            uint8_t dec[256];
            size_t dl = b64_decode(t, strlen(t), dec, sizeof(dec) - 1);
            if (dl > 0 && s->ctx.mail.username[0]) {
                dec[dl] = '\0';
                cred_add(PROTO_SMTP, CRED_PLAINTEXT, s->ctx.mail.username, (char*)dec, NULL, 0.95f, s);
                s->state = STATE_AUTH_COMPLETE;
            }
        }
    }
}

/* IMAP: LOGIN user pass */
static void parse_imap(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 10) return;
    
    char line[512];
    size_t ll = len < 511 ? len : 511;
    memcpy(line, data, ll);
    line[ll] = '\0';
    
    /* Find LOGIN command */
    char *login = strcasestr(line, " LOGIN ");
    if (!login) return;
    login += 7;
    
    char user[MAX_USERNAME] = {0}, pass[MAX_PASSWORD] = {0};
    char *p = login;
    
    /* Parse user (may be quoted) */
    if (*p == '"') {
        p++;
        char *end = strchr(p, '"');
        if (end) {
            size_t ul = end - p;
            if (ul < MAX_USERNAME) memcpy(user, p, ul);
            p = end + 1;
        }
    } else {
        char *sp = strchr(p, ' ');
        if (sp) {
            size_t ul = sp - p;
            if (ul < MAX_USERNAME) memcpy(user, p, ul);
            p = sp;
        }
    }
    
    while (*p == ' ') p++;
    
    /* Parse pass */
    if (*p == '"') {
        p++;
        char *end = strchr(p, '"');
        if (end) {
            size_t pl = end - p;
            if (pl < MAX_PASSWORD) memcpy(pass, p, pl);
        }
    } else {
        char *end = strpbrk(p, "\r\n ");
        if (end) {
            size_t pl = end - p;
            if (pl < MAX_PASSWORD) memcpy(pass, p, pl);
        } else {
            safe_strcpy(pass, p, MAX_PASSWORD);
        }
    }
    
    if (user[0] && pass[0]) {
        cred_add(PROTO_IMAP, CRED_PLAINTEXT, user, pass, NULL, 0.95f, s);
    }
}

/* HTTP: Basic Auth, Digest, Form POST */
static void parse_http(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 20) return;
    
    /* Basic Auth */
    const char *auth = memmem(data, len, "Authorization: Basic ", 21);
    if (!auth) auth = memmem(data, len, "authorization: basic ", 21);
    if (auth) {
        auth += 21;
        const char *end = memchr(auth, '\r', len - (auth - (const char*)data));
        if (!end) end = memchr(auth, '\n', len - (auth - (const char*)data));
        if (end) {
            uint8_t dec[256];
            size_t dl = b64_decode(auth, end - auth, dec, sizeof(dec) - 1);
            dec[dl] = '\0';
            char *colon = strchr((char*)dec, ':');
            if (colon) {
                *colon = '\0';
                cred_add(PROTO_HTTP, CRED_PLAINTEXT, (char*)dec, colon + 1, NULL, 0.95f, s);
            }
        }
        return;
    }
    
    /* Digest Auth */
    auth = memmem(data, len, "Authorization: Digest ", 22);
    if (!auth) auth = memmem(data, len, "authorization: digest ", 22);
    if (auth) {
        auth += 22;
        const char *end = memmem(auth, len - (auth - (const char*)data), "\r\n", 2);
        if (!end) end = (const char*)data + len;
        
        char user[MAX_USERNAME] = {0};
        char response[64] = {0};
        char uri[256] = {0};
        char nonce[128] = {0};
        char realm[128] = {0};
        
        /* Parse fields */
        const char *p = auth;
        while (p < end) {
            while (p < end && (*p == ' ' || *p == ',')) p++;
            if (p >= end) break;
            
            #define PARSE_FIELD(name, buf) \
                if (strncmp(p, name "=\"", strlen(name)+2) == 0) { \
                    p += strlen(name) + 2; \
                    const char *q = strchr(p, '"'); \
                    if (q && q - p < (int)sizeof(buf)) { \
                        memcpy(buf, p, q - p); \
                        buf[q - p] = '\0'; \
                        p = q + 1; \
                        continue; \
                    } \
                }
            
            PARSE_FIELD("username", user)
            PARSE_FIELD("response", response)
            PARSE_FIELD("uri", uri)
            PARSE_FIELD("nonce", nonce)
            PARSE_FIELD("realm", realm)
            #undef PARSE_FIELD
            
            p++;
        }
        
        if (user[0] && response[0]) {
            char hash[512];
            snprintf(hash, sizeof(hash), "$digest$%s$%s$%s$%s$%s",
                     user, realm, nonce, uri, response);
            cred_add(PROTO_HTTP, CRED_CHALLENGE_RESPONSE, user, NULL, hash, 0.9f, s);
        }
        return;
    }
    
    /* Form POST */
    if (memmem(data, len, "POST ", 5) || memmem(data, len, "post ", 5)) {
        const char *body = memmem(data, len, "\r\n\r\n", 4);
        if (body) {
            body += 4;
            size_t body_len = len - (body - (const char*)data);
            
            const char *patterns[][2] = {
                {"username=", "password="},
                {"user=", "pass="},
                {"login=", "password="},
                {"email=", "password="},
                {"uname=", "passwd="},
                {NULL, NULL}
            };
            
            for (int i = 0; patterns[i][0]; i++) {
                const char *u = memmem(body, body_len, patterns[i][0], strlen(patterns[i][0]));
                const char *p = memmem(body, body_len, patterns[i][1], strlen(patterns[i][1]));
                
                if (u && p) {
                    u += strlen(patterns[i][0]);
                    p += strlen(patterns[i][1]);
                    
                    const char *u_end = strpbrk(u, "&\r\n ");
                    const char *p_end = strpbrk(p, "&\r\n ");
                    if (!u_end) u_end = body + body_len;
                    if (!p_end) p_end = body + body_len;
                    
                    char user[MAX_USERNAME] = {0}, pass[MAX_PASSWORD] = {0};
                    size_t ul = u_end - u, pl = p_end - p;
                    if (ul > 0 && ul < MAX_USERNAME && pl > 0 && pl < MAX_PASSWORD) {
                        memcpy(user, u, ul);
                        memcpy(pass, p, pl);
                        cred_add(PROTO_HTTP, CRED_PLAINTEXT, user, pass, NULL, 0.8f, s);
                    }
                    break;
                }
            }
        }
    }
}

/* MySQL Native Auth */
static void parse_mysql(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 5) return;
    
    if (!is_client) {
        /* Server greeting - protocol 10 */
        if (len > 40 && data[4] == 0x0a) {
            const uint8_t *p = memchr(data + 5, 0, len - 5);
            if (p && p + 20 < data + len) {
                /* Salt part 1 (8 bytes) */
                memcpy(s->ctx.mysql.salt, p + 1, 8);
                /* Salt part 2 after capabilities */
                if (p + 32 < data + len) {
                    memcpy(s->ctx.mysql.salt + 8, p + 32, 12);
                }
                s->state = STATE_GREETING;
            }
        }
    }
    else if (s->state == STATE_GREETING && len > 36) {
        /* Client auth response */
        const uint8_t *user_start = data + 36;
        const uint8_t *user_end = memchr(user_start, 0, len - 36);
        if (user_end) {
            size_t ulen = user_end - user_start;
            if (ulen < MAX_USERNAME) {
                memcpy(s->ctx.mysql.username, user_start, ulen);
                s->ctx.mysql.username[ulen] = '\0';
                
                const uint8_t *auth = user_end + 1;
                if (auth < data + len) {
                    size_t auth_len = *auth;
                    if (auth_len > 0 && auth_len < 32 && auth + 1 + auth_len <= data + len) {
                        char salt_hex[64], resp_hex[64];
                        hex_encode(s->ctx.mysql.salt, 20, salt_hex);
                        hex_encode(auth + 1, auth_len, resp_hex);
                        
                        char hash[256];
                        snprintf(hash, sizeof(hash), "$mysqlna$%s$%s", salt_hex, resp_hex);
                        cred_add(PROTO_MYSQL, CRED_CHALLENGE_RESPONSE, 
                                s->ctx.mysql.username, NULL, hash, 0.9f, s);
                    }
                }
            }
        }
    }
}

/* PostgreSQL */
static void parse_postgresql(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 5) return;
    
    if (!is_client) {
        /* AuthenticationMD5Password: R + len + type(5) + salt(4) */
        if (data[0] == 'R' && len >= 13) {
            uint32_t auth_type = ntohl(*(uint32_t*)(data + 5));
            if (auth_type == 5) {
                memcpy(s->ctx.postgresql.salt, data + 9, 4);
                s->ctx.postgresql.auth_type = 5;
                s->state = STATE_CHALLENGE_SENT;
            }
            else if (auth_type == 3) {
                s->ctx.postgresql.auth_type = 3;  /* Cleartext */
                s->state = STATE_CHALLENGE_SENT;
            }
        }
    }
    else {
        /* Password message (p) or Startup message */
        if (data[0] == 'p' && len > 5 && s->state == STATE_CHALLENGE_SENT) {
            const char *pass = (const char*)(data + 5);
            
            if (s->ctx.postgresql.auth_type == 5 && strncmp(pass, "md5", 3) == 0) {
                char hash[256];
                snprintf(hash, sizeof(hash), "%s", pass);
                cred_add(PROTO_POSTGRESQL, CRED_HASH, 
                        s->ctx.postgresql.username, NULL, hash, 0.9f, s);
            }
            else {
                cred_add(PROTO_POSTGRESQL, CRED_PLAINTEXT,
                        s->ctx.postgresql.username, pass, NULL, 0.95f, s);
            }
            s->state = STATE_AUTH_COMPLETE;
        }
        else if (len > 8 && data[0] != 'p') {
            /* Startup message - extract user */
            const char *p = (const char*)(data + 8);
            const char *end = (const char*)(data + len);
            while (p < end - 1) {
                if (strcmp(p, "user") == 0) {
                    p += 5;
                    if (p < end) {
                        safe_strcpy(s->ctx.postgresql.username, p, MAX_USERNAME);
                    }
                    break;
                }
                p += strlen(p) + 1;
                if (p < end) p += strlen(p) + 1;
            }
        }
    }
}

/* MSSQL TDS */
static void parse_mssql(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 50) return;
    
    /* TDS7 Login packet (0x10) */
    if (data[0] != 0x10) return;
    
    /* Offsets in TDS7 login */
    uint16_t user_off = *(uint16_t*)(data + 48);
    uint16_t user_len = *(uint16_t*)(data + 50);
    uint16_t pass_off = *(uint16_t*)(data + 52);
    uint16_t pass_len = *(uint16_t*)(data + 54);
    
    if (8 + user_off + user_len * 2 > len || 8 + pass_off + pass_len * 2 > len) return;
    
    /* Username (UTF-16LE) */
    char username[MAX_USERNAME] = {0};
    for (size_t i = 0; i < user_len && i < MAX_USERNAME - 1; i++) {
        username[i] = data[8 + user_off + i * 2];
    }
    
    /* Password (XOR 0xA5, nibble swap) */
    char password[MAX_PASSWORD] = {0};
    for (size_t i = 0; i < pass_len && i < MAX_PASSWORD - 1; i++) {
        uint8_t b = data[8 + pass_off + i * 2];
        b ^= 0xA5;
        b = ((b >> 4) | (b << 4)) & 0xFF;
        password[i] = b;
    }
    
    if (username[0]) {
        cred_add(PROTO_MSSQL, CRED_PLAINTEXT, username, password, NULL, 0.95f, s);
    }
}

/* Redis */
static void parse_redis(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 6) return;
    
    char line[512];
    size_t ll = len < 511 ? len : 511;
    memcpy(line, data, ll);
    line[ll] = '\0';
    
    if (strncasecmp(line, "AUTH ", 5) == 0) {
        char *args = line + 5;
        char *sp = strchr(args, ' ');
        
        if (sp) {
            /* Redis 6+ ACL: AUTH user pass */
            *sp = '\0';
            char *pass = trim(sp + 1);
            char *user = trim(args);
            cred_add(PROTO_REDIS, CRED_PLAINTEXT, user, pass, NULL, 0.95f, s);
        }
        else {
            /* Legacy: AUTH pass */
            char *pass = trim(args);
            char *nl = strpbrk(pass, "\r\n");
            if (nl) *nl = '\0';
            cred_add(PROTO_REDIS, CRED_PLAINTEXT, "default", pass, NULL, 0.95f, s);
        }
    }
    /* RESP format: *N\r\n$4\r\nAUTH\r\n... */
    else if (data[0] == '*' && memmem(data, len, "AUTH", 4)) {
        const char *auth = memmem(line, len, "AUTH", 4);
        if (auth) {
            auth += 4;
            while (*auth == '\r' || *auth == '\n') auth++;
            if (*auth == '$') {
                const char *nl = strchr(auth, '\n');
                if (nl) {
                    nl++;
                    const char *end = strpbrk(nl, "\r\n");
                    if (end) {
                        char pass[MAX_PASSWORD];
                        size_t pl = end - nl;
                        if (pl < MAX_PASSWORD) {
                            memcpy(pass, nl, pl);
                            pass[pl] = '\0';
                            cred_add(PROTO_REDIS, CRED_PLAINTEXT, "default", pass, NULL, 0.9f, s);
                        }
                    }
                }
            }
        }
    }
}

/* MongoDB connection string */
static void parse_mongodb(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 20) return;
    
    /* mongodb://user:pass@host */
    const char *uri = memmem(data, len, "mongodb://", 10);
    if (uri) {
        uri += 10;
        const char *colon = strchr(uri, ':');
        const char *at = strchr(uri, '@');
        
        if (colon && at && colon < at) {
            char user[MAX_USERNAME], pass[MAX_PASSWORD];
            size_t ul = colon - uri, pl = at - colon - 1;
            
            if (ul < MAX_USERNAME && pl < MAX_PASSWORD) {
                memcpy(user, uri, ul); user[ul] = '\0';
                memcpy(pass, colon + 1, pl); pass[pl] = '\0';
                cred_add(PROTO_MONGODB, CRED_PLAINTEXT, user, pass, NULL, 0.95f, s);
            }
        }
    }
}

/* MQTT CONNECT */
static void parse_mqtt(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 10) return;
    
    /* CONNECT packet type = 0x10 */
    if ((data[0] >> 4) != 1) return;
    
    /* Decode remaining length */
    size_t off = 1;
    uint32_t rem_len = 0, mult = 1;
    while (off < len) {
        uint8_t b = data[off++];
        rem_len += (b & 0x7F) * mult;
        mult *= 128;
        if (!(b & 0x80)) break;
    }
    
    if (off + 6 > len) return;
    
    /* Protocol name length */
    uint16_t proto_len = ntohs(*(uint16_t*)(data + off));
    off += 2 + proto_len;
    if (off >= len) return;
    
    uint8_t proto_level = data[off++];
    if (off >= len) return;
    
    uint8_t flags = data[off++];
    bool has_user = (flags & 0x80) != 0;
    bool has_pass = (flags & 0x40) != 0;
    
    off += 2;  /* Keep alive */
    
    /* MQTT 5.0 properties */
    if (proto_level == 5 && off < len) {
        uint32_t props_len = data[off++];
        off += props_len;
    }
    
    if (off + 2 > len) return;
    
    /* Client ID */
    uint16_t cid_len = ntohs(*(uint16_t*)(data + off));
    off += 2 + cid_len;
    
    /* Skip will */
    if (flags & 0x04) {
        if (off + 2 <= len) {
            uint16_t wt_len = ntohs(*(uint16_t*)(data + off));
            off += 2 + wt_len;
        }
        if (off + 2 <= len) {
            uint16_t wm_len = ntohs(*(uint16_t*)(data + off));
            off += 2 + wm_len;
        }
    }
    
    char user[MAX_USERNAME] = {0}, pass[MAX_PASSWORD] = {0};
    
    if (has_user && off + 2 <= len) {
        uint16_t ul = ntohs(*(uint16_t*)(data + off));
        off += 2;
        if (off + ul <= len && ul < MAX_USERNAME) {
            memcpy(user, data + off, ul);
            off += ul;
        }
    }
    
    if (has_pass && off + 2 <= len) {
        uint16_t pl = ntohs(*(uint16_t*)(data + off));
        off += 2;
        if (off + pl <= len && pl < MAX_PASSWORD) {
            memcpy(pass, data + off, pl);
        }
    }
    
    if (user[0] || pass[0]) {
        cred_add(PROTO_MQTT, CRED_PLAINTEXT, user, pass, NULL, 0.95f, s);
    }
}

/* VNC Challenge-Response */
static void parse_vnc(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client) {
        if (len == 16 && s->state != STATE_CHALLENGE_SENT) {
            memcpy(s->ctx.vnc.challenge, data, 16);
            s->state = STATE_CHALLENGE_SENT;
        }
    }
    else {
        if (len == 16 && s->state == STATE_CHALLENGE_SENT) {
            memcpy(s->ctx.vnc.response, data, 16);
            
            char chall_hex[64], resp_hex[64];
            hex_encode(s->ctx.vnc.challenge, 16, chall_hex);
            hex_encode(s->ctx.vnc.response, 16, resp_hex);
            
            char hash[256];
            snprintf(hash, sizeof(hash), "$vnc$*%s*%s", chall_hex, resp_hex);
            cred_add(PROTO_VNC, CRED_CHALLENGE_RESPONSE, NULL, NULL, hash, 0.9f, s);
            s->state = STATE_AUTH_COMPLETE;
        }
    }
}

/* NTLM (embedded in various protocols) */
static void parse_ntlm(tcp_stream_t *s, const uint8_t *data, size_t len) {
    const uint8_t *ntlm = memmem(data, len, "NTLMSSP\x00", 8);
    if (!ntlm || ntlm + 12 > data + len) return;
    
    uint32_t msg_type = *(uint32_t*)(ntlm + 8);
    
    if (msg_type == 2 && ntlm + 32 <= data + len) {
        /* Type 2: Challenge */
        memcpy(s->ctx.ntlm.challenge, ntlm + 24, 8);
        s->ctx.ntlm.flags = *(uint32_t*)(ntlm + 20);
        s->state = STATE_CHALLENGE_SENT;
    }
    else if (msg_type == 3 && ntlm + 64 <= data + len) {
        /* Type 3: Authenticate */
        uint16_t lm_len = *(uint16_t*)(ntlm + 12);
        uint16_t lm_off = *(uint16_t*)(ntlm + 16);
        uint16_t nt_len = *(uint16_t*)(ntlm + 20);
        uint16_t nt_off = *(uint16_t*)(ntlm + 24);
        uint16_t dom_len = *(uint16_t*)(ntlm + 28);
        uint16_t dom_off = *(uint16_t*)(ntlm + 32);
        uint16_t user_len = *(uint16_t*)(ntlm + 36);
        uint16_t user_off = *(uint16_t*)(ntlm + 40);
        
        char username[MAX_USERNAME] = {0};
        char domain[MAX_DOMAIN] = {0};
        
        /* Extract UTF-16LE strings */
        if (user_off + user_len <= len && user_len > 0) {
            for (size_t i = 0; i < user_len/2 && i < MAX_USERNAME-1; i++)
                username[i] = ntlm[user_off + i*2];
        }
        if (dom_off + dom_len <= len && dom_len > 0) {
            for (size_t i = 0; i < dom_len/2 && i < MAX_DOMAIN-1; i++)
                domain[i] = ntlm[dom_off + i*2];
        }
        
        bool is_v2 = (nt_len > 24);
        int mode = is_v2 ? 5600 : 5500;
        
        if (nt_off + nt_len <= len && nt_len > 0) {
            char chall_hex[32], nt_hex[1024], lm_hex[64];
            hex_encode(s->ctx.ntlm.challenge, 8, chall_hex);
            
            size_t nt_copy = nt_len < 512 ? nt_len : 512;
            hex_encode(ntlm + nt_off, nt_copy, nt_hex);
            
            char hash[MAX_HASH];
            if (is_v2) {
                snprintf(hash, sizeof(hash), "%s::%s:%s:%.32s:%s",
                         username, domain, chall_hex, nt_hex, nt_hex + 32);
            } else {
                if (lm_off + lm_len <= len && lm_len == 24) {
                    hex_encode(ntlm + lm_off, 24, lm_hex);
                } else {
                    memset(lm_hex, '0', 48);
                    lm_hex[48] = '\0';
                }
                snprintf(hash, sizeof(hash), "%s::%s:%s:%s:%s",
                         username, domain, lm_hex, nt_hex, chall_hex);
            }
            
            credential_t *c = cred_add(PROTO_NTLM, CRED_CHALLENGE_RESPONSE, 
                                       username, NULL, hash, 0.95f, s);
            if (c) {
                safe_strcpy(c->domain, domain, MAX_DOMAIN);
                c->hashcat_mode = mode;
            }
        }
    }
}

/* SMB2/3 Session Setup */
static void parse_smb2(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 68) return;
    
    /* SMB2 header: \xFE\x53\x4D\x42 */
    if (memcmp(data, "\xFESMB", 4) != 0) return;
    
    uint16_t cmd = *(uint16_t*)(data + 12);
    
    /* Session Setup (0x0001) */
    if (cmd == 0x0001) {
        s->ctx.smb.dialect = 2;
        
        /* Look for NTLMSSP in security buffer */
        if (memmem(data, len, "NTLMSSP", 7)) {
            parse_ntlm(s, data, len);
        }
    }
}

/* SMB1 */
static void parse_smb1(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (len < 36) return;
    
    /* SMB1 header: \xFF\x53\x4D\x42 */
    if (memcmp(data, "\xFFSMB", 4) != 0) return;
    
    uint8_t cmd = data[4];
    
    /* Session Setup AndX (0x73) */
    if (cmd == 0x73) {
        s->ctx.smb.dialect = 1;
        
        if (memmem(data, len, "NTLMSSP", 7)) {
            parse_ntlm(s, data, len);
        }
    }
}

/* Kerberos AS-REP / TGS-REP */
static void parse_kerberos(const uint8_t *data, size_t len, tcp_stream_t *s) {
    if (len < 10) return;
    
    uint8_t tag = data[0];
    
    /* AS-REP (0x6b) or TGS-REP (0x6d) */
    if (tag != 0x6b && tag != 0x6d) return;
    
    /* Look for etype=23 (RC4) */
    const uint8_t *etype = memmem(data, len, "\xa0\x03\x02\x01\x17", 5);
    if (!etype) return;
    
    /* Find cipher */
    const uint8_t *cipher = memmem(etype, len - (etype - data), "\xa2", 1);
    if (!cipher || cipher + 4 >= data + len) return;
    
    size_t cipher_len = 0;
    const uint8_t *cipher_data = NULL;
    
    if (cipher[1] < 0x80) {
        cipher_len = cipher[1];
        cipher_data = cipher + 2;
    } else if (cipher[1] == 0x82 && cipher + 4 < data + len) {
        cipher_len = (cipher[2] << 8) | cipher[3];
        cipher_data = cipher + 4;
    }
    
    if (!cipher_data || cipher_len == 0 || cipher_data + cipher_len > data + len) return;
    
    /* Extract principal name */
    char name[MAX_USERNAME] = "unknown";
    const uint8_t *name_ptr = memmem(data, len, "\x1b", 1);
    if (name_ptr && name_ptr + 2 < data + len) {
        size_t nl = name_ptr[1];
        if (nl < MAX_USERNAME && name_ptr + 2 + nl <= data + len) {
            memcpy(name, name_ptr + 2, nl);
            name[nl] = '\0';
        }
    }
    
    char hash[MAX_HASH];
    char cipher_hex[2048];
    size_t hex_len = cipher_len < 1000 ? cipher_len : 1000;
    hex_encode(cipher_data, hex_len, cipher_hex);
    
    if (tag == 0x6b) {
        /* AS-REP: mode 18200 */
        snprintf(hash, sizeof(hash), "$krb5asrep$23$%s@UNKNOWN:%s", name, cipher_hex);
        credential_t *c = cred_add(PROTO_KERBEROS, CRED_TICKET, name, NULL, hash, 0.9f, s);
        if (c) c->hashcat_mode = 18200;
    } else {
        /* TGS-REP: mode 13100 */
        snprintf(hash, sizeof(hash), "$krb5tgs$23$*%s$UNKNOWN$%s*$%s", name, name, cipher_hex);
        credential_t *c = cred_add(PROTO_KERBEROS, CRED_TICKET, name, NULL, hash, 0.9f, s);
        if (c) c->hashcat_mode = 13100;
    }
}

/* TLS ClientHello SNI extraction */
static void parse_tls(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 50) return;
    
    /* Content type 22 (Handshake), version, length */
    if (data[0] != 0x16) return;
    
    /* Handshake type 1 (ClientHello) */
    if (data[5] != 0x01) return;
    
    /* Look for SNI extension (0x0000) */
    const uint8_t *p = data + 43;  /* Skip fixed headers */
    const uint8_t *end = data + len;
    
    /* Skip session ID */
    if (p >= end) return;
    uint8_t sid_len = *p++;
    p += sid_len;
    
    /* Skip cipher suites */
    if (p + 2 > end) return;
    uint16_t cs_len = ntohs(*(uint16_t*)p);
    p += 2 + cs_len;
    
    /* Skip compression */
    if (p >= end) return;
    uint8_t comp_len = *p++;
    p += comp_len;
    
    /* Extensions */
    if (p + 2 > end) return;
    uint16_t ext_len = ntohs(*(uint16_t*)p);
    p += 2;
    
    const uint8_t *ext_end = p + ext_len;
    if (ext_end > end) ext_end = end;
    
    while (p + 4 < ext_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)p);
        uint16_t ext_data_len = ntohs(*(uint16_t*)(p + 2));
        p += 4;
        
        if (ext_type == 0x0000 && p + ext_data_len <= ext_end) {
            /* SNI extension */
            if (p + 5 < ext_end) {
                uint16_t name_len = ntohs(*(uint16_t*)(p + 3));
                if (name_len < MAX_HOSTNAME && p + 5 + name_len <= ext_end) {
                    memcpy(s->ctx.tls.server_name, p + 5, name_len);
                    s->ctx.tls.server_name[name_len] = '\0';
                }
            }
            break;
        }
        p += ext_data_len;
    }
}

/* LDAP Simple Bind */
static void parse_ldap(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 10) return;
    
    /* ASN.1 SEQUENCE */
    if (data[0] != 0x30) return;
    
    /* Find BindRequest (0x60) */
    const uint8_t *bind = memmem(data, len, "\x60", 1);
    if (!bind || bind + 20 > data + len) return;
    
    /* Find simple auth (0x80) */
    const uint8_t *simple = memmem(bind, data + len - bind, "\x80", 1);
    if (!simple || simple + 2 > data + len) return;
    
    size_t pass_len = simple[1];
    if (simple + 2 + pass_len > data + len || pass_len >= MAX_PASSWORD) return;
    
    char password[MAX_PASSWORD];
    memcpy(password, simple + 2, pass_len);
    password[pass_len] = '\0';
    
    /* Try to find DN */
    char dn[MAX_USERNAME] = "unknown";
    const uint8_t *dn_ptr = memmem(bind, simple - bind, "\x04", 1);
    if (dn_ptr && dn_ptr + 2 < simple) {
        size_t dn_len = dn_ptr[1];
        if (dn_len < MAX_USERNAME && dn_ptr + 2 + dn_len <= simple) {
            memcpy(dn, dn_ptr + 2, dn_len);
            dn[dn_len] = '\0';
        }
    }
    
    cred_add(PROTO_LDAP, CRED_PLAINTEXT, dn, password, NULL, 0.85f, s);
}

/* SNMP Community String */
static void parse_snmp(const uint8_t *data, size_t len, uint32_t sip, uint32_t dip) {
    if (len < 10 || data[0] != 0x30) return;
    
    const uint8_t *p = data + 2;
    
    /* Skip version */
    if (*p == 0x02) {
        p += 2 + p[1];
    }
    
    /* Community string */
    if (p < data + len && *p == 0x04) {
        size_t clen = p[1];
        p += 2;
        
        if (p + clen <= data + len && clen < MAX_PASSWORD) {
            char community[MAX_PASSWORD];
            memcpy(community, p, clen);
            community[clen] = '\0';
            
            /* Skip defaults */
            if (strcmp(community, "public") != 0 && strcmp(community, "private") != 0) {
                credential_t *c = cred_add(PROTO_SNMP, CRED_PLAINTEXT, 
                                          "community", community, NULL, 0.9f, NULL);
                if (c) {
                    c->src_ip = sip;
                    c->dst_ip = dip;
                }
            }
        }
    }
}

/* RADIUS Authentication */
static void parse_radius(const uint8_t *data, size_t len, uint32_t sip, uint32_t dip) {
    if (len < 20 || data[0] != 1) return;  /* Access-Request only */
    uint16_t pkt_len = ntohs(*(uint16_t*)(data + 2));
    if (pkt_len > len) return;
    
    char username[MAX_USERNAME] = {0};
    char mschap_resp[256] = {0}, mschap_chal[64] = {0};
    char auth_hex[64];
    hex_encode(data + 4, 16, auth_hex);
    
    const uint8_t *attr = data + 20, *end = data + pkt_len;
    while (attr + 2 <= end) {
        uint8_t type = attr[0], alen = attr[1];
        if (alen < 2 || attr + alen > end) break;
        if (type == 1 && alen - 2 < MAX_USERNAME) {
            memcpy(username, attr + 2, alen - 2);
            username[alen - 2] = '\0';
        }
        else if (type == 26 && alen > 8) {
            uint32_t vendor = ntohl(*(uint32_t*)(attr + 2));
            if (vendor == 311) {  /* Microsoft */
                uint8_t vs_type = attr[6], vs_len = attr[7];
                if (vs_type == 11 && vs_len > 2)
                    hex_encode(attr + 8, vs_len - 2 < 16 ? vs_len - 2 : 16, mschap_chal);
                else if (vs_type == 25 && vs_len > 26)
                    hex_encode(attr + 8, vs_len - 2 < 50 ? vs_len - 2 : 50, mschap_resp);
            }
        }
        attr += alen;
    }
    
    if (username[0] && mschap_resp[0]) {
        char hash[512];
        snprintf(hash, sizeof(hash), "$MSCHAPv2$%s$%s$%s", mschap_chal, mschap_resp, username);
        credential_t *c = cred_add(PROTO_RADIUS, CRED_CHALLENGE_RESPONSE, username, NULL, hash, 0.9f, NULL);
        if (c) { c->src_ip = sip; c->dst_ip = dip; c->hashcat_mode = 5600; }
    }
}

/* SIP Digest Authentication */
static void parse_sip(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 20) return;
    
    const char *auth = memmem(data, len, "Authorization: Digest ", 22);
    if (!auth) auth = memmem(data, len, "Proxy-Authorization: Digest ", 28);
    if (!auth) return;
    
    auth = strchr(auth, ' ') + 1;
    auth = strchr(auth, ' ') + 1;
    
    const char *end = memmem(auth, len - (auth - (char*)data), "\r\n", 2);
    if (!end) end = (char*)data + len;
    
    char user[MAX_USERNAME] = {0}, response[64] = {0}, nonce[128] = {0};
    char uri[256] = {0}, realm[128] = {0}, method[16] = "REGISTER";
    
    if (len > 10) {
        const char *sp = memchr(data, ' ', 10);
        if (sp) memcpy(method, data, sp - (char*)data < 15 ? sp - (char*)data : 15);
    }
    
    const char *p = auth;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == ',')) p++;
        #define PARSE_SIP(name, buf) if (strncmp(p, name "=\"", strlen(name)+2) == 0) { \
            p += strlen(name) + 2; const char *q = strchr(p, '"'); \
            if (q && q < end) { memcpy(buf, p, q - p < (int)sizeof(buf) ? q - p : sizeof(buf) - 1); p = q + 1; continue; } }
        PARSE_SIP("username", user) PARSE_SIP("response", response)
        PARSE_SIP("nonce", nonce) PARSE_SIP("uri", uri) PARSE_SIP("realm", realm)
        #undef PARSE_SIP
        p++;
    }
    
    if (user[0] && response[0] && nonce[0]) {
        char hash[1024];
        snprintf(hash, sizeof(hash), "$sip$*%s*%s*%s*%s*%s*%s**%s",
                 uri, user, realm, method, uri, nonce, response);
        credential_t *c = cred_add(PROTO_SIP, CRED_CHALLENGE_RESPONSE, user, NULL, hash, 0.9f, s);
        if (c) c->hashcat_mode = 11400;
    }
}

/* SOCKS5 Username/Password */
static void parse_socks(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 5 || data[0] != 0x01) return;
    
    uint8_t ulen = data[1];
    if (2 + ulen + 1 > len) return;
    uint8_t plen = data[2 + ulen];
    if (2 + ulen + 1 + plen > len) return;
    
    char user[MAX_USERNAME] = {0}, pass[MAX_PASSWORD] = {0};
    if (ulen < MAX_USERNAME) memcpy(user, data + 2, ulen);
    if (plen < MAX_PASSWORD) memcpy(pass, data + 3 + ulen, plen);
    
    if (user[0]) cred_add(PROTO_SOCKS, CRED_PLAINTEXT, user, pass, NULL, 0.95f, s);
}

/* WPA Handshake (EAPOL) - simplified */
typedef struct {
    uint8_t bssid[6];
    uint8_t client[6];
    char ssid[33];
    uint8_t anonce[32];
    uint8_t mic[16];
    uint8_t eapol[256];
    size_t eapol_len;
    uint8_t msg_mask;
    bool complete;
} wpa_hs_t;

static wpa_hs_t wpa_handshakes[1024];
static int wpa_count = 0;
static pthread_mutex_t wpa_lock = PTHREAD_MUTEX_INITIALIZER;

static wpa_hs_t *wpa_find_or_create(const uint8_t *bssid, const uint8_t *client) {
    pthread_mutex_lock(&wpa_lock);
    for (int i = 0; i < wpa_count; i++) {
        if (memcmp(wpa_handshakes[i].bssid, bssid, 6) == 0 &&
            memcmp(wpa_handshakes[i].client, client, 6) == 0) {
            pthread_mutex_unlock(&wpa_lock);
            return &wpa_handshakes[i];
        }
    }
    if (wpa_count < 1024) {
        wpa_hs_t *hs = &wpa_handshakes[wpa_count++];
        memset(hs, 0, sizeof(wpa_hs_t));
        memcpy(hs->bssid, bssid, 6);
        memcpy(hs->client, client, 6);
        pthread_mutex_unlock(&wpa_lock);
        return hs;
    }
    pthread_mutex_unlock(&wpa_lock);
    return NULL;
}

static void wpa_add_credential(wpa_hs_t *hs) {
    if (!hs->complete || !hs->ssid[0]) return;
    
    char hash[MAX_HASH], bh[16], ch[16], sh[128], ah[80], mh[48], eh[600];
    hex_encode(hs->bssid, 6, bh);
    hex_encode(hs->client, 6, ch);
    hex_encode((uint8_t*)hs->ssid, strlen(hs->ssid), sh);
    hex_encode(hs->anonce, 32, ah);
    hex_encode(hs->mic, 16, mh);
    hex_encode(hs->eapol, hs->eapol_len, eh);
    
    snprintf(hash, sizeof(hash), "WPA*02*%s*%s*%s*%s*%s*%s*00", mh, bh, ch, sh, ah, eh);
    credential_t *c = cred_add(PROTO_WPA, CRED_HASH, hs->ssid, NULL, hash, 0.95f, NULL);
    if (c) c->hashcat_mode = 22000;
}

static void parse_eapol(const uint8_t *data, size_t len, const uint8_t *src, const uint8_t *dst, const char *ssid) {
    if (len < 99) return;
    uint8_t type = data[1];
    if (type != 0x03) return;  /* EAPOL-Key */
    
    uint16_t body_len = ntohs(*(uint16_t*)(data + 2));
    if (4 + body_len > len) return;
    
    const uint8_t *key = data + 4;
    uint16_t key_info = ntohs(*(uint16_t*)(key + 1));
    
    bool key_ack = (key_info & 0x0080) != 0;
    bool key_mic = (key_info & 0x0100) != 0;
    bool install = (key_info & 0x0040) != 0;
    bool secure = (key_info & 0x0200) != 0;
    
    int msg = 0;
    if (key_ack && !key_mic && !install) msg = 1;
    else if (!key_ack && key_mic && !install) msg = 2;
    else if (key_ack && key_mic && install) msg = 3;
    else if (!key_ack && key_mic && secure) msg = 4;
    if (msg == 0) return;
    
    const uint8_t *bssid, *client;
    if (msg == 1 || msg == 3) { bssid = src; client = dst; }
    else { bssid = dst; client = src; }
    
    wpa_hs_t *hs = wpa_find_or_create(bssid, client);
    if (!hs) return;
    
    if (ssid && ssid[0] && !hs->ssid[0]) safe_strcpy(hs->ssid, ssid, 33);
    
    const uint8_t *nonce = key + 13;
    const uint8_t *mic = key + 77;
    
    if (msg == 1) {
        memcpy(hs->anonce, nonce, 32);
        hs->msg_mask |= 0x01;
    }
    else if (msg == 2) {
        memcpy(hs->mic, mic, 16);
        size_t el = 4 + body_len;
        if (el <= sizeof(hs->eapol)) {
            memcpy(hs->eapol, data, el);
            memset(hs->eapol + 4 + 77, 0, 16);
            hs->eapol_len = el;
        }
        hs->msg_mask |= 0x02;
    }
    else if (msg == 3) {
        if (!(hs->msg_mask & 0x01)) memcpy(hs->anonce, nonce, 32);
        hs->msg_mask |= 0x04;
    }
    else if (msg == 4) {
        hs->msg_mask |= 0x08;
    }
    
    if ((hs->msg_mask & 0x03) == 0x03 && !hs->complete) {
        hs->complete = true;
        wpa_add_credential(hs);
    }
}

static void process_wifi(const uint8_t *data, size_t len) {
    if (len < 4 || data[0] != 0) return;
    uint16_t rt_len = *(uint16_t*)(data + 2);
    if (rt_len > len) return;
    
    const uint8_t *frame = data + rt_len;
    size_t frame_len = len - rt_len;
    if (frame_len < 24) return;
    
    uint16_t fc = *(uint16_t*)frame;
    uint8_t type = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0f;
    
    const uint8_t *addr1 = frame + 4;
    const uint8_t *addr2 = frame + 10;
    
    char ssid[33] = {0};
    
    if (type == 0 && (subtype == 8 || subtype == 5) && frame_len > 36) {
        const uint8_t *ies = frame + 36;
        size_t ies_len = frame_len - 36;
        while (ies_len >= 2) {
            uint8_t ie_id = ies[0], ie_len = ies[1];
            if (2 + ie_len > ies_len) break;
            if (ie_id == 0 && ie_len > 0 && ie_len < 33) {
                memcpy(ssid, ies + 2, ie_len);
                ssid[ie_len] = '\0';
                break;
            }
            ies += 2 + ie_len;
            ies_len -= 2 + ie_len;
        }
    }
    else if (type == 2) {
        size_t hdr_len = 24;
        if (fc & 0x8000) hdr_len += 2;
        if (frame_len > hdr_len + 8) {
            const uint8_t *llc = frame + hdr_len;
            if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
                llc[6] == 0x88 && llc[7] == 0x8E) {
                parse_eapol(llc + 8, frame_len - hdr_len - 8, addr2, addr1, ssid);
            }
        }
    }
}

/* Oracle TNS */
static void parse_oracle(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    if (!is_client || len < 10) return;
    
    const char *text = (const char*)data;
    const char *user = strcasestr(text, "USER=");
    const char *pass = strcasestr(text, "PASSWORD=");
    
    if (user && pass) {
        user += 5;
        pass += 9;
        
        const char *user_end = strpbrk(user, ")( \t\r\n");
        const char *pass_end = strpbrk(pass, ")( \t\r\n");
        
        char username[MAX_USERNAME] = {0}, password[MAX_PASSWORD] = {0};
        
        if (user_end && user_end - user < MAX_USERNAME) {
            memcpy(username, user, user_end - user);
        }
        if (pass_end && pass_end - pass < MAX_PASSWORD) {
            memcpy(password, pass, pass_end - pass);
        }
        
        if (username[0] && password[0]) {
            cred_add(PROTO_ORACLE, CRED_PLAINTEXT, username, password, NULL, 0.9f, s);
        }
    }
}

/* RDP - primarily NTLM via CredSSP */
static void parse_rdp(tcp_stream_t *s, const uint8_t *data, size_t len, bool is_client) {
    /* Look for NTLM in CredSSP */
    if (memmem(data, len, "NTLMSSP", 7)) {
        parse_ntlm(s, data, len);
    }
}

/* ============================================================================
 * STREAM PROCESSING
 * ============================================================================ */

static void process_stream_data(tcp_stream_t *s, bool is_client) {
    uint8_t *buf = is_client ? s->client_buffer : s->server_buffer;
    size_t len = is_client ? s->client_len : s->server_len;
    
    if (len == 0) return;
    
    /* Check for NTLM in any protocol */
    if (memmem(buf, len, "NTLMSSP", 7)) {
        parse_ntlm(s, buf, len);
    }
    
    /* Protocol-specific parsing */
    switch (s->protocol) {
        case PROTO_FTP:
            parse_ftp(s, buf, len, is_client);
            break;
        case PROTO_TELNET:
            parse_telnet(s, buf, len, is_client);
            break;
        case PROTO_SMTP:
            parse_smtp(s, buf, len, is_client);
            break;
        case PROTO_POP3:
            parse_pop3(s, buf, len, is_client);
            break;
        case PROTO_IMAP:
            parse_imap(s, buf, len, is_client);
            break;
        case PROTO_HTTP:
            parse_http(s, buf, len, is_client);
            break;
        case PROTO_TLS:
            parse_tls(s, buf, len, is_client);
            /* After SNI, check for HTTP inside */
            if (memmem(buf, len, "Authorization:", 14)) {
                parse_http(s, buf, len, is_client);
            }
            break;
        case PROTO_LDAP:
            parse_ldap(s, buf, len, is_client);
            break;
        case PROTO_MYSQL:
            parse_mysql(s, buf, len, is_client);
            break;
        case PROTO_POSTGRESQL:
            parse_postgresql(s, buf, len, is_client);
            break;
        case PROTO_MSSQL:
            parse_mssql(s, buf, len, is_client);
            break;
        case PROTO_ORACLE:
            parse_oracle(s, buf, len, is_client);
            break;
        case PROTO_MONGODB:
            parse_mongodb(s, buf, len, is_client);
            break;
        case PROTO_REDIS:
            parse_redis(s, buf, len, is_client);
            break;
        case PROTO_MQTT:
            parse_mqtt(s, buf, len, is_client);
            break;
        case PROTO_VNC:
            parse_vnc(s, buf, len, is_client);
            break;
        case PROTO_RDP:
            parse_rdp(s, buf, len, is_client);
            break;
        case PROTO_SMB:
            if (len >= 4) {
                if (buf[0] == 0xFE && buf[1] == 'S') {
                    parse_smb2(s, buf, len, is_client);
                } else if (buf[0] == 0xFF && buf[1] == 'S') {
                    parse_smb1(s, buf, len, is_client);
                }
            }
            break;
        case PROTO_KERBEROS:
            parse_kerberos(buf, len, s);
            break;
        default:
            break;
    }
}

/* ============================================================================
 * PACKET PROCESSING
 * ============================================================================ */

static void process_tcp(const uint8_t *data, size_t len,
                        uint32_t sip, uint32_t dip,
                        const struct tcphdr *tcp) {
    size_t tcp_hdr_len = tcp->th_off * 4;
    if (tcp_hdr_len > len) return;
    
    uint16_t sp = ntohs(tcp->th_sport);
    uint16_t dp = ntohs(tcp->th_dport);
    uint32_t seq = ntohl(tcp->th_seq);
    uint32_t ack = ntohl(tcp->th_ack);
    uint8_t flags = tcp->th_flags;
    
    const uint8_t *payload = data + tcp_hdr_len;
    size_t payload_len = len - tcp_hdr_len;
    
    pthread_mutex_lock(&G.stream_lock);
    tcp_stream_t *s = stream_find(sip, dip, sp, dp);
    pthread_mutex_unlock(&G.stream_lock);
    
    /* SYN - new connection */
    if ((flags & TH_SYN) && !(flags & TH_ACK)) {
        if (!s) {
            protocol_t proto = detect_protocol(dp);
            if (proto == PROTO_UNKNOWN) proto = detect_protocol(sp);
            if (proto != PROTO_UNKNOWN) {
                s = stream_create(sip, dip, sp, dp, seq, proto);
            }
        }
        return;
    }
    
    /* SYN-ACK */
    if ((flags & TH_SYN) && (flags & TH_ACK) && s) {
        s->server_isn = seq;
        s->server_next_seq = seq + 1;
        return;
    }
    
    if (!s) return;
    
    /* Determine direction */
    bool is_client = (sip == s->src_ip && sp == s->src_port);
    
    /* Data */
    if (payload_len > 0) {
        uint32_t *next_seq = is_client ? &s->client_next_seq : &s->server_next_seq;
        uint8_t *buffer = is_client ? s->client_buffer : s->server_buffer;
        size_t *buf_len = is_client ? &s->client_len : &s->server_len;
        tcp_segment_t **ooo = is_client ? &s->client_ooo : &s->server_ooo;
        
        if (seq == *next_seq) {
            /* In order - append to buffer */
            size_t space = STREAM_BUFFER_SIZE - *buf_len;
            size_t copy = payload_len < space ? payload_len : space;
            
            if (copy > 0) {
                memcpy(buffer + *buf_len, payload, copy);
                *buf_len += copy;
                *next_seq += copy;
                G.stats.tcp_reassembled++;
            }
            
            /* Try to reassemble OOO segments */
            try_reassemble(s, is_client);
            
            /* Process data */
            process_stream_data(s, is_client);
        }
        else if ((int32_t)(seq - *next_seq) > 0) {
            /* Out of order - queue */
            insert_ooo_segment(ooo, seq, payload, payload_len);
        }
        /* else: retransmit, ignore */
        
        s->last_activity = time(NULL);
    }
    
    /* FIN/RST */
    if (flags & (TH_FIN | TH_RST)) {
        s->state = STATE_CLOSED;
    }
}

static void process_udp(const uint8_t *data, size_t len,
                        uint32_t sip, uint32_t dip,
                        uint16_t sp, uint16_t dp) {
    if (len < 8) return;
    
    const uint8_t *payload = data + 8;
    size_t payload_len = len - 8;
    
    /* SNMP */
    if (dp == 161 || dp == 162 || sp == 161 || sp == 162) {
        parse_snmp(payload, payload_len, sip, dip);
    }
    
    /* Kerberos */
    if (dp == 88 || sp == 88) {
        parse_kerberos(payload, payload_len, NULL);
    }
    
    /* RADIUS */
    if (dp == 1812 || dp == 1813 || sp == 1812 || sp == 1813) {
        parse_radius(payload, payload_len, sip, dip);
    }
    
    /* SIP */
    if (dp == 5060 || sp == 5060) {
        tcp_stream_t dummy = {.src_ip = sip, .dst_ip = dip, .src_port = sp, .dst_port = dp};
        parse_sip(&dummy, payload, payload_len, true);
    }
}

static uint32_t g_linktype = DLT_EN10MB;

static void process_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
    (void)user;
    
    if (G.stop) return;
    
    pthread_mutex_lock(&G.stats_lock);
    G.stats.packets_total++;
    G.stats.bytes_total += hdr->len;
    pthread_mutex_unlock(&G.stats_lock);
    
    /* WiFi frames (Radiotap) */
    if (g_linktype == 127 || g_linktype == 105) {
        process_wifi(pkt, hdr->len);
        return;
    }
    
    if (hdr->len < 14) return;
    
    uint16_t eth_type = ntohs(*(uint16_t*)(pkt + 12));
    const uint8_t *ip_pkt = pkt + 14;
    size_t ip_len = hdr->len - 14;
    
    /* VLAN */
    if (eth_type == 0x8100 && ip_len >= 4) {
        eth_type = ntohs(*(uint16_t*)(ip_pkt + 2));
        ip_pkt += 4;
        ip_len -= 4;
    }
    
    /* IPv4 */
    if (eth_type == 0x0800 && ip_len >= 20) {
        const struct ip *iph = (const struct ip*)ip_pkt;
        if (iph->ip_v != 4) return;
        
        size_t iph_len = iph->ip_hl * 4;
        if (iph_len < 20 || iph_len > ip_len) return;
        
        uint32_t sip = iph->ip_src.s_addr;
        uint32_t dip = iph->ip_dst.s_addr;
        
        const uint8_t *transport = ip_pkt + iph_len;
        size_t transport_len = ntohs(iph->ip_len) - iph_len;
        if (transport_len > ip_len - iph_len) transport_len = ip_len - iph_len;
        
        if (iph->ip_p == IPPROTO_TCP && transport_len >= 20) {
            G.stats.packets_tcp++;
            process_tcp(transport, transport_len, sip, dip, (const struct tcphdr*)transport);
        }
        else if (iph->ip_p == IPPROTO_UDP && transport_len >= 8) {
            G.stats.packets_udp++;
            const struct udphdr *udp = (const struct udphdr*)transport;
            process_udp(transport, transport_len, sip, dip,
                       ntohs(udp->uh_sport), ntohs(udp->uh_dport));
        }
    }
    /* IPv6 */
    else if (eth_type == 0x86DD && ip_len >= 40) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr*)ip_pkt;
        
        uint32_t sip = ip6->ip6_src.s6_addr32[3];
        uint32_t dip = ip6->ip6_dst.s6_addr32[3];
        
        uint8_t next = ip6->ip6_nxt;
        const uint8_t *transport = ip_pkt + 40;
        size_t transport_len = ntohs(ip6->ip6_plen);
        
        if (next == IPPROTO_TCP && transport_len >= 20) {
            G.stats.packets_tcp++;
            process_tcp(transport, transport_len, sip, dip, (const struct tcphdr*)transport);
        }
        else if (next == IPPROTO_UDP && transport_len >= 8) {
            G.stats.packets_udp++;
            const struct udphdr *udp = (const struct udphdr*)transport;
            process_udp(transport, transport_len, sip, dip,
                       ntohs(udp->uh_sport), ntohs(udp->uh_dport));
        }
    }
}

/* ============================================================================
 * IMPORT FUNCTIONS
 * ============================================================================ */

static void import_responder(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "Error: Cannot open %s\n", dir);
        return;
    }
    
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_type != DT_REG) continue;
        
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        
        FILE *f = fopen(path, "r");
        if (!f) continue;
        
        char line[2048];
        while (fgets(line, sizeof(line), f)) {
            char *t = trim(line);
            if (!*t || *t == '#') continue;
            
            if (strstr(ent->d_name, "NTLMv") && strstr(t, "::")) {
                credential_t *c = cred_add(PROTO_NTLM, CRED_CHALLENGE_RESPONSE,
                                          NULL, NULL, t, 0.95f, NULL);
                if (c) {
                    char *colon = strchr(t, ':');
                    if (colon) {
                        size_t ul = colon - t;
                        if (ul < MAX_USERNAME) {
                            memcpy(c->username, t, ul);
                            c->username[ul] = '\0';
                        }
                    }
                }
            }
            else if (strstr(ent->d_name, "Cleartext")) {
                char *colon = strchr(t, ':');
                if (colon) {
                    *colon = '\0';
                    cred_add(PROTO_SMB, CRED_PLAINTEXT, t, colon + 1, NULL, 0.95f, NULL);
                }
            }
        }
        fclose(f);
    }
    closedir(d);
    printf("[+] Imported Responder logs: %s\n", dir);
}

static void import_secretsdump(const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s\n", file);
        return;
    }
    
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *t = trim(line);
        if (!*t || *t == '#' || *t == '[') continue;
        
        /* DCC2 */
        if (strncmp(t, "$DCC2$", 6) == 0) {
            credential_t *c = cred_add(PROTO_DCC2, CRED_HASH, NULL, NULL, t, 0.99f, NULL);
            if (c) {
                c->hashcat_mode = 2100;
                char *h1 = strchr(t + 6, '#');
                if (h1) {
                    char *h2 = strchr(h1 + 1, '#');
                    if (h2) {
                        size_t ul = h2 - h1 - 1;
                        if (ul < MAX_USERNAME) {
                            memcpy(c->username, h1 + 1, ul);
                            c->username[ul] = '\0';
                        }
                    }
                }
            }
            continue;
        }
        
        /* SAM/NTDS: user:rid:lm:nt::: */
        char *parts[8] = {0};
        int n = 0;
        char *p = t;
        while (*p && n < 8) {
            parts[n++] = p;
            p = strchr(p, ':');
            if (p) *p++ = '\0';
            else break;
        }
        
        if (n >= 4 && strlen(parts[2]) == 32 && strlen(parts[3]) == 32) {
            char hash[128];
            snprintf(hash, sizeof(hash), "%s:%s", parts[2], parts[3]);
            
            char *user = parts[0];
            char *domain = NULL;
            char *bs = strchr(user, '\\');
            if (bs) {
                *bs = '\0';
                domain = user;
                user = bs + 1;
            }
            
            protocol_t proto = domain ? PROTO_NTDS : PROTO_SAM;
            credential_t *c = cred_add(proto, CRED_HASH, user, NULL, hash, 0.99f, NULL);
            if (c) {
                c->hashcat_mode = 1000;
                if (domain) safe_strcpy(c->domain, domain, MAX_DOMAIN);
            }
        }
    }
    fclose(f);
    printf("[+] Imported secretsdump: %s\n", file);
}

/* ============================================================================
 * EXPORT FUNCTIONS
 * ============================================================================ */

static void export_json(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "{\n  \"meta\": {\n");
    fprintf(f, "    \"tool\": \"pcredz\",\n");
    fprintf(f, "    \"version\": \"%s\",\n", VERSION);
    fprintf(f, "    \"total\": %u\n", G.cred_count);
    fprintf(f, "  },\n  \"credentials\": [\n");
    
    char esc_user[MAX_USERNAME*2], esc_pass[MAX_PASSWORD*2];
    char esc_hash[MAX_HASH*2], esc_dom[MAX_DOMAIN*2];
    bool first = true;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        for (credential_t *c = G.creds[i]; c; c = c->next) {
            if (!first) fprintf(f, ",\n");
            first = false;
            
            char sip[32], dip[32];
            ip4_str(c->src_ip, sip, sizeof(sip));
            ip4_str(c->dst_ip, dip, sizeof(dip));
            
            json_escape(c->username, esc_user, sizeof(esc_user));
            json_escape(c->password, esc_pass, sizeof(esc_pass));
            json_escape(c->hash, esc_hash, sizeof(esc_hash));
            json_escape(c->domain, esc_dom, sizeof(esc_dom));
            
            fprintf(f, "    {\"id\":%u,\"proto\":\"%s\",\"user\":\"%s\"",
                    c->id, proto_names[c->protocol], esc_user);
            if (c->password[0]) fprintf(f, ",\"pass\":\"%s\"", esc_pass);
            if (c->hash[0]) fprintf(f, ",\"hash\":\"%s\"", esc_hash);
            if (c->domain[0]) fprintf(f, ",\"domain\":\"%s\"", esc_dom);
            fprintf(f, ",\"src\":\"%s:%u\",\"dst\":\"%s:%u\"",
                    sip, c->src_port, dip, c->dst_port);
            fprintf(f, ",\"mode\":%d,\"conf\":%.2f}", c->hashcat_mode, c->confidence);
        }
    }
    
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    printf("[+] Exported: %s\n", path);
}

static void export_csv(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "id,protocol,username,password,hash,domain,src_ip,src_port,dst_ip,dst_port,hashcat_mode,confidence\n");
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        for (credential_t *c = G.creds[i]; c; c = c->next) {
            char sip[32], dip[32];
            ip4_str(c->src_ip, sip, sizeof(sip));
            ip4_str(c->dst_ip, dip, sizeof(dip));
            
            fprintf(f, "%u,%s,\"%s\",\"%s\",\"%s\",\"%s\",%s,%u,%s,%u,%d,%.2f\n",
                    c->id, proto_names[c->protocol],
                    c->username, c->password, c->hash, c->domain,
                    sip, c->src_port, dip, c->dst_port,
                    c->hashcat_mode, c->confidence);
        }
    }
    
    fclose(f);
    printf("[+] Exported: %s\n", path);
}

static void export_hashcat(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        for (credential_t *c = G.creds[i]; c; c = c->next) {
            if (c->hash[0]) fprintf(f, "%s\n", c->hash);
        }
    }
    
    fclose(f);
    printf("[+] Exported: %s\n", path);
}

static void export_hashscan(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "# Pcredz v%s - Network Credential Extraction\n", VERSION);
    fprintf(f, "# Total: %u credentials\n\n", G.cred_count);
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        for (credential_t *c = G.creds[i]; c; c = c->next) {
            char sip[32], dip[32];
            ip4_str(c->src_ip, sip, sizeof(sip));
            ip4_str(c->dst_ip, dip, sizeof(dip));
            
            fprintf(f, "# %s | %s | mode:%d\n", proto_names[c->protocol],
                    c->username[0] ? c->username : "unknown", c->hashcat_mode);
            fprintf(f, "# %s:%u -> %s:%u\n", sip, c->src_port, dip, c->dst_port);
            
            if (c->hash[0]) {
                fprintf(f, "%s\n", c->hash);
            } else if (c->password[0]) {
                fprintf(f, "# PLAINTEXT: %s:%s\n", c->username, c->password);
            }
            fprintf(f, "\n");
        }
    }
    
    fclose(f);
    printf("[+] Exported: %s\n", path);
}

static void export_sqlite(const char *path) {
    sqlite3 *db;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        fprintf(stderr, "Error: Cannot create SQLite DB\n");
        return;
    }
    
    const char *schema = 
        "CREATE TABLE IF NOT EXISTS credentials ("
        "  id INTEGER PRIMARY KEY,"
        "  protocol TEXT,"
        "  username TEXT,"
        "  password TEXT,"
        "  hash TEXT,"
        "  domain TEXT,"
        "  src_ip TEXT,"
        "  src_port INTEGER,"
        "  dst_ip TEXT,"
        "  dst_port INTEGER,"
        "  hashcat_mode INTEGER,"
        "  confidence REAL,"
        "  timestamp INTEGER"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_proto ON credentials(protocol);"
        "CREATE INDEX IF NOT EXISTS idx_user ON credentials(username);";
    
    sqlite3_exec(db, schema, NULL, NULL, NULL);
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db,
        "INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &stmt, NULL);
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        for (credential_t *c = G.creds[i]; c; c = c->next) {
            char sip[32], dip[32];
            ip4_str(c->src_ip, sip, sizeof(sip));
            ip4_str(c->dst_ip, dip, sizeof(dip));
            
            sqlite3_bind_int(stmt, 1, c->id);
            sqlite3_bind_text(stmt, 2, proto_names[c->protocol], -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, c->username, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, c->password, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 5, c->hash, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, c->domain, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 7, sip, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 8, c->src_port);
            sqlite3_bind_text(stmt, 9, dip, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 10, c->dst_port);
            sqlite3_bind_int(stmt, 11, c->hashcat_mode);
            sqlite3_bind_double(stmt, 12, c->confidence);
            sqlite3_bind_int64(stmt, 13, c->timestamp);
            
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(db);
    
    printf("[+] Exported: %s\n", path);
}

/* ============================================================================
 * CLEANUP
 * ============================================================================ */

static void cleanup(void) {
    /* Free streams */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        tcp_stream_t *s = G.streams[i];
        while (s) {
            tcp_stream_t *next = s->next;
            stream_free(s);
            s = next;
        }
    }
    
    /* Free credentials */
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        credential_t *c = G.creds[i];
        while (c) {
            credential_t *next = c->next;
            free(c);
            c = next;
        }
    }
    
    pthread_mutex_destroy(&G.stream_lock);
    pthread_mutex_destroy(&G.cred_lock);
    pthread_mutex_destroy(&G.stats_lock);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║   ██████╗  ██████╗██████╗ ███████╗██████╗ ███████╗           ║\n");
    printf("║   ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗╚══███╔╝           ║\n");
    printf("║   ██████╔╝██║     ██████╔╝█████╗  ██║  ██║  ███╔╝            ║\n");
    printf("║   ██╔═══╝ ██║     ██╔══██╗██╔══╝  ██║  ██║ ███╔╝             ║\n");
    printf("║   ██║     ╚██████╗██║  ██║███████╗██████╔╝███████╗           ║\n");
    printf("║   ╚═╝      ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝           ║\n");
    printf("║                                                               ║\n");
    printf("║   Network Credential Extraction Tool v%s                   ║\n", VERSION);
    printf("║   30 Protocols • WPA • Multi-threaded • HTML Reports          ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  22+ Protocols: FTP TELNET SMTP POP3 IMAP HTTP LDAP SNMP     ║\n");
    printf("║  MySQL PostgreSQL MSSQL Oracle MongoDB Redis MQTT VNC RDP    ║\n");
    printf("║  SMB1/2/3 NTLM Kerberos TLS-SNI RADIUS SIP WPA/WPA2          ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("Input:\n");
    printf("  -f, --file FILE       PCAP file\n");
    printf("  -i, --interface IF    Live capture\n");
    printf("  --responder DIR       Import Responder logs\n");
    printf("  --secretsdump FILE    Import secretsdump\n");
    printf("\nOutput:\n");
    printf("  -o, --output DIR      Output directory (default: ./output)\n");
    printf("  --json/--csv/--hashcat/--hashscan/--sqlite\n");
    printf("\nOptions:\n");
    printf("  --filter EXPR         BPF filter\n");
    printf("  --timeout SEC         Capture timeout\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  --no-banner           Suppress banner\n");
    printf("\nExamples:\n");
    printf("  %s -f capture.pcap -o ./results\n", prog);
    printf("  %s -i eth0 --filter 'port 445' --timeout 60\n", prog);
    printf("\n");
}

static void print_summary(void) {
    double elapsed = difftime(G.stats.end_time, G.stats.start_time);
    if (elapsed < 1) elapsed = 1;
    
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("                         SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Duration:             %.1f seconds\n", elapsed);
    printf("  Packets:              %lu (%.0f pkt/s)\n", 
           G.stats.packets_total, G.stats.packets_total / elapsed);
    printf("  TCP/UDP:              %lu / %lu\n", G.stats.packets_tcp, G.stats.packets_udp);
    printf("  Bytes:                %lu MB\n", G.stats.bytes_total / (1024*1024));
    printf("  TCP Sessions:         %lu\n", G.stats.tcp_sessions);
    printf("  Reassembled:          %lu segments\n", G.stats.tcp_reassembled);
    printf("  Credentials:          %lu unique\n", G.stats.credentials_unique);
    
    bool has_proto = false;
    for (int i = 1; i < PROTO_COUNT; i++) {
        if (G.stats.proto_counts[i] > 0) has_proto = true;
    }
    
    if (has_proto) {
        printf("───────────────────────────────────────────────────────────────\n");
        printf("  By Protocol:\n");
        for (int i = 1; i < PROTO_COUNT; i++) {
            if (G.stats.proto_counts[i] > 0) {
                printf("    %-15s %lu\n", proto_names[i], G.stats.proto_counts[i]);
            }
        }
    }
    printf("═══════════════════════════════════════════════════════════════\n");
}

int main(int argc, char **argv) {
    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        }
        else if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) && i+1 < argc)
            opts.input_file = argv[++i];
        else if ((!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface")) && i+1 < argc)
            opts.interface = argv[++i];
        else if (!strcmp(argv[i], "--responder") && i+1 < argc)
            opts.responder_dir = argv[++i];
        else if (!strcmp(argv[i], "--secretsdump") && i+1 < argc)
            opts.secretsdump_file = argv[++i];
        else if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) && i+1 < argc)
            opts.output_dir = argv[++i];
        else if (!strcmp(argv[i], "--filter") && i+1 < argc)
            opts.bpf_filter = argv[++i];
        else if (!strcmp(argv[i], "--timeout") && i+1 < argc)
            opts.capture_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            opts.verbose = true;
        else if (!strcmp(argv[i], "--no-banner"))
            opts.no_banner = true;
        else if (!strcmp(argv[i], "--no-progress"))
            opts.no_progress = true;
    }
    
    if (!opts.no_banner) print_banner();
    
    if (!opts.input_file && !opts.interface && !opts.responder_dir && !opts.secretsdump_file) {
        fprintf(stderr, "Error: No input specified\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Initialize */
    pthread_mutex_init(&G.stream_lock, NULL);
    pthread_mutex_init(&G.cred_lock, NULL);
    pthread_mutex_init(&G.stats_lock, NULL);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    G.stats.start_time = time(NULL);
    
    /* Process PCAP */
    if (opts.input_file) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *h = pcap_open_offline(opts.input_file, errbuf);
        if (!h) {
            fprintf(stderr, "Error: %s\n", errbuf);
            return 1;
        }
        
        g_linktype = pcap_datalink(h);
        G.pcap_handle = h;
        
        if (opts.bpf_filter) {
            struct bpf_program fp;
            if (pcap_compile(h, &fp, opts.bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(h, &fp);
                pcap_freecode(&fp);
            }
        }
        
        printf("[*] Processing: %s (linktype: %d)\n", opts.input_file, g_linktype);
        pcap_loop(h, 0, process_packet, NULL);
        pcap_close(h);
    }
    
    /* Live capture */
    if (opts.interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *h = pcap_open_live(opts.interface, 65535, 1, 1000, errbuf);
        if (!h) {
            fprintf(stderr, "Error: %s\n", errbuf);
            return 1;
        }
        
        g_linktype = pcap_datalink(h);
        G.pcap_handle = h;
        
        if (opts.bpf_filter) {
            struct bpf_program fp;
            if (pcap_compile(h, &fp, opts.bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(h, &fp);
                pcap_freecode(&fp);
            }
        }
        
        printf("[*] Live capture: %s (linktype: %d)\n", opts.interface, g_linktype);
        if (opts.capture_timeout) {
            printf("[*] Timeout: %d seconds\n", opts.capture_timeout);
            alarm(opts.capture_timeout);
        }
        
        pcap_loop(h, 0, process_packet, NULL);
        pcap_close(h);
    }
    
    /* Import */
    if (opts.responder_dir) import_responder(opts.responder_dir);
    if (opts.secretsdump_file) import_secretsdump(opts.secretsdump_file);
    
    G.stats.end_time = time(NULL);
    
    /* Export */
    mkdir_p(opts.output_dir);
    char path[512];
    
    if (opts.json_output) {
        snprintf(path, sizeof(path), "%s/credentials.json", opts.output_dir);
        export_json(path);
    }
    if (opts.csv_output) {
        snprintf(path, sizeof(path), "%s/credentials.csv", opts.output_dir);
        export_csv(path);
    }
    if (opts.hashcat_output) {
        snprintf(path, sizeof(path), "%s/hashes.txt", opts.output_dir);
        export_hashcat(path);
    }
    if (opts.hashscan_output) {
        snprintf(path, sizeof(path), "%s/hashscan_input.txt", opts.output_dir);
        export_hashscan(path);
    }
    if (opts.sqlite_output) {
        snprintf(path, sizeof(path), "%s/credentials.db", opts.output_dir);
        export_sqlite(path);
    }
    
    print_summary();
    cleanup();
    
    return 0;
}
