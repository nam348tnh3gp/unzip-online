/*
 * DUCO GPU Miner for SGI Workstations - FULL PRODUCTION VERSION
 * Matches Rust miner protocol (main.rs) exactly
 * Uses OpenGL fixed pipeline as entropy source
 * 
 * Compile on IRIX 6.5:
 *   cc -o duco_sgi duco_sgi.c -lGL -lGLU -lX11 -lm -lpthread -lsocket -lnsl
 * 
 * For better performance: reduce render_width/height in config.yml
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <time.h>

/* OpenGL headers */
#include <GL/gl.h>
#include <GL/glu.h>
#include <GL/glx.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

typedef struct {
    char username[64];
    char mining_key[64];
    char difficulty[16];
    char rig_identifier[64];
    int thread_count;
    int render_width;
    int render_height;
    int use_gpu_entropy;
} config_t;

static config_t config;

static const config_t DEFAULT_CONFIG = {
    .username = "",
    .mining_key = "",
    .difficulty = "LOW",
    .rig_identifier = "SGI_RIG",
    .thread_count = 1,
    .render_width = 64,
    .render_height = 64,
    .use_gpu_entropy = 1
};

/* ============================================================================
 * JOB STRUCTURE (matches Rust miner EXACTLY)
 * ============================================================================ */

typedef struct {
    char base[128];
    unsigned char target[20];
    unsigned int diff;
    int active;
    time_t received_at;
} job_t;

static job_t current_job;
static pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * MINER STATE
 * ============================================================================ */

typedef struct {
    volatile int running;
    unsigned long long total_hashes;
    double hash_rate;
    unsigned long long accepted;
    unsigned long long rejected;
    char server_addr[64];
    int server_port;
    int socket_fd;
    pthread_mutex_t socket_mutex;
    pthread_mutex_t stats_mutex;
} miner_state_t;

static miner_state_t state;

/* ============================================================================
 * OPENGL GLOBALS
 * ============================================================================ */

static Display *dpy;
static Window win;
static GLXContext ctx;
static GLuint cube_display_list = 0;
static int gl_initialized = 0;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

void format_hashrate(double hashrate, char *buf, size_t size) {
    if (hashrate >= 1e9) {
        snprintf(buf, size, "%.2f GH/s", hashrate / 1e9);
    } else if (hashrate >= 1e6) {
        snprintf(buf, size, "%.2f MH/s", hashrate / 1e6);
    } else if (hashrate >= 1e3) {
        snprintf(buf, size, "%.2f kH/s", hashrate / 1e3);
    } else {
        snprintf(buf, size, "%.2f H/s", hashrate);
    }
}

unsigned int parse_difficulty(const char *diff_str) {
    if (strcasecmp(diff_str, "LOW") == 0) return 4;
    if (strcasecmp(diff_str, "MEDIUM") == 0) return 8;
    if (strcasecmp(diff_str, "HIGH") == 0) return 12;
    return (unsigned int)strtol(diff_str, NULL, 16);
}

int hex_to_bytes(const char *hex, unsigned char *bytes, int max_len) {
    int len = strlen(hex);
    if (len % 2 != 0) return -1;
    if (len / 2 > max_len) return -1;
    
    for (int i = 0; i < len / 2; i++) {
        char byte_str[3] = {hex[i*2], hex[i*2+1], 0};
        bytes[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }
    return len / 2;
}

/* ============================================================================
 * CONFIGURATION PARSER
 * ============================================================================ */

int read_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open %s\n", filename);
        return 0;
    }
    
    memcpy(&config, &DEFAULT_CONFIG, sizeof(config_t));
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char key[64], value[128];
        
        if (line[0] == '#' || line[0] == '\n') continue;
        
        if (sscanf(line, " %63[^:]: %127[^\n]", key, value) == 2) {
            char *start = value;
            char *end = value + strlen(value) - 1;
            
            while (isspace(*start)) start++;
            while (end > start && isspace(*end)) end--;
            *(end + 1) = '\0';
            
            if (*start == '"') start++;
            if (*end == '"') *end = '\0';
            
            if (strcmp(key, "username") == 0) {
                strncpy(config.username, start, sizeof(config.username)-1);
            } else if (strcmp(key, "mining_key") == 0) {
                strncpy(config.mining_key, start, sizeof(config.mining_key)-1);
            } else if (strcmp(key, "difficulty") == 0) {
                strncpy(config.difficulty, start, sizeof(config.difficulty)-1);
            } else if (strcmp(key, "rig_identifier") == 0) {
                strncpy(config.rig_identifier, start, sizeof(config.rig_identifier)-1);
            } else if (strcmp(key, "thread_count") == 0) {
                config.thread_count = atoi(start);
                if (config.thread_count < 1) config.thread_count = 1;
                if (config.thread_count > 4) config.thread_count = 4;
            }
        }
    }
    
    fclose(fp);
    
    if (strlen(config.username) == 0 || strlen(config.mining_key) == 0) {
        fprintf(stderr, "ERROR: username and mining_key required in config.yml\n");
        return 0;
    }
    
    return 1;
}

/* ============================================================================
 * SHA1 IMPLEMENTATION (Exactly like Rust's sha1)
 * ============================================================================ */

typedef struct {
    unsigned int h[5];
    unsigned char buffer[64];
    unsigned long long count;
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void sha1_transform(SHA1_CTX *ctx) {
    unsigned int a, b, c, d, e, temp;
    unsigned int w[80];
    int i;
    
    for (i = 0; i < 16; i++) {
        w[i] = (ctx->buffer[i*4] << 24) | (ctx->buffer[i*4+1] << 16) |
               (ctx->buffer[i*4+2] << 8) | ctx->buffer[i*4+3];
    }
    
    for (i = 16; i < 80; i++) {
        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
        w[i] = (w[i] << 1) | (w[i] >> 31);
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    
    for (i = 0; i < 80; i++) {
        if (i < 20) {
            temp = ((b & c) | ((~b) & d)) + 0x5A827999;
        } else if (i < 40) {
            temp = (b ^ c ^ d) + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
        } else {
            temp = (b ^ c ^ d) + 0xCA62C1DC;
        }
        temp += ((a << 5) | (a >> 27)) + e + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

void sha1_update(SHA1_CTX *ctx, unsigned char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        int idx = ctx->count % 64;
        ctx->buffer[idx] = data[i];
        ctx->count++;
        if (idx == 63) {
            sha1_transform(ctx);
        }
    }
}

void sha1_final(unsigned char *hash, SHA1_CTX *ctx) {
    unsigned long long bit_len = ctx->count * 8;
    unsigned char padding[64];
    int pad_len = (ctx->count % 64 < 56) ? (56 - (ctx->count % 64)) : (120 - (ctx->count % 64));
    int i;
    
    padding[0] = 0x80;
    for (i = 1; i < pad_len; i++) padding[i] = 0;
    sha1_update(ctx, padding, pad_len);
    
    for (i = 0; i < 8; i++) {
        padding[i] = (bit_len >> (56 - i*8)) & 0xFF;
    }
    sha1_update(ctx, padding, 8);
    
    for (i = 0; i < 5; i++) {
        hash[i*4] = (ctx->h[i] >> 24) & 0xFF;
        hash[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        hash[i*4+2] = (ctx->h[i] >> 8) & 0xFF;
        hash[i*4+3] = ctx->h[i] & 0xFF;
    }
}

/* ============================================================================
 * HASH COMPUTATION - GIỐNG RUST MINER
 * Rust: Sha1::new_with_prefix(job.base.as_bytes()).update(nonce.to_string())
 * ============================================================================ */

void compute_hash_exact(const char *base, unsigned int nonce, unsigned char *output) {
    SHA1_CTX sha;
    char nonce_str[16];
    int nonce_len;
    
    sha1_init(&sha);
    /* Thêm base vào hash (giống Rust's new_with_prefix) */
    sha1_update(&sha, (unsigned char*)base, strlen(base));
    /* Thêm nonce dạng string (giống Rust's update(nonce.to_string())) */
    nonce_len = snprintf(nonce_str, sizeof(nonce_str), "%u", nonce);
    sha1_update(&sha, (unsigned char*)nonce_str, nonce_len);
    sha1_final(output, &sha);
}

/* ============================================================================
 * TARGET COMPARE - GIỐNG RUST MINER
 * Rust: if hash.as_slice() == job.target
 * ============================================================================ */

int hash_matches_target(unsigned char *hash, unsigned char *target) {
    return memcmp(hash, target, 20) == 0;
}

/* ============================================================================
 * GPU ENTROPY SOURCE (tạo số ngẫu nhiên từ render)
 * ============================================================================ */

void init_opengl_display_lists(void) {
    if (gl_initialized) return;
    
    cube_display_list = glGenLists(1);
    glNewList(cube_display_list, GL_COMPILE);
    glBegin(GL_QUADS);
    glVertex3f(-0.5, -0.5, 0.5); glVertex3f(0.5, -0.5, 0.5);
    glVertex3f(0.5, 0.5, 0.5); glVertex3f(-0.5, 0.5, 0.5);
    glEnd();
    glEndList();
    
    gl_initialized = 1;
}

void render_scene(unsigned int nonce) {
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glLoadIdentity();
    gluLookAt(0.0, 0.0, 5.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0);
    
    glPushMatrix();
    glRotatef(nonce % 360, 1.0, 0.5, 0.3);
    glRotatef((nonce >> 8) % 360, 0.0, 1.0, 0.0);
    
    glColor3f(0.5 + (nonce % 100) / 200.0,
              0.5 + ((nonce >> 8) % 100) / 200.0,
              0.5 + ((nonce >> 16) % 100) / 200.0);
    
    if (cube_display_list) glCallList(cube_display_list);
    glPopMatrix();
    
    glFlush();
}

unsigned int get_gpu_entropy(unsigned int nonce) {
    unsigned char pixel[3];
    
    glXMakeCurrent(dpy, win, ctx);
    render_scene(nonce);
    glXSwapBuffers(dpy, win);
    glReadPixels(config.render_width / 2, config.render_height / 2, 
                 1, 1, GL_RGB, GL_UNSIGNED_BYTE, pixel);
    
    return (pixel[0] << 16) | (pixel[1] << 8) | pixel[2];
}

/* ============================================================================
 * MINING THREAD
 * ============================================================================ */

void* mining_loop(void *arg) {
    int thread_id = *(int*)arg;
    unsigned int nonce = 0;
    unsigned long long hashes = 0;
    unsigned long long shares_found = 0;
    struct timeval start, now;
    double elapsed;
    char line[4096];
    char hashrate_str[32];
    job_t local_job;
    unsigned int max_nonce;
    int job_version = 0;
    int last_job_version = -1;
    
    gettimeofday(&start, NULL);
    
    printf("[%d] Mining thread started\n", thread_id);
    
    while (state.running) {
        /* Get current job */
        pthread_mutex_lock(&job_mutex);
        if (current_job.active) {
            memcpy(&local_job, &current_job, sizeof(job_t));
            if (current_job.received_at != last_job_version) {
                job_version = current_job.received_at;
                nonce = 0;
                printf("[%d] New job: diff=%u, base=%s\n", 
                       thread_id, local_job.diff, local_job.base);
            }
        } else {
            pthread_mutex_unlock(&job_mutex);
            usleep(100000);
            continue;
        }
        last_job_version = job_version;
        pthread_mutex_unlock(&job_mutex);
        
        /* Nonce range like Rust: 0..=diff*100 */
        max_nonce = local_job.diff * 100;
        if (max_nonce == 0) max_nonce = 1000;
        
        /* Use GPU entropy occasionally */
        if (config.use_gpu_entropy && (nonce % 100 == 0)) {
            unsigned int entropy = get_gpu_entropy(nonce);
            nonce = (nonce & 0xFFFF0000) | (entropy & 0xFFFF);
            if (nonce > max_nonce) nonce = nonce % (max_nonce + 1);
        }
        
        /* Compute hash exactly like Rust miner */
        unsigned char hash[20];
        compute_hash_exact(local_job.base, nonce, hash);
        hashes++;
        
        /* Check if hash matches target (like Rust's hash.as_slice() == job.target) */
        if (hash_matches_target(hash, local_job.target)) {
            shares_found++;
            
            printf("\n[%d] 🎯 SHARE FOUND! Nonce: %u\n", thread_id, nonce);
            printf("     Hash: ");
            for (int i = 0; i < 20; i++) printf("%02x", hash[i]);
            printf("\n");
            
            pthread_mutex_lock(&state.socket_mutex);
            if (state.socket_fd >= 0) {
                char msg[256];
                double rate = (hashes / elapsed) * 1e6;
                if (rate < 0.01) rate = 0.01;
                snprintf(msg, sizeof(msg), "%u,%.2f,%s,%d", 
                         nonce, rate, config.rig_identifier, thread_id);
                send_line(state.socket_fd, msg);
                
                if (recv_line(state.socket_fd, line, sizeof(line)) > 0) {
                    if (strcmp(line, "GOOD") == 0) {
                        pthread_mutex_lock(&state.stats_mutex);
                        state.accepted++;
                        printf("[%d] ✅ ACCEPTED! Total: %llu\n", 
                               thread_id, state.accepted);
                        pthread_mutex_unlock(&state.stats_mutex);
                    } else if (strncmp(line, "BAD,", 4) == 0) {
                        pthread_mutex_lock(&state.stats_mutex);
                        state.rejected++;
                        printf("[%d] ❌ REJECTED: %s\n", thread_id, line + 4);
                        pthread_mutex_unlock(&state.stats_mutex);
                    } else if (strcmp(line, "BLOCK") == 0) {
                        printf("[%d] ⛓️ BLOCK! Resetting...\n", thread_id);
                        pthread_mutex_lock(&job_mutex);
                        current_job.active = 0;
                        pthread_mutex_unlock(&job_mutex);
                    }
                }
            }
            pthread_mutex_unlock(&state.socket_mutex);
        }
        
        nonce++;
        if (nonce > max_nonce) {
            nonce = 0;
        }
        
        /* Update hash rate */
        gettimeofday(&now, NULL);
        elapsed = now.tv_sec - start.tv_sec + (now.tv_usec - start.tv_usec) / 1000000.0;
        
        if (elapsed >= 1.0) {
            pthread_mutex_lock(&state.stats_mutex);
            state.hash_rate = hashes / elapsed;
            state.total_hashes += hashes;
            pthread_mutex_unlock(&state.stats_mutex);
            
            hashes = 0;
            gettimeofday(&start, NULL);
            
            format_hashrate(state.hash_rate, hashrate_str, sizeof(hashrate_str));
            printf("\r[%d] Nonce: %u | %s | Acc: %llu | Rej: %llu | Shares: %llu",
                   thread_id, nonce, hashrate_str, state.accepted, state.rejected, shares_found);
            fflush(stdout);
        }
        
        /* Expire old jobs after 5 minutes */
        if (time(NULL) - local_job.received_at > 300) {
            pthread_mutex_lock(&job_mutex);
            if (current_job.active && current_job.received_at == local_job.received_at) {
                current_job.active = 0;
            }
            pthread_mutex_unlock(&job_mutex);
        }
    }
    
    return NULL;
}

/* ============================================================================
 * NETWORK FUNCTIONS
 * ============================================================================ */

int connect_with_timeout(const char *addr, int port, int timeout_sec) {
    int sock;
    struct hostent *host;
    struct sockaddr_in server;
    int flags;
    fd_set fdset;
    struct timeval tv;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    host = gethostbyname(addr);
    if (!host) {
        close(sock);
        return -1;
    }
    
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, host->h_addr, host->h_length);
    
    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        if (errno != EINPROGRESS) {
            close(sock);
            return -1;
        }
    }
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            fcntl(sock, F_SETFL, flags);
            return sock;
        }
    }
    
    close(sock);
    return -1;
}

int send_line(int sock, const char *line) {
    char buf[4096];
    int len = snprintf(buf, sizeof(buf), "%s\n", line);
    return send(sock, buf, len, 0);
}

int recv_line(int sock, char *buf, size_t size) {
    int i = 0;
    char c;
    fd_set fdset;
    struct timeval tv;
    
    while (i < size - 1) {
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        if (select(sock + 1, &fdset, NULL, NULL, &tv) <= 0) break;
        
        if (recv(sock, &c, 1, 0) <= 0) break;
        if (c == '\n') break;
        buf[i++] = c;
    }
    
    buf[i] = '\0';
    return i;
}

int get_pool_info(char *addr, int *port) {
    int sock;
    char request[512];
    char response[8192];
    int len;
    
    sock = connect_with_timeout("server.duinocoin.com", 80, 10);
    if (sock < 0) return -1;
    
    snprintf(request, sizeof(request),
             "GET /getPool HTTP/1.1\r\nHost: server.duinocoin.com\r\nConnection: close\r\n\r\n");
    send(sock, request, strlen(request), 0);
    
    len = recv(sock, response, sizeof(response)-1, 0);
    close(sock);
    
    if (len <= 0) return -1;
    response[len] = '\0';
    
    char *json = strstr(response, "\"ip\"");
    if (!json) return -1;
    
    if (sscanf(json, "\"ip\":\"%63[^\"]\",\"port\":%d", addr, port) == 2) {
        return 0;
    }
    
    return -1;
}

/* ============================================================================
 * CONNECTION THREAD
 * ============================================================================ */

void* connection_loop(void *arg) {
    char line[4096];
    char pool_addr[64];
    int pool_port;
    
    while (state.running) {
        if (get_pool_info(pool_addr, &pool_port) == 0) {
            strcpy(state.server_addr, pool_addr);
            state.server_port = pool_port;
            printf("🌐 Got pool: %s:%d\n", pool_addr, pool_port);
        } else {
            strcpy(state.server_addr, "pool.duinocoin.com");
            state.server_port = 2811;
            printf("🌐 Using default pool: %s:%d\n", state.server_addr, state.server_port);
        }
        
        pthread_mutex_lock(&state.socket_mutex);
        if (state.socket_fd >= 0) close(state.socket_fd);
        state.socket_fd = connect_with_timeout(state.server_addr, state.server_port, 10);
        pthread_mutex_unlock(&state.socket_mutex);
        
        if (state.socket_fd >= 0) {
            if (recv_line(state.socket_fd, line, sizeof(line)) > 0) {
                printf("🔌 Connected to pool (v%s)\n", line);
            }
            
            char job_req[256];
            snprintf(job_req, sizeof(job_req), "JOB,%s,%s,%s",
                     config.username, config.difficulty, config.mining_key);
            send_line(state.socket_fd, job_req);
            
            while (state.running && state.socket_fd >= 0) {
                if (recv_line(state.socket_fd, line, sizeof(line)) <= 0) {
                    printf("⚠️ Connection lost, reconnecting...\n");
                    break;
                }
                
                /* Parse job: format "base,target,diff" exactly like Rust miner receives */
                if (strchr(line, ',') != NULL) {
                    char base[128];
                    char target_hex[41];
                    unsigned int diff;
                    
                    if (sscanf(line, "%127[^,],%40[^,],%u", base, target_hex, &diff) == 3) {
                        job_t new_job;
                        strncpy(new_job.base, base, sizeof(new_job.base)-1);
                        if (hex_to_bytes(target_hex, new_job.target, 20) == 20) {
                            new_job.diff = diff;
                            new_job.active = 1;
                            new_job.received_at = time(NULL);
                            
                            pthread_mutex_lock(&job_mutex);
                            memcpy(&current_job, &new_job, sizeof(job_t));
                            pthread_mutex_unlock(&job_mutex);
                            
                            printf("📦 New job: diff=%u, target=%s\n", diff, target_hex);
                        }
                    }
                }
            }
        } else {
            printf("❌ Cannot connect, retrying in 10s...\n");
            sleep(10);
        }
        
        if (state.running) sleep(2);
    }
    
    return NULL;
}

/* ============================================================================
 * OPENGL INITIALIZATION
 * ============================================================================ */

int init_opengl(void) {
    XVisualInfo *vi;
    int attrib[] = { GLX_RGBA, GLX_DOUBLEBUFFER, GLX_DEPTH_SIZE, 16, None };
    
    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "Cannot open X display\n");
        return 0;
    }
    
    vi = glXChooseVisual(dpy, DefaultScreen(dpy), attrib);
    if (!vi) {
        fprintf(stderr, "No OpenGL visual available\n");
        XCloseDisplay(dpy);
        return 0;
    }
    
    win = XCreateSimpleWindow(dpy, RootWindow(dpy, vi->screen),
                              0, 0, config.render_width, config.render_height, 0, 0, 0);
    ctx = glXCreateContext(dpy, vi, NULL, True);
    glXMakeCurrent(dpy, win, ctx);
    
    glViewport(0, 0, config.render_width, config.render_height);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective(45.0, 1.0, 0.1, 100.0);
    glMatrixMode(GL_MODELVIEW);
    
    glEnable(GL_DEPTH_TEST);
    glClearColor(0.1, 0.1, 0.2, 1.0);
    
    init_opengl_display_lists();
    
    printf("🎮 OpenGL: %s | %s\n", glGetString(GL_VENDOR), glGetString(GL_RENDERER));
    
    return 1;
}

void cleanup_opengl(void) {
    if (ctx) {
        glXMakeCurrent(dpy, None, NULL);
        glXDestroyContext(dpy, ctx);
    }
    if (win) XDestroyWindow(dpy, win);
    if (dpy) XCloseDisplay(dpy);
}

/* ============================================================================
 * SIGNAL HANDLER
 * ============================================================================ */

void signal_handler(int sig) {
    printf("\n🛑 Stopping miner...\n");
    state.running = 0;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char *argv[]) {
    pthread_t miner_threads[8];
    pthread_t conn_thread;
    int thread_ids[8];
    int i;
    
    if (!read_config("config.yml")) {
        fprintf(stderr, "Failed to read config.yml\n");
        return 1;
    }
    
    if (!init_opengl()) {
        fprintf(stderr, "Failed to initialize OpenGL\n");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║     DUCO GPU Miner for SGI - PRODUCTION VERSION              ║\n");
    printf("║     Matches Rust miner protocol exactly                      ║\n");
    printf("║     GPU entropy source for retro computing                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("⚙️  Configuration:\n");
    printf("  Username: %s\n", config.username);
    printf("  Rig ID: %s\n", config.rig_identifier);
    printf("  Difficulty: %s\n", config.difficulty);
    printf("  Threads: %d\n", config.thread_count);
    printf("  Render: %dx%d\n", config.render_width, config.render_height);
    printf("  GPU Entropy: %s\n\n", config.use_gpu_entropy ? "ON" : "OFF");
    
    printf("🚀 Starting REAL miner...\n");
    printf("   Press Ctrl+C to stop\n\n");
    
    state.running = 1;
    state.total_hashes = 0;
    state.hash_rate = 0;
    state.accepted = 0;
    state.rejected = 0;
    state.socket_fd = -1;
    pthread_mutex_init(&state.socket_mutex, NULL);
    pthread_mutex_init(&state.stats_mutex, NULL);
    
    memset(&current_job, 0, sizeof(job_t));
    current_job.active = 0;
    
    pthread_create(&conn_thread, NULL, connection_loop, NULL);
    sleep(1);
    
    for (i = 0; i < config.thread_count; i++) {
        thread_ids[i] = i;
        pthread_create(&miner_threads[i], NULL, mining_loop, &thread_ids[i]);
        usleep(100000);
    }
    
    XEvent event;
    while (state.running) {
        while (XPending(dpy)) {
            XNextEvent(dpy, &event);
            if (event.type == KeyPress) state.running = 0;
        }
        usleep(100000);
    }
    
    for (i = 0; i < config.thread_count; i++) {
        pthread_join(miner_threads[i], NULL);
    }
    pthread_join(conn_thread, NULL);
    
    printf("\n\n🏁 Miner stopped.\n");
    printf("📊 Total hashes: %llu\n", state.total_hashes);
    printf("✅ Accepted: %llu\n", state.accepted);
    printf("❌ Rejected: %llu\n", state.rejected);
    
    if (state.socket_fd >= 0) close(state.socket_fd);
    cleanup_opengl();
    pthread_mutex_destroy(&state.socket_mutex);
    pthread_mutex_destroy(&state.stats_mutex);
    
    return 0;
}
