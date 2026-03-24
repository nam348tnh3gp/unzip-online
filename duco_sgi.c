/*
 * DUCO GPU Miner for SGI Workstations
 * Based on official Rust miner protocol
 * Reads config from config.yml
 * Compile on IRIX: cc -o duco_sgi duco_sgi.c -lGL -lGLU -lX11 -lm -lpthread -lsocket -lnsl
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
#include <GL/gl.h>
#include <GL/glu.h>
#include <GL/glx.h>
#include <X11/Xlib.h>

/* === CẤU HÌNH TỪ FILE === */
typedef struct {
    char username[64];
    char mining_key[64];
    char difficulty[16];
    char rig_identifier[64];
    int thread_count;
} config_t;

static config_t config;

/* === HẰNG SỐ MẶC ĐỊNH === */
#define RENDER_WIDTH 256
#define RENDER_HEIGHT 256
#define MAX_BUFFER 4096

/* === CẤU TRÚC === */
typedef struct {
    volatile int running;
    unsigned long long total_hashes;
    double hash_rate;
    unsigned long long accepted;
    unsigned long long rejected;
    char server_addr[64];
    int server_port;
} miner_state_t;

typedef struct {
    char base[128];
    unsigned char target[20];
    unsigned int diff;
} job_t;

/* === GLOBAL === */
static Display *dpy;
static Window win;
static GLXContext ctx;
static miner_state_t state;
static pthread_mutex_t socket_mutex = PTHREAD_MUTEX_INITIALIZER;
static int sock_fd = -1;

/* === ĐỌC FILE CONFIG.YML === */
int read_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("❌ Cannot open %s\n", filename);
        return 0;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char key[64], value[128];
        if (sscanf(line, " %63[^:]: %127[^\n]", key, value) == 2) {
            /* Xóa dấu ngoặc kép và khoảng trắng */
            char *start = value;
            char *end = value + strlen(value) - 1;
            if (*start == '"') start++;
            if (*end == '"') *end = '\0';
            while (isspace(*start)) start++;
            
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
            }
        }
    }
    
    fclose(fp);
    
    /* Giá trị mặc định nếu thiếu */
    if (config.thread_count <= 0) config.thread_count = 1;
    if (strlen(config.difficulty) == 0) strcpy(config.difficulty, "08");
    
    return 1;
}

/* === CHUYỂN DIFFICULTY STRING THÀNH SỐ HEX === */
unsigned int parse_difficulty(const char *diff_str) {
    if (strcasecmp(diff_str, "LOW") == 0) return 4;
    if (strcasecmp(diff_str, "MEDIUM") == 0) return 8;
    if (strcasecmp(diff_str, "HIGH") == 0) return 12;
    if (strncasecmp(diff_str, "CUSTOM", 6) == 0) {
        int val;
        if (sscanf(diff_str + 6, "%d", &val) == 1) return val;
    }
    /* Nếu là hex string */
    return (unsigned int)strtol(diff_str, NULL, 16);
}

/* === UTILITY === */
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

/* === SHA1 IMPLEMENTATION === */
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
        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) << 1;
        w[i] |= (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) >> 31;
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
        temp += a + e + w[i];
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
    
    padding[0] = 0x80;
    for (int i = 1; i < pad_len; i++) padding[i] = 0;
    sha1_update(ctx, padding, pad_len);
    
    for (int i = 0; i < 8; i++) {
        padding[i] = (bit_len >> (56 - i*8)) & 0xFF;
    }
    sha1_update(ctx, padding, 8);
    
    for (int i = 0; i < 5; i++) {
        hash[i*4] = (ctx->h[i] >> 24) & 0xFF;
        hash[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        hash[i*4+2] = (ctx->h[i] >> 8) & 0xFF;
        hash[i*4+3] = ctx->h[i] & 0xFF;
    }
}

/* === OPENGL FIXED PIPELINE RENDER === */
void render_scene(unsigned int nonce) {
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glLoadIdentity();
    
    gluLookAt(0.0, 0.0, 5.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0);
    
    glPushMatrix();
    glRotatef(nonce % 360, 1.0, 0.0, 0.0);
    glRotatef((nonce >> 8) % 360, 0.0, 1.0, 0.0);
    glRotatef((nonce >> 16) % 360, 0.0, 0.0, 1.0);
    
    float scale = 0.5 + (nonce % 100) / 100.0;
    glScalef(scale, scale, scale);
    
    static GLuint cube_list = 0;
    if (cube_list == 0) {
        cube_list = glGenLists(1);
        glNewList(cube_list, GL_COMPILE);
        glBegin(GL_QUADS);
        glVertex3f(-0.5, -0.5, 0.5); glVertex3f(0.5, -0.5, 0.5);
        glVertex3f(0.5, 0.5, 0.5); glVertex3f(-0.5, 0.5, 0.5);
        glVertex3f(-0.5, -0.5, -0.5); glVertex3f(-0.5, 0.5, -0.5);
        glVertex3f(0.5, 0.5, -0.5); glVertex3f(0.5, -0.5, -0.5);
        glEnd();
        glEndList();
    }
    
    glColor3f(0.2, 0.6, 0.8);
    glCallList(cube_list);
    
    float light_pos[] = {2.0, 2.0, 3.0, 1.0};
    float light_ambient[] = {0.2, 0.2, 0.2, 1.0};
    float light_diffuse[] = {0.8, 0.8, 0.8, 1.0};
    glLightfv(GL_LIGHT0, GL_POSITION, light_pos);
    glLightfv(GL_LIGHT0, GL_AMBIENT, light_ambient);
    glLightfv(GL_LIGHT0, GL_DIFFUSE, light_diffuse);
    
    glPopMatrix();
    
    for (int i = 0; i < 5; i++) {
        glPushMatrix();
        glTranslatef(sin(i * 1.2 + nonce * 0.01) * 2.0,
                     cos(i * 1.5 + nonce * 0.008) * 2.0,
                     sin(i * 2.0 + nonce * 0.005) * 1.5);
        glRotatef(nonce * 0.1 + i * 72.0, 1.0, 1.0, 0.0);
        glColor3f(0.8, 0.4, 0.2);
        glBegin(GL_TRIANGLES);
        glVertex3f(0.0, 0.5, 0.0);
        glVertex3f(-0.4, -0.3, 0.3);
        glVertex3f(0.4, -0.3, 0.3);
        glEnd();
        glPopMatrix();
    }
}

void read_pixel_buffer(unsigned char *buffer) {
    glReadPixels(0, 0, RENDER_WIDTH, RENDER_HEIGHT, GL_RGB, GL_UNSIGNED_BYTE, buffer);
}

/* === HASH TỪ GPU === */
void hash_from_gpu(unsigned int nonce, unsigned char *output) {
    unsigned char pixel_buffer[RENDER_WIDTH * RENDER_HEIGHT * 3];
    SHA1_CTX sha;
    
    render_scene(nonce);
    glXSwapBuffers(dpy, win);
    read_pixel_buffer(pixel_buffer);
    
    sha1_init(&sha);
    sha1_update(&sha, pixel_buffer, RENDER_WIDTH * RENDER_HEIGHT * 3);
    sha1_update(&sha, (unsigned char*)&nonce, 4);
    sha1_final(output, &sha);
}

/* === KIỂM TRA DIFFICULTY === */
int check_difficulty(unsigned char *hash, unsigned int diff) {
    int zeros = 0;
    unsigned char h = hash[0];
    
    while (zeros < diff) {
        if ((h & 0xF0) == 0) { zeros += 4; h <<= 4; }
        else if ((h & 0xE0) == 0) { zeros += 3; h <<= 3; }
        else if ((h & 0xC0) == 0) { zeros += 2; h <<= 2; }
        else if ((h & 0x80) == 0) { zeros += 1; h <<= 1; }
        else break;
    }
    return zeros >= diff;
}

/* === KẾT NỐI ĐẾN POOL === */
int connect_to_pool(const char *addr, int port) {
    struct sockaddr_in server;
    struct hostent *host;
    int sock;
    
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
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

int send_line(int sock, const char *line) {
    char buf[MAX_BUFFER];
    int len = snprintf(buf, sizeof(buf), "%s\n", line);
    return send(sock, buf, len, 0);
}

int recv_line(int sock, char *buf, size_t size) {
    int i = 0;
    char c;
    while (i < size - 1 && recv(sock, &c, 1, 0) > 0) {
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

/* === LUỒNG MINING === */
void* mining_loop(void *arg) {
    int thread_id = *(int*)arg;
    unsigned int nonce = 0;
    unsigned long long hashes = 0;
    struct timeval start, now;
    double elapsed;
    char hash_hex[41];
    char line[MAX_BUFFER];
    char hashrate_str[32];
    unsigned int difficulty = parse_difficulty(config.difficulty);
    
    gettimeofday(&start, NULL);
    
    while (state.running) {
        unsigned char hash[20];
        
        hash_from_gpu(nonce, hash);
        hashes++;
        
        if (check_difficulty(hash, difficulty)) {
            for (int i = 0; i < 20; i++) {
                sprintf(hash_hex + i*2, "%02x", hash[i]);
            }
            
            double hashrate = (hashes / elapsed) * 1e6;
            format_hashrate(hashrate, hashrate_str, sizeof(hashrate_str));
            
            printf("[%d] 🎯 Share found! Nonce: %u | Hash: %s | Rate: %s\n",
                   thread_id, nonce, hash_hex, hashrate_str);
            
            pthread_mutex_lock(&socket_mutex);
            if (sock_fd >= 0) {
                char msg[256];
                snprintf(msg, sizeof(msg), "%u,%.2f,%s,%d", 
                         nonce, hashrate, config.rig_identifier, thread_id);
                send_line(sock_fd, msg);
                
                if (recv_line(sock_fd, line, sizeof(line)) > 0) {
                    if (strcmp(line, "GOOD") == 0) {
                        state.accepted++;
                        printf("[%d] ✅ Share accepted! Total: %llu\n", 
                               thread_id, state.accepted);
                    } else if (strncmp(line, "BAD,", 4) == 0) {
                        state.rejected++;
                        printf("[%d] ❌ Rejected: %s\n", thread_id, line + 4);
                    } else if (strcmp(line, "BLOCK") == 0) {
                        printf("[%d] ⛓️ New block!\n", thread_id);
                    }
                }
            }
            pthread_mutex_unlock(&socket_mutex);
        }
        
        nonce++;
        
        gettimeofday(&now, NULL);
        elapsed = now.tv_sec - start.tv_sec + (now.tv_usec - start.tv_usec) / 1000000.0;
        
        if (elapsed >= 1.0) {
            state.hash_rate = hashes / elapsed;
            state.total_hashes += hashes;
            hashes = 0;
            gettimeofday(&start, NULL);
            
            char hr_str[32];
            format_hashrate(state.hash_rate, hr_str, sizeof(hr_str));
            printf("\r[%d] 🔹 Nonce: %u | Hashrate: %s | Acc: %llu | Rej: %llu",
                   thread_id, nonce, hr_str, state.accepted, state.rejected);
            fflush(stdout);
        }
    }
    
    return NULL;
}

/* === LUỒNG KẾT NỐI POOL === */
void* connection_loop(void *arg) {
    char line[MAX_BUFFER];
    
    while (state.running) {
        int control_sock = connect_to_pool("server.duinocoin.com", 80);
        if (control_sock >= 0) {
            char request[256];
            snprintf(request, sizeof(request),
                     "GET /getPool HTTP/1.1\r\nHost: server.duinocoin.com\r\nConnection: close\r\n\r\n");
            send(control_sock, request, strlen(request), 0);
            
            char response[4096];
            int len = recv(control_sock, response, sizeof(response)-1, 0);
            close(control_sock);
            
            if (len > 0) {
                response[len] = '\0';
                char *json = strstr(response, "\"ip\"");
                if (json) {
                    char ip[64];
                    int port;
                    sscanf(json, "\"ip\":\"%[^\"]\",\"port\":%d", ip, &port);
                    strcpy(state.server_addr, ip);
                    state.server_port = port;
                    printf("🌐 Got pool: %s:%d\n", ip, port);
                }
            }
        }
        
        pthread_mutex_lock(&socket_mutex);
        if (sock_fd >= 0) close(sock_fd);
        sock_fd = connect_to_pool(state.server_addr, state.server_port);
        pthread_mutex_unlock(&socket_mutex);
        
        if (sock_fd >= 0) {
            if (recv_line(sock_fd, line, sizeof(line)) > 0) {
                printf("🔌 Connected to pool (v%s)\n", line);
            }
            
            char job_req[256];
            snprintf(job_req, sizeof(job_req), "JOB,%s,%s,%s",
                     config.username, config.difficulty, config.mining_key);
            send_line(sock_fd, job_req);
            
            while (state.running && sock_fd >= 0) {
                if (recv_line(sock_fd, line, sizeof(line)) <= 0) break;
            }
        }
        
        sleep(5);
    }
    
    return NULL;
}

/* === SIGNAL HANDLER === */
void signal_handler(int sig) {
    printf("\n🛑 Stopping miner...\n");
    state.running = 0;
}

/* === MAIN === */
int main(int argc, char *argv[]) {
    pthread_t miner_threads[16];
    pthread_t conn_thread;
    XVisualInfo *vi;
    int attrib[] = { GLX_RGBA, GLX_DOUBLEBUFFER, GLX_DEPTH_SIZE, 16, None };
    
    /* Đọc config */
    if (!read_config("config.yml")) {
        printf("❌ Failed to read config.yml\n");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║     DUCO GPU Miner for SGI Workstations                       ║\n");
    printf("║     Using OpenGL 1.x Fixed Pipeline                           ║\n");
    printf("║     Based on Rust miner protocol                     ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    /* Khởi tạo OpenGL */
    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        printf("❌ Cannot open X display\n");
        return 1;
    }
    
    vi = glXChooseVisual(dpy, DefaultScreen(dpy), attrib);
    if (!vi) {
        printf("❌ No OpenGL visual available\n");
        XCloseDisplay(dpy);
        return 1;
    }
    
    win = XCreateSimpleWindow(dpy, RootWindow(dpy, vi->screen),
                              0, 0, RENDER_WIDTH, RENDER_HEIGHT, 0, 0, 0);
    ctx = glXCreateContext(dpy, vi, NULL, True);
    glXMakeCurrent(dpy, win, ctx);
    
    glViewport(0, 0, RENDER_WIDTH, RENDER_HEIGHT);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    gluPerspective(45.0, 1.0, 0.1, 100.0);
    glMatrixMode(GL_MODELVIEW);
    
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_LIGHTING);
    glEnable(GL_LIGHT0);
    glEnable(GL_COLOR_MATERIAL);
    glClearColor(0.1, 0.1, 0.2, 1.0);
    
    printf("🎮 OpenGL Context:\n");
    printf("   Vendor: %s\n", glGetString(GL_VENDOR));
    printf("   Renderer: %s\n", glGetString(GL_RENDERER));
    printf("   Version: %s\n\n", glGetString(GL_VERSION));
    
    printf("⚙️  Configuration:\n");
    printf("   Username: %s\n", config.username);
    printf("   Mining Key: %s\n", config.mining_key);
    printf("   Difficulty: %s\n", config.difficulty);
    printf("   Rig ID: %s\n", config.rig_identifier);
    printf("   Threads: %d\n\n", config.thread_count);
    
    printf("🚀 Starting GPU miner...\n");
    printf("   Press Ctrl+C to stop\n\n");
    
    state.running = 1;
    state.total_hashes = 0;
    state.hash_rate = 0;
    state.accepted = 0;
    state.rejected = 0;
    sock_fd = -1;
    
    /* Khởi tạo connection thread */
    pthread_create(&conn_thread, NULL, connection_loop, NULL);
    
    /* Khởi tạo mining threads */
    int thread_ids[16];
    for (int i = 0; i < config.thread_count && i < 16; i++) {
        thread_ids[i] = i;
        pthread_create(&miner_threads[i], NULL, mining_loop, &thread_ids[i]);
        usleep(100000);
    }
    
    /* Vòng lặp xử lý sự kiện X */
    XEvent event;
    while (state.running) {
        while (XPending(dpy)) {
            XNextEvent(dpy, &event);
            if (event.type == KeyPress) state.running = 0;
        }
        usleep(50000);
    }
    
    for (int i = 0; i < config.thread_count && i < 16; i++) {
        pthread_join(miner_threads[i], NULL);
    }
    pthread_join(conn_thread, NULL);
    
    printf("\n\n🏁 Miner stopped.\n");
    printf("📊 Total hashes: %llu\n", state.total_hashes);
    printf("✅ Accepted shares: %llu\n", state.accepted);
    printf("❌ Rejected shares: %llu\n", state.rejected);
    
    if (sock_fd >= 0) close(sock_fd);
    glXMakeCurrent(dpy, None, NULL);
    glXDestroyContext(dpy, ctx);
    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    
    return 0;
}
