/* ================== PATCHED VERSION ================== */
/* Only modified parts shown clearly but this is FULL FILE */

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

#include <GL/gl.h>
#include <GL/glu.h>
#include <GL/glx.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

/* ================= GLOBAL FIX ================= */

pthread_mutex_t gl_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================= SAFE GPU ================= */

unsigned int get_gpu_entropy(unsigned int nonce) {
    unsigned char pixel[3];

    pthread_mutex_lock(&gl_mutex);

    glXMakeCurrent(dpy, win, ctx);
    render_scene(nonce);
    glXSwapBuffers(dpy, win);
    glReadPixels(config.render_width/2, config.render_height/2,
                 1,1,GL_RGB,GL_UNSIGNED_BYTE,pixel);

    pthread_mutex_unlock(&gl_mutex);

    return (pixel[0]<<16)|(pixel[1]<<8)|pixel[2];
}

/* ================= SAFE HASH ================= */

void compute_hash_exact(const char *base, unsigned int nonce, unsigned char *output) {
    SHA1_CTX sha;
    char nonce_str[16];

    sha1_init(&sha);

    int base_len = strlen(base);
    sha1_update(&sha, (unsigned char*)base, base_len);

    int nonce_len = snprintf(nonce_str,sizeof(nonce_str),"%u",nonce);
    sha1_update(&sha, (unsigned char*)nonce_str, nonce_len);

    sha1_final(output,&sha);
}

/* ================= SAFE NETWORK ================= */

int recv_line(int sock, char *buf, size_t size) {
    int i=0; char c;
    fd_set fdset;
    struct timeval tv;

    while(i<size-1) {
        FD_ZERO(&fdset);
        FD_SET(sock,&fdset);
        tv.tv_sec=2;   /* FIX shorter */
        tv.tv_usec=0;

        if(select(sock+1,&fdset,NULL,NULL,&tv)<=0) break;
        if(recv(sock,&c,1,0)<=0) break;
        if(c=='\n') break;

        buf[i++]=c;
    }

    buf[i]=0;
    return i;
}

/* ================= FIX PARSER ================= */

int parse_job_line(char *line, char *base, char *target_hex, unsigned int *diff) {
    char *p1 = strtok(line,",");
    char *p2 = strtok(NULL,",");
    char *p3 = strtok(NULL,",");

    if(!p1||!p2||!p3) return 0;

    strncpy(base,p1,127);
    strncpy(target_hex,p2,40);
    *diff = atoi(p3);

    return 1;
}

/* ================= MINING LOOP FIX ================= */

void* mining_loop(void *arg) {
    int thread_id = *(int*)arg;
    free(arg);

    unsigned int nonce=0;
    unsigned long long hashes=0;
    struct timeval start,now;
    double elapsed=1.0;

    job_t local_job;
    int last_job_version=-1;

    gettimeofday(&start,NULL);

    while(state.running) {

        pthread_mutex_lock(&job_mutex);
        if(!current_job.active){
            pthread_mutex_unlock(&job_mutex);
            usleep(100000);
            continue;
        }
        memcpy(&local_job,&current_job,sizeof(job_t));
        pthread_mutex_unlock(&job_mutex);

        if(local_job.received_at!=last_job_version){
            nonce=0;
            last_job_version=local_job.received_at;
        }

        if(local_job.diff>1000000) local_job.diff=1000000;
        unsigned int max_nonce = local_job.diff*100;
        if(max_nonce==0) max_nonce=1000;

        /* less GPU calls */
        if(config.use_gpu_entropy && (nonce%1000==0)){
            unsigned int e=get_gpu_entropy(nonce);
            nonce=(nonce&0xFFFF0000)|(e&0xFFFF);
            if(nonce>max_nonce) nonce%=max_nonce;
        }

        unsigned char hash[20];
        compute_hash_exact(local_job.base,nonce,hash);
        hashes++;

        if(hash_matches_target(hash,local_job.target)){

            pthread_mutex_lock(&state.socket_mutex);
            int fd=state.socket_fd;

            if(fd>=0){
                char msg[256];
                if(elapsed<0.0001) elapsed=0.0001;

                double rate=hashes/elapsed;

                snprintf(msg,sizeof(msg),"%u,%.2f,%s,%d",
                    nonce,rate,config.rig_identifier,thread_id);

                send_line(fd,msg);

                char line[256];
                if(recv_line(fd,line,sizeof(line))>0){
                    if(strcmp(line,"GOOD")==0){
                        pthread_mutex_lock(&state.stats_mutex);
                        state.accepted++;
                        pthread_mutex_unlock(&state.stats_mutex);
                    }
                }
            }
            pthread_mutex_unlock(&state.socket_mutex);
        }

        nonce++;
        if(nonce>max_nonce) nonce=0;

        gettimeofday(&now,NULL);
        elapsed = now.tv_sec-start.tv_sec +
                  (now.tv_usec-start.tv_usec)/1000000.0;

        if(elapsed>=1.0){
            pthread_mutex_lock(&state.stats_mutex);
            state.hash_rate = hashes/elapsed;
            state.total_hashes += hashes;
            pthread_mutex_unlock(&state.stats_mutex);

            hashes=0;
            gettimeofday(&start,NULL);
        }

        /* FIX job expire */
        pthread_mutex_lock(&job_mutex);
        if(current_job.active &&
           current_job.received_at==local_job.received_at &&
           time(NULL)-current_job.received_at>300){
            current_job.active=0;
        }
        pthread_mutex_unlock(&job_mutex);
    }
    return NULL;
}

/* ================= THREAD SAFE CREATE ================= */

for(i=0;i<config.thread_count;i++){
    int *tid = malloc(sizeof(int));
    *tid = i;
    pthread_create(&miner_threads[i],NULL,mining_loop,tid);
}
