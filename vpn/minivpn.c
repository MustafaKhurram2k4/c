#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <syslog.h>
#include <ini.h>

#define MAX_KEY_LENGTH 32
#define IV_LENGTH 16
#define BUFFER_LENGTH 4096
#define HASH_LENGTH 32
#define MAX_BLOCK_LENGTH (BUFFER_LENGTH + EVP_MAX_BLOCK_LENGTH + HASH_LENGTH)
#define POKE_INTERVAL 3

#define CHK_NULL(x) if (!(x)) { syslog(LOG_ERR, "Null pointer: %s", #x); exit(1); }
#define CHK_ERR(err,s) if ((err) == -1) { syslog(LOG_ERR, "%s: %s", s, strerror(errno)); exit(1); }
#define CHK_SSL(err,s) if ((err) <= 0) { ERR_print_errors_fp(stderr); syslog(LOG_ERR, "%s", s); exit(2); }

typedef enum { CLIENT, SERVER } Mode;

typedef struct {
    char key[MAX_KEY_LENGTH + 1];
    unsigned char iv[IV_LENGTH];
    char cert_file[256];
    char key_file[256];
    char ca_file[256];
    char interface[IFNAMSIZ];
    int port;
    char target_ip[16];
    Mode mode;
    int debug;
} Config;

typedef struct {
    int tun_fd;
    int udp_fd;
    int tcp_fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    struct sockaddr_in remote_addr;
    int remote_len;
    int pipe_fd[2];
    int timer_fd;
} Connection;

Config config = {
    .key = "defaultkey1234567890123456789012",
    .iv = {0},
    .cert_file = "cert.pem",
    .key_file = "key.pem",
    .ca_file = "ca.pem",
    .interface = "tun%d",
    .port = 0,
    .target_ip = "",
    .mode = -1,
    .debug = 0
};

void log_message(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (config.debug) {
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    }
    vsyslog(level, fmt, args);
    va_end(args);
}

int init_tun_device(const char *ifname) {
    struct ifreq ifr = {0};
    int fd = open("/dev/net/tun", O_RDWR);
    CHK_ERR(fd, "open tun device");
    
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    CHK_ERR(ioctl(fd, TUNSETIFF, &ifr), "ioctl TUNSETIFF");
    
    log_message(LOG_INFO, "Allocated interface %s", ifr.ifr_name);
    return fd;
}

int init_udp_socket(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHK_ERR(fd, "create UDP socket");
    
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };
    
    CHK_ERR(bind(fd, (struct sockaddr*)&sin, sizeof(sin)), "bind UDP socket");
    return fd;
}

int init_tcp_socket(int port, Mode mode) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(fd, "create TCP socket");
    
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };
    
    CHK_ERR(bind(fd, (struct sockaddr*)&sin, sizeof(sin)), "bind TCP socket");
    if (mode == SERVER) {
        CHK_ERR(listen(fd, 5), "listen TCP socket");
    }
    return fd;
}

SSL_CTX* init_ssl_context(Mode mode) {
    const SSL_METHOD *method = mode == CLIENT ? TLS_client_method() : TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    CHK_NULL(ctx);
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    CHK_ERR(SSL_CTX_load_verify_locations(ctx, config.ca_file, NULL), "load CA");
    CHK_ERR(SSL_CTX_use_certificate_file(ctx, config.cert_file, SSL_FILETYPE_PEM), "load cert");
    CHK_ERR(SSL_CTX_use_PrivateKey_file(ctx, config.key_file, SSL_FILETYPE_PEM), "load key");
    CHK_ERR(SSL_CTX_check_private_key(ctx), "check private key");
    
    return ctx;
}

void encrypt_data(const unsigned char *in, int in_len, unsigned char *out, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHK_NULL(ctx);
    
    int tmp_len;
    CHK_ERR(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)config.key, config.iv), "encrypt init");
    CHK_ERR(EVP_EncryptUpdate(ctx, out, out_len, in, in_len), "encrypt update");
    CHK_ERR(EVP_EncryptFinal_ex(ctx, out + *out_len, &tmp_len), "encrypt final");
    *out_len += tmp_len;
    
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_data(const unsigned char *in, int in_len, unsigned char *out, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHK_NULL(ctx);
    
    int tmp_len;
    CHK_ERR(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)config.key, config.iv), "decrypt init");
    CHK_ERR(EVP_DecryptUpdate(ctx, out, out_len, in, in_len), "decrypt update");
    CHK_ERR(EVP_DecryptFinal_ex(ctx, out + *out_len, &tmp_len), "decrypt final");
    *out_len += tmp_len;
    
    EVP_CIPHER_CTX_free(ctx);
}

void create_hmac(const unsigned char *in, int in_len, unsigned char *out, unsigned int *out_len) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    CHK_NULL(ctx);
    
    CHK_ERR(HMAC_Init_ex(ctx, config.key, strlen(config.key), EVP_sha256(), NULL), "HMAC init");
    CHK_ERR(HMAC_Update(ctx, in, in_len), "HMAC update");
    CHK_ERR(HMAC_Final(ctx, out, out_len), "HMAC final");
    
    HMAC_CTX_free(ctx);
}

int verify_hmac(const unsigned char *data, int data_len, const unsigned char *received_hmac, int hmac_len) {
    unsigned char computed_hmac[HASH_LENGTH];
    unsigned int computed_len;
    
    create_hmac(data, data_len, computed_hmac, &computed_len);
    return computed_len == hmac_len && memcmp(computed_hmac, received_hmac, hmac_len) == 0;
}

int load_config(const char *filename) {
    ini_t *ini = ini_load(filename, NULL);
    if (!ini) {
        log_message(LOG_ERR, "Failed to load config file %s", filename);
        return -1;
    }
    
    const char *value;
    if ((value = ini_get(ini, "crypto", "key"))) strncpy(config.key, value, MAX_KEY_LENGTH);
    if ((value = ini_get(ini, "crypto", "cert_file"))) strncpy(config.cert_file, value, 256);
    if ((value = ini_get(ini, "crypto", "key_file"))) strncpy(config.key_file, value, 256);
    if ((value = ini_get(ini, "crypto", "ca_file"))) strncpy(config.ca_file, value, 256);
    if ((value = ini_get(ini, "network", "interface"))) strncpy(config.interface, value, IFNAMSIZ);
    if ((value = ini_get(ini, "network", "port"))) config.port = atoi(value);
    if ((value = ini_get(ini, "network", "target_ip"))) strncpy(config.target_ip, value, 16);
    if ((value = ini_get(ini, "general", "mode"))) config.mode = strcmp(value, "client") == 0 ? CLIENT : SERVER;
    if ((value = ini_get(ini, "general", "debug"))) config.debug = atoi(value);
    
    ini_free(ini);
    return 0;
}

void display_client_menu(void) {
    printf("\n");
    printf("k - Enter KEY\n");
    printf("i - Enter IV\n");
    printf("r - Randomize KEY/IV pair\n");
    printf("c - Clear Session\n");
    printf("s - STOP\n");
    printf("> ");
    fflush(stdout);
}

void randomize_string(char *str, int len) {
    for (int i = 0; i < len; i++) {
        str[i] = (rand() % 93) + 33;
    }
    str[len] = '\0';
}

void randomize_array(unsigned char *arr, int len) {
    for (int i = 0; i < len; i++) {
        arr[i] = rand() % 256;
    }
}

void handle_client(Connection *conn) {
    fd_set fdset;
    char msg[BUFFER_LENGTH];
    char pokemsg[BUFFER_LENGTH];
    char common_name[512] = {0};
    int poke_count = 0;
    int cn_valid = 0, key_valid = 0, iv_valid = 0;
    
    conn->tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(conn->tcp_fd, "create TCP socket");
    
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(config.port)
    };
    inet_aton(config.target_ip, &sa.sin_addr);
    
    CHK_ERR(connect(conn->tcp_fd, (struct sockaddr*)&sa, sizeof(sa)), "connect TCP socket");
    
    conn->ssl = SSL_new(conn->ssl_ctx);
    CHK_NULL(conn->ssl);
    SSL_set_fd(conn->ssl, conn->tcp_fd);
    CHK_SSL(SSL_connect(conn->ssl), "SSL connect");
    
    log_message(LOG_INFO, "SSL connection using %s", SSL_get_cipher(conn->ssl));
    
    X509 *server_cert = SSL_get_peer_certificate(conn->ssl);
    CHK_NULL(server_cert);
    char *str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    log_message(LOG_INFO, "Server certificate subject: %s", str);
    OPENSSL_free(str);
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    log_message(LOG_INFO, "Server certificate issuer: %s", str);
    OPENSSL_free(str);
    X509_free(server_cert);
    
    printf("MiniVPN Client...\n");
    display_client_menu();
    
    while (1) {
        FD_ZERO(&fdset);
        FD_SET(STDIN_FILENO, &fdset);
        FD_SET(conn->tcp_fd, &fdset);
        
        if (select(conn->tcp_fd + 1, &fdset, NULL, NULL, NULL) < 0) {
            log_message(LOG_ERR, "Client select: %s", strerror(errno));
            break;
        }
        
        if (FD_ISSET(conn->tcp_fd, &fdset)) {
            int err = SSL_read(conn->ssl, pokemsg, sizeof(pokemsg) - 1);
            if (err <= 0) {
                log_message(LOG_ERR, "SSL read failed");
                break;
            }
            pokemsg[err] = '\0';
            if (strncmp(pokemsg, "POKE", 4) == 0) {
                log_message(LOG_DEBUG, "Received POKE, sending POKE_ACK (%d)", poke_count++);
                CHK_SSL(SSL_write(conn->ssl, "POKE_ACK", strlen("POKE_ACK")), "SSL write POKE_ACK");
            }
        }
        
        if (FD_ISSET(STDIN_FILENO, &fdset)) {
            // Notify child to stop
            strcpy(msg, "STOP");
            write(conn->pipe_fd[1], msg, strlen(msg) + 1);
            sleep(1);
            
            // Clear SSL session
            if (conn->ssl) {
                SSL_shutdown(conn->ssl);
                SSL_free(conn->ssl);
                conn->ssl = NULL;
            }
            if (conn->tcp_fd >= 0) {
                close(conn->tcp_fd);
                conn->tcp_fd = -1;
            }
            poke_count = 0;
            
            char input = getchar();
            while (getchar() != '\n'); // Clear input buffer
            
            if (tolower(input) == 'k') {
                printf("Enter CommonName (CN):\n>");
                scanf("%511s", common_name);
                printf("Enter KEY:\n>");
                scanf("%31s", config.key);
                while (getchar() != '\n');
            } else if (tolower(input) == 'i') {
                printf("Enter CommonName (CN):\n>");
                scanf("%511s", common_name);
                printf("Enter IV (%d bytes):\n", IV_LENGTH);
                for (int i = 0; i < IV_LENGTH; i++) config.iv[i] = getchar();
                while (getchar() != '\n');
            } else if (tolower(input) == 'r') {
                printf("Enter CommonName (CN):\n>");
                scanf("%511s", common_name);
                randomize_string(config.key, MAX_KEY_LENGTH);
                randomize_array(config.iv, IV_LENGTH);
                log_message(LOG_INFO, "Randomized KEY: %s", config.key);
            } else if (tolower(input) == 'c') {
                log_message(LOG_INFO, "Clearing SSL session");
                sleep(1);
                display_client_menu();
                continue;
            } else if (tolower(input) == 's') {
                log_message(LOG_INFO, "Closing tunnel");
                close(conn->tun_fd);
                close(conn->udp_fd);
                killpg(getpgid(getpid()), SIGTERM);
                exit(0);
            } else {
                display_client_menu();
                continue;
            }
            
            // Re-establish SSL connection
            conn->tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            CHK_ERR(conn->tcp_fd, "create TCP socket");
            CHK_ERR(connect(conn->tcp_fd, (struct sockaddr*)&sa, sizeof(sa)), "connect TCP socket");
            
            conn->ssl = SSL_new(conn->ssl_ctx);
            CHK_NULL(conn->ssl);
            SSL_set_fd(conn->ssl, conn->tcp_fd);
            CHK_SSL(SSL_connect(conn->ssl), "SSL connect");
            
            // Send CN
            snprintf(msg, sizeof(msg), "CN:%s", common_name);
            CHK_SSL(SSL_write(conn->ssl, msg, strlen(msg)), "SSL write CN");
            int err = SSL_read(conn->ssl, msg, sizeof(msg) - 1);
            CHK_SSL(err, "SSL read CN response");
            msg[err] = '\0';
            cn_valid = strncmp(msg, "CN_ACK", 6) == 0;
            log_message(cn_valid ? LOG_INFO : LOG_ERR, "CN response: %s", msg);
            
            // Send KEY
            snprintf(msg, sizeof(msg), "KEY:%s", config.key);
            CHK_SSL(SSL_write(conn->ssl, msg, strlen(msg)), "SSL write KEY");
            err = SSL_read(conn->ssl, msg, sizeof(msg) - 1);
            CHK_SSL(err, "SSL read KEY response");
            msg[err] = '\0';
            key_valid = strncmp(msg, "KEY_ACK", 7) == 0;
            log_message(key_valid ? LOG_INFO : LOG_ERR, "KEY response: %s", msg);
            
            // Send IV
            strcpy(msg, "IV:");
            memcpy(msg + 3, config.iv, IV_LENGTH);
            CHK_SSL(SSL_write(conn->ssl, msg, 3 + IV_LENGTH), "SSL write IV");
            err = SSL_read(conn->ssl, msg, sizeof(msg) - 1);
            CHK_SSL(err, "SSL read IV response");
            msg[err] = '\0';
            iv_valid = strncmp(msg, "IV_ACK", 6) == 0;
            log_message(iv_valid ? LOG_INFO : LOG_ERR, "IV response: %s", msg);
            
            if (cn_valid && key_valid && iv_valid) {
                // Send KEY to child
                snprintf(msg, sizeof(msg), "KEY:%s", config.key);
                write(conn->pipe_fd[1], msg, strlen(msg) + 1);
                sleep(1);
                
                // Send IV to child
                strcpy(msg, "IV:");
                memcpy(msg + 3, config.iv, IV_LENGTH);
                write(conn->pipe_fd[1], msg, 3 + IV_LENGTH);
                sleep(1);
                
                // Send remote address to child
                strcpy(msg, "FROM:");
                memcpy(msg + 5, &sa, sizeof(sa));
                write(conn->pipe_fd[1], msg, 5 + sizeof(sa));
                sleep(1);
                
                // Start child
                strcpy(msg, "START");
                write(conn->pipe_fd[1], msg, strlen(msg) + 1);
                sleep(1);
            }
            
            display_client_menu();
        }
    }
    
    if (conn->ssl) SSL_free(conn->ssl);
    if (conn->tcp_fd >= 0) close(conn->tcp_fd);
}

void handle_server(Connection *conn) {
    fd_set fdset;
    char msg[BUFFER_LENGTH];
    char pokemsg[BUFFER_LENGTH];
    int poke_count = 0;
    int cn_valid = 0, key_valid = 0, iv_valid = 0;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    conn->timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    CHK_ERR(conn->timer_fd, "create timer");
    
    struct itimerspec time_period = {{POKE_INTERVAL, 0}, {POKE_INTERVAL, 0}};
    CHK_ERR(timerfd_settime(conn->timer_fd, 0, &time_period, NULL), "set timer");
    
    printf("MiniVPN Server...\n");
    
    while (1) {
        FD_ZERO(&fdset);
        FD_SET(conn->tcp_fd, &fdset);
        FD_SET(conn->timer_fd, &fdset);
        
        if (select(conn->tcp_fd + conn->timer_fd + 1, &fdset, NULL, NULL, NULL) < 0) {
            log_message(LOG_ERR, "Server select: %s", strerror(errno));
            break;
        }
        
        if (FD_ISSET(conn->timer_fd, &fdset)) {
            uint64_t exp;
            read(conn->timer_fd, &exp, sizeof(exp));
            
            if (conn->ssl) {
                CHK_SSL(SSL_write(conn->ssl, "POKE", strlen("POKE")), "SSL write POKE");
                int err = SSL_read(conn->ssl, pokemsg, sizeof(pokemsg) - 1);
                if (err <= 0 || strncmp(pokemsg, "POKE_ACK", 8) != 0) {
                    log_message(LOG_ERR, "POKE failed, closing SSL");
                    if (conn->ssl) {
                        SSL_shutdown(conn->ssl);
                        SSL_free(conn->ssl);
                        conn->ssl = NULL;
                    }
                    if (conn->tcp_fd >= 0) {
                        close(conn->tcp_fd);
                        conn->tcp_fd = -1;
                    }
                    poke_count = 0;
                    strcpy(pokemsg, "STOP");
                    write(conn->pipe_fd[1], pokemsg, strlen(pokemsg) + 1);
                } else {
                    pokemsg[err] = '\0';
                    log_message(LOG_DEBUG, "Received POKE_ACK (%d)", poke_count++);
                }
            }
        }
        
        if (FD_ISSET(conn->tcp_fd, &fdset)) {
            strcpy(msg, "STOP");
            write(conn->pipe_fd[1], msg, strlen(msg) + 1);
            sleep(1);
            
            if (!conn->ssl || conn->tcp_fd < 0) {
                conn->tcp_fd = accept(conn->tcp_fd, (struct sockaddr*)&client_addr, &client_len);
                CHK_ERR(conn->tcp_fd, "accept TCP connection");
                log_message(LOG_INFO, "Connection from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                
                conn->ssl = SSL_new(conn->ssl_ctx);
                CHK_NULL(conn->ssl);
                SSL_set_fd(conn->ssl, conn->tcp_fd);
                CHK_SSL(SSL_accept(conn->ssl), "SSL accept");
                
                X509 *client_cert = SSL_get_peer_certificate(conn->ssl);
                CHK_NULL(client_cert);
                char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
                char subject[512];
                strncpy(subject, str, sizeof(subject) - 1);
                log_message(LOG_INFO, "Client certificate subject: %s", str);
                OPENSSL_free(str);
                str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
                log_message(LOG_INFO, "Client certificate issuer: %s", str);
                OPENSSL_free(str);
                X509_free(client_cert);
                
                // Receive and verify CN
                int err = SSL_read(conn->ssl, msg, sizeof(msg) - 1);
                CHK_SSL(err, "SSL read CN");
                msg[err] = '\0';
                log_message(LOG_DEBUG, "Received CN: %s", msg);
                cn_valid = 0;
                if (strncmp(msg, "CN:", 3) == 0) {
                    char *cn_start = strstr(subject, "/CN=");
                    if (cn_start) {
                        char *cn_end = strstr(&cn_start[1], "/");
                        if (cn_end) {
                            int cn_len = cn_end - (cn_start + 4);
                            if (strncmp(cn_start + 4, msg + 3, cn_len) == 0) {
                                cn_valid = 1;
                            }
                        }
                    }
                }
                CHK_SSL(SSL_write(conn->ssl, cn_valid ? "CN_ACK" : "CN_NACK", cn_valid ? 6 : 7), "SSL write CN response");
                
                // Receive KEY
                err = SSL_read(conn->ssl, msg, sizeof(msg) - 1);
                CHK_SSL(err, "SSL read KEY");
                msg[err] = '\0';
                log_message(LOG_DEBUG, "Received KEY: %s", msg);
                key_valid = 0;
                if (strncmp(msg, "KEY:", 4) == 0) {
                    strncpy(config.key, msg + 4, MAX_KEY_LENGTH);
                    key_valid = 1;
                }
                CHK_SSL(SSL_write(conn->ssl, key_valid ? "KEY_ACK" : "KEY_NACK", key_valid ? 7 : 8), "SSL write KEY response");
                
                // Receive IV
                err = SSL_read(conn->ssl, msg, sizeof(msg) - 1);
                CHK_SSL(err, "SSL read IV");
                msg[err] = '\0';
                iv_valid = 0;
                if (strncmp(msg, "IV:", 3) == 0) {
                    memcpy(config.iv, msg + 3, IV_LENGTH);
                    iv_valid = 1;
                }
                CHK_SSL(SSL_write(conn->ssl, iv_valid ? "IV_ACK" : "IV_NACK", iv_valid ? 6 : 7), "SSL write IV response");
                
                if (cn_valid && key_valid && iv_valid) {
                    strcpy(msg, "KEY:");
                    strcat(msg, config.key);
                    write(conn->pipe_fd[1], msg, strlen(msg) + 1);
                    sleep(1);
                    
                    strcpy(msg, "IV:");
                    memcpy(msg + 3, config.iv, IV_LENGTH);
                    write(conn->pipe_fd[1], msg, 3 + IV_LENGTH);
                    sleep(1);
                    
                    strcpy(msg, "FROM:");
                    memcpy(msg + 5, &client_addr, sizeof(client_addr));
                    write(conn->pipe_fd[1], msg, 5 + sizeof(client_addr));
                    sleep(1);
                    
                    strcpy(msg, "START");
                    write(conn->pipe_fd[1], msg, strlen(msg) + 1);
                    sleep(1);
                }
            }
        }
    }
    
    if (conn->ssl) SSL_free(conn->ssl);
    if (conn->tcp_fd >= 0) close(conn->tcp_fd);
    if (conn->timer_fd >= 0) close(conn->timer_fd);
}

void handle_child(Connection *conn) {
    char buf[MAX_BLOCK_LENGTH];
    unsigned char out[MAX_BLOCK_LENGTH];
    unsigned char hmac[HASH_LENGTH];
    int ok_to_start = 0;
    struct sockaddr_in from = {0};
    fd_set fdset;
    
    close(conn->pipe_fd[1]); // Close write end
    
    while (1) {
        FD_ZERO(&fdset);
        FD_SET(conn->pipe_fd[0], &fdset);
        FD_SET(conn->tun_fd, &fdset);
        FD_SET(conn->udp_fd, &fdset);
        
        if (select(conn->pipe_fd[0] + conn->tun_fd + conn->udp_fd + 1, &fdset, NULL, NULL, NULL) < 0) {
            log_message(LOG_ERR, "Child select: %s", strerror(errno));
            break;
        }
        
        if (FD_ISSET(conn->pipe_fd[0], &fdset)) {
            memset(buf, 0, sizeof(buf));
            int len = read(conn->pipe_fd[0], buf, sizeof(buf));
            CHK_ERR(len, "read pipe");
            
            if (strncmp(buf, "KEY:", 4) == 0) {
                log_message(LOG_DEBUG, "Received KEY: %s", buf + 4);
                strncpy(config.key, buf + 4, MAX_KEY_LENGTH);
            } else if (strncmp(buf, "IV:", 3) == 0) {
                log_message(LOG_DEBUG, "Received IV");
                memcpy(config.iv, buf + 3, IV_LENGTH);
            } else if (strncmp(buf, "FROM:", 5) == 0) {
                log_message(LOG_DEBUG, "Received FROM");
                memcpy(&from, buf + 5, sizeof(from));
            } else if (strncmp(buf, "START", 5) == 0) {
                log_message(LOG_INFO, "Tunnel starting");
                ok_to_start = 1;
            } else if (strncmp(buf, "STOP", 4) == 0) {
                log_message(LOG_INFO, "Tunnel stopping");
                ok_to_start = 0;
            }
        }
        
        if (FD_ISSET(conn->tun_fd, &fdset) && ok_to_start) {
            int len = read(conn->tun_fd, buf, sizeof(buf));
            CHK_ERR(len, "read tun");
            
            int out_len;
            encrypt_data((unsigned char*)buf, len, out, &out_len);
            if (out_len > MAX_BLOCK_LENGTH - HASH_LENGTH) {
                log_message(LOG_ERR, "Encrypted data too large");
                continue;
            }
            
            unsigned int hmac_len;
            create_hmac((unsigned char*)buf, len, hmac, &hmac_len);
            memcpy(out + out_len, hmac, hmac_len);
            out_len += hmac_len;
            
            if (sendto(conn->udp_fd, out, out_len, 0, (struct sockaddr*)&from, sizeof(from)) < 0) {
                log_message(LOG_ERR, "sendto: %s", strerror(errno));
            }
        } else if (FD_ISSET(conn->tun_fd, &fdset)) {
            read(conn->tun_fd, buf, sizeof(buf)); // Discard
        }
        
        if (FD_ISSET(conn->udp_fd, &fdset) && ok_to_start) {
            struct sockaddr_in src_addr;
            socklen_t src_len = sizeof(src_addr);
            int len = recvfrom(conn->udp_fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
            CHK_ERR(len, "recvfrom");
            
            if (src_addr.sin_addr.s_addr != from.sin_addr.s_addr || src_addr.sin_port != from.sin_port) {
                log_message(LOG_WARNING, "Packet from unexpected source %s:%d", 
                           inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                continue;
            }
            
            len -= HASH_LENGTH;
            if (!verify_hmac((unsigned char*)buf, len, (unsigned char*)buf + len, HASH_LENGTH)) {
                log_message(LOG_ERR, "HMAC verification failed");
                continue;
            }
            
            int out_len;
            decrypt_data((unsigned char*)buf, len, out, &out_len);
            if (write(conn->tun_fd, out, out_len) < 0) {
                log_message(LOG_ERR, "write tun: %s", strerror(errno));
            }
        } else if (FD_ISSET(conn->udp_fd, &fdset)) {
            struct sockaddr_in src_addr;
            socklen_t src_len = sizeof(src_addr);
            read(conn->udp_fd, buf, sizeof(buf)); // Discard
        }
    }
    
    close(conn->pipe_fd[0]);
    close(conn->tun_fd);
    close(conn->udp_fd);
}

int main(int argc, char *argv[]) {
    openlog("tunproxy", LOG_PID, LOG_DAEMON);
    srand(time(NULL));
    
    int opt;
    char *config_file = "tunproxy.conf";
    while ((opt = getopt(argc, argv, "c:dh")) != -1) {
        switch (opt) {
            case 'c': config_file = optarg; break;
            case 'd': config.debug = 1; break;
            case 'h':
                printf("Usage: %s [-c config_file] [-d] [-h]\n", argv[0]);
                return 0;
            default: return 1;
        }
    }
    
    if (load_config(config_file) < 0) {
        log_message(LOG_ERR, "Configuration loading failed");
        return 1;
    }
    
    if (config.mode == -1) {
        log_message(LOG_ERR, "Mode (client/server) must be specified in config");
        return 1;
    }
    
    Connection conn = {0};
    conn.tun_fd = init_tun_device(config.interface);
    conn.udp_fd = init_udp_socket(config.port);
    conn.tcp_fd = init_tcp_socket(config.port, config.mode);
    conn.ssl_ctx = init_ssl_context(config.mode);
    
    CHK_ERR(pipe(conn.pipe_fd), "create pipe");
    
    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERR, "Fork failed: %s", strerror(errno));
        return 1;
    }
    
    if (pid > 0) { // Parent process
        close(conn.pipe_fd[0]); // Close read end
        if (config.mode == CLIENT) {
            handle_client(&conn);
        } else {
            handle_server(&conn);
        }
        close(conn.pipe_fd[1]);
    } else { // Child process
        handle_child(&conn);
    }
    
    if (conn.ssl_ctx) SSL_CTX_free(conn.ssl_ctx);
    if (conn.tcp_fd >= 0) close(conn.tcp_fd);
    if (conn.udp_fd >= 0) close(conn.udp_fd);
    if (conn.tun_fd >= 0) close(conn.tun_fd);
    
    closelog();
    return 0;
}
