#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <termios.h>

#define PORT 8090
#define SM4_KEY_SIZE 16
#define SM3_DIGEST_LENGTH 32
#define SM4_IV_SIZE 16
#define BUF_SIZE 1024

volatile int g_exit = 0;
int g_sock;
unsigned char g_sm4_key[SM4_KEY_SIZE];

static int send_all(int fd, const void *buf, int len) {
    const uint8_t *p = buf;
    while (len > 0) {
        int n = send(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, int len) {
    uint8_t *p = buf;
    while (len > 0) {
        int n = recv(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

void sm3_hmac(const unsigned char *key, int key_len, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned int out_len = SM3_DIGEST_LENGTH;
    HMAC(EVP_sm3(), key, key_len, data, len, out, &out_len);
}

EVP_PKEY *load_sm2_pub() {
    FILE *fp = fopen("sm2.pub", "r");
    if (!fp) { perror("打开sm2.pub失败"); return NULL; }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) ERR_print_errors_fp(stderr);
    return pkey;
}

int sm2_encrypt(EVP_PKEY *pkey, const unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_encrypt(ctx, out, out_len, in, in_len) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int sm4_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *in, int in_len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, cipher_len = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    EVP_EncryptUpdate(ctx, out, &len, in, in_len);
    cipher_len = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    cipher_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
}

int sm4_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *in, int in_len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plain_len = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    EVP_DecryptUpdate(ctx, out, &len, in, in_len);
    plain_len = len;
    EVP_DecryptFinal_ex(ctx, out + len, &len);
    plain_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plain_len;
}

int send_msg(int fd, const unsigned char *key, const char *msg) {
    unsigned char iv[SM4_IV_SIZE];
    RAND_bytes(iv, SM4_IV_SIZE);

    int msg_len = strlen(msg);
    unsigned char cipher[BUF_SIZE] = {0};
    int cipher_len = sm4_encrypt(key, iv, (unsigned char *)msg, msg_len, cipher);
    if (cipher_len < 0) return -1;

    unsigned char hmac[SM3_DIGEST_LENGTH] = {0};
    sm3_hmac(key, SM4_KEY_SIZE, (unsigned char *)msg, msg_len, hmac);

    uint32_t net_len = htonl(cipher_len);
    if (send_all(fd, iv, SM4_IV_SIZE) < 0 ||
        send_all(fd, &net_len, sizeof(net_len)) < 0 ||
        send_all(fd, cipher, cipher_len) < 0 ||
        send_all(fd, hmac, SM3_DIGEST_LENGTH) < 0)
        return -1;
    return 0;
}

int recv_msg(int fd, const unsigned char *key, char *out_msg, int max_len) {
    unsigned char iv[SM4_IV_SIZE];
    uint32_t net_len;
    unsigned char cipher[BUF_SIZE];
    unsigned char recv_hmac[SM3_DIGEST_LENGTH];

    if (recv_all(fd, iv, SM4_IV_SIZE) < 0 ||
        recv_all(fd, &net_len, sizeof(net_len)) < 0)
        return -1;

    int cipher_len = ntohl(net_len);
    if (cipher_len < 0 || cipher_len >= BUF_SIZE) return -1;

    if (recv_all(fd, cipher, cipher_len) < 0 ||
        recv_all(fd, recv_hmac, SM3_DIGEST_LENGTH) < 0)
        return -1;

    unsigned char plain[BUF_SIZE] = {0};
    int plain_len = sm4_decrypt(key, iv, cipher, cipher_len, plain);
    if (plain_len < 0 || plain_len >= max_len) return -1;

    unsigned char calc_hmac[SM3_DIGEST_LENGTH] = {0};
    sm3_hmac(key, SM4_KEY_SIZE, plain, plain_len, calc_hmac);
    if (memcmp(calc_hmac, recv_hmac, SM3_DIGEST_LENGTH) != 0) {
        printf("HMAC校验失败\n");
        return -1;
    }

    memcpy(out_msg, plain, plain_len);
    out_msg[plain_len] = 0;
    return 0;
}

void *recv_thread(void *arg) {
    char buf[BUF_SIZE];
    while (!g_exit) {
        if (recv_msg(g_sock, g_sm4_key, buf, BUF_SIZE) < 0) {
            g_exit = 1;
            break;
        }

        if (strcmp(buf, "exit") == 0) {
            printf("\n服务端已退出，通信结束\n");
            g_exit = 1;
            break;
        }

        printf("\r\033[K【服务器回复】：%s\n【客户端】：", buf);
        fflush(stdout);
    }
    return NULL;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(g_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("连接服务端失败");
        return -1;
    }

    printf("=== 安全通信客户端 ===\n");
    printf("已连接服务端\n");

    EVP_PKEY *sm2_pub = load_sm2_pub();
    RAND_bytes(g_sm4_key, SM4_KEY_SIZE);

    unsigned char enc_key[BUF_SIZE] = {0};
    size_t enc_len = sizeof(enc_key);
    sm2_encrypt(sm2_pub, g_sm4_key, SM4_KEY_SIZE, enc_key, &enc_len);

    uint32_t net_enc_len = htonl(enc_len);
    send_all(g_sock, &net_enc_len, sizeof(net_enc_len));
    send_all(g_sock, enc_key, enc_len);
    printf("[SM2] 加密密钥发送成功\n");

    printf("[SM4] 会话密钥协商完成，消息加密启用\n");
    printf("[SM3] 消息完整性校验启用\n");
    printf("\n==== 安全通信建立完成，开始聊天 ====\n\n");

    pthread_t recv_t;
    pthread_create(&recv_t, NULL, recv_thread, NULL);

    char buf[BUF_SIZE];
    printf("【客户端】：");
    fflush(stdout);

    while (!g_exit) {
        if (!fgets(buf, BUF_SIZE, stdin)) {
            g_exit = 1;
            break;
        }
        buf[strcspn(buf, "\n")] = 0;

        if (g_exit) break;

        if (strcmp(buf, "exit") == 0) {
            send_msg(g_sock, g_sm4_key, "exit");
            printf("\n客户端退出，通信结束\n");
            g_exit = 1;
            break;
        }

        send_msg(g_sock, g_sm4_key, buf);
        printf("【客户端】：");
        fflush(stdout);
    }

    pthread_join(recv_t, NULL);
    close(g_sock);
    EVP_PKEY_free(sm2_pub);
    return 0;
}