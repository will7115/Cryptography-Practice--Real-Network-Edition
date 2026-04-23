# 基于国密 SM2/SM4/SM3 的安全通信系统

[![C Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_\(programming_language\))
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.x-green.svg)](https://www.openssl.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#许可证)

> 基于 C/S 架构的国密算法安全通信系统，实现 SM2 非对称加密、SM4 对称加密、SM3-HMAC 完整性校验的端到端加密通信。

## 目录

- [项目简介](#项目简介)
- [功能特性](#功能特性)
- [技术架构](#技术架构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [完整代码](#完整代码)
- [安全测试](#安全测试)
- [实验分析](#实验分析)
- [项目结构](#项目结构)
- [许可证](#许可证)

***

## 项目简介

本项目采用 **VMware + Ubuntu 虚拟机 + C 语言** 实现安全通信系统，是兼顾实验要求与工程实践的最优方案，完全贴合真实安全通信系统部署场景。

### 方案核心优势

| 优势         | 说明                                    |
| ---------- | ------------------------------------- |
| 零基础、零额外成本  | Ubuntu 原生支持 OpenSSL，一键安装即可使用国密算法      |
| 贴合工业级服务端实践 | 安全服务端主流部署于 Linux 环境，可熟练掌握进程管理等工程技能    |
| 环境搭建简单     | 虚拟机网络配置标准化，可内置 Wireshark 抓包分析、模拟网络攻击  |
| 环境稳定无兼容问题  | Linux 网络通信、多线程稳定性更强，无 Windows 端口占用等问题 |

***

## 功能特性

- **SM2 非对称加密**：用于安全协商 SM4 会话密钥
- **SM4 对称加密**：CBC 模式高速消息加解密
- **SM3-HMAC 完整性校验**：防止消息篡改
- **多线程通信**：支持同时收发消息
- **会话密钥协商**：客户端生成随机 SM4 密钥，通过 SM2 加密传输

***

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                        客户端                                │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                  │
│  │ SM2加密 │───▶│ SM4加密  │───▶│SM3-HMAC │                  │
│  │ 会话密钥│     │ 消息内容  │    │ 完整性  │                  │
│  └─────────┘    └─────────┘    └─────────┘                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   TCP Socket    │
                    │   Port: 8090    │
                    └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        服务端                                │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                  │
│  │ SM2解密 │───▶ │ SM4解密 │───▶│SM3-HMAC │                  │
│  │ 会话密钥 │    │ 消息内容  │    │ 验证    │                  │
│  └─────────┘    └─────────┘    └─────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

***

## 环境要求

- **操作系统**：Ubuntu 22.04.5 LTS长期支持版本
- **编译器**：GCC 7.0+
- **依赖库**：OpenSSL 1.1.1+ (支持国密算法，如：OpenSSL 3.0.2 15 Mar 2022)

***

## 快速开始

### 步骤 1：更新软件源

```bash
sudo apt update
```

### 步骤 2：安装 GCC、OpenSSL 并检查版本

```bash
sudo apt install gcc openssl libssl-dev -y
openssl version
```

### 步骤 3：创建项目目录

```bash
mkdir ~/sm
cd ~/sm
```

### 步骤 4：生成 SM2 国密密钥对

```bash
# 生成 SM2 私钥
openssl ecparam -name SM2 -genkey -noout -out sm2.key

# 导出 SM2 公钥
openssl ec -in sm2.key -pubout -out sm2.pub
```

### 步骤 5：编写服务端代码

```bash
nano server.c
```

粘贴代码后：`Ctrl+O` → 回车 → `Ctrl+X`

### 步骤 6：编写客户端代码

```bash
nano client.c
```

粘贴代码后保存退出。

### 步骤 7：编译程序

```bash
gcc server.c -o server -lcrypto -pthread
gcc client.c -o client -lcrypto -pthread
```

### 步骤 8：运行程序

**终端1（服务端）**

```bash
cd ~/sm
./server
```

**终端2（客户端）**

```bash
cd ~/sm
./client
```

***

## 完整代码

### 服务端代码 server.c

```c
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
int g_client_fd;
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

EVP_PKEY *load_sm2_key() {
    FILE *fp = fopen("sm2.key", "r");
    if (!fp) { perror("打开sm2.key失败"); return NULL; }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) ERR_print_errors_fp(stderr);
    return pkey;
}

int sm2_decrypt(EVP_PKEY *pkey, const unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_decrypt(ctx, out, out_len, in, in_len) <= 0) {
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
        if (recv_msg(g_client_fd, g_sm4_key, buf, BUF_SIZE) < 0) {
            g_exit = 1;
            break;
        }

        if (strcmp(buf, "exit") == 0) {
            printf("\n客户端已退出，通信结束\n");
            g_exit = 1;
            break;
        }

        printf("\r\033[K【客户端发送】：%s\n【服务端】：", buf);
        fflush(stdout);
    }
    return NULL;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("绑定端口失败");
        return -1;
    }
    listen(server_fd, 5);

    printf("=== 安全通信服务端 ===\n");
    printf("等待客户端连接...\n\n");

    EVP_PKEY *sm2_key = load_sm2_key();
    g_client_fd = accept(server_fd, NULL, NULL);
    printf("客户端已连接\n");

    uint32_t enc_len;
    recv_all(g_client_fd, &enc_len, sizeof(enc_len));
    enc_len = ntohl(enc_len);

    unsigned char enc_key[BUF_SIZE];
    recv_all(g_client_fd, enc_key, enc_len);

    size_t sm4_len = SM4_KEY_SIZE;
    sm2_decrypt(sm2_key, enc_key, enc_len, g_sm4_key, &sm4_len);
    printf("[SM2] 密钥解密成功，获取SM4会话密钥\n");

    printf("[SM4] 会话密钥准备完成，消息将使用SM4-CBC加密传输\n");
    printf("[SM3] 消息完整性校验使用SM3-HMAC\n");
    printf("\n==== 安全通信建立完成，开始聊天 ====\n\n");

    pthread_t recv_t;
    pthread_create(&recv_t, NULL, recv_thread, NULL);

    char buf[BUF_SIZE];
    printf("【服务端】：");
    fflush(stdout);

    while (!g_exit) {
        if (!fgets(buf, BUF_SIZE, stdin)) {
            g_exit = 1;
            break;
        }
        buf[strcspn(buf, "\n")] = 0;

        if (g_exit) break;

        if (strcmp(buf, "exit") == 0) {
            send_msg(g_client_fd, g_sm4_key, "exit");
            printf("\n服务端退出，通信结束\n");
            g_exit = 1;
            break;
        }

        send_msg(g_client_fd, g_sm4_key, buf);
        printf("【服务端】：");
        fflush(stdout);
    }

    pthread_join(recv_t, NULL);
    close(g_client_fd);
    close(server_fd);
    EVP_PKEY_free(sm2_key);
    return 0;
}
```

### 客户端代码 client.c

```c
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
```

***

## 安全测试

### 实验一：抓包分析（机密性验证）

**目的**：验证 SM4 加密后，网络传输仅可见密文，无法获取明文。

#### 1. 安装 Wireshark

```bash
sudo apt install wireshark -y
sudo usermod -aG wireshark $USER
newgrp wireshark
```

#### 2. 启动 Wireshark

```bash
wireshark
```

#### 3. 抓包配置

- 选择网卡：`Loopback: lo`
- 过滤器：`tcp port 8090`
- 点击开始捕获

#### 4. 运行服务端与客户端，发送测试消息

#### 5. 停止抓包 → 右键数据包 → 追踪流 → TCP 流

**结果**：仅显示密文乱码，无明文，机密性验证成功。

***

### 实验二：协议降级攻击（漏洞复现）

**攻击原理**：攻击者使用明文 TCP 客户端连接，服务端错误解析长度字段，导致无限阻塞，形成拒绝服务。

#### 1. 启动服务端

```bash
./server
```

#### 2. 使用 nc 模拟恶意客户端

```bash
nc 127.0.0.1 8090
hello I am hacker
```

#### 3. 现象

服务端直接卡死，无法处理新连接。

#### 实验结论

系统缺少**协议版本协商**、**加密强制校验**、**长度合法性校验**，存在协议降级攻击与拒绝服务漏洞。

***

## 实验分析

### 需求与架构

| 需求   | 实现状态  | 说明                     |
| ---- | ----- | ---------------------- |
| 机密性  | ✅ 已实现 | SM2 + SM4 混合加密，满足端到端加密 |
| 完整性  | ✅ 已实现 | 基于 SM3-HMAC 校验，防止消息篡改  |
| 身份认证 | ❌ 未实现 | 未实现公钥验证与数字证书，无法抵抗中间人攻击 |

### 核心模块

| 模块        | 功能                |
| --------- | ----------------- |
| SM2 非对称加密 | 用于安全协商 SM4 会话密钥   |
| SM4 对称加密  | 用于消息高速加解密（CBC 模式） |
| SM3-HMAC  | 用于消息完整性校验         |
| C/S 多线程通信 | 支持同时收发消息          |

### 系统评价

- 已实现国密加密通信核心流程，运行稳定
- 缺少强身份认证，存在中间人攻击风险
- 缺少协议校验，存在协议降级攻击风险
- 适合教学演示，可进一步扩展证书、签名、防重放等安全机制

***

## 项目结构

```
secure_comm/
├── server.c      # 服务端源代码
├── client.c      # 客户端源代码
├── sm2.key       # SM2 私钥（需生成）
├── sm2.pub       # SM2 公钥（需生成）
├── server        # 编译后的服务端可执行文件
├── client        # 编译后的客户端可执行文件
└── README.md     # 项目说明文档
```

***

## 许可证

本项目仅供学习研究使用，采用 [MIT License](LICENSE) 开源协议。
