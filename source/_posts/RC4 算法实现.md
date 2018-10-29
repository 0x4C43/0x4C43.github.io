---
title: RC4 算法实现
tags:
  - RC4
categories: Crypto
keywords:
  - RC4
translate_title: rc4-algorithm-implementation
date: 2017-09-19 15:38:29
---

RC4 是一种对称秘钥流加密算法，对称加密算法使用的加密和解密秘钥是相同的，或是从其中一个能很容易推导出另一个。RC4 算法的特点是算法简单，运行速度快，而且密钥长度是可变的，密钥长度范围为 1-256 字节。

# 0x01 算法原理
算法主要包括两个部分：1）使用 key-scheduling algorithm (KSA) 算法根据用户输入的秘钥 key 生成 S 盒；2）使用 Pseudo-random generation algorithm (PRGA) 算法生成秘钥流用于加密数据。
## 1）初始化 S 盒
KSA算法初始化长度为 256 的 S 盒。第一个 for 循环将 0 到 255 的互不重复的元素装入 S 盒；第二个 for 循环根据密钥打乱 S 盒。
```C
for i from 0 to 255
    S[i] := i
endfor
j := 0
for i from 0 to 255
    j := (j + S[i] + key[i mod keylength]) mod 256
    swap values of S[i] and S[j]
endfor
```

## 2) 加密
Pseudo-random generation algorithm (PRGA) 算法根据 S 盒生成与明文长度相同的秘钥流，使用秘钥流加密明文。秘钥流的生成如下图所示：    
![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e9/RC4.svg/800px-RC4.svg.png)     
循环体中每收到一个字节，a 和 b 定位S盒中的一个元素，并与输入字节异或，得到密文 k；同时，c 还改变了 S 盒。由于异或运算的特性，使得加密与解密过程一致。如果输入的是明文，输出的就是密文；如果输入的是密文，输出的就是明文。
```C
i := 0
j := 0
while GeneratingOutput:
    i := (i + 1) mod 256  // a
    j := (j + S[i]) mod 256 // b
    swap values of S[i] and S[j]  // c
    K := inputByte ^ S[(S[i] + S[j]) mod 256] // d
    output K
endwhile
```

# 0x02 算法实现
[开源项目](https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/crypto/rc4/rc4.c)中的算法实现（稍作修改）如下。
## 1）开源实现
```C
// RC4.h
#ifndef _SYS_CRYPTO_RC4_RC4_H_
#define _SYS_CRYPTO_RC4_RC4_H_

struct rc4_state {
    unsigned char  perm[256];
    unsigned char  index1;
    unsigned char  index2;
};

extern void rc4_init(struct rc4_state *const state, const unsigned char *key, int keylen);
extern void rc4_crypt(struct rc4_state *const state, const unsigned char *inbuf, unsigned char *outbuf, int buflen);

void swap_bytes(unsigned char *a, unsigned char *b)
{
    unsigned char temp;
    temp = *a;
    *a = *b;
    *b = temp;
}

/*
* Initialize an RC4 state buffer using the supplied key,
* which can have arbitrary length.
*/
void rc4_init(struct rc4_state *const state, const unsigned char *key, int keylen)
{
    unsigned char j;
    int i;

    /* Initialize state with identity permutation */
    for (i = 0; i < 256; i++)
        state->perm[i] = (unsigned char)i;
    state->index1 = 0;
    state->index2 = 0;

    /* Randomize the permutation using key data */
    for (j = i = 0; i < 256; i++) {
        j = (j + state->perm[i] + key[i % keylen]) % 256;
        swap_bytes(&state->perm[i], &state->perm[j]);
    }
}

/*
* Encrypt some data using the supplied RC4 state buffer.
* The input and output buffers may be the same buffer.
* Since RC4 is a stream cypher, this function is used
* for both encryption and decryption.
*/
void rc4_crypt(struct rc4_state *const state,
    const unsigned char *inbuf, unsigned char *outbuf, int buflen)
{
    int i;
    unsigned char j;

    for (i = 0; i < buflen; i++) {

        /* Update modification indicies */
        state->index1 = (state->index1 + 1) % 256;
        state->index2 = (state->index2 + state->perm[state->index1]) % 256;

        /* Modify permutation */
        swap_bytes(&state->perm[state->index1], &state->perm[state->index2]);

        /* Encrypt/decrypt next byte */
        j = (state->perm[state->index1] + state->perm[state->index2]) % 256;
        outbuf[i] = inbuf[i] ^ state->perm[j];
    }
}

#endif
```

## 2）测试
使用以下代码进行测试加密和解密的结果。
```C
#include <stdio.h>
#include "RC4.h"
#include <string.h>
#define LEN 50

void main(int argc, char* argv[]) {
    unsigned char plaintext[LEN] = { 0 };
    unsigned char crypt[LEN]{ 0 };
    unsigned char decrypt[LEN]{ 0 };
    unsigned char key[LEN] = "1234567890";
    struct rc4_state state;

    while (true)
    {
        scanf("%s", plaintext);
        printf("plaintext:\n");
        for (int i = 0; i < strlen((const char*)plaintext); i++) {
            printf("%c ", plaintext[i]);
        }

        rc4_init(&state, key, strlen((const char*)key));// this code is very important
        rc4_crypt(&state, plaintext, crypt, strlen((const char*)plaintext));
        printf("\n\ncrypt:\n");
        for (int i = 0; i < strlen((const char*)plaintext); i++) {
            printf("%c,", crypt[i]);
        }

        printf("\n\ndecrypt: \n");
        rc4_init(&state, key, strlen((const char*)key));// this code is very important
        rc4_crypt(&state, crypt, decrypt, strlen((const char*)plaintext));
        for (int i = 0; i < strlen((const char*)plaintext); i++) {
            printf("%c ", decrypt[i]);
        }
        printf("\n-------------------------------------------------\n\n");
    }
}
```
运行结果如下：    
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-9-19/88889666.jpg)

____
References:   
[1] [RC4](https://en.wikipedia.org/wiki/RC4)    
[2] [流加密RC4的C语言实现](http://gttiankai.github.io/2015/01/18/Rc4.html)    
[3] [RC4加密算法](http://www.cnblogs.com/zibility/p/5404478.html)
