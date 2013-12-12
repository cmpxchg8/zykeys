/**
 *  The MIT License:
 *
 *  Copyright (c) 2012 Kevin Devine, Damien O'Reilly
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction,  including without limitation 
 *  the rights to use,  copy,  modify,  merge,  publish,  distribute,  
 *  sublicense,  and/or sell copies of the Software,  and to permit persons to 
 *  whom the Software is furnished to do so,  subject to the following 
 *  conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 *  OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/md5.h>

#define SSID_PREFIX "eircom"
#define ISP_OUI "001349"
#define ACS_SECRET "0Z1y2X"

#define SSID_LEN 8
#define SERIAL_LEN 13

void md5(const char in[], uint8_t out[]) {
    MD5_CTX ctx;

    if (out != 0 && in != 0) {
        MD5_Init(&ctx);
        MD5_Update(&ctx, in, strlen(in));
        MD5_Final(out, &ctx);
    }
}

char *bin2hex(uint8_t dig[], char str[], size_t n) {
    size_t i;

    for (i = 0;i < n;i++) {
        snprintf(&str[i*2], 3, "%02x", dig[i]);
    }
    return str;
}

/**
 *  generate ACS password for Zyxel router
 *  hash password with md5 and convert to base64
 *
 */
void base64_md5(char passw[]) {
    BIO *b64, *mem;
    uint8_t dgst[16];
    char *base64_str;

    md5(passw, dgst);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);

    BIO_write(b64, dgst, 16);
    BIO_flush(b64);
    BIO_get_mem_data(b64, &base64_str);

    printf("\n  ACS Password : %s\n", base64_str);
    BIO_free_all(b64);
}

void gen_acs(const char serial[]) {
    char tmp[64];

    printf("\n\n  ACS Username : %s-%s", ISP_OUI, serial);
    snprintf(tmp, sizeof(tmp), "%s-%s%s", ISP_OUI, serial, ACS_SECRET);
    base64_md5(tmp);
}

/**
 *
 *  Generate 64-bit WEP keys with password
 *
 *  P-660HW-T1 V3
 *
 */
void gen_wep64(char passw[]) {
    size_t len = strlen(passw);
    uint8_t pw[4] = {0};
    uint32_t key = 0;
    int i, j;

    for (i = 0;i < len;i++) {
        pw[i % 4] ^= passw[i];
    }
     
    key = (pw[0] | (pw[1] << 8) | (pw[2] << 16) | (pw[3] << 24));

    for (i = 0;i < 4;i++) {
        printf("\n  64-Bit WEP Key #%i: ", (i + 1));
        for (j = 0;j < 5;j++) {
            key = 214013 * key + 2531011;
            printf("%02x", (key >> 16) & 0xff);
        }
    }
    putchar('\n');
}

/**
 *
 *  Generate 128-bit WEP key with password
 *
 *
 */
void gen_wep128(char passw[]) {
    size_t len = strlen(passw);
    uint8_t dgst[16];
    char key[128];
    int i;

    memset(key, 0, sizeof(key));

    if (len != 0) {
        for (i = 0;i < 64;i++) {
            key[i] = passw[i % len];
        }
    }

    md5(key, dgst);
    printf("\n  128-Bit WEP Key : %s\n", bin2hex(dgst, key, 13));
}

/**
 *
 *  Generate default SSID
 *
 *  P-660HN-T1A uses string of MAC
 *  P-660HW-T1 V3 uses binary of MAC
 *
 */
void gen_ssid(void *in, size_t len) {
    int i;
    MD5_CTX ctx;
    uint8_t dgst[16];

    MD5_Init(&ctx);
    MD5_Update(&ctx, in, len);
    MD5_Final(dgst, &ctx);

    printf("\n  SSID     : %s", SSID_PREFIX);

    for (i = 0;i < SSID_LEN;i++) {
        putchar((dgst[i] % 10) + '0');
    }
}

/**
 *
 *  P-660HN-T1A
 *
 */
void gen_psk(const char s1[], const char s2[]) {
    char ambig[] = "B8G6I1L0OQDS5Z2";
    char unambig[] = "3479ACEFHJKMNPRTUVWXYabcdefghijklmnopqrstuvwxyz";
    size_t tbl_len = strlen(unambig);

    char md5_str[32+1], tmp[64];
    uint8_t dgst[16];
    uint32_t p1;
    int idx, pos;
    char *s, c;

    printf("\n  WPA2-PSK : ");

    // hash the 2 strings
    md5(s2, dgst);
    snprintf(tmp, sizeof(tmp), "%sPSK_%s", bin2hex(dgst, md5_str, 16), s1);
    md5(tmp, dgst);
    
    // get 16 bits of hash
    p1 = (dgst[0] << 8) | dgst[1];

    // create PSK from 13 bits of p1
    for (idx = 0;idx < SERIAL_LEN;idx++) {
        if ((p1 >> idx) & 1) {
            c = (dgst[idx] % 26) + 'A';
        } else {
            c = (dgst[idx] % 10) + '0';
        }
        // replace ambiguous characters
        s = strchr(ambig, c);
        pos = (s == NULL) ? -1 : (s - ambig);

        if (pos != -1) {
            c = unambig[ (p1 + pos) % tbl_len ];
        }
        putchar(c);
    }
}

// just trying combo since we've no idea what s1 + s2 are for gen_psk()
void gen_all(void) {
    const char *a[] = { "B0B2DCA742B4", "eircom76162802", "S121K27025123" };
    int i, j;

    for (i = 0;i < 3;i++) {
        for (j = 0;j < 3;j++) {
            gen_psk(a[i], a[j]);
        }
    }
    putchar('\n');
}

int main(int argc, char *argv[]) {
    puts("\n  ZyXEL key generator v1.0"
         "\n  Copyright (c) 2012 Kevin Devine, Damien O'Reilly");

    gen_wep64("password");
    gen_wep128("password");
    gen_ssid("B0B2DCA742B4", 12);
    gen_psk("B0B2DCA742B4", "S121K27025123");
    gen_acs("S121K27025123");

    return 0;
}

