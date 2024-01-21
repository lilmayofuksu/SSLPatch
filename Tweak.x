/*
 *    SSLPatch (CVE-2014-1266)
 *    https://github.com/linusyang/SSLPatch
 *
 *    Runtime Patch for SSL verfication exploit (CVE-2014-1266)
 *    Copyright (c) 2014 Linus Yang <laokongzi@gmail.com>
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "minimal.h"
#include "ssl_hooks.h"

/* Minimal Cydia Substrate header */
typedef const void *MSImageRef;
MSImageRef MSGetImageByName(const char *file);
void *MSFindSymbol(MSImageRef image, const char *name);
void MSHookFunction(void *symbol, void *replace, void **result);

#define LIBRARY_PATH "/System/Library/Frameworks/Security.framework/Security"
#define LOAD_SYMBOL(name) do { \
    _ ## name = MSFindSymbol(image, "_" #name); \
    if (_ ## name == NULL) { \
        NSLog(@"SSLPatch: Failed to find symbol: " #name "."); \
        return; \
    } \
} while(0)

// the other way is just patch all functions that uses KnownCipherSuites and I'm NOT doing that
// at least for now..
void PatchKnownCipherSuites(MSImageRef image) {
    SSLCipherSuite* array = (SSLCipherSuite*)MSFindSymbol(image, "_KnownCipherSuites");
    if (array == NULL) {
        NSLog(@"it overload..");
        return;
    }

    array[4] = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256; //TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    array[10] = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384; //TLS_ECDHE_RSA_WITH_RC4_128_SHA
}

void (*orig_InitCipherSpec)(struct SSLRecordInternalContext *ctx, uint16_t selectedCipher);
OSStatus (*orig_SSLInitPendingCiphers)(SSLContext *ctx);
int (*orig_ssl3WriteRecord)(SSLRecord rec, struct SSLRecordInternalContext *ctx);
int (*orig_tls1DecryptRecord)(
	uint8_t type,
	SSLBuffer *payload,
	struct SSLRecordInternalContext *ctx);

int (*_sslRand)(SSLBuffer *buf);

typedef	unsigned int aes_32t;
typedef struct
{   aes_32t ks[60];
    aes_32t rn;
} ccaes_arm_encrypt_ctx;

int (*_ccaes_arm_encrypt)(const unsigned char *in, unsigned char *out, const ccaes_arm_encrypt_ctx cx[1]);
const void *(*_ccaes_ecb_encrypt_mode)(void);

%ctor {
    MSImageRef image = NULL;

    void *_SSLProcessServerKeyExchange = NULL;
    void *_SSLInitPendingCiphers = NULL;
    void *_InitCipherSpec = NULL;
    void *_ssl3WriteRecord = NULL;
    void *_tls1DecryptRecord = NULL;

    image = MSGetImageByName(LIBRARY_PATH);
    if (image == NULL) {
        NSLog(@"SSLPatch: Failed to load Security framework.");
        return;
    }

    LOAD_SYMBOL(SSLProcessServerKeyExchange);
    LOAD_SYMBOL(InitCipherSpec);
    LOAD_SYMBOL(SSLInitPendingCiphers);
    LOAD_SYMBOL(ssl3WriteRecord);
    LOAD_SYMBOL(tls1DecryptRecord);
    LOAD_SYMBOL(CSSMOID_SHA1WithRSA);
    LOAD_SYMBOL(CSSMOID_SHA256WithRSA);
    LOAD_SYMBOL(CSSMOID_SHA384WithRSA);
    LOAD_SYMBOL(SSLHashMD5);
    LOAD_SYMBOL(SSLHashSHA1);
    LOAD_SYMBOL(SSLHashSHA256);
    LOAD_SYMBOL(SSLHashSHA384);
    LOAD_SYMBOL(SSLAllocBuffer);
    LOAD_SYMBOL(SSLFreeBuffer);
    LOAD_SYMBOL(SSLDecodeInt);
    LOAD_SYMBOL(SSLEncodeInt);
    LOAD_SYMBOL(sslFreePubKey);
    LOAD_SYMBOL(sslGetPubKeyFromBits);
    LOAD_SYMBOL(ReadyHash);
    LOAD_SYMBOL(SSLDecodeDHKeyParams);
    LOAD_SYMBOL(sslRsaVerify);
    LOAD_SYMBOL(sslRawVerify);

    LOAD_SYMBOL(ccaes_arm_encrypt);
    LOAD_SYMBOL(ccaes_ecb_encrypt_mode);
    LOAD_SYMBOL(SSLDecodeUInt64);
    LOAD_SYMBOL(SSLEncodeUInt64);
    LOAD_SYMBOL(sslRand);
    LOAD_SYMBOL(ccDRBGGetRngState);

    PatchKnownCipherSuites(image);

    MSHookFunction(_SSLProcessServerKeyExchange, custom_SSLProcessServerKeyExchange, NULL);
    MSHookFunction(_InitCipherSpec, custom_InitCipherSpec, (void **)&orig_InitCipherSpec);
    MSHookFunction(_SSLInitPendingCiphers, custom_SSLInitPendingCiphers, (void **)&orig_SSLInitPendingCiphers);
    MSHookFunction(_ssl3WriteRecord, custom_ssl3WriteRecord, (void **)&orig_ssl3WriteRecord);
    MSHookFunction(_tls1DecryptRecord, custom_tls1DecryptRecord, (void **)&orig_tls1DecryptRecord);
}
