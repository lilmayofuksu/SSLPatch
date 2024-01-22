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
void MSHookMemory(void *target, const void *data, size_t size);


#define SECURITY_LIBRARY_PATH "/System/Library/Frameworks/Security.framework/Security"
#define CORECRYPTO_LIBRARY_PATH "/usr/lib/system/libcorecrypto.dylib"
#define COMMONCRYPTO_LIBRARY_PATH "/usr/lib/system/libcommonCrypto.dylib"

#define LOAD_SYMBOL(img, name) do { \
    _ ## name = MSFindSymbol(img, "_" #name); \
    if (_ ## name == NULL) { \
        NSLog(@"SSLPatch: Failed to find symbol: " #name "."); \
        return; \
    } \
} while(0)


#define ENSURE_KERN_SUCCESS(ret) \
if (ret != KERN_SUCCESS) { \
    NSLog(@"it overload.. (write failed)"); \
    return; \
} \

#include <mach/mach.h> // mach_task_self, vm_protect

void write_memory(void* destination, const void* data, size_t size) {
    // We can't use MSHookMemory, so try and remap the permissions
    mach_port_t our_port = mach_task_self();

    // Attempt to map as RWX
    ENSURE_KERN_SUCCESS(vm_protect(our_port, (vm_address_t)destination, size, false, VM_PROT_READ | VM_PROT_WRITE))

    // Write to memory
    ENSURE_KERN_SUCCESS(vm_write(our_port, (vm_address_t)destination, (vm_offset_t)data, size))

    // Map back to RX
    ENSURE_KERN_SUCCESS(vm_protect(our_port, (vm_address_t)destination, size, false, VM_PROT_READ))
}

#import <Foundation/Foundation.h>

void debug(const char *message, ...) __attribute__((format(printf, 1, 2)));
void debug(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    NSLog(@"%@",[[NSString alloc] initWithFormat:[NSString stringWithUTF8String:message] arguments:args]);
    va_end(args);
}


// the other way is just patch all functions that uses KnownCipherSuites and I'm NOT doing that
// at least for now..
void PatchKnownCipherSuites(MSImageRef image) {
    SSLCipherSuite* array = (SSLCipherSuite*)MSFindSymbol(image, "_KnownCipherSuites");
    if (array == NULL) {
        NSLog(@"it overload.. (can't find KnownCipherSuites)");
        return;
    }

    NSLog(@"SSLPatch: Got the array, 4: %u, 10: %u", array[4], array[10]);

    //array[4] = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256; //TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    //array[10] = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384; //TLS_ECDHE_RSA_WITH_RC4_128_SHA
    SSLCipherSuite a = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    write_memory((void*)&array[4], &a, 2);
    SSLCipherSuite b = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    write_memory((void*)&array[10], &b, 2);

    NSLog(@"SSLPatch: After the patch: 4: %u, 10: %u", array[4], array[10]);
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
    MSImageRef sec_image = NULL;
    MSImageRef corecrypto_image = NULL;
    MSImageRef commoncrypto_image = NULL;

    void *_SSLProcessServerKeyExchange = NULL;
    void *_SSLInitPendingCiphers = NULL;
    void *_InitCipherSpec = NULL;
    void *_ssl3WriteRecord = NULL;
    void *_tls1DecryptRecord = NULL;

    sec_image = MSGetImageByName(SECURITY_LIBRARY_PATH);
    if (sec_image == NULL) {
        NSLog(@"SSLPatch: Failed to load Security framework.");
        return;
    }

    corecrypto_image = MSGetImageByName(CORECRYPTO_LIBRARY_PATH);
    if (corecrypto_image == NULL) {
        NSLog(@"SSLPatch: Failed to load corecrypto library.");
        return;
    }

    commoncrypto_image = MSGetImageByName(COMMONCRYPTO_LIBRARY_PATH);
    if (commoncrypto_image == NULL) {
        NSLog(@"SSLPatch: Failed to load commoncrypto library.");
        return;
    }

    LOAD_SYMBOL(sec_image, SSLProcessServerKeyExchange);
    LOAD_SYMBOL(sec_image, InitCipherSpec);
    LOAD_SYMBOL(sec_image, SSLInitPendingCiphers);
    LOAD_SYMBOL(sec_image, ssl3WriteRecord);
    LOAD_SYMBOL(sec_image, tls1DecryptRecord);
    LOAD_SYMBOL(sec_image, CSSMOID_SHA1WithRSA);
    LOAD_SYMBOL(sec_image, CSSMOID_SHA256WithRSA);
    LOAD_SYMBOL(sec_image, CSSMOID_SHA384WithRSA);
    LOAD_SYMBOL(sec_image, SSLHashMD5);
    LOAD_SYMBOL(sec_image, SSLHashSHA1);
    LOAD_SYMBOL(sec_image, SSLHashSHA256);
    LOAD_SYMBOL(sec_image, SSLHashSHA384);
    LOAD_SYMBOL(sec_image, SSLAllocBuffer);
    LOAD_SYMBOL(sec_image, SSLFreeBuffer);
    LOAD_SYMBOL(sec_image, SSLDecodeInt);
    LOAD_SYMBOL(sec_image, SSLEncodeInt);
    LOAD_SYMBOL(sec_image, sslFreePubKey);
    LOAD_SYMBOL(sec_image, sslGetPubKeyFromBits);
    LOAD_SYMBOL(sec_image, ReadyHash);
    LOAD_SYMBOL(sec_image, SSLDecodeDHKeyParams);
    LOAD_SYMBOL(sec_image, sslRsaVerify);
    LOAD_SYMBOL(sec_image, sslRawVerify);
    LOAD_SYMBOL(sec_image, SSLDecodeUInt64);
    LOAD_SYMBOL(sec_image, SSLEncodeUInt64);
    LOAD_SYMBOL(sec_image, sslRand);

    LOAD_SYMBOL(commoncrypto_image, ccDRBGGetRngState);
    LOAD_SYMBOL(corecrypto_image, ccaes_arm_encrypt);
    LOAD_SYMBOL(corecrypto_image, ccaes_ecb_encrypt_mode);

    PatchKnownCipherSuites(sec_image);

    MSHookFunction(_SSLProcessServerKeyExchange, custom_SSLProcessServerKeyExchange, NULL);
    MSHookFunction(_InitCipherSpec, custom_InitCipherSpec, (void **)&orig_InitCipherSpec);
    MSHookFunction(_SSLInitPendingCiphers, custom_SSLInitPendingCiphers, (void **)&orig_SSLInitPendingCiphers);
    MSHookFunction(_ssl3WriteRecord, custom_ssl3WriteRecord, (void **)&orig_ssl3WriteRecord);
    MSHookFunction(_tls1DecryptRecord, custom_tls1DecryptRecord, (void **)&orig_tls1DecryptRecord);
}
