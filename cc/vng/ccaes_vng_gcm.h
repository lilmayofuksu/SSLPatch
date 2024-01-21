#include "cc_gcm.h"
#include "cc_config.h"

#ifndef __CCAES_VNG_GCM_H_
#define __CCAES_VNG_GCM_H_

#if	!defined(__NO_ASM__) && ((CCAES_INTEL && defined(__x86_64__)) || (CCAES_ARM && defined(__ARM_NEON__)))
#define	CCMODE_GCM_VNG_SPEEDUP	1
#else
#define	CCMODE_GCM_VNG_SPEEDUP	0
#endif


#if CCMODE_GCM_VNG_SPEEDUP
void ccaes_vng_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *key,
                        size_t rawkey_len, const void *rawkey);


void ccaes_vng_gcm_set_iv(ccgcm_ctx *key, size_t iv_size, const void *iv);

void ccaes_vng_gcm_gmac(ccgcm_ctx *key, size_t nbytes, const void *in);

void ccaes_vng_gcm_decrypt(ccgcm_ctx *key, size_t nbytes,
                           const void *in, void *out);

void ccaes_vng_gcm_encrypt(ccgcm_ctx *key, size_t nbytes,
                           const void *in, void *out);

void ccaes_vng_gcm_finalize(ccgcm_ctx *key, size_t tag_size, void *tag);

void ccaes_vng_gcm_mult_h(ccgcm_ctx *key, unsigned char *I);

void ccaes_vng_gcm_gf_mult(const unsigned char *a, const unsigned char *b,
                           unsigned char *c);

extern void gcm_init(void *Htable, void *H);
extern void gcm_gmult(const void *X, const void *Htable, void *out);
extern void gcm_ghash(void *X, void *Htable, const void *in, size_t len);
extern void gcmEncrypt(const void*, void*, void*, unsigned int, void*, void*);
extern void gcmDecrypt(const void*, void*, void*, unsigned int, void*, void*);

struct ccmode_ecb* ccaes_ecb_encrypt_mode();
void ccmode_gcm_reset(ccgcm_ctx *key);

struct _ccaes_vng_gcm_tables {
#if !defined(__arm64__) && defined(__ARM_NEON__)
    unsigned char Htable[8*2] __attribute__((aligned(16)));
#else
    unsigned char Htable[16*8*2] __attribute__((aligned(16)));
#endif
};
#define VNG_GCM_TABLE_SIZE sizeof(struct _ccaes_vng_gcm_tables)

#define CCMODE_GCM_KEY_Htable(K) (((struct _ccaes_vng_gcm_tables*)&_CCMODE_GCM_KEY(K)->u[0])->Htable)

/* Use this to statically initialize a ccmode_gcm object for decryption. */
#define CCAES_VNG_GCM_DECRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key))  \
+ GCM_ECB_KEY_SIZE(ECB_ENCRYPT)  \
+ VNG_GCM_TABLE_SIZE, \
.block_size = 1, \
.init = ccaes_vng_gcm_init, \
.set_iv = ccaes_vng_gcm_set_iv, \
.gmac = ccaes_vng_gcm_gmac, \
.gcm = ccaes_vng_gcm_decrypt, \
.finalize = ccaes_vng_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use this to statically initialize a ccmode_gcm object for encryption. */
#define CCAES_VNG_GCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key))  \
+ GCM_ECB_KEY_SIZE(ECB_ENCRYPT)  \
+ VNG_GCM_TABLE_SIZE, \
.block_size = 1, \
.init = ccaes_vng_gcm_init, \
.set_iv = ccaes_vng_gcm_set_iv, \
.gmac = ccaes_vng_gcm_gmac, \
.gcm = ccaes_vng_gcm_encrypt, \
.finalize = ccaes_vng_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use these function to runtime initialize a ccmode_gcm decrypt object (for
 example if it's part of a larger structure). For GCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccaes_vng_gcm_decrypt_mode_setup(struct ccmode_gcm *gcm) {
    struct ccmode_gcm gcm_decrypt = CCAES_VNG_GCM_DECRYPT(ccaes_ecb_encrypt_mode());
    *gcm = gcm_decrypt;
}

/* Use these function to runtime initialize a ccmode_gcm encrypt object (for
 example if it's part of a larger structure). For GCM you always pass a
 ecb encrypt mode implementation of some underlying algorithm as the ecb
 parameter. */
CC_INLINE
void ccaes_vng_gcm_encrypt_mode_setup(struct ccmode_gcm *gcm) {
    struct ccmode_gcm gcm_encrypt = CCAES_VNG_GCM_ENCRYPT(ccaes_ecb_encrypt_mode());
    *gcm = gcm_encrypt;
}
#endif //CCMODE_GCM_VNG_SPEEDUP
#endif