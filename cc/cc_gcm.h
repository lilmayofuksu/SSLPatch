#include <stddef.h>
#include <stdint.h>

#include "cc.h"

#ifndef __CC_GCM_H_
#define __CC_GCM_H_

/* Declare a struct element with a guarenteed alignment of _alignment_.
   The resulting struct can be used to create arrays that are aligned by
   a certain amount.  */
#define cc_aligned_struct(_alignment_)  \
    typedef struct { \
        uint8_t b[_alignment_]; \
    } __attribute__((aligned(_alignment_)))


/* ECB mode. */
cc_aligned_struct(16) ccecb_ctx;


/* Actual symmetric algorithm implementation should provide you one of these. */
struct ccmode_ecb {
    size_t size;        /* first argument to ccecb_ctx_decl(). */
    unsigned long block_size;
    void (*init)(const struct ccmode_ecb *ecb, ccecb_ctx *ctx,
                 size_t key_len, const void *key);
    void (*ecb)(const ccecb_ctx *ctx, unsigned long nblocks, const void *in,
                void *out);
};

cc_aligned_struct(16) ccgcm_ctx;

struct ccmode_gcm {
    size_t size;        /* first argument to ccgcm_ctx_decl(). */
    unsigned long block_size;
    void (*init)(const struct ccmode_gcm *gcm, ccgcm_ctx *ctx,
                 size_t key_len, const void *key);
    void (*set_iv)(ccgcm_ctx *ctx, size_t iv_size, const void *iv);
    void (*gmac)(ccgcm_ctx *ctx, size_t nbytes, const void *in);  // could just be gcm with NULL out
    void (*gcm)(ccgcm_ctx *ctx, size_t nbytes, const void *in, void *out);
    void (*finalize)(ccgcm_ctx *key, size_t tag_size, void *tag);
    void (*reset)(ccgcm_ctx *ctx);
    const void *custom;
};

struct _ccmode_gcm_key {
    // 5 blocks of temp space.
    unsigned char H[16];       /* multiplier */
    unsigned char X[16];       /* accumulator */
    unsigned char Y[16];       /* counter */
    unsigned char Y_0[16];     /* initial counter */
    unsigned char buf[16];      /* buffer for stuff */

    // State and length
    uint32_t ivmode;       /* Which mode is the IV in? */
    uint32_t mode;         /* mode the GCM code is in */
    uint32_t buflen;       /* length of data in buf */

    uint64_t totlen;       /* 64-bit counter used for IV and AAD */
    uint64_t pttotlen;     /* 64-bit counter for the PT */

    // ECB
    const struct ccmode_ecb *ecb;              // ecb mode
    // Pointer to the ECB key in the buffer
    void *ecb_key;                             // address of the ecb_key in u, set in init function
    // Buffer with ECB key and H table if applicable
    unsigned char u[] __attribute__ ((aligned (16))); // ecb key + tables
};

#define _CCMODE_GCM_KEY(K) ((struct _ccmode_gcm_key *)(K))
#define CCMODE_GCM_KEY_H(K) (_CCMODE_GCM_KEY(K)->H)
#define CCMODE_GCM_KEY_X(K) (_CCMODE_GCM_KEY(K)->X)
#define CCMODE_GCM_KEY_Y(K) (_CCMODE_GCM_KEY(K)->Y)
#define CCMODE_GCM_KEY_Y_0(K) (_CCMODE_GCM_KEY(K)->Y_0)
#define CCMODE_GCM_KEY_PAD_LEN(K) (_CCMODE_GCM_KEY(K)->buflen)
#define CCMODE_GCM_KEY_PAD(K) (_CCMODE_GCM_KEY(K)->buf)

#define _CCMODE_GCM_ECB_MODE(K) ((struct _ccmode_gcm_key *)(K))
#define CCMODE_GCM_KEY_ECB(K) (_CCMODE_GCM_ECB_MODE(K)->ecb)
#define CCMODE_GCM_KEY_ECB_KEY(K) ((ccecb_ctx *)_CCMODE_GCM_ECB_MODE(K)->ecb_key)  // set in init function

#define GCM_ECB_KEY_SIZE(ECB_ENCRYPT) \
        ((5 * ccn_sizeof_size((ECB_ENCRYPT)->block_size)) \
    + ccn_sizeof_size((ECB_ENCRYPT)->size))


/* Use this to statically initialize a ccmode_gcm object for decryption. */
#define CCMODE_FACTORY_GCM_DECRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key)) \
        + GCM_ECB_KEY_SIZE(ECB_ENCRYPT) \
        + GCM_TABLE_SIZE, \
.block_size = 1, \
.init = ccmode_gcm_init, \
.set_iv = ccmode_gcm_set_iv, \
.gmac = ccmode_gcm_gmac, \
.gcm = ccmode_gcm_decrypt, \
.finalize = ccmode_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT) \
}

/* Use this to statically initialize a ccmode_gcm object for encryption. */
#define CCMODE_FACTORY_GCM_ENCRYPT(ECB_ENCRYPT) { \
.size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key))  \
        + GCM_ECB_KEY_SIZE(ECB_ENCRYPT)  \
        + GCM_TABLE_SIZE, \
.block_size = 1, \
.init = ccmode_gcm_init, \
.set_iv = ccmode_gcm_set_iv, \
.gmac = ccmode_gcm_gmac, \
.gcm = ccmode_gcm_encrypt, \
.finalize = ccmode_gcm_finalize, \
.reset = ccmode_gcm_reset, \
.custom = (ECB_ENCRYPT) \
}

#define CCMODE_GCM_MODE_IV    0
#define CCMODE_GCM_MODE_AAD   1
#define CCMODE_GCM_MODE_TEXT  2

/* GCM FEATURES. */
//#define CCMODE_GCM_TABLES  1
#define CCMODE_GCM_FAST  1

#ifdef CCMODE_GCM_FAST
#define CCMODE_GCM_FAST_TYPE cc_unit
#endif

#ifndef GCM_TABLE_SIZE
#define GCM_TABLE_SIZE 0
#endif

void ccmode_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *ctx,
                     size_t rawkey_len, const void *rawkey);
void ccmode_gcm_set_iv(ccgcm_ctx *ctx, size_t iv_size, const void *iv);
void ccmode_gcm_gmac(ccgcm_ctx *ctx, size_t nbytes, const void *in);
void ccmode_gcm_decrypt(ccgcm_ctx *ctx, size_t nbytes, const void *in,
                        void *out);
void ccmode_gcm_encrypt(ccgcm_ctx *ctx, size_t nbytes, const void *in,
                        void *out);
void ccmode_gcm_finalize(ccgcm_ctx *key, size_t tag_size, void *tag);
void ccmode_gcm_reset(ccgcm_ctx *key);

#endif