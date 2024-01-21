#include <CommonCrypto/CommonCrypto.h>
#include "minimal.h"
#include "cc_gcm.h"

#define TLS_AES_GCM_TAG_SIZE 16
#define TLS_AES_GCM_IMPLICIT_IV_SIZE 4
#define TLS_AES_GCM_EXPLICIT_IV_SIZE 8

enum {
    errSSLRecordInternal            = -10000,
    errSSLRecordWouldBlock          = -10001,
    errSSLRecordProtocol            = -10002,
    errSSLRecordNegotiation         = -10003,
    errSSLRecordClosedAbort         = -10004,
	errSSLRecordConnectionRefused   = -10005,	/* peer dropped connection before responding */
	errSSLRecordDecryptionFail      = -10006,	/* decryption failure */
	errSSLRecordBadRecordMac        = -10007,	/* bad MAC */
	errSSLRecordRecordOverflow      = -10008,	/* record overflow */
	errSSLRecordUnexpectedRecord    = -10009,	/* unexpected (skipped) record in DTLS */
};

struct SymCipherContext {
    const struct ccmode_gcm *gcm;
    ccgcm_ctx *gcmCtx;
    uint8_t   gcmIV[TLS_AES_GCM_IMPLICIT_IV_SIZE+TLS_AES_GCM_EXPLICIT_IV_SIZE];
};

typedef struct SymCipherContext *SymCipherContext;

static
int CCGCMSymmInit(
                  const SSLSymmetricCipherParams *params,
                  int encrypting,
                  uint8_t *key,
                  uint8_t* iv,
                  struct ccrng_state *rng,
                  SymCipherContext *cipherCtx)
{
    SymCipherContext ctx = *cipherCtx;

    /* FIXME: this should not be needed as long as CCSymFinish is called */
    if(ctx) {
        sslFree(ctx);
        ctx = NULL;
    }

    const struct ccmode_gcm *gcm = encrypting?ccaes_gcm_encrypt_mode():ccaes_gcm_decrypt_mode();
    ctx = malloc(sizeof(struct SymCipherContext));

    if(ctx==NULL) {
        sslErrorLog("CCSymmInit: Can't allocate context\n");
        return errSSLRecordInternal;
    }

    ctx->gcm = gcm;
    ctx->gcmCtx = malloc(gcm->size);

    ccgcm_init(gcm, ctx->gcmCtx, params->keySize, key);
    memcpy(ctx->gcmIV, iv, TLS_AES_GCM_IMPLICIT_IV_SIZE);

    ccrng_generate(rng, TLS_AES_GCM_EXPLICIT_IV_SIZE, &ctx->gcmIV[TLS_AES_GCM_IMPLICIT_IV_SIZE]);

    *cipherCtx = ctx;
    return 0;
}

static
int CCSymmAEADSetIV(
                    const uint8_t *srcIV,
                    SymCipherContext cipherCtx)
{
    uint64_t iv;
    if(cipherCtx == NULL || cipherCtx->gcm == NULL) {
        sslErrorLog("CCSymmAEADSetIV: NULL cipherCtx\n");
        return errSSLRecordInternal;
    }
    /* copy the explicit IV */
    memcpy(&cipherCtx->gcmIV[TLS_AES_GCM_IMPLICIT_IV_SIZE], srcIV, TLS_AES_GCM_EXPLICIT_IV_SIZE);

    /* set iv in the gcm context */
    ccgcm_set_iv(cipherCtx->gcm, cipherCtx->gcmCtx, TLS_AES_GCM_IMPLICIT_IV_SIZE+TLS_AES_GCM_EXPLICIT_IV_SIZE, cipherCtx->gcmIV);

    /* Increment IV */
    iv = SSLDecodeUInt64(&cipherCtx->gcmIV[TLS_AES_GCM_IMPLICIT_IV_SIZE], 8);
    iv++;
    SSLEncodeUInt64(&cipherCtx->gcmIV[TLS_AES_GCM_IMPLICIT_IV_SIZE], iv);
    return 0;
}

static
int CCSymmAEADGetIV(
                    uint8_t *destIV,
                    SymCipherContext cipherCtx)
{
    if(cipherCtx == NULL || cipherCtx->gcm == NULL) {
        sslErrorLog("CCSymmAEADSetIV: NULL cipherCtx\n");
        return errSSLRecordInternal;
    }
    /* copy the explicit IV */
    memcpy(destIV, &cipherCtx->gcmIV[TLS_AES_GCM_IMPLICIT_IV_SIZE], TLS_AES_GCM_EXPLICIT_IV_SIZE);

    return 0;
}

static
int CCSymmAEADEncrypt(
                             const uint8_t *src,
                             uint8_t *dest,
                             size_t len,
                             SymCipherContext cipherCtx)
{
    if(cipherCtx == NULL || cipherCtx->gcm == NULL) {
        sslErrorLog("CCSymmAEADEncrypt: NULL cipherCtx\n");
        return errSSLRecordInternal;
    }
    ccgcm_update(cipherCtx->gcm, cipherCtx->gcmCtx, len-(TLS_AES_GCM_EXPLICIT_IV_SIZE+TLS_AES_GCM_TAG_SIZE), src+TLS_AES_GCM_EXPLICIT_IV_SIZE, dest+TLS_AES_GCM_EXPLICIT_IV_SIZE);
    ccgcm_finalize(cipherCtx->gcm, cipherCtx->gcmCtx, TLS_AES_GCM_TAG_SIZE, &dest[len-TLS_AES_GCM_TAG_SIZE]);
    ccgcm_reset(cipherCtx->gcm, cipherCtx->gcmCtx);
    return 0;
}

static
int CCSymmAEADDecrypt(
                             const uint8_t *src,
                             uint8_t *dest,
                             size_t len,
                             SymCipherContext cipherCtx)
{
    int err = 0;
    if(cipherCtx == NULL || cipherCtx->gcm == NULL) {
        printf("CCSymmAEADDecrypt: NULL cipherCtx\n");
        return -1;
    }
    uint8_t computedTag[TLS_AES_GCM_TAG_SIZE];
    ccgcm_update(cipherCtx->gcm, cipherCtx->gcmCtx, len-TLS_AES_GCM_TAG_SIZE, src, dest);
    ccgcm_finalize(cipherCtx->gcm, cipherCtx->gcmCtx, sizeof(computedTag), computedTag);

    /* Compare received MAC tag with the computed MAC tag */
    const uint8_t *receivedTag = &src[len-TLS_AES_GCM_TAG_SIZE];
    if (cc_cmp_safe(sizeof(computedTag), computedTag, receivedTag) == 0)
        err = 0;
    else err = -1;
    ccgcm_reset(cipherCtx->gcm, cipherCtx->gcmCtx);
    return err;
}

static
int CCSymmAddADD(
                 const uint8_t *src,
                 size_t  len,
                 SymCipherContext cipherCtx)
{
    if(cipherCtx == NULL || cipherCtx->gcm == NULL) {
        sslErrorLog("CCSymmAddADD: NULL cipherCtx\n");
        return errSSLRecordInternal;
    }
    ccgcm_gmac(cipherCtx->gcm, cipherCtx->gcmCtx, len, src);

    return 0;
}

static
int CCSymmFinish(
                 SymCipherContext cipherCtx)
{
    if(cipherCtx) {
        ccgcm_ctx_clear(cipherCtx->gcm->size, cipherCtx->gcmCtx);
        sslFree(cipherCtx->gcmCtx);
        sslFree(cipherCtx);
    }
    return 0;
}

const SSLSymmetricCipher SSLCipherAES_128_GCM = {
    .params = &SSLCipherAES_128_GCMParams,
    .c.aead = {
        .initialize = CCGCMSymmInit,
        .setIV = CCSymmAEADSetIV,
        .getIV = CCSymmAEADGetIV,
        .update = CCSymmAddADD,
        .encrypt = CCSymmAEADEncrypt,
        .decrypt = CCSymmAEADDecrypt,
    },
    .finish = CCSymmFinish
};

const SSLSymmetricCipher SSLCipherAES_256_GCM = {
    .params = &SSLCipherAES_256_GCMParams,
    .c.aead = {
        .initialize = CCGCMSymmInit,
        .setIV = CCSymmAEADSetIV,
        .getIV = CCSymmAEADGetIV,
        .update = CCSymmAddADD,
        .encrypt = CCSymmAEADEncrypt,
        .decrypt = CCSymmAEADDecrypt,
    },
    .finish = CCSymmFinish
};
