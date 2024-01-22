#include "ssl_hooks.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void debug(const char *message, ...) __attribute__((format(printf, 1, 2)));

extern const SSLSymmetricCipher SSLCipherAES_128_GCM;
extern const SSLSymmetricCipher SSLCipherAES_256_GCM;
extern void (*orig_InitCipherSpec)(struct SSLRecordInternalContext *ctx, uint16_t selectedCipher);
extern OSStatus (*orig_SSLInitPendingCiphers)(SSLContext *ctx);
extern int (*orig_ssl3WriteRecord)(SSLRecord rec, struct SSLRecordInternalContext *ctx);
extern int (*orig_tls1DecryptRecord)(
	uint8_t type,
	SSLBuffer *payload,
	struct SSLRecordInternalContext *ctx);

extern int (*_sslRand)(SSLBuffer *buf);
#define SSLAllocBuffer (*_SSLAllocBuffer)
#define SSLFreeBuffer (*_SSLFreeBuffer)

#define SSLDecodeUInt64 (*_SSLDecodeUInt64)
#define SSLEncodeUInt64 (*_SSLEncodeUInt64)
#define SSLDecodeInt (*_SSLDecodeInt)
#define SSLEncodeInt (*_SSLEncodeInt)
#define sslRand (*_sslRand)

static int
custom_SSLInitInternalRecordLayerPendingCiphers(SSLRecordContextRef ref, uint16_t selectedCipher, bool isServer, SSLBuffer key);

#define TLS_AES_GCM_TAG_SIZE 16
#define TLS_AES_GCM_IMPLICIT_IV_SIZE 4
#define TLS_AES_GCM_EXPLICIT_IV_SIZE 8
#define TLS_RECORD_HEADER_SIZE 5
#define DTLS_RECORD_HEADER_SIZE 13

void
IncrementUInt64(sslUint64 *v)
{
    (*v)++;
}

void custom_InitCipherSpec(struct SSLRecordInternalContext *ctx, uint16_t selectedCipher) {
    debug("custom_InitCipherSpec: %d\n", selectedCipher);

    orig_InitCipherSpec(ctx, selectedCipher); // dirty hack to get macAlgorithm correct lol
    if (selectedCipher == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || selectedCipher == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
        SSLRecordCipherSpec *dst = &ctx->selectedCipherSpec;
        ctx->selectedCipher = selectedCipher;
        if (selectedCipher == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            dst->cipher = &SSLCipherAES_256_GCM;
        else 
            dst->cipher = &SSLCipherAES_128_GCM;
    }
    return;
}

OSStatus
custom_SSLInitPendingCiphers(SSLContext *ctx)
{
    debug("custom_SSLInitPendingCiphers: %d\n", ctx->selectedCipher);

    //if (ctx->selectedCipher != SSL_CipherAlgorithmAES_256_GCM || ctx->selectedCipher != SSL_CipherAlgorithmAES_128_GCM)
    if (ctx->selectedCipher != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 && ctx->selectedCipher != TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        return orig_SSLInitPendingCiphers(ctx);

    OSStatus        err;
    SSLBuffer       key;
    int             keyDataLen;

    err = errSecSuccess;
    key.data = 0;

    keyDataLen = ctx->selectedCipherSpecParams.macSize +
                    ctx->selectedCipherSpecParams.keySize +
                    ctx->selectedCipherSpecParams.ivSize;
    keyDataLen *= 2;        /* two of everything */

    if ((err = SSLAllocBuffer(&key, keyDataLen)))
        return err;
    //assert(ctx->sslTslCalls != NULL);

    ctx->sslTslCalls->generateKeyMaterial(key, ctx);

    if ((err = ctx->sslTslCalls->generateKeyMaterial(key, ctx)) != 0)
        goto fail;

    if((err = custom_SSLInitInternalRecordLayerPendingCiphers(ctx->recCtx, ctx->selectedCipher, (ctx->protocolSide==kSSLServerSide), key)) != 0)
        goto fail;

    ctx->writePending_ready = 1;
    ctx->readPending_ready = 1;

    fail:
        SSLFreeBuffer(&key);
        return err;
}

static int
custom_SSLInitInternalRecordLayerPendingCiphers(SSLRecordContextRef ref, uint16_t selectedCipher, bool isServer, SSLBuffer key)
{   int        err;
    uint8_t         *keyDataProgress, *keyPtr, *ivPtr;
    CipherContext   *serverPending, *clientPending;

    struct SSLRecordInternalContext *ctx = ref;

    custom_InitCipherSpec(ctx, selectedCipher);

    ctx->readPending.macRef = ctx->selectedCipherSpec.macAlgorithm;
    ctx->writePending.macRef = ctx->selectedCipherSpec.macAlgorithm;
    ctx->readPending.symCipher = ctx->selectedCipherSpec.cipher;
    ctx->writePending.symCipher = ctx->selectedCipherSpec.cipher;
    /* This need to be reinitialized because the whole thing is zeroed sometimes */
    ctx->readPending.encrypting = 0;
    ctx->writePending.encrypting = 1;

    if(ctx->negProtocolVersion == DTLS_Version_1_0)
    {
        ctx->readPending.sequenceNum = (ctx->readPending.sequenceNum & (0xffffULL<<48)) + (1ULL<<48);
        ctx->writePending.sequenceNum = (ctx->writePending.sequenceNum & (0xffffULL<<48)) + (1ULL<<48);
    } else {
        ctx->writePending.sequenceNum = 0;
        ctx->readPending.sequenceNum = 0;
    }

    if (isServer)
    {   serverPending = &ctx->writePending;
        clientPending = &ctx->readPending;
    }
    else
    {   serverPending = &ctx->readPending;
        clientPending = &ctx->writePending;
    }
    /* Check the size of the 'key' buffer - <rdar://problem/11204357> */
    if (ctx->selectedCipherSpec.cipher->params->cipherType != aeadCipherType) {
        if(key.length != ctx->selectedCipherSpec.macAlgorithm->hash->digestSize*2
                    + ctx->selectedCipherSpec.cipher->params->keySize*2
                    + ctx->selectedCipherSpec.cipher->params->ivSize*2)
        {
            return errSSLRecordInternal;
        }
    } else {
        if(key.length != ctx->selectedCipherSpec.cipher->params->keySize*2
           + ctx->selectedCipherSpec.cipher->params->ivSize*2)
        {
            return errSSLRecordInternal;
        }
    }

    keyDataProgress = key.data;
    memcpy(clientPending->macSecret, keyDataProgress,
           ctx->selectedCipherSpec.macAlgorithm->hash->digestSize);
    keyDataProgress += ctx->selectedCipherSpec.macAlgorithm->hash->digestSize;
    memcpy(serverPending->macSecret, keyDataProgress,
           ctx->selectedCipherSpec.macAlgorithm->hash->digestSize);
    keyDataProgress += ctx->selectedCipherSpec.macAlgorithm->hash->digestSize;

    /* init the reusable-per-record MAC contexts */
    err = ctx->sslTslCalls->initMac(clientPending);
    if(err) {
        goto fail;
    }
    err = ctx->sslTslCalls->initMac(serverPending);
    if(err) {
        goto fail;
    }

    keyPtr = keyDataProgress;
    keyDataProgress += ctx->selectedCipherSpec.cipher->params->keySize;
    /* Skip server write key to get to IV */
    ivPtr = keyDataProgress + ctx->readPending.symCipher->params->ivSize;
    if ((err = ctx->selectedCipherSpec.cipher->c.cipher.initialize(clientPending->symCipher->params, clientPending->encrypting, keyPtr, ivPtr,
                                                                   &clientPending->cipherCtx)) != 0)
        goto fail;

    keyPtr = keyDataProgress;
    keyDataProgress += ctx->selectedCipherSpec.cipher->params->keySize;

    /* Skip client write IV to get to server write IV */
    if (ctx->readPending.symCipher->params->cipherType == aeadCipherType) {
        /* We only need the 4-byte implicit IV for GCM */
        ivPtr = keyDataProgress + ctx->readPending.symCipher->params->ivSize - TLS_AES_GCM_EXPLICIT_IV_SIZE;
    } else {
        ivPtr = keyDataProgress + ctx->readPending.symCipher->params->ivSize;
    }
    if ((err = ctx->selectedCipherSpec.cipher->c.cipher.initialize(serverPending->symCipher->params, serverPending->encrypting, keyPtr, ivPtr,
                                                                   &serverPending->cipherCtx)) != 0)
        goto fail;

    /* Ciphers are ready for use */
    ctx->writePending.ready = 1;
    ctx->readPending.ready = 1;

    /* Ciphers get swapped by sending or receiving a change cipher spec message */
    err = 0;

fail:
    return err;
}

int custom_ssl3WriteRecord(
	SSLRecord rec,
	struct SSLRecordInternalContext *ctx)
{
    debug("custom_ssl3WriteRecord: %d\n", ctx->selectedCipher);
    //if (ctx->selectedCipher != SSL_CipherAlgorithmAES_256_GCM || ctx->selectedCipher != SSL_CipherAlgorithmAES_128_GCM)
    if (ctx->selectedCipher != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 && ctx->selectedCipher != TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        return orig_ssl3WriteRecord(rec, ctx);

	int        err;
    int             padding = 0, i;
    WaitingRecord   *out = NULL, *queue;
    SSLBuffer       payload, mac;
    uint8_t           *charPtr;
    uint16_t          payloadSize,blockSize = 0;
    int             head = 5;

	switch(rec.protocolVersion) {
        case DTLS_Version_1_0:
            head += 8;
		case SSL_Version_3_0:
		case TLS_Version_1_0:
        case TLS_Version_1_1:
        case TLS_Version_1_2:
			break;
		default:
			check(0);
			return errSSLRecordInternal;
	}
    check(rec.contents.length <= 16384);

    /*sslLogRecordIo("type = %02x, ver = %04x, len = %ld, seq = %016llx",
                   rec.contentType, rec.protocolVersion, rec.contents.length,
                   ctx->writeCipher.sequenceNum);*/

    /* Allocate enough room for the transmitted record, which will be:
     *  5 bytes of header (13 for DTLS) +
     *  IV [block cipher and TLS1.1 or DTLS 1.0 only]
     *  encrypted contents +
     *  macLength +
     *  padding [block ciphers only] +
     *  padding length field (1 byte) [block ciphers only]
     */
    payloadSize = (uint16_t) rec.contents.length;
    CipherType cipherType = ctx->writeCipher.symCipher->params->cipherType;
    const Cipher *cipher = &ctx->writeCipher.symCipher->c.cipher;
    const AEADCipher *aead = &ctx->writeCipher.symCipher->c.aead;
    blockSize = ctx->writeCipher.symCipher->params->blockSize;
    switch (cipherType) {
        case blockCipherType:
            payloadSize += ctx->writeCipher.macRef->hash->digestSize;
            padding = blockSize - (payloadSize % blockSize) - 1;
            payloadSize += padding + 1;
            /* TLS 1.1, TLS1.2 and DTLS 1.0 have an extra block for IV */
            if(ctx->negProtocolVersion >= TLS_Version_1_1) {
                payloadSize += blockSize;
            }
            break;
        case streamCipherType:
            payloadSize += ctx->writeCipher.macRef->hash->digestSize;
            break;
        case aeadCipherType:
            /* AES_GCM doesn't need padding. */
            //payloadSize += aead->macSize;
            payloadSize += TLS_AES_GCM_EXPLICIT_IV_SIZE+TLS_AES_GCM_TAG_SIZE;//16mac+8iv
            break;
        default:
            check(0);
			return errSSLRecordInternal;
    }

	out = (WaitingRecord *)malloc(offsetof(WaitingRecord, data) +
		head + payloadSize);
	out->next = NULL;
	out->sent = 0;
	out->length = head + payloadSize;

    charPtr = out->data;
    *(charPtr++) = rec.contentType;
    charPtr = SSLEncodeInt(charPtr, rec.protocolVersion, 2);

    /* DTLS sequence number */
    if(rec.protocolVersion == DTLS_Version_1_0)
        charPtr = SSLEncodeUInt64(charPtr,ctx->writeCipher.sequenceNum);

    charPtr = SSLEncodeInt(charPtr, payloadSize, 2);

    /* Also for DTLS */
    if((ctx->negProtocolVersion >= TLS_Version_1_1) &&
       (cipherType == blockCipherType))
    {
        SSLBuffer randomIV;
        randomIV.data = charPtr;
        randomIV.length = blockSize;
        if((err = sslRand(&randomIV)) != 0)
            return err;
        charPtr += blockSize;
    }
    if (cipherType == aeadCipherType) {
        /* Encode the explicit iv, for AES_GCM we just use the 8 byte
           sequenceNum as the explicitIV.
           Ideally this needs to be done in the algorithm itself, by an
           extra function pointer in AEADCipher.  */
        //charPtr = SSLEncodeUInt64(charPtr,ctx->writeCipher.sequenceNum);
        /* TODO: If we ever add any mode other than GCM this code might have
           to be different. */
        /* TODO: Pass 4 byte implicit and 8 byte explicit IV to cipher */
        //err = ctx->writeCipher.symCipher->c.aead.setIV(charPtr, &ctx->writeCipher, ctx);
        if((err = ctx->writeCipher.symCipher->c.aead.getIV(charPtr, ctx->writeCipher.cipherCtx)) != 0)
            return err;

        charPtr += TLS_AES_GCM_EXPLICIT_IV_SIZE;

        if ((err = ctx->writeCipher.symCipher->c.aead.setIV(charPtr-TLS_AES_GCM_EXPLICIT_IV_SIZE,
                                                            ctx->writeCipher.cipherCtx)) != 0)
            goto fail;

        uint8_t aad[13];
        /* First copy the 8 byte sequence number */
        SSLEncodeUInt64(aad, ctx->writeCipher.sequenceNum);
        /* Copy the 5 byte TLS header already encoded in packet to aad */
        memcpy(aad+8, charPtr-13, TLS_RECORD_HEADER_SIZE);
        /* Update length to length of plaintext after copying TLS header over */
        aad[11]=rec.contents.length>>8;
        aad[12]=rec.contents.length&0xff;
        if ((err = ctx->writeCipher.symCipher->c.aead.update(aad, 13, ctx->writeCipher.cipherCtx)) != 0)
            goto fail;
    }

    /* Copy the contents into the output buffer */
    memcpy(charPtr, rec.contents.data, rec.contents.length);
    payload.data = charPtr;
    payload.length = rec.contents.length;

    charPtr += rec.contents.length;

    /* MAC the data */
    if (cipherType != aeadCipherType) {
        /* MAC immediately follows data */
        mac.data = charPtr;
        mac.length = ctx->writeCipher.macRef->hash->digestSize;
        charPtr += mac.length;
        if (mac.length > 0)     /* Optimize away null case */
        {
            check(ctx->sslTslCalls != NULL);
            if ((err = ctx->sslTslCalls->computeMac(rec.contentType,
                    payload,
                    mac,
                    &ctx->writeCipher,
                    ctx->writeCipher.sequenceNum,
                    ctx)) != 0)
                goto fail;
        }
    }

    /* For TLS 1.1 and DTLS, we would need to specifiy the IV, but instead
     we are clever like this: since the IV is just one block in front,
     we encrypt it with the rest of the data. The actual transmitted IV
     is the result of the encryption, with whatever internal IV is used.
     This method is explained in the TLS 1.1 RFC */
    if(ctx->negProtocolVersion >= TLS_Version_1_1 &&
       cipherType == blockCipherType)
    {
            payload.data -= blockSize;
    }

    /* Update payload to reflect encrypted data: IV, contents, mac & padding */
    payload.length = payloadSize;


    switch (cipherType) {
        case blockCipherType:
            /* Fill in the padding bytes & padding length field with the
             * padding value; the protocol only requires the last byte,
             * but filling them all in avoids leaking data */
            for (i = 1; i <= padding + 1; ++i)
                payload.data[payload.length - i] = padding;
            /* DROPTRHOUGH */
        case streamCipherType:
            /* Encrypt the data */
            if ((err = cipher->encrypt(payload.data,
                payload.data, payload.length, ctx->writeCipher.cipherCtx)) != 0)
                goto fail;
            break;
        case aeadCipherType:
            if ((err = aead->encrypt(payload.data,
                                       payload.data, payload.length, ctx->writeCipher.cipherCtx)) != 0)
                goto fail;
            break;
        default:
            check(0);
			return errSSLRecordInternal;
    }

    /* Enqueue the record to be written from the idle loop */
    if (ctx->recordWriteQueue == 0)
        ctx->recordWriteQueue = out;
    else
    {   queue = ctx->recordWriteQueue;
        while (queue->next != 0)
            queue = queue->next;
        queue->next = out;
    }

    /* Increment the sequence number */
    IncrementUInt64(&ctx->writeCipher.sequenceNum);

    return 0;

fail:
	/*
	 * Only for if we fail between when the WaitingRecord is allocated and when
	 * it is queued
	 */
	free(out);
    return err;
}

int custom_tls1DecryptRecord(
	uint8_t type,
	SSLBuffer *payload,
	struct SSLRecordInternalContext *ctx)
{
	int    err;
    SSLBuffer   content;

    CipherType cipherType = ctx->readCipher.symCipher->params->cipherType;
    debug("custom_tls1DecryptRecord: %d\n", cipherType);
    if (cipherType != aeadCipherType) {
        return orig_tls1DecryptRecord(type, payload, ctx);
    }

    if ((err = ctx->readCipher.symCipher->c.aead.setIV(payload->data, ctx->readCipher.cipherCtx)) != 0)
        return errSSLRecordParam;
    /*
     The additional authenticated data is defined as follows:
     additional_data = seq_num + type + version + length;
     where "+" denotes concatenation.
     */

    uint8_t aad[13];
    uint8_t *seq = &aad[0];
    SSLEncodeUInt64(seq, ctx->readCipher.sequenceNum);
    memcpy(aad+8, payload->data-TLS_RECORD_HEADER_SIZE, TLS_RECORD_HEADER_SIZE); // !!!!!!!!!!!!
    unsigned long len=payload->length-24;
    aad[11] = len>>8;
    aad[12] = len & 0xff;

    if ((err = ctx->readCipher.symCipher->c.aead.update(aad, 13, ctx->readCipher.cipherCtx)) != 0)
        return errSSLRecordParam;

    if ((err = ctx->readCipher.symCipher->c.aead.decrypt(payload->data+TLS_AES_GCM_EXPLICIT_IV_SIZE,
                                                         payload->data+TLS_AES_GCM_EXPLICIT_IV_SIZE,
                                                         payload->length-TLS_AES_GCM_EXPLICIT_IV_SIZE,
                                                           ctx->readCipher.cipherCtx)) != 0) {
        return errSSLRecordDecryptionFail;
    }

    content.data = payload->data + TLS_AES_GCM_EXPLICIT_IV_SIZE;
    content.length = payload->length - (TLS_AES_GCM_EXPLICIT_IV_SIZE+TLS_AES_GCM_TAG_SIZE);

    /* Test for underflow - if the record size is smaller than required */
    if(content.length > payload->length) {
        return errSSLRecordClosedAbort;
    }

    err = 0;

    *payload = content;     /* Modify payload buffer to indicate content length */
    return err;
}
