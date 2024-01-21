#include "minimal.h"

#ifndef _SSL_HOOKS_H
#define _SSL_HOOKS_H

typedef OSStatus (*generateKeyMaterialFcn) (
	SSLBuffer key, 					// caller mallocs and specifies length of
									//   required key material here
	SSLContext *ctx);

typedef OSStatus (*generateExportKeyAndIvFcn) (
	SSLContext *ctx,				// clientRandom, serverRandom valid
	const SSLBuffer clientWriteKey,
	const SSLBuffer serverWriteKey,
	SSLBuffer finalClientWriteKey,	// RETURNED, mallocd by caller
	SSLBuffer finalServerWriteKey,	// RETURNED, mallocd by caller
	SSLBuffer finalClientIV,		// RETURNED, mallocd by caller
	SSLBuffer finalServerIV);		// RETURNED, mallocd by caller

/*
 * On entry: clientRandom, serverRandom, preMasterSecret valid
 * On return: masterSecret valid
 */
typedef OSStatus (*generateMasterSecretFcn) (
	SSLContext *ctx);

typedef OSStatus (*computeFinishedMacFcn) (
	SSLContext *ctx,
	SSLBuffer finished, 		// output - mallocd by caller
	Boolean isServer);

typedef OSStatus (*computeCertVfyMacFcn) (
	SSLContext *ctx,
    SSLBuffer *finished,		// output - mallocd by caller
    SSL_HashAlgorithm hash);    //only used in TLS 1.2


typedef struct _SslTlsCallouts {
	generateKeyMaterialFcn		generateKeyMaterial;
	generateMasterSecretFcn		generateMasterSecret;
	computeFinishedMacFcn		computeFinishedMac;
	computeCertVfyMacFcn		computeCertVfyMac;
} SslTlsCallouts;

typedef int
(*SSLRecordReadFunc)                (SSLRecordContextRef    ref,
                                     SSLRecord              *rec);

typedef int
(*SSLRecordWriteFunc)               (SSLRecordContextRef    ref,
                                     SSLRecord              rec);

typedef int
(*SSLRecordInitPendingCiphersFunc)  (SSLRecordContextRef    ref,
                                     uint16_t               selectedCipher,
                                     bool                   server,
                                     SSLBuffer              key);

typedef int
(*SSLRecordAdvanceWriteCipherFunc)  (SSLRecordContextRef    ref);

typedef int
(*SSLRecordRollbackWriteCipherFunc) (SSLRecordContextRef    ref);

typedef int
(*SSLRecordAdvanceReadCipherFunc)   (SSLRecordContextRef    ref);

typedef int
(*SSLRecordSetProtocolVersionFunc)  (SSLRecordContextRef    ref,
                                     SSLProtocolVersion     protocolVersion);

typedef int
(*SSLRecordFreeFunc)                (SSLRecordContextRef    ref,
                                     SSLRecord              rec);

typedef int
(*SSLRecordServiceWriteQueueFunc)   (SSLRecordContextRef    ref);


struct SSLRecordFuncs
{   SSLRecordReadFunc                   read;
    SSLRecordWriteFunc                  write;
    SSLRecordInitPendingCiphersFunc     initPendingCiphers;
    SSLRecordAdvanceWriteCipherFunc     advanceWriteCipher;
    SSLRecordRollbackWriteCipherFunc    rollbackWriteCipher;
    SSLRecordAdvanceReadCipherFunc      advanceReadCipher;
    SSLRecordSetProtocolVersionFunc     setProtocolVersion;
    SSLRecordFreeFunc                   free;
    SSLRecordServiceWriteQueueFunc      serviceWriteQueue;
};

void custom_InitCipherSpec(struct SSLRecordInternalContext *ctx, uint16_t selectedCipher);
OSStatus custom_SSLInitPendingCiphers(SSLContext *ctx);
int custom_ssl3WriteRecord(SSLRecord rec, struct SSLRecordInternalContext *ctx);
int custom_tls1DecryptRecord(
	uint8_t type,
	SSLBuffer *payload,
	struct SSLRecordInternalContext *ctx);
#endif /* _SSL_HOOKS_H */