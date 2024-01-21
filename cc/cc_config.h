#ifndef _CC_CONFIG_H_
#define _CC_CONFIG_H_

//#define cc_assert(x) assert(x)
#define cc_assert(x) 

#if !defined(__arm64__) && defined(__ARM_NEON__)
#define CCAES_ARM 1
#endif

#if !defined(CCN_UNIT_SIZE)
#if defined(__arm64__) || defined(__x86_64__)
#define CCN_UNIT_SIZE  8
#elif defined(__arm__) || defined(__i386__)
#define CCN_UNIT_SIZE  4
#else
#define CCN_UNIT_SIZE  2
#endif
#endif /* !defined(CCN_UNIT_SIZE) */

#if defined(DEBUG) && (DEBUG)
/* CC_DEBUG is already used in CommonCrypto */
#define CORECRYPTO_DEBUG 1
#else
#define CORECRYPTO_DEBUG 0
#endif
#endif