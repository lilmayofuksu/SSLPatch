#ifndef _CC_H_
#define _CC_H_

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include "cc_config.h"

typedef uint8_t cc_byte;
typedef size_t cc_size;

#define cc_zero(_size_,_data_) memset((_data_),0 ,(_size_))
#define CC_INLINE static inline

#ifndef __CC_DEBUG_ASSERT_PRODUCTION_CODE
#define __CC_DEBUG_ASSERT_PRODUCTION_CODE !CORECRYPTO_DEBUG
#endif

#ifndef cc_require
#if __CC_DEBUG_ASSERT_PRODUCTION_CODE
    #define cc_require(assertion, exceptionLabel) \
        do { \
            if ( __builtin_expect(!(assertion), 0) ) { \
                goto exceptionLabel; \
            } \
        } while ( 0 )
#else
    #define cc_require(assertion, exceptionLabel) \
        do { \
            if ( __builtin_expect(!(assertion), 0) ) { \
                __CC_DEBUG_ASSERT_MESSAGE(__CC_DEBUG_ASSERT_COMPONENT_NAME_STRING, \
                    #assertion, #exceptionLabel, 0, __FILE__, __LINE__,  0); \
                goto exceptionLabel; \
            } \
        } while ( 0 )
#endif
#endif

#define CC_MEMCPY(D,S,L) memcpy((D),(S),(L))
#define CC_MEMMOVE(D,S,L) memmove((D),(S),(L))
#define CC_MEMSET(D,V,L) memset((D),(V),(L))

#define	CC_STORE32_LE(x, y) do {                                    \
    ((unsigned char *)(y))[3] = (unsigned char)(((x)>>24)&255);		\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>16)&255);		\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>8)&255);		\
    ((unsigned char *)(y))[0] = (unsigned char)((x)&255);			\
} while(0)

#define	CC_LOAD32_LE(x, y) do {                                     \
x = ((uint32_t)(((const unsigned char *)(y))[3] & 255)<<24) |			    \
    ((uint32_t)(((const unsigned char *)(y))[2] & 255)<<16) |			    \
    ((uint32_t)(((const unsigned char *)(y))[1] & 255)<<8)  |			    \
    ((uint32_t)(((const unsigned char *)(y))[0] & 255));				    \
} while(0)

// MARK: -- 64 bits - little endian

#define	CC_STORE64_LE(x, y) do {                                    \
    ((unsigned char *)(y))[7] = (unsigned char)(((x)>>56)&255);     \
    ((unsigned char *)(y))[6] = (unsigned char)(((x)>>48)&255);		\
    ((unsigned char *)(y))[5] = (unsigned char)(((x)>>40)&255);		\
    ((unsigned char *)(y))[4] = (unsigned char)(((x)>>32)&255);		\
    ((unsigned char *)(y))[3] = (unsigned char)(((x)>>24)&255);		\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>16)&255);		\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>8)&255);		\
    ((unsigned char *)(y))[0] = (unsigned char)((x)&255);			\
} while(0)

#define	CC_LOAD64_LE(x, y) do {                                     \
x = (((uint64_t)(((const unsigned char *)(y))[7] & 255))<<56) |           \
    (((uint64_t)(((const unsigned char *)(y))[6] & 255))<<48) |           \
    (((uint64_t)(((const unsigned char *)(y))[5] & 255))<<40) |           \
    (((uint64_t)(((const unsigned char *)(y))[4] & 255))<<32) |           \
    (((uint64_t)(((const unsigned char *)(y))[3] & 255))<<24) |           \
    (((uint64_t)(((const unsigned char *)(y))[2] & 255))<<16) |           \
    (((uint64_t)(((const unsigned char *)(y))[1] & 255))<<8)  |           \
    (((uint64_t)(((const unsigned char *)(y))[0] & 255)));                \
} while(0)

// MARK: -- 32 bits - big endian
// MARK: --- intel version

#if (defined(__i386__) || defined(__x86_64__))

#define CC_STORE32_BE(x, y)     \
    __asm__ __volatile__ (      \
    "bswapl %0     \n\t"        \
    "movl   %0,(%1)\n\t"        \
    "bswapl %0     \n\t"        \
    ::"r"(x), "r"(y))

#define CC_LOAD32_BE(x, y)      \
    __asm__ __volatile__ (      \
    "movl (%1),%0\n\t"          \
    "bswapl %0\n\t"             \
    :"=r"(x): "r"(y))

#else
// MARK: --- default version
#define	CC_STORE32_BE(x, y) do {                                \
    ((unsigned char *)(y))[0] = (unsigned char)(((x)>>24)&255);	\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>16)&255);	\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>8)&255);	\
    ((unsigned char *)(y))[3] = (unsigned char)((x)&255);       \
} while(0)

#define	CC_LOAD32_BE(x, y) do {                             \
x = ((uint32_t)(((const unsigned char *)(y))[0] & 255)<<24) |	    \
    ((uint32_t)(((const unsigned char *)(y))[1] & 255)<<16) |		\
    ((uint32_t)(((const unsigned char *)(y))[2] & 255)<<8)  |		\
    ((uint32_t)(((const unsigned char *)(y))[3] & 255));          \
} while(0)

#endif

// MARK: -- 64 bits - big endian

// MARK: --- intel 64 bits version

#if defined(__x86_64__)

#define	CC_STORE64_BE(x, y)   \
__asm__ __volatile__ (        \
"bswapq %0     \n\t"          \
"movq   %0,(%1)\n\t"          \
"bswapq %0     \n\t"          \
::"r"(x), "r"(y))

#define	CC_LOAD64_BE(x, y)    \
__asm__ __volatile__ (        \
"movq (%1),%0\n\t"            \
"bswapq %0\n\t"               \
:"=r"(x): "r"(y))

#else

// MARK: --- default version

#define CC_STORE64_BE(x, y) do {                                    \
    ((unsigned char *)(y))[0] = (unsigned char)(((x)>>56)&255);		\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>48)&255);		\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>40)&255);		\
    ((unsigned char *)(y))[3] = (unsigned char)(((x)>>32)&255);		\
    ((unsigned char *)(y))[4] = (unsigned char)(((x)>>24)&255);		\
    ((unsigned char *)(y))[5] = (unsigned char)(((x)>>16)&255);		\
    ((unsigned char *)(y))[6] = (unsigned char)(((x)>>8)&255);		\
    ((unsigned char *)(y))[7] = (unsigned char)((x)&255);			\
} while(0)

#define	CC_LOAD64_BE(x, y) do {                                     \
x = (((uint64_t)(((const unsigned char *)(y))[0] & 255))<<56) |           \
    (((uint64_t)(((const unsigned char *)(y))[1] & 255))<<48) |           \
    (((uint64_t)(((const unsigned char *)(y))[2] & 255))<<40) |           \
    (((uint64_t)(((const unsigned char *)(y))[3] & 255))<<32) |           \
    (((uint64_t)(((const unsigned char *)(y))[4] & 255))<<24) |           \
    (((uint64_t)(((const unsigned char *)(y))[5] & 255))<<16) |           \
    (((uint64_t)(((const unsigned char *)(y))[6] & 255))<<8)  |          	\
    (((uint64_t)(((const unsigned char *)(y))[7] & 255)));	            \
} while(0)

#endif


#if  CCN_UNIT_SIZE == 8
typedef uint64_t cc_unit;          // 64 bit unit
typedef unsigned cc_dunit __attribute__((mode(TI)));         // 128 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  6  // 2^6 = 64 bits
#define CC_UNIT_C(x) UINT64_C(x)
#elif  CCN_UNIT_SIZE == 4
typedef uint32_t cc_unit;          // 32 bit unit
typedef uint64_t cc_dunit;         // 64 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  5  // 2^5 = 32 bits
#define CC_UNIT_C(x) UINT32_C(x)
#elif CCN_UNIT_SIZE == 2
typedef uint16_t cc_unit;          // 16 bit unit
typedef uint32_t cc_dunit;         // 32 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  4  // 2^4 = 16 bits
#define CC_UNIT_C(x) UINT16_C(x)
#elif CCN_UNIT_SIZE == 1
typedef uint8_t cc_unit;           // 8 bit unit
typedef uint16_t cc_dunit;         // 16 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  3  // 2^3 = 8 bits
#define CC_UNIT_C(x) UINT8_C(x)
#else
#error invalid CCN_UNIT_SIZE
#endif

// All mp types have units in little endian unit order.
typedef cc_unit *ccn_t;                // n unit long mp
typedef cc_unit *ccnp1_t;              // n + 1 unit long mp
typedef cc_unit *cc2n_t;               // 2 * n unit long mp
typedef cc_unit *cc2np2_t;             // 2 * n + 2 unit long mp
typedef const cc_unit *ccn_in_t;       // n unit long mp
typedef const cc_unit *ccnp1_in_t;     // n + 1 unit long mp
typedef const cc_unit *cc2n_in_t;      // 2 * n unit long mp
typedef const cc_unit *cc2np2_in_t;    // 2 * n + 2 unit long mp

#define CCN_UNIT_BITS  (sizeof(cc_unit) * 8)
#define CCN_UNIT_MASK  ((cc_unit)~0)

typedef struct {
    cc_unit *start;      // First cc_unit of the workspace
    cc_unit *end;        // address and beyond NOT TO BE TOUCHED
} cc_ws,*cc_ws_t;

/* Conversions between n sizeof and bits */

/* Returns the sizeof a ccn vector of length _n_ units. */
#define ccn_sizeof_n(_n_)  (sizeof(cc_unit) * (_n_))

/* Returns the count (n) of a ccn vector that can represent _bits_. */
#define ccn_nof(_bits_)  (((_bits_) + CCN_UNIT_BITS - 1) / CCN_UNIT_BITS)

/* Returns the sizeof a ccn vector that can represent _bits_. */
#define ccn_sizeof(_bits_)  (ccn_sizeof_n(ccn_nof(_bits_)))

/* Returns the count (n) of a ccn vector that can represent _size_ bytes. */
#define ccn_nof_size(_size_)  (((_size_) + CCN_UNIT_SIZE - 1) / CCN_UNIT_SIZE)

/* Return the max number of bits a ccn vector of _n_ units can hold. */
#define ccn_bitsof_n(_n_)  ((_n_) * CCN_UNIT_BITS)

/* Return the max number of bits a ccn vector of _size_ bytes can hold. */
#define ccn_bitsof_size(_size_)  ((_size_) * 8)

/* Return the size of a ccn of size bytes in bytes. */
#define ccn_sizeof_size(_size_)  ccn_sizeof_n(ccn_nof_size(_size_))

/* Returns the value of bit _k_ of _ccn_, both are only evaluated once.  */
#define ccn_bit(_ccn_, _k_) ({__typeof__ (_k_) __k = (_k_); \
    1 & ((_ccn_)[__k / CCN_UNIT_BITS] >> (__k & (CCN_UNIT_BITS - 1)));})

/* Set the value of bit _k_ of _ccn_ to the value _v_  */
#define ccn_set_bit(_ccn_, _k_, _v_) ({__typeof__ (_k_) __k = (_k_);        \
    if (_v_)                                                                \
        (_ccn_)[__k/CCN_UNIT_BITS] |= CC_UNIT_C(1) << (__k & (CCN_UNIT_BITS - 1));     \
    else                                                                    \
        (_ccn_)[__k/CCN_UNIT_BITS] &= ~(CC_UNIT_C(1) << (__k & (CCN_UNIT_BITS - 1)));  \
    })

/* number of array elements used in a cc_ctx_decl */
#define cc_ctx_n(_type_, _size_) ((_size_ + sizeof(_type_) - 1) / sizeof(_type_))

/* sizeof of a context declared with cc_ctx_decl */
#define cc_ctx_sizeof(_type_, _size_) sizeof(_type_[cc_ctx_n(_type_, _size_)])

#define cc_ctx_decl(_type_, _size_, _name_)  \
    _type_ _name_[cc_ctx_n(_type_, _size_)]

void cc_clear(size_t len, void *dst);
int cc_cmp_safe (size_t num, const void * ptr1, const void * ptr2);

#endif