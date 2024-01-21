#include "cc_gcm.h"

#if defined(CCMODE_GCM_TABLES) || defined(LRW_TABLES) || defined(CCMODE_GCM_FAST)

/* this is x*2^128 mod p(x) ... the results are 16 bytes each stored in a packed format.  Since only the
 * lower 16 bits are not zero'ed I removed the upper 14 bytes */
const unsigned char gcm_shift_table[256*2] = {
    0x00, 0x00, 0x01, 0xc2, 0x03, 0x84, 0x02, 0x46, 0x07, 0x08, 0x06, 0xca, 0x04, 0x8c, 0x05, 0x4e,
    0x0e, 0x10, 0x0f, 0xd2, 0x0d, 0x94, 0x0c, 0x56, 0x09, 0x18, 0x08, 0xda, 0x0a, 0x9c, 0x0b, 0x5e,
    0x1c, 0x20, 0x1d, 0xe2, 0x1f, 0xa4, 0x1e, 0x66, 0x1b, 0x28, 0x1a, 0xea, 0x18, 0xac, 0x19, 0x6e,
    0x12, 0x30, 0x13, 0xf2, 0x11, 0xb4, 0x10, 0x76, 0x15, 0x38, 0x14, 0xfa, 0x16, 0xbc, 0x17, 0x7e,
    0x38, 0x40, 0x39, 0x82, 0x3b, 0xc4, 0x3a, 0x06, 0x3f, 0x48, 0x3e, 0x8a, 0x3c, 0xcc, 0x3d, 0x0e,
    0x36, 0x50, 0x37, 0x92, 0x35, 0xd4, 0x34, 0x16, 0x31, 0x58, 0x30, 0x9a, 0x32, 0xdc, 0x33, 0x1e,
    0x24, 0x60, 0x25, 0xa2, 0x27, 0xe4, 0x26, 0x26, 0x23, 0x68, 0x22, 0xaa, 0x20, 0xec, 0x21, 0x2e,
    0x2a, 0x70, 0x2b, 0xb2, 0x29, 0xf4, 0x28, 0x36, 0x2d, 0x78, 0x2c, 0xba, 0x2e, 0xfc, 0x2f, 0x3e,
    0x70, 0x80, 0x71, 0x42, 0x73, 0x04, 0x72, 0xc6, 0x77, 0x88, 0x76, 0x4a, 0x74, 0x0c, 0x75, 0xce,
    0x7e, 0x90, 0x7f, 0x52, 0x7d, 0x14, 0x7c, 0xd6, 0x79, 0x98, 0x78, 0x5a, 0x7a, 0x1c, 0x7b, 0xde,
    0x6c, 0xa0, 0x6d, 0x62, 0x6f, 0x24, 0x6e, 0xe6, 0x6b, 0xa8, 0x6a, 0x6a, 0x68, 0x2c, 0x69, 0xee,
    0x62, 0xb0, 0x63, 0x72, 0x61, 0x34, 0x60, 0xf6, 0x65, 0xb8, 0x64, 0x7a, 0x66, 0x3c, 0x67, 0xfe,
    0x48, 0xc0, 0x49, 0x02, 0x4b, 0x44, 0x4a, 0x86, 0x4f, 0xc8, 0x4e, 0x0a, 0x4c, 0x4c, 0x4d, 0x8e,
    0x46, 0xd0, 0x47, 0x12, 0x45, 0x54, 0x44, 0x96, 0x41, 0xd8, 0x40, 0x1a, 0x42, 0x5c, 0x43, 0x9e,
    0x54, 0xe0, 0x55, 0x22, 0x57, 0x64, 0x56, 0xa6, 0x53, 0xe8, 0x52, 0x2a, 0x50, 0x6c, 0x51, 0xae,
    0x5a, 0xf0, 0x5b, 0x32, 0x59, 0x74, 0x58, 0xb6, 0x5d, 0xf8, 0x5c, 0x3a, 0x5e, 0x7c, 0x5f, 0xbe,
    0xe1, 0x00, 0xe0, 0xc2, 0xe2, 0x84, 0xe3, 0x46, 0xe6, 0x08, 0xe7, 0xca, 0xe5, 0x8c, 0xe4, 0x4e,
    0xef, 0x10, 0xee, 0xd2, 0xec, 0x94, 0xed, 0x56, 0xe8, 0x18, 0xe9, 0xda, 0xeb, 0x9c, 0xea, 0x5e,
    0xfd, 0x20, 0xfc, 0xe2, 0xfe, 0xa4, 0xff, 0x66, 0xfa, 0x28, 0xfb, 0xea, 0xf9, 0xac, 0xf8, 0x6e,
    0xf3, 0x30, 0xf2, 0xf2, 0xf0, 0xb4, 0xf1, 0x76, 0xf4, 0x38, 0xf5, 0xfa, 0xf7, 0xbc, 0xf6, 0x7e,
    0xd9, 0x40, 0xd8, 0x82, 0xda, 0xc4, 0xdb, 0x06, 0xde, 0x48, 0xdf, 0x8a, 0xdd, 0xcc, 0xdc, 0x0e,
    0xd7, 0x50, 0xd6, 0x92, 0xd4, 0xd4, 0xd5, 0x16, 0xd0, 0x58, 0xd1, 0x9a, 0xd3, 0xdc, 0xd2, 0x1e,
    0xc5, 0x60, 0xc4, 0xa2, 0xc6, 0xe4, 0xc7, 0x26, 0xc2, 0x68, 0xc3, 0xaa, 0xc1, 0xec, 0xc0, 0x2e,
    0xcb, 0x70, 0xca, 0xb2, 0xc8, 0xf4, 0xc9, 0x36, 0xcc, 0x78, 0xcd, 0xba, 0xcf, 0xfc, 0xce, 0x3e,
    0x91, 0x80, 0x90, 0x42, 0x92, 0x04, 0x93, 0xc6, 0x96, 0x88, 0x97, 0x4a, 0x95, 0x0c, 0x94, 0xce,
    0x9f, 0x90, 0x9e, 0x52, 0x9c, 0x14, 0x9d, 0xd6, 0x98, 0x98, 0x99, 0x5a, 0x9b, 0x1c, 0x9a, 0xde,
    0x8d, 0xa0, 0x8c, 0x62, 0x8e, 0x24, 0x8f, 0xe6, 0x8a, 0xa8, 0x8b, 0x6a, 0x89, 0x2c, 0x88, 0xee,
    0x83, 0xb0, 0x82, 0x72, 0x80, 0x34, 0x81, 0xf6, 0x84, 0xb8, 0x85, 0x7a, 0x87, 0x3c, 0x86, 0xfe,
    0xa9, 0xc0, 0xa8, 0x02, 0xaa, 0x44, 0xab, 0x86, 0xae, 0xc8, 0xaf, 0x0a, 0xad, 0x4c, 0xac, 0x8e,
    0xa7, 0xd0, 0xa6, 0x12, 0xa4, 0x54, 0xa5, 0x96, 0xa0, 0xd8, 0xa1, 0x1a, 0xa3, 0x5c, 0xa2, 0x9e,
    0xb5, 0xe0, 0xb4, 0x22, 0xb6, 0x64, 0xb7, 0xa6, 0xb2, 0xe8, 0xb3, 0x2a, 0xb1, 0x6c, 0xb0, 0xae,
    0xbb, 0xf0, 0xba, 0x32, 0xb8, 0x74, 0xb9, 0xb6, 0xbc, 0xf8, 0xbd, 0x3a, 0xbf, 0x7c, 0xbe, 0xbe };

#endif

#ifndef CCMODE_GCM_FAST
/* right shift */
/* TODO: Check if we don't already have this function in the xts code somewhere. */
static void gcm_rightshift(unsigned char *a)
{
    int x;
    for (x = 15; x > 0; x--) {
        a[x] = (a[x]>>1) | ((a[x-1]<<7)&0x80);
    }
    a[0] >>= 1;
}

/* c = b*a */
static const unsigned char mask[] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
static const unsigned char poly[] = { 0x00, 0xE1 };


/*!
 GCM GF multiplier (internal use only)  bitserial
 @param a   First value
 @param b   Second value
 @param c   Destination for a * b
 */
void ccmode_gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
    unsigned char Z[16], V[16];
    unsigned x, y, z;

    cc_zero(16, Z);
    CC_MEMCPY(V, a, 16);
    for (x = 0; x < 128; x++) {
        if (b[x>>3] & mask[x&7]) {
            for (y = 0; y < 16; y++) {
                Z[y] ^= V[y];
            }
        }
        z     = V[15] & 0x01;
        gcm_rightshift(V);
        V[0] ^= poly[z];
    }
    CC_MEMCPY(c, Z, 16);
}

#else

/* map normal numbers to "ieee" way ... e.g. bit reversed */
#define M(x) ( ((x&8)>>3) | ((x&4)>>1) | ((x&2)<<1) | ((x&1)<<3) )

#define BPD (sizeof(CCMODE_GCM_FAST_TYPE) * 8)
#define WPV (1 + (16 / sizeof(CCMODE_GCM_FAST_TYPE)))

/*!
 GCM GF multiplier (internal use only)  word oriented
 @param a   First value
 @param b   Second value
 @param c   Destination for a * b
 */
void ccmode_gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
    int i, j, k, u;
    CCMODE_GCM_FAST_TYPE B[16][WPV], tmp[32 / sizeof(CCMODE_GCM_FAST_TYPE)], pB[16 / sizeof(CCMODE_GCM_FAST_TYPE)], zz, z;
    unsigned char pTmp[32];

    /* create simple tables */
    cc_zero(sizeof(B[0]), B[0]);
    cc_zero(sizeof(B[M(1)]), B[M(1)]);

#if CCN_UNIT_SIZE == 4
    for (i = 0; i < 4; i++) {
        CC_LOAD32_BE(B[M(1)][i], a + (i<<2));
        CC_LOAD32_LE(pB[i],      b + (i<<2));
    }
#elif CCN_UNIT_SIZE == 8
    for (i = 0; i < 2; i++) {
        CC_LOAD64_BE(B[M(1)][i], a + (i<<3));
        CC_LOAD64_LE(pB[i],      b + (i<<3));
    }
#else
#error unsupported CCN_UNIT_SIZE
#endif

    /* now create 2, 4 and 8 */
    B[M(2)][0] = B[M(1)][0] >> 1;
    B[M(4)][0] = B[M(1)][0] >> 2;
    B[M(8)][0] = B[M(1)][0] >> 3;
    for (i = 1; i < (int)WPV; i++) {
        B[M(2)][i] = (B[M(1)][i-1] << (BPD-1)) | (B[M(1)][i] >> 1);
        B[M(4)][i] = (B[M(1)][i-1] << (BPD-2)) | (B[M(1)][i] >> 2);
        B[M(8)][i] = (B[M(1)][i-1] << (BPD-3)) | (B[M(1)][i] >> 3);
    }

    /*  now all values with two bits which are 3, 5, 6, 9, 10, 12 */
    for (i = 0; i < (int)WPV; i++) {
        B[M(3)][i]  = B[M(1)][i] ^ B[M(2)][i];
        B[M(5)][i]  = B[M(1)][i] ^ B[M(4)][i];
        B[M(6)][i]  = B[M(2)][i] ^ B[M(4)][i];
        B[M(9)][i]  = B[M(1)][i] ^ B[M(8)][i];
        B[M(10)][i] = B[M(2)][i] ^ B[M(8)][i];
        B[M(12)][i] = B[M(8)][i] ^ B[M(4)][i];

        /*  now all 3 bit values and the only 4 bit value: 7, 11, 13, 14, 15 */
        B[M(7)][i]  = B[M(3)][i] ^ B[M(4)][i];
        B[M(11)][i] = B[M(3)][i] ^ B[M(8)][i];
        B[M(13)][i] = B[M(1)][i] ^ B[M(12)][i];
        B[M(14)][i] = B[M(6)][i] ^ B[M(8)][i];
        B[M(15)][i] = B[M(7)][i] ^ B[M(8)][i];
    }

    cc_zero(sizeof(tmp), tmp);

    /* compute product four bits of each word at a time */
    /* for each nibble */
    for (i = (BPD/4)-1; i >= 0; i--) {
        /* for each word */
        for (j = 0; j < (int)(WPV-1); j++) {
            /* grab the 4 bits recall the nibbles are backwards so it's a shift by (i^1)*4 */
            u = (pB[j] >> ((i^1)<<2)) & 15;

            /* add offset by the word count the table looked up value to the result */
            for (k = 0; k < (int)WPV; k++) {
                tmp[k+j] ^= B[u][k];
            }
        }
        /* shift result up by 4 bits */
        if (i != 0) {
            for (z = j = 0; j < (int)(32 / sizeof(CCMODE_GCM_FAST_TYPE)); j++) {
                zz = tmp[j] << (BPD-4);
                tmp[j] = (tmp[j] >> 4) | z;
                z = zz;
            }
        }
    }

    /* store product */
#if CCN_UNIT_SIZE == 4
    for (i = 0; i < 8; i++) {
        CC_STORE32_BE(tmp[i], pTmp + (i<<2));
    }
#elif CCN_UNIT_SIZE == 8
    for (i = 0; i < 4; i++) {
        CC_STORE64_BE(tmp[i], pTmp + (i<<3));
    }
#else
#error unsupported CCN_UNIT_SIZE
#endif

    /* reduce by taking most significant byte and adding the appropriate two byte sequence 16 bytes down */
    for (i = 31; i >= 16; i--) {
        pTmp[i-16] ^= gcm_shift_table[((unsigned)pTmp[i]<<1)];
        pTmp[i-15] ^= gcm_shift_table[((unsigned)pTmp[i]<<1)+1];
    }

    for (i = 0; i < 16; i++) {
        c[i] = pTmp[i];
    }
}

#endif

/*!
 GCM multiply by H
 @param gcm   The GCM state which holds the H value
 @param I     The value to multiply H by
 */
void ccmode_gcm_mult_h(ccgcm_ctx *key, unsigned char *I)
{
    unsigned char T[16];
#ifdef CCMODE_GCM_TABLES
    struct _ccmode_gcm_key *gcm = _CCMODE_GCM_KEY(key);
    int x, y;
#ifdef CCMODE_GCM_TABLES_SSE2
    asm("movdqa (%0),%%xmm0"::"r"(&gcm->PC[0][I[0]][0]));
    for (x = 1; x < 16; x++) {
        asm("pxor (%0),%%xmm0"::"r"(&gcm->PC[x][I[x]][0]));
    }
    asm("movdqa %%xmm0,(%0)"::"r"(&T));
#else /* !CCMODE_GCM_TABLES_SSE2 */
    CC_MEMCPY(T, &gcm->PC[0][I[0]][0], 16);
    for (x = 1; x < 16; x++) {
#ifdef CCMODE_GCM_FAST
        for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
            *((CCMODE_GCM_FAST_TYPE *)(T + y)) ^= *((CCMODE_GCM_FAST_TYPE *)(&gcm->PC[x][I[x]][y]));
        }
#else /* !CCMODE_GCM_FAST */
        for (y = 0; y < 16; y++) {
            T[y] ^= gcm->PC[x][I[x]][y];
        }
#endif /* !CCMODE_GCM_FAST */
    }
#endif /* !CCMODE_GCM_TABLES_SSE2 */
#else /* !CCMODE_GCM_TABLES */
    ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(key), I, T);
#endif /* !CCMODE_GCM_TABLES */
    CC_MEMCPY(I, T, 16);
}

void ccmode_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *key,
                     size_t rawkey_len, const void *rawkey) {
    const struct ccmode_ecb *ecb = gcm->custom;
    cc_assert(((GCM_TABLE_SIZE % CCN_UNIT_SIZE) == 0));
    _CCMODE_GCM_ECB_MODE(key)->ecb = ecb;
    _CCMODE_GCM_ECB_MODE(key)->ecb_key = &_CCMODE_GCM_KEY(key)->u[0] + GCM_TABLE_SIZE;

    ecb->init(ecb, CCMODE_GCM_KEY_ECB_KEY(key), rawkey_len, rawkey);

    /* gmac init: X=0, PAD=0, H = E(0) */
    cc_zero(16, CCMODE_GCM_KEY_X(key));
    cc_zero(16, CCMODE_GCM_KEY_PAD(key));
    ecb->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1, CCMODE_GCM_KEY_X(key),
             CCMODE_GCM_KEY_H(key));

    CCMODE_GCM_KEY_PAD_LEN(key) = 0;
    _CCMODE_GCM_KEY(key)->mode = CCMODE_GCM_MODE_IV;
    _CCMODE_GCM_KEY(key)->ivmode = 0;
    _CCMODE_GCM_KEY(key)->totlen = 0;
    _CCMODE_GCM_KEY(key)->pttotlen = 0;

#ifdef CCMODE_GCM_TABLES
    /* setup tables */
    int x, y, z, t;
    unsigned char B[16] = {};

    /* generate the first table as it has no shifting (from which we make the other tables) */
    for (y = 0; y < 256; y++) {
        B[0] = y;
        ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(key), B, &_CCMODE_GCM_KEY(key)->PC[0][y][0]);
    }

    /* now generate the rest of the tables based the previous table */
    for (x = 1; x < 16; x++) {
        for (y = 0; y < 256; y++) {
            /* now shift it right by 8 bits */
            t = _CCMODE_GCM_KEY(key)->PC[x-1][y][15];
            for (z = 15; z > 0; z--) {
                _CCMODE_GCM_KEY(key)->PC[x][y][z] = _CCMODE_GCM_KEY(key)->PC[x-1][y][z-1];
            }
            _CCMODE_GCM_KEY(key)->PC[x][y][0] = gcm_shift_table[t<<1];
            _CCMODE_GCM_KEY(key)->PC[x][y][1] ^= gcm_shift_table[(t<<1)+1];
        }
    }
#endif /* !CCMODE_GCM_TABLES */
}

void ccmode_gcm_set_iv(ccgcm_ctx *key, size_t iv_size, const void *iv) {
    size_t x, y;
    const uint8_t *IV = iv;

    /* must be in IV mode */
    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV,errOut); /* CRYPT_INVALID_ARG */

    /* trip the ivmode flag */
    if (iv_size + CCMODE_GCM_KEY_PAD_LEN(key) > 12) {
        _CCMODE_GCM_KEY(key)->ivmode |= 1;
    }

    x = 0;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {
        for (x = 0; x < (iv_size & ~15U); x += 16) {
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_X(key)[y])) ^= *((const CCMODE_GCM_FAST_TYPE*)(&IV[x + y]));
            }
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
        IV += x;
    }
#endif

    /* start adding IV data to the state */
    for (; x < iv_size; x++) {
        CCMODE_GCM_KEY_PAD(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] = *IV++;

        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            /* GF mult it */
            for (y = 0; y < 16; y++) {
                CCMODE_GCM_KEY_X(key)[y] ^= CCMODE_GCM_KEY_PAD(key)[y];
            }
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
    }
errOut:
    return;
}

void ccmode_gcm_gmac(ccgcm_ctx *key, size_t nbytes, const void *in) {
    const char *bytes = in;
    size_t x;
#ifdef CCMODE_GCM_FAST
    size_t y;
#endif

    /* in IV mode? */
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV) {
        /* let's process the IV */
        if (_CCMODE_GCM_KEY(key)->ivmode || CCMODE_GCM_KEY_PAD_LEN(key) != 12) {
            for (x = 0; x < CCMODE_GCM_KEY_PAD_LEN(key); x++) {
                CCMODE_GCM_KEY_X(key)[x] ^= CCMODE_GCM_KEY_PAD(key)[x];
            }
            if (CCMODE_GCM_KEY_PAD_LEN(key)) {
                _CCMODE_GCM_KEY(key)->totlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
                ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            }

            /* mix in the length */
            cc_zero(8, CCMODE_GCM_KEY_PAD(key));
            CC_STORE64_BE(_CCMODE_GCM_KEY(key)->totlen, CCMODE_GCM_KEY_PAD(key)+8);
            for (x = 0; x < 16; x++) {
                CCMODE_GCM_KEY_X(key)[x] ^= CCMODE_GCM_KEY_PAD(key)[x];
            }
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

            /* copy counter out */
            CC_MEMCPY(CCMODE_GCM_KEY_Y(key), CCMODE_GCM_KEY_X(key), 16);
            cc_zero(16, CCMODE_GCM_KEY_X(key));
        } else {
            CC_MEMCPY(CCMODE_GCM_KEY_Y(key), CCMODE_GCM_KEY_PAD(key), 12);
            CCMODE_GCM_KEY_Y(key)[12] = 0;
            CCMODE_GCM_KEY_Y(key)[13] = 0;
            CCMODE_GCM_KEY_Y(key)[14] = 0;
            CCMODE_GCM_KEY_Y(key)[15] = 1;
        }
        CC_MEMCPY(CCMODE_GCM_KEY_Y_0(key), CCMODE_GCM_KEY_Y(key), 16);
        //cc_zero(16, CCMODE_GCM_KEY_PAD(key));
        CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        _CCMODE_GCM_KEY(key)->totlen = 0;
        _CCMODE_GCM_KEY(key)->mode   = CCMODE_GCM_MODE_AAD;
    }

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_AAD && CCMODE_GCM_KEY_PAD_LEN(key) < 16,errOut); /* CRYPT_INVALID_ARG */

    x = 0;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {
        for (x = 0; x < (nbytes & ~15UL); x += 16) {
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_X(key)[y])) ^= *((const CCMODE_GCM_FAST_TYPE*)(&bytes[x + y]));
            }
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
        bytes += x;
    }
#endif

    /* start adding AAD data to the state */
    for (; x < nbytes; x++) {
        CCMODE_GCM_KEY_X(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] ^= *bytes++;

        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            /* GF mult it */
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
    }
errOut:
    return;
}

void ccmode_gcm_decrypt(ccgcm_ctx *key, size_t nbytes,
                        const void *in, void *out) {
    size_t x, y;
    unsigned char b;

    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV) {
        // This allows the gmac routine to be skipped by callers.
        ccmode_gcm_gmac(key, 0, NULL);
    }
    /* in AAD mode? */
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_AAD) {
        /* let's process the AAD */
        if (CCMODE_GCM_KEY_PAD_LEN(key)) {
            _CCMODE_GCM_KEY(key)->totlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
        }

        /* increment counter */
        for (y = 15; y >= 12; y--) {
            if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
        }
        /* encrypt the counter */
        CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_GCM_KEY_Y(key),
                                     CCMODE_GCM_KEY_PAD(key));
        CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        _CCMODE_GCM_KEY(key)->mode   = CCMODE_GCM_MODE_TEXT;
        _CCMODE_GCM_KEY(key)->pttotlen = 0;
    }

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    x = 0;
    const unsigned char *ct = in;
    unsigned char *pt = out;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {
        for (x = 0; x < (nbytes & ~15U); x += 16) {
            /* ctr encrypt */
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&_CCMODE_GCM_KEY(key)->X[y])) ^= *((const CCMODE_GCM_FAST_TYPE*)(&ct[x+y]));
                *((CCMODE_GCM_FAST_TYPE*)(&pt[x + y])) = *((const CCMODE_GCM_FAST_TYPE*)(&ct[x+y])) ^ *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_PAD(key)[y]));
            }
            /* GMAC it */
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccmode_gcm_mult_h(key, _CCMODE_GCM_KEY(key)->X);
            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
        }
    }
#endif // CCMODE_GCM_FAST

    /* process text */
    for (; x < nbytes; x++) {
        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        }

        b = ct[x];
        pt[x] = ct[x] ^ CCMODE_GCM_KEY_PAD(key)[CCMODE_GCM_KEY_PAD_LEN(key)];
        CCMODE_GCM_KEY_X(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] ^= b;
    }
errOut:
    return;
}

void ccmode_gcm_encrypt(ccgcm_ctx *key, size_t nbytes,
                       const void *in, void *out) {
    size_t x, y;
    unsigned char b;
    
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV) {
        // This allows the gmac routine to be skipped by callers.
        ccmode_gcm_gmac(key, 0, NULL);
    }
    /* in AAD mode? */
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_AAD) {
        /* let's process the AAD */
        if (CCMODE_GCM_KEY_PAD_LEN(key)) {
            _CCMODE_GCM_KEY(key)->totlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
        }

        /* increment counter */
        for (y = 15; y >= 12; y--) {
            if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
        }
        /* encrypt the counter */
        CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_GCM_KEY_Y(key),
                                     CCMODE_GCM_KEY_PAD(key));
        CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        _CCMODE_GCM_KEY(key)->mode   = CCMODE_GCM_MODE_TEXT;
        _CCMODE_GCM_KEY(key)->pttotlen = 0;
    }

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    x = 0;
    const unsigned char *pt = in;
    unsigned char *ct = out;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {
        for (x = 0; x < (nbytes & ~15U); x += 16) {
            /* ctr encrypt */
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&ct[x + y])) = *((const CCMODE_GCM_FAST_TYPE*)(&pt[x+y])) ^ *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_PAD(key)[y]));
                *((CCMODE_GCM_FAST_TYPE*)(&_CCMODE_GCM_KEY(key)->X[y])) ^= *((CCMODE_GCM_FAST_TYPE*)(&ct[x+y]));
            }
            /* GMAC it */
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccmode_gcm_mult_h(key, _CCMODE_GCM_KEY(key)->X);
            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
        }
    }
#endif // CCMODE_GCM_FAST

    /* process text */
    for (; x < nbytes; x++) {
        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        }

        b = ct[x] = pt[x] ^ CCMODE_GCM_KEY_PAD(key)[CCMODE_GCM_KEY_PAD_LEN(key)];
        CCMODE_GCM_KEY_X(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] ^= b;
    }
errOut:
    return;
}

void ccmode_gcm_finalize(ccgcm_ctx *key, size_t tag_size, void *tag) {
    size_t x;

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    /* handle remaining ciphertext */
    if (CCMODE_GCM_KEY_PAD_LEN(key)) {
        _CCMODE_GCM_KEY(key)->pttotlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
        ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
    }

    /* length */
    CC_STORE64_BE(_CCMODE_GCM_KEY(key)->totlen, CCMODE_GCM_KEY_PAD(key));
    CC_STORE64_BE(_CCMODE_GCM_KEY(key)->pttotlen, CCMODE_GCM_KEY_PAD(key)+8);
    for (x = 0; x < 16; x++) {
        CCMODE_GCM_KEY_X(key)[x] ^= CCMODE_GCM_KEY_PAD(key)[x];
    }
    ccmode_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

    /* encrypt original counter */
    CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_GCM_KEY_Y_0(key),
                                 CCMODE_GCM_KEY_PAD(key));
    uint8_t *out = tag;
    for (x = 0; x < 16 && x < tag_size; x++) {
        out[x] = CCMODE_GCM_KEY_PAD(key)[x] ^ CCMODE_GCM_KEY_X(key)[x];
    }
errOut:
    return;
}

void ccmode_gcm_reset(ccgcm_ctx *key)
{
    cc_clear(16, CCMODE_GCM_KEY_X(key));
    cc_clear(16, CCMODE_GCM_KEY_PAD(key));
    CCMODE_GCM_KEY_PAD_LEN(key) = 0;
    _CCMODE_GCM_KEY(key)->mode = CCMODE_GCM_MODE_IV;
    _CCMODE_GCM_KEY(key)->ivmode = 0;
    _CCMODE_GCM_KEY(key)->totlen = 0;
    _CCMODE_GCM_KEY(key)->pttotlen = 0;
}