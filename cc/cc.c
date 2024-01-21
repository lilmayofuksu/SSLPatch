#include "cc.h"

void cc_clear(size_t len, void *dst)
{
#if ( CC_HAS_MEMSET_S == 1 ) && (defined( __STDC_WANT_LIB_EXT1__ ) && ( __STDC_WANT_LIB_EXT1__ == 1 ) )
    memset_s(dst,len,0,len);
#else
    volatile size_t ctr=0;
    volatile uint8_t *data=dst;
    if (len) {
        cc_zero(len,dst);
        (void)data[ctr]; // Touch the buffer so that the compiler does not
            // Optimize out the zeroing
    }
#endif
}

int cc_cmp_safe(size_t num, const void * ptr1, const void * ptr2)
{
    size_t i;
    const uint8_t *s=(const uint8_t *)ptr1;
    const uint8_t *t=(const uint8_t *)ptr2;
    uint8_t flag=((num<=0)?1:0); // If 0 return an error
    for (i=0;i<num;i++)
    {
        flag|=(s[i]^t[i]);
    }
    return flag; // 0 iff all bytes were equal
}

typedef	unsigned int aes_32t;
typedef struct
{   aes_32t ks[60];
    aes_32t rn;
} ccaes_arm_encrypt_ctx;

extern int (*_ccaes_arm_encrypt)(const unsigned char *in, unsigned char *out, const ccaes_arm_encrypt_ctx cx[1]);
int ccaes_arm_encrypt_wrap(const unsigned char *in, unsigned char *out, const ccaes_arm_encrypt_ctx cx[1]) {
    return _ccaes_arm_encrypt(in, out, cx);
}
