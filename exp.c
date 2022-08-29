#include <stdio.h>
#include <openssl/bn.h>

/**
 * @brief https://koreascience.kr/article/JAKO201108863880845.pdf - 2page
 * 
 * @param r result
 * @param a a
 * @param e a를 e만큼 지수승
 * @param m 모듈러
 * @return int 
 */
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *c = BN_new();
    BN_one(c);

    for(int i = BN_num_bits(e); i >= 0; i--)
    {
        BN_mod_mul(c, c, c, m, ctx);

        if(BN_is_bit_set(e, i)){
            BN_mod_mul(c, c, a, m, ctx);
        }

    }

    BN_copy(r, c);
    return 0;
}


void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}