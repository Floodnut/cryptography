#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>


typedef struct _b11rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB11_RSA;

/**
 * @brief RSA 구조체를 생성하여 포인터를 리턴하는 함수
 * 
 * @return BOB11_RSA* 
 */
BOB11_RSA *BOB11_RSA_new();

/**
 * @brief RSA 구조체 포인터를 해제하는 함수
 * 
 * @param b11rsa 
 * @return int 
 */
int BOB11_RSA_free(BOB11_RSA *b11rsa);


/**
 * @brief RSA 키 생성 함수
 * 입력 : nBits (RSA modulus bit size)
 * 출력 : b11rsa (구조체에 n, e, d 가  생성돼 있어야 함)
 * p=C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7
 * q=F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F
 * 
 * @param b11rsa 
 * @param nBits 
 * @return int 
 */
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits);

/**
 * @brief RSA 암호화 함수
 * 입력 : 공개키를 포함한 b11rsa, 메시지 m
 * 출력 : 암호문 c
 * 
 * @param c 
 * @param m 
 * @param b11rsa 
 * @return int
 */
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa);

/**
 * @brief RSA 복호화 함수
 * 입력 : 공개키를 포함한 b11rsa, 암호문 c
 * 출력 : 평문 m
 * 
 * @param m 
 * @param c 
 * @param b11rsa 
 * @return int 
 */
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa);


/**
 * @brief 밀러라빈 소수 판정
 * 
 * @param n 
 * @param tc 
 * @return int 
 */
int Miller_Rabin(BIGNUM *n, uint32_t tc);

/* ========================= 이전 과제 ========================= */
/**
 * @brief 과제1
 * 
 * @param x 
 * @param y 
 * @param a 
 * @param b 
 * @return BIGNUM* 
 */
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);

/**
 * @brief 과제2 - https://koreascience.kr/article/JAKO201108863880845.pdf - 2page
 *        
 * 
 * @param r result
 * @param a a
 * @param e a를 e만큼 지수승
 * @param m 모듈러
 * @return int 
 */
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);

/* ========================= 이전 과제 ========================= */

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
    BOB11_RSA *b11rsa = BOB11_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB11_RSA_KeyGen(b11rsa,1024);
        BN_print_fp(stdout,b11rsa->n);
        printf(" ");
        BN_print_fp(stdout,b11rsa->e);
        printf(" ");
        BN_print_fp(stdout,b11rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b11rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b11rsa->e, argv[2]);
            BOB11_RSA_Enc(out,in, b11rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b11rsa->d, argv[2]);
            BOB11_RSA_Dec(out,in, b11rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b11rsa!= NULL) BOB11_RSA_free(b11rsa);

    return 0;
}


/*
1. 입출력은 모두 Hexadecimal 표현을 사용할 것!
2. Modular inversion과 modular exponentiation은 반드시 이전에 숙제로 작성했던 것을 사용할 것!
3. libcrypto의 함수는 가감승제와 비트연산, 입출력 함수 외에는 사용하지 말 것 (알아서 이 과정의 교육목표에 맞게 쓰시기 바랍니다).
*/

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *t0 = BN_new(); 
    BIGNUM *t1 = BN_new();
    BN_copy(t0, a);
    BN_copy(t1, b);

    BIGNUM *u0 = BN_new();
    BIGNUM *v0 = BN_new();
    BIGNUM *u1 = BN_new();
    BIGNUM *v1 = BN_new();
    BN_dec2bn(&u0,"1");
    BN_dec2bn(&v0,"0");
    BN_dec2bn(&u1,"0");
    BN_dec2bn(&v1,"1");


    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *u2 = BN_new();
    BIGNUM *v2 = BN_new();
    BIGNUM *tmp = BN_new();


    while(!BN_is_zero(t1)){

        BN_div(q, r, t0, t1, ctx);

        BN_copy(t0, t1);
        BN_copy(t1, r);

        BN_mul(tmp, q, u1, ctx);
        BN_sub(u2, u0, tmp);

        BN_mul(tmp, q, v1, ctx);
        BN_sub(v2, v0, tmp);

        BN_copy(u0, u1);
        BN_copy(v0, v1);
        BN_copy(u1, u2);
        BN_copy(v1, v2);

    }

    BN_copy(x, u0);
    BN_copy(y, v0);
    return t0;
}


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
    return 1;
}


BOB11_RSA *BOB11_RSA_new(){
    BOB11_RSA* rsa = (BOB11_RSA*) malloc(sizeof(BOB11_RSA));
    rsa->n = BN_new();
    rsa->e = BN_new();
    rsa->d = BN_new();
    
    return rsa;
}


int BOB11_RSA_free(BOB11_RSA *b11rsa){
    BN_free(b11rsa->e);
    BN_free(b11rsa->d);
    BN_free(b11rsa->n);

    free(b11rsa);

    return 0;
}


int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *N = BN_new();

    BIGNUM *phi = BN_new();
    BIGNUM *p0 = BN_new();
    BIGNUM *q0 = BN_new();
    BIGNUM *c = BN_new();
    BN_one(c);

    while(1){
        BN_priv_rand(p, nBits / 2, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
        BN_priv_rand(q, nBits / 2, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);  
        if(Miller_Rabin(p, 10) == 1 && Miller_Rabin(q, 10) == 1){
            break;
        }
    }
    
    BN_mul(N, p, q, ctx);
    BN_copy(b11rsa->n, N);

    BN_sub(p0, p, c);
    BN_sub(q0, q, c);
    BN_mul(phi, p0, q0, ctx);
    /* 공개키*/
    BN_dec2bn(&b11rsa->e, "68713"); 
    
    XEuclid(b11rsa->d, q0, b11rsa->e, phi);
    ExpMod(b11rsa->d, b11rsa->d, c, phi);
    BN_free(c);

    return 0;
}


int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa){
    ExpMod(c, m, b11rsa->e, b11rsa->n);
    return 1;
}


int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa){
    ExpMod(m, c, b11rsa->d, b11rsa->n);
    return 1;
}

int Miller_Rabin(BIGNUM *n, uint32_t tc){ 
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *range = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *l = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *div = BN_new();
    BIGNUM *cmp = BN_new();
    BIGNUM *cmp2 = BN_new();
    BIGNUM *cmp3 = BN_new();
    BIGNUM *cmp4 = BN_new();
    BIGNUM *cmp5 = BN_new();
    BIGNUM *random = BN_new();

    BN_dec2bn(&l , "1");
    BN_dec2bn(&a , "2");
    BN_dec2bn(&cmp , "1");
    BN_dec2bn(&cmp2 , "1");
    BN_dec2bn(&cmp3 , "1");
    BN_dec2bn(&cmp4 , "2");
    BN_sub(b, n, cmp);

    while(1){
        
        BN_exp(div, a, l, ctx);
        BN_div(q, r, b, div, ctx);
        BN_add(l, l, cmp);
        if(BN_is_zero(r) && BN_is_odd(q)){
            BN_sub(l, l, cmp);
            break;
        }
    }
    
    BN_sub(range, n, cmp);
   
    for(int t = 0 ; t < tc ; t++){
        while(1){
            BN_rand_range(random, range);

            if(BN_is_one(random) || BN_is_zero(random))
                continue;
            
            break;
        }

        ExpMod(random, random, q, n);
       
        if (BN_is_one(random))
            continue;

        BN_copy(cmp, l);
        BN_dec2bn(&cmp5, "1");
        BN_sub(cmp2, n, cmp5);
        
        while(1){
            BN_mod(result, random, n, ctx);
            BN_sub(cmp, cmp, cmp3);

            if(BN_cmp(result, cmp2) == 0)
                break;
            
            if(BN_is_zero(cmp))
                break;
            
            /* BN_mod_exp 사용에 비해 시간이 조금 더 걸림 */
            ExpMod(random, random, cmp4, n); 
        }
        if(BN_cmp(result, cmp2) == 0)
            continue;
        
        return 0;     
    }

    if (ctx != NULL)
        BN_CTX_free(ctx);
    if (a != NULL)
        BN_free(a);
    if (q != NULL)
        BN_free(q);

    return 1;
}