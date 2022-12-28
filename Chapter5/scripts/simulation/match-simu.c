#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>


// if defined, then SHA3 is used to create checksum
//#define HASHSHA3 1
// if defined CRC8 is used to create checksum
// #define HASHCRC 1
// if neither is defined, ad hoc checksum is used

#ifdef HASHSHA3
#include "sha3.h"
#include "sha3.c"
#endif // HASHSHA3

// used as pseudo-random number generator transition function
#include "aes.h"
#include "aes.c"

// if not defined, then only cases of matching bits will be counted
#define FULLCHECK 1 // then complex will not only test if at most t bits are not matched, but will also check if the first checksum hit re-constructs the intended message

#define MAXITER 50000000 // no of tests
#define MASKMSG(no) ((1<<no)-1) // mask for no bit secret msg chunk

// both not in use currently
#define NOFLAG 0
#define SPLITFLAG 1 // options referring to splitflag currently not implemented and not used

// variants of DUST
#define DUST_BASIC 0
#define DUST_EXT 1

typedef struct myiterator{
    int dim;
    int range;
    int* vals;
} myiterator_t;

typedef struct myprng{
    uint8_t state[16];
    uint8_t statenew[16];
    uint8_t key[16];
} myprng_t;

// random number generator with AES as state transition function

unsigned int getrand(myprng_t* rng){
    unsigned int result = 0;
    int i;

    AES128_ECB_encrypt(rng->state,rng->key,rng->statenew);
    for(i=0;i<16;i++) rng->state[i] = rng->statenew[i];
    for(i=0;i<4;i++) result = (result << 8) | (unsigned int)(rng->state[i]);

    return result;
}

void resetrand(myprng_t* rng){
    int i;

    for(i=0;i<16;i++){
        rng->state[i] = 0;
        rng->statenew[i] = 0;
    }

    getrand(rng);



}

myprng_t* initrand(unsigned long int seed){
    myprng_t* rng;
    int i;

    rng = (myprng_t*)malloc(sizeof(myprng_t));
    for(i=4;i<16;i++){
        rng->key[i] = 0;
    }
    for(i=0;i<4;i++){
        rng->key[0] = (uint8_t)(seed & 0xff);
        seed = seed >> 8;
    }

    resetrand(rng);

    return rng;
}

void destroyrand(myprng_t* ptr){
    free(ptr);
}

// iterator enumerates all subsets of size dim of indices 0...range-1

int getiteratordim(myiterator_t* ptr){
    return ptr->dim;
}

int getiteratorrange(myiterator_t* ptr){
    return ptr->range;
}

int getiteratorval(myiterator_t* ptr,int i){
    if((i>=0) && (i<ptr->dim))
        return ptr->vals[i];
    else
        return -1;
}

void resetiterator(myiterator_t* ptr){
    int i;

    for(i=0;i<ptr->dim;i++) ptr->vals[i] = i;
}

#define MAXRANGE 32
#define MAXDIM 8
#define DEFAULTRANGE 10 // must be <= MAXRANGE
#define DEFAULTDIM 1    // must be <= MAXDIM

myiterator_t* createiterator(int dim,int range1,int range2,int splitflag){
    myiterator_t* ptr;

    if((range1<1)||(range1>MAXRANGE)){
        printf("resetting iterator range from %d to %d\n",range1,DEFAULTRANGE);
        range1 = DEFAULTRANGE;
    }
    if((dim<1) || (dim>MAXDIM)){
        printf("resetting iterator dim from %d to %d\n",dim,DEFAULTDIM);
        dim = DEFAULTDIM;
    }
    if(range1 < dim){
        printf("setting range %d to dim %d\n",range1,dim);
        range1 = dim;
    }
    ptr = (myiterator_t*)malloc(sizeof(myiterator_t));
    ptr->dim = dim;
    ptr->range = range1;
    ptr->vals = (int*)malloc(dim*sizeof(int));
    resetiterator(ptr);
    return ptr;
}

int islastiterator(myiterator_t* ptr){
    int i;
    int result = 1;

    for(i=0;i<ptr->dim;i++) if(ptr->vals[i] < ptr->range - ptr->dim + i) result = 0;

    return result;
}

int nextiterator(myiterator_t* ptr){
    int i,j;

    if(!islastiterator(ptr)){
        for(i=ptr->dim -1;i>=0;i--){
            if(ptr->vals[i] < ptr->range - ptr->dim + i){
                ptr->vals[i]++;
                for(j=i+1;j<ptr->dim;j++) ptr->vals[j] = ptr->vals[j-1] + 1;
                break;
            }
        }
    }

    return islastiterator(ptr);
}

void destroyiterator(myiterator_t* ptr){
free(ptr->vals);
free(ptr);
}

void printiterator(myiterator_t* ptr){
    int i;

    for(i=0;i<ptr->dim;i++) printf("%d ",ptr->vals[i]);
    printf("\n");
}

void testiterator(int dim,int range){
    myiterator_t* ptr;
    int flag = 0;

    ptr = createiterator(dim,range,1,NOFLAG);
    printf("iterator dim=%d range=%d\n",dim,range);

    while(!flag){
        printiterator(ptr);
        if(islastiterator(ptr)) flag = 1;
        else nextiterator(ptr);
    }
    destroyiterator(ptr);
}

// CRC8 implementation

char CRC8(unsigned int msg,int bit)
{
   char crc = 0x00;
   char extract;
   char sum;
   int length;

   length = (bit+7) / 8;
   for(int i=0;i<length;i++)
   {
      extract = (char)(msg & 0xff);
      msg = msg >> 8;
      for (char tempI = 8; tempI; tempI--)
      {
         sum = (crc ^ extract) & 0x01;
         crc >>= 1;
         if (sum)
            crc ^= 0x8C;
         extract >>= 1;
      }
   }
   return crc;
}

// checksum

unsigned int getchksum(unsigned int msg,int bit,int chkbit){
    unsigned int result;

#ifdef HASHSHA3
    // TODO: get SHA3(msg) shorten to chkbit bits
    // CURRENTLY: take chkbit bits of msg, modify slightly
    uint8_t w[32], r[32];
    for(int i=0;i<4;i++){
        for(int j=0;j<8;j++){
            w[i+4*j] = (uint8_t)(msg & 0xff);
            r[i+4*j] = 0;
        }
        msg = msg >> 8;
    }
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, w, 32, r, 32);
    result = 0;
    for(int i=0;i<4;i++){
        result = result | (unsigned int)r[2*i+4];
        if(i<3) result = result << 8;
    }
    result = result & MASKMSG(chkbit);
#elif HASHCRC
    result = ((unsigned int)CRC8(msg,bit)) & MASKMSG(chkbit);
#else
    result = msg & MASKMSG(chkbit);
    if(bit>chkbit)
        result += (msg >> chkbit) & MASKMSG(chkbit);
    if(bit>2*chkbit)
        result += (msg >> (2*chkbit)) & MASKMSG(chkbit);
    result = result + 9;
    result = result & MASKMSG(chkbit);
#endif
    return result;
}


int bitcnt(unsigned int inp){
    int result = 0;

    while(inp != 0){
        if(inp & 1) result++;
        inp = inp >> 1;
    }
    return result;
}

int testcorrectedhval(unsigned int secretmsg,unsigned int correctedhval,int bit,int chkbit){
    int result;
    unsigned int possiblemsg;
    unsigned int possiblechksum;
    unsigned int recomputedchksum;

    result = 0;
    possiblemsg = correctedhval & MASKMSG(bit);
    possiblechksum = (correctedhval >> bit) & MASKMSG(chkbit);
    recomputedchksum    = getchksum(possiblemsg,bit,chkbit);
    if(recomputedchksum == possiblechksum){
        if(possiblemsg == secretmsg) result = 1;
        else result = -1;
    }
    return result;
}


// returns: 1 = secret msg + chksum are first correction found
// -1: secret msg + chksum are NOT first correction found
// 0: no suitable correction found
int isfirstcorrectati(unsigned int secretmsg,unsigned int chksum,unsigned int hval,int bit,int chkbit,int tolerance,int i,int splitflag){
    unsigned int correctedhval;
    int result = 0;
    int j,k,l;
    myiterator_t* ptr;
    int flag;

    if(i == 0){
        correctedhval = hval;
        result = testcorrectedhval(secretmsg,correctedhval,bit,chkbit);
    }else{
        ptr = createiterator(i,bit+chkbit,chkbit,splitflag);
        flag = 0;
        while(!flag){
            correctedhval = hval;
            for(j=getiteratordim(ptr)-1;j>=0;j--){
                k = getiteratorval(ptr,j);
                correctedhval = correctedhval ^ (1 << k);
            }
            result = testcorrectedhval(secretmsg,correctedhval,bit,chkbit);
            if(result) break;
            if(islastiterator(ptr)) flag = 1;
            else nextiterator(ptr);
        }
        destroyiterator(ptr);
    }

    return result;
}


int isfirstcorrection(unsigned int secretmsg,unsigned int chksum,unsigned int hval,int bit,int chkbit,int tolerance,int splitflag){
    int i;
    int result = 0;
    int tmp;

    for(i=tolerance;i>=0;i--){
        tmp = isfirstcorrectati(secretmsg,chksum,hval,bit,chkbit,tolerance,i,splitflag);
        if(tmp) break;
    }
    if(tmp>0) result = 1;
    if(tmp == 0){
        printf("No suitable correction found!\n");
    }

    return result;
}

// complex = DUST-Ext
int checkcomplex(unsigned int secretmsg,unsigned int chksum,unsigned int hval,int bit,int chkbit,int tolerance,int splitflag){
    int result = 0;
//    unsigned int encodedmsg;
    int match1,match2;
    int condition;

    match1 = ~(secretmsg ^ hval);
    match1 = match1 & MASKMSG(bit);
    match2 = ~(chksum ^ (hval >> bit));
    match2 = match2 & MASKMSG(chkbit);

    if(splitflag == NOFLAG){
        condition = (bitcnt(match1) + bitcnt(match2)) >= (bit+chkbit-tolerance);
    }else
    if(splitflag == SPLITFLAG){
        condition = (match1 >= (bit - tolerance/2)) && (match2 >= (chkbit - tolerance/2 - tolerance&1));
    }else
        printf("unknown split condition\n");

//    encodedmsg = (chksum << bit) | secretmsg;
//    match = ~(encodedmsg ^ hval); // set all bit positions where msg and hval match
//    match = match & MASKMSG(bit+chkbit);

    // printf("secret msg %08x\n",secretmsg);
    // printf("check sum  %08x\n",chksum);
    // printf("encodedmsg %08x\n",encodedmsg);
    // printf("hash val   %08x\n",hval);
    // printf("match      %08x\n")
    if(condition){ // prerequisite for signal
#ifdef FULLCHECK
        if(isfirstcorrection(secretmsg,chksum,hval,bit,chkbit,tolerance,splitflag))
#endif
            result = 1;
    }

    return result;
}

// trivial = DUST-Basic
int checktrivial(unsigned int secretmsg,unsigned int hval,int bit){
    int result = 0;
    int match = ~(secretmsg ^ hval); // set all bit positions where msg and hval match
    match = match & MASKMSG(bit);

    if(bitcnt(match) == bit){ // as msg and hval have bit bits, this should be identical to secretmsg == hval
        result = 1;
    }

    return result;
}

void printctr(unsigned int i,unsigned int ctr,char* str,FILE* fp,int bit,int chkbit,int tolerance){
    unsigned int ratio;
    if(ctr>0) ratio = i / ctr;
    else ratio = i;
    if(fp == stdout){
        fprintf(fp,"no. iterations: %d ctr %s: %d (ratio: %d)\n",i,str,ctr,ratio);
    }else{
        fprintf(fp,"%d;%d;%d;%d\n",bit,chkbit,tolerance,ratio);
    }
}

void checksecretmsg(unsigned int secretmsg,int bit,int chkbit,int tolerance,myprng_t* rng,unsigned int maxiter,FILE* fp,int whichvariant){
    unsigned int hval;
    unsigned int i;
    unsigned int chksum;
    unsigned int ctr_trivial = 0;
    unsigned int ctr_complex = 0;
    unsigned int ctr_complex2 = 0;

    // fprintf(fp,"no bits %d no chkbits %d tolerance %d\n",bit,chkbit,tolerance);
    printf("no bits %d no chkbits %d tolerance %d\n",bit,chkbit,tolerance);

    secretmsg = secretmsg & MASKMSG(bit);
    chksum    = getchksum(secretmsg,bit,chkbit);

    for(i=0;i<maxiter;i++){
        if(!(i % 5000000)){
            if(whichvariant == DUST_BASIC)
                printctr(i,ctr_trivial,"trivial",stdout,bit,0,0);
            else
                printctr(i,ctr_complex,"complex",stdout,bit,chkbit,tolerance);
            // printctr(i,ctr_complex2,"complex with split",stdout);
        }
        hval = getrand(rng); // fake hash value
        if(whichvariant == DUST_BASIC)
            ctr_trivial  += checktrivial(secretmsg,hval & MASKMSG(bit),bit);
        else
            ctr_complex  += checkcomplex(secretmsg,chksum,hval & MASKMSG(bit+chkbit),bit,chkbit,tolerance,NOFLAG);
        // ctr_complex2 += checkcomplex(secretmsg,chksum,hval & MASKMSG(bit+chkbit),bit,chkbit,tolerance,SPLITFLAG);
    }
    if(whichvariant == DUST_BASIC)
        printctr(i,ctr_trivial,"trivial",fp,bit,0,0);
    else
        printctr(i,ctr_complex,"complex",fp,bit,chkbit,tolerance);
    // printctr(i,ctr_complex2,"complex with split",fp);
}

// eval command line parameters
void evalCLP(int argc,char* argv[],unsigned long int* seed,char** filename,unsigned int* secretmsg,int* bit,int* chkbit,int* tolerance){
    char* s;

    *seed = /* 1212121212; */  /* 1010101010; */ 100100;
    *secretmsg = 0;
    *filename = NULL;
    *bit = 16;
    *chkbit = 8;
    *tolerance = 3;

    printf("argc = %d\n",argc);

    if(*filename == NULL) *filename = (char*)malloc(100*sizeof(char));
    strcpy(*filename,"out.txt");

    for(int i=1;i<argc;i++){
        s = argv[i];
        printf("%d %s\n",i,s);

        if((*s == '-') && (*(s+1) =='s')){
            sscanf(s+2,"%d",seed);
        }
        if((*s == '-') && (*(s+1) =='b')){
            sscanf(s+2,"%d",bit);
        }
        if((*s == '-') && (*(s+1) =='c')){
            sscanf(s+2,"%d",chkbit);
        }
        if((*s == '-') && (*(s+1) =='f')){
            sscanf(s+2,"%s",filename);
        }
        if((*s == '-') && (*(s+1) =='m')){
            sscanf(s+2,"%d",secretmsg);
        }
    }
}


int main(int argc,char* argv[]){

    unsigned long int seed = 1; // seed for PRNG
    char* filename = NULL; // filename for outputs
    unsigned int secretmsg;
    unsigned int output;
    FILE* fp;
    int bit,chkbit; // no of bits in secret msg chunk, for checksum
    int tolerance; // max no of allowable non-matches between encoded msg and hval
    myprng_t* rng;


    printf("Start\n");

    // seed: for PRNG
    // filename: for result output
    // secret msg: h-c bits of secret msg
    // bit: value of h-c, bit length of secret msg
    // chckbit: value of c, bit length of checksum
    // tolerance: t of max hamming distance between hash value and secret message concat checksum
    evalCLP(argc,argv,&seed,&filename,&secretmsg,&bit,&chkbit,&tolerance);

    printf("CLP evaluated\n");

    if(filename != NULL){
        fp = fopen(filename,"wb");
        printf("Output file %s opened\n",filename);
    }else fp = stdout;

    rng = initrand(seed);

    printf("PRNG initialised with seed %d\n",seed);

    checksecretmsg(secretmsg,bit,chkbit,tolerance,rng,MAXITER,fp,DUST_EXT);

    // Alternative to CLP eval: enumerate desired cases
    /*
    for(int b=14;b<=22;b++){
        checksecretmsg(secretmsg,b,0,0,rng,MAXITER,fp,DUST_BASIC);
        resetrand(rng);

    }
    */

    // completely DUST_EXT: b=14...18 cb=6...10 t=1..5
    /*
    for(int b=18;b<=18;b++) for(int cb=6;cb<=10;cb++) for(int t=1;t<=5;t++){
        checksecretmsg(secretmsg,b,cb,t,rng,MAXITER,fp,DUST_EXT);
        resetrand(rng);
    }
    */
    if(filename != NULL)
        fclose(fp);

    printf("done\n");

    return 0;
}
