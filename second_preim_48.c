#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "xoshiro256starstar.h"
#include <math.h>

#define ROTL24_16(x) ((((x) << 16) ^ ((x) >> 8)) & 0xFFFFFF)
#define ROTL24_3(x) ((((x) << 3) ^ ((x) >> 21)) & 0xFFFFFF)

#define ROTL24_8(x) ((((x) << 8) ^ ((x) >> 16)) & 0xFFFFFF)
#define ROTL24_21(x) ((((x) << 21) ^ ((x) >> 3)) & 0xFFFFFF)

#define IV 0x010203040506ULL

/*
 * the 96-bit key is stored in four 24-bit chunks in the low bits of k[0]...k[3]
 * the 48-bit plaintext is stored in two 24-bit chunks in the low bits of p[0], p[1]
 * the 48-bit ciphertext is written similarly in c
 */

/* Key ... 96 ->
 * */
void speck48_96(const uint32_t k[4], const uint32_t p[2], uint32_t c[2])
{
    uint32_t rk[23];
    uint32_t ell[3] = {k[1], k[2], k[3]};

    rk[0] = k[0];

    c[0] = p[0];
    c[1] = p[1];

    /* full key schedule */
    for (unsigned i = 0; i < 22; i++)
    {
        uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF; // addition (+) is done mod 2**24
        rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
        ell[0] = ell[1];
        ell[1] = ell[2];
        ell[2] = new_ell;
    }

    for (unsigned i = 0; i < 23; i++)
    {

        c[0] = ((ROTL24_16(c[0]) + c[1]) ^ rk[i]) & 0xFFFFFF;
        c[1] = ROTL24_3(c[1]) ^ c[0];
    }


    return;
}

/* the inverse cipher */
void speck48_96_inv(const uint32_t k[4], const uint32_t c[2], uint32_t p[2])
{   uint32_t rk[23];
    uint32_t ell[3] = {k[1], k[2], k[3]};

    rk[0] = k[0];

    p[0] = c[0];
    p[1] = c[1];

    /* full key schedule */
    for (unsigned i = 0; i < 22; i++)
    {
        uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF; // addition (+) is done mod 2**24
        rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
        ell[0] = ell[1];
        ell[1] = ell[2];
        ell[2] = new_ell;
    }

    for( int i = 22 ; i >= 0  ; i--)
    {
        p[1] = ROTL24_21(p[1]^p[0] );
        p[0] = ROTL24_8(((p[0]^rk[i]) - p[1]) & 0xFFFFFF);

    }


}

/* The Davies-Meyer compression function based on speck48_96,
 * using an XOR feedforward
 * The input/output chaining value is given on the 48 low bits of a single 64-bit word,
 * whose 24 lower bits are set to the low half of the "plaintext"/"ciphertext" (p[0]/c[0])
 * and whose 24 higher bits are set to the high half (p[1]/c[1])
 */
uint64_t cs48_dm(const uint32_t m[4], const uint64_t h)
{

    uint32_t h_vet[2] = {(uint32_t)( (h >>24)& 0xFFFFFF ), (uint32_t)h & 0xFFFFFF};
    uint64_t old_h = h;

    speck48_96(m,h_vet,h_vet);
    uint64_t res = ( ((uint64_t)h_vet[1] )<<24) + (uint64_t)h_vet[0];
    res = res & 0xFFFFFFFFFFFF;
    res = res ^ old_h;
    /*printf("%x\n",h_2);
    printf("%x\n",h_1);*/
    return res;


}

/* assumes message length is fourlen * four blocks of 24 bits, each stored as the low bits of 32-bit words
 * fourlen is stored on 48 bits (as the 48 low bits of a 64-bit word)
 * when padding is include, simply adds one block (96 bits) of padding with fourlen and zeros on higher pos */
uint64_t hs48(const uint32_t *m, uint64_t fourlen, int padding, int verbose)
{
    uint64_t h = IV;
    const uint32_t *mp = m;

    for (uint64_t i = 0; i < fourlen; i++)
    {
        h = cs48_dm(mp, h);
        if (verbose)
            printf("@%llu : %06X %06X %06X %06X => %06llX\n", i, mp[0], mp[1], mp[2], mp[3], h);
        mp += 4;
    }
    if (padding)
    {
        uint32_t pad[4];
        pad[0] = fourlen & 0xFFFFFF;
        pad[1] = (fourlen >> 24) & 0xFFFFFF;
        pad[2] = 0;
        pad[3] = 0;
        h = cs48_dm(pad, h);
        if (verbose)
            printf("@%llu : %06X %06X %06X %06X => %06llX\n", fourlen, pad[0], pad[1], pad[2], pad[3], h);
    }

    return h;
}

/* Computes the unique fixed-point for cs48_dm for the message m */
uint64_t get_cs48_dm_fp(uint32_t m[4])
{
    uint32_t p[2];
    uint32_t c[2] = {0,0};
    speck48_96_inv(m,c,p);
    return  (uint64_t)(((uint64_t)p[0]) << 24) + (uint64_t)p[1];


}

/* Finds a two-block expandable message for hs48, using a fixed-point
 * That is, computes m1, m2 s.t. hs48_nopad(m1||m2) = hs48_nopad(m1||m2^*),
 * where hs48_nopad is hs48 with no padding */
void find_exp_mess(uint32_t m1[4], uint32_t m2[4])
{
    //phase 1: building the hashtable of size N

    uint64_t N = 1 << 24;
    uint64_t* HashTable = malloc( N * sizeof(uint64_t) );
    printf("building the HashTable\n");
    uint32_t ml[4];
    ml[2] = 0; ml[3] = 0;
    uint32_t ml2[4];
    ml2[2] = 0; ml2[3] = 0;
    uint64_t res;
    uint32_t res1,res2;
    uint32_t ml_temp;
    uint32_t ml2_temp;
    uint64_t random1;
    uint64_t random2;
    int nb_collisions = 0;

    for (int i=0; i<N; i++){
      random1 = xoshiro256starstar_random();
      random2 = xoshiro256starstar_random();
      ml[0] = ((uint32_t) random1) & 0xFFFFFF;
      ml[1] = ((uint32_t) random2) & 0xFFFFFF;
      uint64_t h1 = cs48_dm(ml, IV);
      //printf("%llx\n",  ((uint64_t) (ml[0] & 0x00FFFFFF)<<24) ) ;
      HashTable[h1%N] = ( ((uint64_t) ml[0] & 0x00FFFFFF)<<24 ) + ((uint64_t) ml[1]);
      //printf("%llx\n", HashTable[h1%N]);
    }

    printf("HashTable built\nlooking for collisions: ('.' is 2^23 trials) \n");
    //phase 2: try random m2

    for(int i = 1; ; i++){
      random1 = xoshiro256starstar_random();
      ml2[0] = ((uint32_t) random1) & 0xFFFFFF;
      ml2[1] = ( (uint32_t) (random1>>24) ) & 0xFFFFFF;
      uint64_t fixed_point = get_cs48_dm_fp(ml2);
      uint64_t x = HashTable[fixed_point%N];
      if (i%(1<<23) == 0) {printf(".\n");}
      if (x != 0) {
        nb_collisions++;
        ml[0] = (uint32_t) ((x>>24) & 0xFFFFFF);
        ml[1] = (uint32_t) ((x)     & 0xFFFFFF);
        /*if ( cs48_dm(ml, IV)%N != fixed_point%N ) {
          printf("reconstruction problem\n");
          printf("%llx\n", ml[0]);
          printf("%llx\n", ml[1]);
          printf("%llx\n", x);
          return;
        }
        printf("%llx\n", (cs48_dm(ml, IV) & (uint64_t)0xFFFFFFFFFFFF));
        printf("%llx\n", (fixed_point & (uint64_t)0xFFFFFFFFFFFF));
        printf("\n");*/
        if ( (cs48_dm(ml, IV) & (uint64_t)0x00FFFFFFFFFFFF) == (fixed_point & (uint64_t)0x00FFFFFFFFFFFF) ) {

          for (int i=0; i<4; i++) {
            m2[i] = ml2[i];
            m1[i] = ml[i];
          }
          //printf("HashTable collisions (false positives): %i\n", nb_collisions-1);
          return;
        }
      }

    }





}

void attack(void)
{
  //
  //target
  uint32_t* mess = malloc( sizeof(uint32_t) * (1<<20) );
  for (int i = 0; i < (1 << 20); i+=4){
    mess[i + 0] = i;
    mess[i + 1] = 0;
    mess[i + 2] = 0;
    mess[i + 3] = 0;
  }
  //printf("hash(mess)  :  %llx\n", hs48(mess, 1<<18, 0, 0));
  //
  // compute an expandable message (m1, m2)
  printf("computing expandable message\n");
  uint32_t m1[8];
  uint32_t *m2 = m1+4;
  find_exp_mess(m1, m2);
  uint64_t fixed_point = get_cs48_dm_fp(m2);
  
  //
  // create HashTable of  the  chaining  values  of mess
  printf("building HashTable of chaining values\n");
  uint64_t N = 1 << 21; // there is 2^18 values to store so 2^21 is a
  // reasonnable size to avoid having too many duplicates (=overwrights)
  uint64_t* HashTable = malloc( 2 * N * sizeof(uint64_t) );
  // HashTable[h%N] will be the chaining value index
  // HashTable[N + h%N] will be the exact chaining value
  const uint32_t *mp = mess;
  uint64_t h = cs48_dm(mp, IV);
  mp += 4;
  for (uint64_t i = 2; i < (1<<18)+1; i++)
  {
      h = cs48_dm(mp, h);
      HashTable[h%N] = i;
      HashTable[N + (h%N)] = h;
      mp += 4;
  }

  //
  // search for a collision block cm s.t. cm48(cm, fp) is equal to a chaining value
  printf("searching for a collision block  ('.' is 2^27 trials)\n");
  uint32_t collision_index = 0;
  uint32_t cm[4];
  uint64_t random1;
  cm[2] = 0; cm[3] = 0;
  for(int i = 1; collision_index == 0; i++){
    random1 = xoshiro256starstar_random();
    cm[0] = ((uint32_t) random1) & 0xFFFFFF;
    cm[1] = ( (uint32_t) (random1>>24) ) & 0xFFFFFF;
    h = cs48_dm(cm, fixed_point);
    if (i%(1<<27) == 0) {printf(".\n");}
    if (HashTable[N + (h%N)] == h) { // collision found
      collision_index = HashTable[h%N];
      printf("collision_index  :  %d\n", collision_index);
    }
  }

  //
  // construction of the second pre-image
  // if cm48(cm, fp) is equal to the n'th chaining value, then the
  // final second preimage is m1||m2||...||m2||cm||mess[n+1]||mess[n+2]||...
  uint32_t* mess2 = malloc( sizeof(uint32_t) * (1<<20) );

  mess2[0] = m1[0];
  mess2[1] = m1[1];
  mess2[2] = m1[2];
  mess2[3] = m1[3];

  for (int i = 4; i < 4*(collision_index-1); i+=4){
    mess2[i + 0] = m2[0];
    mess2[i + 1] = m2[1];
    mess2[i + 2] = m2[2];
    mess2[i + 3] = m2[3];
  }

  mess2[4*collision_index - 4] = cm[0];
  mess2[4*collision_index - 3] = cm[1];
  mess2[4*collision_index - 2] = cm[2];
  mess2[4*collision_index - 1] = cm[3];

  for (int i = 4*collision_index; i < (1 << 20); i+=4){
    mess2[i + 0] = i;
    mess2[i + 1] = 0;
    mess2[i + 2] = 0;
    mess2[i + 3] = 0;
  }
  printf("mess : %llx ", mess[0]); printf("%llx ", mess[1]); printf("%llx ", mess[2]); printf("%llx ", mess[3]); printf("%llx ", mess[4]); printf("%llx\n", mess[5]);
  printf("mess2: %llx ", mess2[0]);printf("%llx ", mess2[1]);printf("%llx ", mess2[2]);printf("%llx ", mess2[3]);printf("%llx ", mess2[4]);printf("%llx\n", mess2[5]);
  printf("\n");
  printf("hash(mess)  :  %llx\n", hs48(mess, 1<<18, 0, 0));
  printf("hash(mess2) :  %llx\n", hs48(mess2, 1<<18, 0, 0));
    
  return;
}

int test_sp48(void){
    int i;
    uint32_t k[4] = {0x1a1918,0x121110,0x0a0908,0x020100};
    uint32_t k1[4] = {0x020100,0x0a0908,0x121110,0x1a1918};
    uint32_t p[2] = {0x6d2073,0x696874};
    uint32_t p1[2] = {0x696874,0x6d2073};
    uint32_t c[2];
   /* speck48_96(k1,p1,c);
    for ( i = 0; i < 2 ; i++)
    {
        printf("%x\n",c[i]);
    }*/
    speck48_96(k1,p,c);
    for ( i = 0; i < 2 ; i++)
    {
        printf("%x\n",c[i]);
    }
    return 0;
}

int test_sp48_inv(void){
    int i;
    uint32_t k[4] = {0x1a1918,0x121110,0x0a0908,0x020100};
    uint32_t k1[4] = {0x020100,0x0a0908,0x121110,0x1a1918};
    uint32_t p[2] ;
    uint32_t p1[2] = {0x696874,0x6d2073};
    uint32_t c[2] = {0x735e10,0xb6445d};
    /* speck48_96(k1,p1,c);
     for ( i = 0; i < 2 ; i++)
     {
         printf("%x\n",c[i]);
     }*/
    speck48_96_inv(k1,c,p);
    for ( i = 0; i < 2 ; i++)
    {
        printf("%x\n",p[i]);
    }
    return 0;

}

int test_cs48_dm(void){
    uint32_t m[4] = {0,0,0,0};
    uint64_t h = 0;
    uint64_t res = cs48_dm(m,h);
    if (res == 0x7FDD5A6EB248ULL) {
        return 0;
    } else
        return 1;


}
int test_cs48_dm_fp(void){
    uint32_t m[4] = {0,0,0,0};
    uint64_t res = get_cs48_dm_fp(m);

    printf("%llx\n", res);
    printf("%llx\n", cs48_dm(m,res));
    if (res == cs48_dm(m,res)) {
        return 0;
    } else
        return 1;
}

int test_find_exp_mess(void){
  uint32_t m1[12];
  uint32_t *m2 = m1+4;
  find_exp_mess(m1, m2);
  m1[8] = m1[4]; 
  m1[9] = m1[5]; 
  m1[10] = m1[6]; 
  m1[11] = m1[7];
  //printf("m1 : %llx ", m1[0]); printf("%llx ", m1[1]); printf("%llx ", m1[2]); printf("%llx\n", m1[3]);
  //printf("m2 : %llx ", m1[4]); printf("%llx ", m1[5]); printf("%llx ", m1[6]); printf("%llx\n", m1[7]);
  printf("hash(m1||m2)     :  %llx\n", (hs48(m1, 2, 0, 1)));
  printf("hash(m1||m2||m2) :  %llx\n", (hs48(m1, 3, 0, 1)));
  printf("\n");
  if ( hs48(m1, 2, 0, 0) == hs48(m1, 3, 0, 0) ){
      return 0;
  }else{
      return 1;
  }
}
/*
int main()
{

    attack();
    
    //printf("%llx",getRandomWin());
    //find_exp_mess(m1,m2);
    
    for( int i = 0 ; i < 4 ; i++)
        for( int j = 0 ; j < 4 ; j++)
        {x = (uint32_t)(j << 2) + (uint32_t)i;
         y = (uint32_t)(i<<2)+(uint32_t)j;
            printf("%d %d\n",x,y);}

    uint64_t seed[4] = {0x20,0x1b,0xA1,0xFF};
    xoshiro256starstar_random_set(seed);
    printf("%x\n",xoshiro256starstar_random());
    printf("%x\n",xoshiro256starstar_random_unsafe());
    


    return 0;
}*/
