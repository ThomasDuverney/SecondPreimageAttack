#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <inttypes.h>
#include "uthash.h"
#include "xoshiro256starstar.h"

// Circular shift of 8 bits to the right
#define ROTL24_16(x) ((((x) << 16) ^ ((x) >> 8)) & 0xFFFFFF)
// Circular shift of 3 bits to the left
#define ROTL24_3(x) ((((x) << 3) ^ ((x) >> 21)) & 0xFFFFFF)

// Circular shift of 8 bits to the left
#define ROTL24_8(x) ((((x) << 8) ^ ((x) >> 16)) & 0xFFFFFF)
// Circular shift of 3 bits to the right
#define ROTL24_21(x) ((((x) << 21) ^ ((x) >> 3)) & 0xFFFFFF)

#define IV 0x010203040506ULL

// printf in color
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KNRM  "\x1B[0m"

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
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF;
		rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}

	for (unsigned i = 0; i < 23; i++)
	{
    c[1] = (ROTL24_16(c[1]) + c[0]) & 0xFFFFFF;
    c[1] = c[1] ^ rk[i];
    c[0] = ROTL24_3(c[0]) ^ c[1];
	}

	return;
}

/* the inverse cipher */
void speck48_96_inv(const uint32_t k[4], const uint32_t c[2], uint32_t p[2])
{
	uint32_t rk[23];
	uint32_t ell[3] = {k[1], k[2], k[3]};

	rk[0] = k[0];

	p[0] = c[0];
	p[1] = c[1];

	/* full key schedule */
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF;
		rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}

  for (signed i = 22; i >= 0 ; i--)
  {
    p[0] = p[0] ^ p[1];
    p[1] = p[1] ^ rk[i];
    p[0] = ROTL24_21(p[0]);
    p[1] = (p[1] + 0x01000000 - p[0] )& 0xFFFFFF ;
    p[1] = ROTL24_8(p[1]) ;
  }

}

/* The Davies-Meyer compression function based on speck48_96,
 * using an XOR feedforward
 * The input/output chaining value is given on a single 64-bit word, whose
 * low bits are set to the low half of the "plaintext"/"ciphertext" (p[0]/c[0])
 */
uint64_t cs48_dm(const uint32_t m[4], const uint64_t h)
{

  uint32_t p[2] = {h & 0xFFFFFF,(h >> 24) & 0xFFFFFF};
  uint32_t c[2] = {0};

  speck48_96(m,p,c);

  return ((uint64_t) c[0] << 24 | (c[1] & 0xFFFFFF)) ^ h;

}

/* assumes message length is fourlen * four blocks of 24 bits store over 32
 * fourlen is on 48 bits
 * simply add one block of padding with fourlen and zeros on higher pos */
uint64_t hs48(const uint32_t *m, uint64_t fourlen, int padding, int verbose)
{
	uint64_t h = IV;
	uint32_t *mp = m;

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

  uint32_t p[2] = {0};
  uint32_t c[2] = {0x0,0x0};
  speck48_96_inv(m,c,p);
  uint64_t fp = ((uint64_t) p[1] << 24 | (p[0] & 0xFFFFFF));

  //  fp = cs48_dm(m,fp);

  return fp;
}

	struct table_struct{
		uint64_t id;
		uint32_t m[4];
		UT_hash_handle hh;
	};

	struct table_struct *htable = NULL;

void generateRandomMsg(struct table_struct *ts){

		uint64_t ma =  xoshiro256starstar_random();
    uint64_t mb =  xoshiro256starstar_random();

    uint32_t m[4] = {ma & 0xFFFFFF,(ma >> 32) & 0xFFFFFF,
                     mb & 0xFFFFFF,(mb >> 32) & 0xFFFFFF};

    //    uint32_t m[4] = {0x0,0x01,0x02,0x03};
    for (int i = 0; i < 4;i++)
      {
        ts->m[i]= m[i];
      }
}

void randomMsgHash(/* struct table_struct *htable */){

  struct table_struct  *ts = malloc(sizeof(struct table_struct));
  struct table_struct * ts_search = NULL;
  uint64_t h_id;
  do{

    generateRandomMsg(ts);
    h_id = cs48_dm(ts->m, IV);
    ts->id = h_id;

    HASH_FIND_INT(htable,&h_id,ts_search);

  }while(ts_search != NULL);

  HASH_ADD_INT(htable,id,ts);
}

void randomMsgFixedPoint(struct table_struct *ts){
    generateRandomMsg(ts);
    uint64_t fp_id = get_cs48_dm_fp(ts->m);
    ts->id = fp_id;
}

/* Finds a two-block expandable message for hs48, using a fixed-point
 * That is, computes m1, m2 s.t. hs48_nopad(m1||m2) = hs48_nopad(m1||m2^*),
 * where hs48_nopad is hs48 with no padding */

void find_exp_mess(uint32_t m1[4], uint32_t m2[4])
{

  int N = 16777216;	// 2  int N =1;
  int i, j;

  for (i = 0; i < N; i++)
  {
    randomMsgHash();
  }

  struct table_struct *ts_m1;
  struct table_struct *ts_m2 = malloc(sizeof(struct table_struct));

  i = 0;
  while(i < N ){
    randomMsgFixedPoint(ts_m2);
    uint64_t q = ts_m2->id;
    HASH_FIND_INT(htable,&q,ts_m1);
    //    HASH_FIND(hh, records, &l.key, sizeof(record_key_t), p);
    if(ts_m1 != NULL){
      printf("\t0x%016" PRIx64 "0x%016" PRIx64 "\n",ts_m1->id,ts_m2->id);
      ts_m1 = NULL;
    }

    i++;
  }

  if(ts_m1 != NULL)
  {
    printf(" \t\t 0x%016" PRIx64 " 0x%016" PRIx64"\n",ts_m1->id,ts_m2->id);
    for (j = 0; j < 4; j++)
    {
        m1[j] = ts_m1->m[j];
        m2[j] = ts_m2->m[j];
    }
  }else{
    printf("No collision found !! \n");
  }
}

void attack(void)
{
	struct table_struct{
		uint64_t id;
		int m;
		UT_hash_handle hh;
	};

	struct table_struct *h = NULL;
  struct table_struct *s;

  int N = 15;
  uint64_t rand = xoshiro256starstar_random();
  rand = rand && 0xFFFFFF;
  for (int i = 0; i < N; i++)
    {
      s = (struct table_struct*)malloc(sizeof(struct table_struct));
      if(i == 3)
        s->id = rand;

      s->m = i;
      HASH_ADD_INT( h, id, s);
    }

  struct table_struct *p;
  uint64_t j = rand;
  printf("0x%016" PRIx64 "\n",j);
  HASH_FIND_INT(h, &j, p);
  if(p != NULL)
    printf("%i",p->m);
  else
    printf("pouet");
}

int test_sp48(void){

  uint32_t key[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
  uint32_t p[2] = {0x696874, 0x6d2073};
  uint32_t c_exp[2] = {0xb6445d,0x735e10};
  uint32_t c[2] = {0};

  speck48_96(key,p,c);

  if(c_exp[0] == c[0] && c_exp[1] == c[1] ){
    printf("Test_sp46 : %sOK %s\n",KGRN,KNRM);
  }else{
    printf("Test_sp46: %sERROR %s\n",KRED,KNRM);
  }

  printf("\tCipher expected:");
  printf("\t\t 0x%08" PRIx32 " 0x%08" PRIx32"\n",c_exp[0],c_exp[1]);
  printf("\tCipher found:");
  printf("\t\t\t 0x%08" PRIx32 " 0x%08" PRIx32"\n",c[0],c[1]);
  printf("\n\n");
}

int test_sp48_inv(){

  uint32_t key[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
  uint32_t p_exp[2] = {0x696874, 0x6d2073};
  uint32_t c[2] = {0xb6445d,0x735e10};

  uint32_t p[2] = {0};

  speck48_96_inv(key,c,p);

  if(p_exp[0] == p[0] && p_exp[1] == p[1] ){
    printf("Test_sp46_inv : %sOK %s\n",KGRN,KNRM);
  }else{
    printf("Test_sp46_inv : %sERROR %s\n",KRED,KNRM);
  }

  printf("\tPlaintext expected:");
  printf("\t\t 0x%08" PRIx32 " 0x%08" PRIx32"\n",p_exp[0],p_exp[1]);
  printf("\tPlaintext found:");
  printf("\t\t 0x%08" PRIx32 " 0x%08" PRIx32"\n",p[0],p[1]);
  printf("\n\n");

}

void test_cs48_dm(void){

  uint64_t h_exp = 0x7FDD5A6EB248ULL;
  uint32_t plain[4] = {0x00, 0x00, 0x00, 0x00};
  uint64_t h = 0x0;
  h = cs48_dm(plain,h);

  if(h_exp == h){
    printf("Test_cs48_dm : %sOK %s\n",KGRN,KNRM);
  }else{
    printf("Test_cs48_dm : %sERROR %s\n",KRED,KNRM);
  }

  printf("\tHash expected:");
  printf("\t\t 0x%016" PRIx64 "\n",h_exp);
  printf("\tHash found:");
  printf("\t\t 0x%016" PRIx64 "\n",h);
  printf("\n\n");

}

int test_cs48_dm_fp(void){
  //uint32_t plain[4] = {0x07202ab0,0x00007fb9,0x00000000,0x00000000};
  uint32_t plain[4] = {0x0, 0x0, 0x0,0x0};
  uint64_t fp = get_cs48_dm_fp(plain);
  uint64_t fp_cipher  = cs48_dm(plain,fp);

  if(fp == fp_cipher){
    printf("Test_cs48_dm_fp : %sOK %s\n",KGRN,KNRM);
  }else{
    printf("Test_cs48_dm_fp : %sERROR %s\n",KRED,KNRM);
  }

  printf("\tFixed point found:");
  printf("\t\t\t\t 0x%016" PRIx64 "\n",fp);
  printf("\tHash computed with fixed point :");
  printf("\t\t 0x%016" PRIx64 "\n",fp_cipher);
  printf("\n\n");

}

void test_em(void){
  uint32_t m1[4] = {0};
  uint32_t m2[4] = {0};
  find_exp_mess(m1,m2);

  uint32_t * m = malloc(sizeof(uint32_t)*8);
  m[0] = m1[0];
  m[1] = m1[1];
  m[2] = m1[2];
  m[3] = m1[3];
  m[4] = m2[0];
  m[5] = m2[1];
  m[6] = m2[2];
  m[7] = m2[3];

  uint64_t h = hs48(m,2,0,0);
  uint64_t h1 = cs48_dm(m1,IV);
  uint64_t h2 = get_cs48_dm_fp(m2);
  uint64_t h3 = cs48_dm(m2,IV);

  printf("Message m1: \t0x%08" PRIx32 " 0x%08" PRIx32" 0x%08"
          PRIx32" 0x%08" PRIx32"\n",m1[0],m1[1],m1[2],m1[3]);

  printf("Message m2: \t0x%08" PRIx32 " 0x%08" PRIx32" 0x%08"
         PRIx32" 0x%08"PRIx32"\n",m2[0],m2[1],m2[2],m2[3]);

  printf("Hash of m1:\t \t0x%016" PRIx64 "\n",h1);
  printf("Fixed point of m2: \t0x%016" PRIx64 "\n",h2);
  printf("Hash of m2:\t \t0x%016" PRIx64 "\n",h3);
  printf("Hash of m1|m2|...|ml:\t \t0x%016" PRIx64 "\n",h);
}

int main()
{
  //  attack();
  /* test_sp48(); */
  /* test_sp48_inv(); */
  /* test_cs48_dm(); */
  /* test_cs48_dm_fp(); */
   test_em();

	return 0;
}
