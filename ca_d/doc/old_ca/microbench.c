#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include <pbgp.h>
#include <pbgp_common.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/bn.h>


enum{KO,OK};

struct DSA_sign_s {
      BIGNUM r;
      BIGNUM s;
};
typedef struct DSA_sign_s DSA_sign_t;

unsigned char *msg = "Messaggio di prova da firmare e verificare con DSA e IBE";
DSA_sign_t signature;


int
sim_DSA_vrfy(DSA *key)
{
      BIGNUM *r = NULL, *s = NULL;
      BIGNUM w,u1,u2,hm,v,t1,t2;
      BN_CTX *bnctx = NULL;
      unsigned char md[SHA_DIGEST_LENGTH];

      bnctx= BN_CTX_new();
      BN_init(&w);
      BN_init(&u1);
      BN_init(&u2);
      BN_init(&hm);
      BN_init(&t1);
      BN_init(&t2);
      BN_init(&v);
      bzero(md,SHA_DIGEST_LENGTH);

      r = &signature.r;
      s = &signature.s;

      //Reject the signature if 0 < r < q or 0 < s < q is not satisfied.
      if(BN_is_zero(r) || BN_is_zero(s))
            return KO;
      if((BN_cmp(r,key->q) > 0) || (BN_cmp(s,key->q) > 0))
                  return KO;
             
      SHA1(msg, strlen((const char *)msg),(unsigned char *) &md);
      if(!BN_bin2bn(msg,SHA_DIGEST_LENGTH,&hm))
            goto err; 
      //Calculate w = s^−1 mod q
      if ((BN_mod_inverse(&w,s,key->q,bnctx)) == NULL) goto err;

      //Calculate u1 = H(m)*w mod q
      SHA1(msg, strlen((const char *)msg),(unsigned char *) &md);
      if(!BN_bin2bn(msg,SHA_DIGEST_LENGTH,&hm))
            goto err;  
	if (!BN_mod_mul(&u1,&hm,&w,key->q,bnctx)) goto err;
      
      //Calculate u2 = r*w mod q
	if (!BN_mod_mul(&u2,r,&w,key->q,bnctx)) goto err;
     
     
      //Calculate v = ((g^u1*y^u2) mod p) mod q
      if(!BN_mod_exp(&t1,key->g,&u1,key->p,bnctx))
            goto err; 
      if(!BN_mod_exp(&t2,key->pub_key,&u2,key->p,bnctx))
            goto err; 
      if(!BN_mod_mul(&v, &t2,&t1,key->p ,bnctx))
            goto err; 
      
      if(!BN_mod(&v,&v, key->q, bnctx))
            goto err;      
     
      //The signature is valid if v = r
     if(BN_ucmp(&v, r) == 0) 
            return OK;

err:
      return KO;      
}

int
sim_DSA_sign(DSA *key)
{

      struct timeval start,end;

      //BIGNUM k,r,s,hm,t1;
      BIGNUM k,hm,t1;
      BIGNUM *kinv = NULL, *r = NULL, *s = NULL;
      BN_CTX *bnctx = NULL;
      unsigned char md[SHA_DIGEST_LENGTH];
      
      //init elements and context
      bnctx= BN_CTX_new();
      BN_init(&k);
      
      BN_init(&signature.r);
      BN_init(&signature.s);
      r = &signature.r;
      s = &signature.s;

      BN_init(&hm);
      BN_init(&t1);
      bzero(md,SHA_DIGEST_LENGTH);

start:       
      //1. BN_rand < q
      START_TIMER(start);
      if(!BN_rand_range(&k,key->q))
            goto err; 
      END_TIMER("BN_rand_range",start,end);

      //2. r = (g^k mod p) mod q
      START_TIMER(start);
      if(!BN_mod_exp(r,key->g,&k,key->p,bnctx))
            goto err; 
      END_TIMER("BN_mod_exp",start,end);

      START_TIMER(start);
      if(!BN_mod(r,r, key->q, bnctx))
            goto err; 
      gettimeofday(&end,NULL);
      END_TIMER("BN_mod",start,end);
      
      //if r == 0 go back to step 1
      if(BN_is_zero(r))
            goto start;
      //3. s = (inv(k) * (H(m) + x*r ) mod q)
      // where x is the private key
      START_TIMER(start);
      SHA1(msg, strlen((const char *)msg),(unsigned char *) &md);
      if(!BN_bin2bn(msg,SHA_DIGEST_LENGTH,&hm))
            goto err; 
      END_TIMER("hash",start,end);
      
      START_TIMER(start);
      if(!BN_mul(&t1, key->priv_key,r, bnctx))
            goto err; 
      END_TIMER("BN_mod",start,end);

      START_TIMER(start);
      if(!BN_add(&t1,&t1,&hm))
            goto err; 
      END_TIMER("BN_add",start,end);

      kinv=BN_mod_inverse(NULL,&k,key->q,bnctx);
      START_TIMER(start);
      if (!BN_mod_mul(s,&t1,kinv,key->q,bnctx)) 
            goto err;
      END_TIMER("BN_mod_mul",start,end);

      //if s == 0 go back to step 1
      if(BN_is_zero(s))
           goto start;
       
      //the signature is (r,s)
      return OK;      

err:
      return KO;
}

int
main()
{
      uint32_t n = 1,i=0;
      uint32_t dsa_keysize = 1024;
      DSA *key = NULL;
      
      //reBGP     
      char *ca[] = {"key.pub","key.prv","key.par"};
      setup_params_t *setup = NULL;
      ibe_keypair_t *ibk = NULL;
      ibe_signature_t *signature = NULL;
     
      int rv = 0;

      struct timeval start,end;
      
      //geopt 

      // 1. Generate DSA keypair
      key = DSA_generate_parameters(dsa_keysize,NULL,0,NULL,NULL,NULL,NULL);
      if(!key) {
            printf("DSA_generate_parameters :: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
      }

      if( !DSA_generate_key(key) ) {
           printf("DSA_generate_key :: %s\n",strerror(errno));
           exit(EXIT_FAILURE);
      }
      // 2. Perform DSA signing steps (mean over n iteration)
      //gettimeofday(&start,NULL);
      for(i=0; i < n; i++) {
            if(sim_DSA_sign(key) == KO){
                  printf("sim_DSA_sign :: %s\n",strerror(errno));
                  exit(EXIT_FAILURE);
            }
      }
      //gettimeofday(&end,NULL);
      //print_avg_time(start,end,n);
      // 3. Perform DSA verfying steps (mean over n iteration)
      //gettimeofday(&start,NULL);
      for(i=0; i < n; i++) {
            if(sim_DSA_vrfy(key) == KO){
                  printf("sim_DSA_vrfy :: %s\n",strerror(errno));
                  exit(EXIT_FAILURE);
            }
      }
      //gettimeofday(&end,NULL);
      //print_avg_time(start,end,n);

      //setup load
      rv = setup_load (ca[0],ca[1],ca[2],&setup);
      if(rv < 0)
            pbgp_die("setup_load failed, cannot proceed\n");

      //gen first ibe ID
      rv = ibe_keypair_init(&ibk,setup);
      if(rv < 0)
    	      pbgp_die("Abort.");
      ibk->id->asnum = 1234;
      ibe_keypair_gen(ibk);

      rv = ibe_signature_init(&signature,setup);
      if(rv < 0)
    	      pbgp_die("Abort.");
    
      int elem_size = pairing_length_in_bytes_G1(setup->pairing);
      printf("elem size: %d\n",elem_size);
      
      /* Signature */
      //gettimeofday(&start,NULL);
      ibe_sign(signature,ibk,(const uint8_t*)&msg[0],strlen(msg));
      //gettimeofday(&end,NULL);
      //print_time(start,end);

      //gettimeofday(&start,NULL);
      rv = ibe_vrfy_single(signature,setup ,(const uint8_t*)&msg[0],strlen(msg));
      //gettimeofday(&end,NULL);
      //print_time(start,end);
      if(rv != SIGN_VALID) printf("Invalid signature :( \n");
      printf("\n");


      return 0;
}
