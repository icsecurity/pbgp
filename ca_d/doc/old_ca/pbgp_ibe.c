#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pbc.h>
#include <gmp.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>
#include <nettle/sha.h>

#include "pbgp.h"
#include "pbgp_common.h"

//#define TIMING 


#define WRITE_ELEM(bufelem,elem_size,elem,fp) \ 
    bzero(bufelem,elem_size); \
    element_to_bytes(bufelem,elem); \
    fwrite(bufelem,elem_size,1,fp); \

#define READ_ELEM(bufelem,elem_size,elem,fp) \
      bzero(bufelem, elem_size); \ 
	fread(bufelem,elem_size,1,fp); \ 
	element_from_bytes(elem,bufelem); \


int
ibe_keypair_savefp(FILE *fp,ibe_keypair_t *keys)
{
    uint32_t elem_size = 0;
    int rv =0;
    unsigned char *bufelem = NULL;

    //write items to file
    fwrite(keys->id,sizeof(ibeid_t),1,fp);

    //save element
    elem_size = pairing_length_in_bytes_G1(keys->setup->pairing);
    fwrite(&elem_size,sizeof(uint32_t),1,fp);

    bufelem = (unsigned char *)malloc(elem_size);
    if(!bufelem) {
          pbgp_error("ibe_keypair_save() :: cannot allocate bufelem");
          rv = -1;
          goto end;
    }
    bzero(bufelem,elem_size);
    element_to_bytes(bufelem,keys->priv0);
    fwrite(bufelem,elem_size,1,fp);

    bzero(bufelem,elem_size);
    element_to_bytes(bufelem,keys->pub0);
    fwrite(bufelem,elem_size,1,fp);

    bzero(bufelem,elem_size);
    element_to_bytes(bufelem,keys->priv1);
    fwrite(bufelem,elem_size,1,fp);

    bzero(bufelem,elem_size);
    element_to_bytes(bufelem,keys->pub1);
    fwrite(bufelem,elem_size,1,fp);

end:
	if(bufelem) free(bufelem);

	return rv;
}

int
ibe_keypair_save(char *f,ibe_keypair_t *keys)
{
      int rv =0;
      FILE *fp = NULL;

      fp = fopen(f,"wb");
      if(!fp) {
            pbgp_error("ibe_keypair_save :: fopen %s\n",strerror(errno));
            return -1;
      }

      rv = ibe_keypair_savefp(fp,keys);

      fclose(fp);

      return rv;
}

int
ibe_keypair_loadfp(FILE *fp,ibe_keypair_t *keys)
{
	uint32_t elem_size = 0;
	int rv = 0;
	unsigned char *bufelem = NULL;

	fread(keys->id,sizeof(ibeid_t),1,fp);
	fread(&elem_size,sizeof(uint32_t),1,fp);

	bufelem = (unsigned char *)malloc(elem_size);
	if(!bufelem) {
	  pbgp_error("ibe_keypair_load() :: cannot allocate bufelem");
	  rv = -1;
	  goto end;
	}

	bzero(bufelem, elem_size);
	fread(bufelem,elem_size,1,fp);
	element_from_bytes(keys->priv0,bufelem);

	bzero(bufelem,elem_size);

	fread(bufelem,elem_size,1,fp);
	element_from_bytes(keys->pub0,bufelem);

	bzero(bufelem,elem_size);

	fread(bufelem,elem_size,1,fp);
	element_from_bytes(keys->priv1,bufelem);

	bzero(bufelem,elem_size);

	fread(bufelem,elem_size,1,fp);
	element_from_bytes(keys->pub1,bufelem);

end:
	if(bufelem) free(bufelem);

	return rv;
}


int
ibe_keypair_load(char *f,ibe_keypair_t *keys)
{
      int rv = 0;
      FILE *fp = NULL;

      fp = fopen(f,"rb");
      if(!fp) {
            pbgp_error("ibe_keypair_load :: fopen %s\n",strerror(errno));
            return -1;
      }
      rv = ibe_keypair_loadfp(fp,keys);

      fclose(fp);
      return rv;
}

void
ibe_sign_hess(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m,const size_t nelem)
{
      char hexhash[SHA1_DIGEST_HEX];
      setup_params_t *setup = NULL;
      element_t P1,k,t1,t3,t4,t5,r;
      mpz_t t2;

      assert(key && sign && m);

      setup = key->setup;

      mpz_init(t2);

      element_init_G1(P1,setup->pairing);
      element_init_G1(t4,setup->pairing);
      element_init_G1(t5,setup->pairing);

      element_init_GT(t1,setup->pairing);
      element_init_GT(r,setup->pairing);

      element_init_Zr(t3,setup->pairing);
      element_init_Zr(k,setup->pairing);

      hexsha1(hexhash,(uint8_t*)m,nelem);

      element_random(P1);
      element_random(k);
      element_pairing(t1, P1, setup->g);
      element_pow_zn(r, t1, k);
      element_to_mpz(t2, r);

      //h3=h(m)*mpz(r);
      element_from_hash(t3, hexhash, SHA1_DIGEST_HEX);
      element_mul_mpz(sign->v, t3, t2);
      element_mul_zn(t4, key->priv0,sign->v);
      element_mul_zn(t5, P1, k);
      element_add(sign->u, t4, t5);

      mpz_clear(t2);
      element_clear(t1);
      element_clear(t3);
      element_clear(t4);
      element_clear(t5);
      element_clear(r);
      element_clear(P1);
      element_clear(k);
}


int
ibe_vrfy_hess(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m, const size_t nelem)
{
      char hexhash[SHA1_DIGEST_HEX];
      setup_params_t *setup = NULL;
      element_t Ppub,t3,r,t6,t7,t8;
      mpz_t t2;
      int rv = 0;

      assert(key && sign && m);

      setup = key->setup;

      mpz_init(t2);
      element_init_G1 (Ppub,setup->pairing);
      element_init_GT(t6, setup->pairing);
      element_init_GT(t7, setup->pairing);
      element_init_GT(r,setup->pairing);

      element_init_Zr(t3,setup->pairing);
      element_init_Zr(t8,setup->pairing);

      hexsha1(hexhash,(uint8_t*)m,nelem);

      element_printf("sign->u: %B\n",sign->u);
      element_printf("sign->v: %B\n",sign->v);

      element_pairing(t6, sign->u, setup->g);
      element_set(Ppub,setup->ibePub);
      element_neg(Ppub, Ppub);
      element_pairing(t7, key->pub0, Ppub);
      element_pow_zn(t7, t7, sign->v);
      element_mul(r, t6, t7);
      element_to_mpz(t2, r);

      element_from_hash(t3, hexhash, SHA1_DIGEST_HEX);
      element_mul_mpz(t8, t3, t2);

      if (!element_cmp(t8, sign->v)) {
            rv= SIGN_VALID;
      } else {
            rv = SIGN_INVALID;
      }

      element_clear(Ppub);
      element_clear(t3);
      element_clear(t6);
      element_clear(t7);
      element_clear(t8);
      element_clear(r);

      return rv;
}

static inline void
get_id_couple(char *id0,char *id1,char *idstr)
{
    snprintf(id0,MAXIDLEN+2,"%sA",idstr);
    snprintf(id1,MAXIDLEN+2,"%sB",idstr);

    return;
}


/* In this scheme every signer can aggregate a signature on a different message */
int
ibe_sign(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m,const size_t nelem)
{

      char hexhash[SHA1_DIGEST_HEX];
      setup_params_t *setup = NULL;
      element_t ri,t1,t2,t3,t4,ci;
#ifdef TIMING
      struct timeval start,end;
      double tot = 0.0;
#endif     
      //check if is the first signature
      if(sign->ls->size == 0) {
            element_random(sign->w);
            if(element_is0(sign->w)) {
            	pbgp_error("Signature parameter W initialization failed. Did you check /dev/urandom?\n");
            	return -1;
            }
      }

      setup = key->setup;

      element_init_G1(t1,setup->pairing);
      element_init_G1(t2,setup->pairing);
      element_init_G1(t3,setup->pairing);
      element_init_G1(t4,setup->pairing);

      element_init_Zr(ri,setup->pairing);
     

      element_init_Zr(ci,setup->pairing);
      hexsha1(hexhash,m,nelem);
      element_from_hash(ci, hexhash, SHA1_DIGEST_HEX);
      
      element_random(ri);
      //ri*Pw
      //START_TIMER(start);
      element_mul_zn(t1,sign->w,ri);
      //END_TIMER("element_mul_zn",start,end);

      //ci * sP(i,1)
      element_mul_zn(t2,key->priv1,ci);
      //ri * sP(i,0)
      //element_mul(t5,ri,key->pub0);

      //ri*Pw + ci * sP(i,1) + sP(i,0)
      //START_TIMER(start);
      element_add(t3,t1,t2);
      //END_TIMER("element_add",start,end);
      element_add(t3,t3,key->priv0);         //Si

      element_mul_zn(t4,setup->g,ri);        //Ti

      //aggregate signature value
      element_add(sign->u,sign->u,t3);       //u = Si
      element_add(sign->v,sign->v,t4);       //v = Ti

      //add id to aggregated value
      ids_add(sign->ls,key->id);

      //ibe_signature_print(sign);

      element_clear(t1);
      element_clear(t2);
      element_clear(t3);
      element_clear(t4);
      element_clear(ri);
      element_clear(ci);

      return 0;
}

int
ibe_vrfy_single(ibe_signature_t *sign,setup_params_t *setup ,const uint8_t *m, const size_t nelem)
{
	const uint8_t *v_m[1];
	size_t v_nelem[1];

	if(!sign || !sign->ls) {
		pbgp_error("ibe_vrfy_single() :: invalid parameter\n");
		return -1;
	}

	if(sign->ls->size > 1) {
		pbgp_error("ibe_vrfy_single() :: this function must be used for a single message\n");
		return -1;
	}

	v_m[0] = m;
	v_nelem[0] = nelem;
	return ibe_vrfy(sign,setup ,v_m, v_nelem,NULL);
}

#define TIMING
/* In this scheme every signer can aggregate a signature on a different message
*/
int
ibe_vrfy(ibe_signature_t *sign,setup_params_t *setup ,const uint8_t **m, const size_t *nelem,int *subtime)
{
	char hexhash[SHA1_DIGEST_HEX];
	char id0[MAXIDLEN + 2],id1[MAXIDLEN + 2];
	char *idstr = NULL;
	int i = 0, rv = 0, length = 0;
	element_t sumID,sumCi,sumTot,ci,t1,Pubi0,Pubi1,Pm;
	element_t p1,p2,e1,e2;
      pairing_pp_t pp1,pp2,pp3;


#ifdef TIMING
      struct timeval start,end;
      double tot = 0.0;
#endif      

  	if(!sign || !sign->ls) {
  		pbgp_error("ibe_vrfy_single() :: invalid parameter\n");
  		return -1;
  	}
  	if(!m || !(*m) || !nelem) {
  		pbgp_error("ibe_vrfy_single() :: invalid parameter\n");
  		return -1;
  	}


	element_init_G1(sumID,setup->pairing);
	element_init_G1(sumTot,setup->pairing);
	element_init_G1(Pubi0,setup->pairing);
	element_init_G1(Pubi1,setup->pairing);
	element_init_G1(Pm,setup->pairing);
	element_init_G1(t1,setup->pairing);
	element_init_G1(sumCi,setup->pairing);
	element_init_GT(p1,setup->pairing);
	element_init_GT(p2,setup->pairing);
	element_init_GT(e1,setup->pairing);
	element_init_GT(e2,setup->pairing);

	element_init_Zr(ci,setup->pairing);

	element_set0(sumID);
	element_set0(sumCi);

	//Sum all ibe Pi_0 and sum ci*Pi_1
	for(i=0 ; i < sign->ls->size; i++) {
#ifdef TIMING
            gettimeofday(&start,NULL);
#endif
		//initialize vars for current loop
		bzero(id0,MAXIDLEN +2);
		bzero(id1,MAXIDLEN +2);
		id_to_string_clear(idstr);

		id_to_string(&idstr,&sign->ls->head[i]);
		if(idstr == NULL) {
			  pbgp_error("ibe_vrfy :: id_to_string(%s,%p)\n",idstr,sign->ls->head[i]);
			  goto out1;
		}
		get_id_couple(id0,id1,idstr);
		length = strlen(id0);
		//hash id string
		bzero(hexhash,SHA1_DIGEST_HEX);
		hexsha1(hexhash,(uint8_t*)id0,length);
		//generate public id (key)
           element_from_hash(Pubi0,hexhash, SHA1_DIGEST_HEX);
		//hash id string
		bzero(hexhash,SHA1_DIGEST_HEX);
		hexsha1(hexhash,(uint8_t*)id1,length);
		//generate public id (key)
		element_from_hash(Pubi1,hexhash, SHA1_DIGEST_HEX);

		bzero(hexhash,SHA1_DIGEST_HEX);
		hexsha1(hexhash,m[i],nelem[i]);
		element_from_hash(ci, hexhash, SHA1_DIGEST_HEX);
           	element_mul_zn(t1,Pubi1,ci);
		element_add(sumID,sumID,Pubi0);
		element_add(sumCi,sumCi,t1);
#ifdef TIMING
            gettimeofday(&end,NULL);
            tot += get_time_diff(start,end);
#endif
 

	}

#ifdef TIMING
      //printf("\n%.2f\n",tot);
#endif

	element_add(sumTot,sumID,sumCi);
      
#ifdef TIMING
      gettimeofday(&start,NULL);
#endif
	pairing_pp_init(pp1,sumTot,setup->pairing);
      pairing_pp_init(pp2,sign->v,setup->pairing);
      pairing_pp_init(pp3,sign->u,setup->pairing);
#ifdef TIMING
      gettimeofday(&end,NULL);
      tot += get_time_diff(start,end);
#endif
 
	//element_pairing(p1,setup->ibePub,sumTot);       // e(Q,Pi)
      //START_TIMER(start);
      pairing_pp_apply(p1,setup->ibePub,pp1);
	//END_TIMER("pairing_pp_apply",start,end);
      //element_pairing(p2,sign->v,sign->w);            // e(Tn,Pw)
      pairing_pp_apply(p2,sign->w,pp2);
	//element_pairing(e1,sign->u,setup->g);           //e(Sn,P)
      pairing_pp_apply(e1,setup->g,pp3);

      //START_TIMER(start);
	element_mul(e2,p1,p2);
	//END_TIMER("element_mul",start,end);

	rv = element_cmp(e1,e2);

      pairing_pp_clear(pp1);
      pairing_pp_clear(pp2);
      pairing_pp_clear(pp3);

#ifdef TIMING
      if(subtime)
            *subtime = tot;
#endif

out1:
	element_clear(sumID);
	element_clear(sumCi);
	element_clear(sumTot);
	element_clear(t1);
	element_clear(ci);
	element_clear(Pubi0);
	element_clear(Pubi1);
	element_clear(Pm);
	element_clear(p1);
	element_clear(p2);
	element_clear(e1);
	element_clear(e2);

	return rv;
}
#undef TIMING
/* In this scheme the messagge is the same for all the signers */
void
ibe_multisign_sign(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m,const size_t nelem)
{

      char hexhash[SHA1_DIGEST_HEX];
      setup_params_t *setup = NULL;
      element_t Pm,ri,t1,t3,t4;

      setup = key->setup;

      element_init_G1(t1,setup->pairing);
      element_init_G1(t3,setup->pairing);
      element_init_G1(t4,setup->pairing);
      element_init_G1(Pm,setup->pairing);

      element_init_Zr(ri,setup->pairing);

      bzero(hexhash,SHA1_DIGEST_HEX);
      hexsha1(hexhash,(uint8_t*)m,nelem);

      element_from_hash(Pm, hexhash, SHA1_DIGEST_HEX);
      element_random(ri);
      element_mul_zn(t1,ri,Pm);                 //ri*Pm
      element_add(t3,t1,key->priv0);          //ri*Pm + s*Pi

      element_mul_zn(t4,ri,setup->g);           //ri * P

      //aggregate signature value
      element_add(sign->u,sign->u,t3);       //u = Si
      element_add(sign->v,sign->v,t4);       //v = Ti

      //add id to aggregated value
      ids_add(sign->ls,key->id);

      element_clear(t1);
      element_clear(t3);
      element_clear(t4);
      element_clear(Pm);
      element_clear(ri);



}

/* In this scheme the messagge is the same for all the signers */
int
ibe_multisign_vrfy(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m, const size_t nelem)
{
      char hexhash[SHA1_DIGEST_HEX];
      char *s = NULL;
      int i = 0, rv = 0, length = 0;
      setup_params_t *setup = NULL;
      element_t sumID,Pubi,Pm;
      element_t p1,p2,e1,e2;

      setup = key->setup;

      element_init_G1(sumID,setup->pairing);
      element_init_G1(Pubi,setup->pairing);
      element_init_G1(Pm,setup->pairing);
      element_init_GT(p1,setup->pairing);
      element_init_GT(p2,setup->pairing);
      element_init_GT(e1,setup->pairing);
      element_init_GT(e2,setup->pairing);

      element_set0(sumID);
      //Sum all ibe ID
      for(i=0 ; i < sign->ls->size; i++) {
            id_to_string(&s,&sign->ls->head[i]);
            if(s == NULL) {
                  pbgp_error("ibe_vrfy :: id_to_string(%s,%p)\n",s,sign->ls->head[i]);
                  goto out1;
            }
            length = strlen(s);

            //hash id string
            hexsha1(hexhash,(uint8_t*)s,length);
            //generate public id (key)
            element_from_hash(Pubi,hexhash, SHA1_DIGEST_HEX);
            element_add(sumID,sumID,Pubi);

      }
      element_pairing(e1,sign->u,setup->g);           //e(S,P)

      hexsha1(hexhash,(uint8_t*)m,nelem);
      element_from_hash(Pm, hexhash, SHA1_DIGEST_HEX);
      element_pairing(p1,sign->v,Pm);           // e(T,Pm)
      element_pairing(p2,setup->ibePub,sumID);  // e(Q,Pi)
      element_mul(e2,p1,p2);

      rv = element_cmp(e1,e2);

      id_to_string_clear(s);
out1:
      element_clear(sumID);
      element_clear(Pubi);
      element_clear(Pm);
      element_clear(p1);
      element_clear(p2);
      element_clear(e1);
      element_clear(e2);

      return rv;
}


int
ibe_keypair_gen(ibe_keypair_t *keys)
{
      char *s = NULL;
      char id0[MAXIDLEN + 2],id1[MAXIDLEN + 2];
      char hexhash[SHA1_DIGEST_HEX];
      int length =0;
      setup_params_t *setup = NULL;
      ibeid_t *id;

      if(!keys) {
    	  errno = EINVAL;
    	  return -1;
      }
      setup = keys->setup;
      id = keys->id;

      if(!setup || !id) {
    	  errno = EINVAL;
    	  return -1;
      }

      bzero(id0,MAXIDLEN+2);
      bzero(id1,MAXIDLEN+2);

      if(setup->gamma->data == NULL) {
    	  pbgp_error("ibe_keypair_gen() :: Required param is missing (CA private key)\n");
    	  return -1;
      }

      //id to string
      id_to_string(&s,id);
      if(s == NULL) {
            pbgp_error("gen_ibe_keypair() :: id_to_string(%s,%p)\n",s,id);
            return -1;
      }

      get_id_couple(id0,id1,s);
      length = strlen(id0);

      //hash id string
      bzero(hexhash,SHA1_DIGEST_HEX);
      hexsha1(hexhash,(uint8_t*)id0,length);
      //generate public id (key)
      element_from_hash(keys->pub0,hexhash, SHA1_DIGEST_HEX);
      //generate private key from public id
      element_mul_zn(keys->priv0,keys->pub0, setup->gamma);

      bzero(hexhash,SHA1_DIGEST_HEX);
      hexsha1(hexhash,(uint8_t*)id1,length);
      //generate public id (key)
      element_from_hash(keys->pub1,hexhash, SHA1_DIGEST_HEX);
      //generate private key from public id
      element_mul_zn(keys->priv1,keys->pub1, setup->gamma);

      //cleanup
      id_to_string_clear(s);

      return 0;
}


int
ibe_keypair_init(ibe_keypair_t **k,setup_params_t *setup)
{
	ibe_keypair_t *keys = NULL;

	*k = malloc(sizeof(ibe_keypair_t));
	if(!(*k)) {
    	      pbgp_error("ibe_keypair_setup() :: malloc()\n");
    	      goto err;
	}
	keys = *k;
	bzero(keys,sizeof(ibe_keypair_t));

	keys->setup = setup;

	element_init_G1(keys->pub0,keys->setup->pairing);
	element_init_G1(keys->priv0,keys->setup->pairing);
	element_init_G1(keys->pub1,keys->setup->pairing);
	element_init_G1(keys->priv1,keys->setup->pairing);

	keys->id = malloc(sizeof(ibeid_t));
	if(!keys->id) {
		  pbgp_error("ibe_keypair_init() :: malloc\n");
		  goto err;
	}
	memset(keys->id,0,sizeof(ibeid_t));

	return 0;
err:
	if(keys) {
		if(keys->id)
			free(keys->id);
		free(keys);
	}
	return -1;
}

void
ibe_keypair_clear(ibe_keypair_t *keys)
{
	if(keys) {
     element_clear(keys->pub0);
     element_clear(keys->priv0);
     element_clear(keys->pub1);
     element_clear(keys->priv1);

     free(keys->id);
     free(keys);
	}
}

int
ibe_signature_init(ibe_signature_t **s,setup_params_t *setup)
{
	ibe_signature_t *sign = NULL;

	*s = malloc(sizeof(ibe_signature_t));
	if(!(*s)) {
		pbgp_error("ibe_signature_init() :: malloc()\n");
		return -1;
	}
	sign = *s;
	bzero(sign,sizeof(ibe_signature_t));

	element_init_G1(sign->u,setup->pairing);
	element_init_G1(sign->v,setup->pairing);
	element_init_G1(sign->w,setup->pairing);

	element_set0(sign->u);
	element_set0(sign->v);
	element_set0(sign->w);

	ids_init(&sign->ls,NULL);

	sign->setup = setup;

	return 0;
}

int
ibe_signature_init_hess(ibe_signature_t **s,setup_params_t *setup)
{
	ibe_signature_t *sign = NULL;

	*s = malloc(sizeof(ibe_signature_t));
	if(!(*s)) {
		pbgp_error("ibe_signature_init() :: malloc()\n");
		return -1;
	}
	sign = *s;
	bzero(sign,sizeof(ibe_signature_t));

    element_init_G1(sign->u,setup->pairing);
    element_init_Zr(sign->v,setup->pairing);

    return 0;
}

void
ibe_signature_clear(ibe_signature_t *s)
{
	element_clear(s->u);
	element_clear(s->v);
	element_clear(s->w);

    ids_clear(s->ls,NULL);

	free(s);
}

void
ibe_signature_clear_hess(ibe_signature_t *s)
{
	element_clear(s->u);
	element_clear(s->v);
	free(s);
}

void
ibe_signature_print(ibe_signature_t *s)
{
	int i;

	if(!s || !s->ls) {
		errno = EINVAL;
		return ;
	}

	element_printf("u: %B\n",s->u);
	element_printf("v: %B\n",s->v);
	element_printf("w: %B\n",s->w);

    for(i=0 ; i < s->ls->size; i++) {
    	printf("Signer %d = %d\n",i,s->ls->head[i].asnum);
    }
}

/*
 * Return the size in bytes of a signature
 */
int
get_ibesignature_size(setup_params_t *setup,uint16_t nsigners)
{
	uint16_t es = 0;
	uint16_t bufsize = 0;

	es = pairing_length_in_bytes_G1(setup->pairing);

	bufsize  = 3*es;
	bufsize += 3*(sizeof(uint32_t));
	bufsize += sizeof(ibeid_t) * nsigners;

	return bufsize;
}

int
ibe_signature_serialize(unsigned char **buf,ibe_signature_t *s)
{
	unsigned char *dstbuf = NULL;
	int bufsize = 0;
	uint32_t es = 0;

	if(!buf || !s || !s->ls) {
		errno = EINVAL;
		return -1;
	}

	// calculate buffer size
	es = pairing_length_in_bytes_G1(s->setup->pairing);

	//this is the space needed to store the size of each element_t
	bufsize += sizeof(uint32_t);
	bufsize += (3*es);	//u,v,w

	//the number of signers
	bufsize += sizeof(uint32_t);
	//the list of signers
	bufsize += sizeof(ibeid_t) * s->ls->size;

	// allocate buffer
	dstbuf = (unsigned char *) malloc(bufsize);
	if(!dstbuf) {
		return -1;
	}
	bzero(dstbuf,bufsize);
	*buf = dstbuf;

	//element size
	memcpy(dstbuf,&es,sizeof(uint32_t));
	dstbuf += sizeof(uint32_t);
	//copy signature data into the buffer
	SERIALIZE_ELEM(dstbuf,s->u,es);
	SERIALIZE_ELEM(dstbuf,s->v,es);
	SERIALIZE_ELEM(dstbuf,s->w,es);

	//number of signers
	memcpy(dstbuf,&(s->ls->size),sizeof(uint32_t));
	dstbuf +=sizeof(uint32_t);
	//list of signers
	memcpy(dstbuf,s->ls->head,sizeof(ibeid_t) * s->ls->size);

	return bufsize;
}

/* Copy data buffer within ibe_signature_t */
int
ibe_signature_deserialize(ibe_signature_t *s,uint8_t *buf)
{
	int rv = 0;
	uint8_t *p = NULL, *eb = NULL;
	uint32_t es = 0;

	if(!s || !buf) {
		errno = EINVAL;
		return -1;
	}

	p = buf;

	//deserialize the size of one element
	memcpy(&es,p,sizeof(uint32_t));
	p+=sizeof(uint32_t);

	eb = (unsigned char *) malloc(es);
	if(!eb) {
		pbgp_error("ibe_signature_deserialize() :: %s\n",strerror(errno));
		rv = -1;
		goto out;
	}
	bzero(eb,es);

	DESERIALIZE_ELEM(s->u,p,eb,es);
	DESERIALIZE_ELEM(s->v,p,eb,es);
	DESERIALIZE_ELEM(s->w,p,eb,es);

	free(eb);
	eb = NULL;

	//numer of signers
	memcpy(&es,p,sizeof(uint32_t));
	p += sizeof(uint32_t);

	//allocate an id_list
	s->ls = malloc(sizeof(id_list_t));
	if(!s->ls) {
		pbgp_error("ibe_signature_deserialize() :: %s\n",strerror(errno));
		rv = -1;
		goto out;
	}
	bzero(s->ls,sizeof(id_list_t));
	s->ls->size = es;
	s->ls->maxsize = es;

	s->ls->head = malloc(sizeof(ibeid_t) * es);
	if(!s->ls->head) {
		pbgp_error("ibe_signature_deserialize() :: %s\n",strerror(errno));
		rv = -1;
		goto out;
	}
	bzero(s->ls->head,sizeof(ibeid_t) * es);

	memcpy(s->ls->head,p,sizeof(ibeid_t) * es);

out:
	if(rv != 0) {
		if(s && s->ls)
			free(s->ls);
	}

	if(eb) free(eb);

	return rv;
}


//#define IBETEST_MAIN
#ifdef IBETEST_MAIN

int
main()
{
      setup_params_t *setup = NULL;
      ibe_keypair_t *ibk = NULL,*ibk2 = NULL;
      ibe_signature_t *signature = NULL;
      char *ca[] = {"key.pub","key.prv","key.par"};
      const char *m[] =
      {"123456789012345678901234567890123456789012345678901234567890","ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
      const size_t len[] = {50,26};
      int res = 0,rv =0;



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

      //gen second ibe ID
      rv = ibe_keypair_init(&ibk2,setup);
      if(rv < 0)
    	      pbgp_die("Abort.");
      ibk2->id->asnum = 1235;
      ibe_keypair_gen(ibk2);

      rv = ibe_signature_init(&signature,setup);
      if(rv < 0)
    	      pbgp_die("Abort.");
      /* First signature */
      ibe_sign(signature,ibk,(const uint8_t*)m[0],len[0]);

      res = ibe_vrfy_single(signature,setup ,(const uint8_t*)m[0],len[0]);
      if(res == SIGN_VALID) printf("The signature is valid!\n");
      else printf("Invalid signature :( \n");

      uint8_t *serbuf = NULL;
      ibe_signature_t *design = NULL;
      ibe_signature_serialize(&serbuf,signature);
      ibe_signature_init(&design,setup);
      ibe_signature_deserialize(design,serbuf);

      res = ibe_vrfy_single(design,setup ,(const uint8_t*)m[0],len[0]);
      if(res == SIGN_VALID) printf("The deserialized signature is valid!\n");
      else printf("Invalid deserialized signature :( \n");

      ibe_signature_clear(design);
      free(serbuf);
      /* Second signature (aggregate on first signature)*/
      ibe_sign(signature,ibk2,(const uint8_t*)m[1],len[1]);

      //verify
      res = ibe_vrfy(signature,setup,(const uint8_t**)m,len,NULL);
      if(res == SIGN_VALID) printf("The signature is valid!\n");
      else printf("Invalid signature :( \n");

      ibe_signature_clear(signature);
      ibe_keypair_clear(ibk);
      ibe_keypair_clear(ibk2);
      setup_clear(setup);

     return 0 ;
}

#endif
