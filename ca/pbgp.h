#ifndef _H_PBGP
#define _H_PBGP

#include <time.h>
#include <pbc.h>
#include <gmp.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>
#include <nettle/sha.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#ifdef BSD
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <sys/socket.h>


#define KEYSIZE (1024)
#define ESIZE (30)
#define MAX_LOAD_FSIZE (16384)
#define SHA1_DIGEST_HEX ((SHA1_DIGEST_SIZE)*(2))
#define MAX_ENVEL_NAME (20)

#define MAX_PFIX_NUM (20000)
#define MAX_TS_LEN (10)
#define MAX_PFIX_LEN (18)
#define MAX_PF_TS_LEN ((MAX_TS_LEN) + (MAX_PFIX_LEN) + 2 + 10)
#define MAX_ID_STR (10)

#define DESERIALIZE_ELEM(elem,p,eb,es)\
				memcpy(eb,p,es);\
				element_from_bytes(elem,eb);\
				bzero(eb,es);\
				p+=es;\

#define SERIALIZE_ELEM(dst,elem,size)\
				element_to_bytes(dst,elem);\
				dst+= size;\


#define SERIALIZE_AUTH(dst,ip,netmask,ts)\
						memcpy(dst,ip,4);\
						memcpy(dst+4,ts,4);\
						memcpy(dst+8,netmask,1);

enum {FREE,BUSY};
enum {SIGN_VALID,SIGN_INVALID};

struct setup_params_s
{
      //params definitions
      pairing_t pairing;
      pbc_param_t params;
      struct yarrow256_ctx yarrow; //random context, only for random init

      //CA **public** values
      element_t g;
      element_t ibePub;
      element_t z;
      element_t *P;
      uint32_t n;
      //standard RSA public key
      struct rsa_public_key  pub_rsa;

      //CA **private** values
      element_t gamma;
      element_t gammapow_np1;
      //standard RSA private key
      struct rsa_private_key priv_rsa;
};
typedef struct setup_params_s setup_params_t;



struct ibeid_s
{
//      uint32_t network;
//      uint32_t mask;
      	uint32_t asnum;
//		prefls_t *prefixlist;
//      time_t ts;
};
typedef struct ibeid_s ibeid_t;

struct id_list_s
{
      uint32_t size;
      uint32_t maxsize;
      ibeid_t *head;
};
typedef struct id_list_s id_list_t;

struct ar_list_s
{
      id_list_t *act;
      id_list_t *rvk;
};
typedef struct ar_list_s ar_list_t;

struct accumulator_s {
	element_t elem;
	uint32_t nep; //epoch number
};
typedef struct accumulator_s acc_t;

struct epoch_item_s {
      /* epoch index */
      uint32_t epoch;

      /* accumulator */
      acc_t *acc;

      /* list of revoked and added entities */
      ar_list_t epls;
      /* RSA signatures */
      mpz_t s_new;
      mpz_t s_rvk;
      mpz_t s_acc;
     
      setup_params_t *setup;
};
typedef struct epoch_item_s epoch_item_t;

struct ibe_keypair {
     element_t pub0;  //in G1
     element_t priv0; //in G1
     element_t pub1;  //in G1
     element_t priv1; //in G1

     ibeid_t *id;
     setup_params_t *setup;
};
typedef struct ibe_keypair ibe_keypair_t;

struct ibe_signature {
      element_t u; 
      element_t v; 
      element_t w; //common random element

      id_list_t *ls;

      setup_params_t *setup;
};
typedef struct ibe_signature ibe_signature_t;

/*XXX REALLY INEFFICIENT PREFIXLIST MANAGEMENT, FIX ASAP */
struct prefls_s
{
    setup_params_t *setup;

	//prefixlist (es:{"10.0.0.0/24","10.0.1.0/24"})
	struct in_addr ina[MAX_PFIX_NUM];
	//array of signatures. One for each pfix
	ibe_signature_t *pf_sign[MAX_PFIX_NUM];
	//the number of bits for the netmask
    uint8_t netmask[MAX_PFIX_NUM];

	time_t tsca;


	uint32_t asnum;
	//number of prefixes
	uint32_t size;

};
typedef struct prefls_s prefls_t;

struct action_data_s
{
      ibe_keypair_t *ibk;
      element_t witness;
      mpz_t signature; //CA signature of the envelope TODO
      prefls_t *pfixlist;
      ar_list_t glb;
      ar_list_t epoch;
};
typedef struct action_data_s action_data_t;


/**
 * Initialize setup structure for random initilization.
 */
void
setup_init(setup_params_t **setup_s, int rbits, int qbits, uint32_t n);

/**
 * Fill the setup structure with random values.
 */
void
setup_random (setup_params_t * setup_s);
/**
 * Free and set to zero the memory allocated for the setup_s strucutre.
 */
void
setup_clear(setup_params_t *setup_s);

/**
 * Save public key and private key into the file pointed by fp_pub and fp_priv.
 * Save also the pbc params in ASCII format into the file pointed by fp_param.
 */
int
setup_save (char *f_pub, char *f_priv,char *f_param ,setup_params_t * setup_d);

/**
 * Load public key and private key from the file pointed by fp_pub and fp_priv.
 * Load also the pbc params in ASCII format from the file pointed by fp_param.
 */
int
setup_load (char *f_pub,char *f_priv,char *f_param,setup_params_t **setup_d);

void
setup_print(setup_params_t *setup);

/* Epoch functions */
int
newepoch_init(epoch_item_t **ep, setup_params_t *setup);

int
newepoch_gen(char *out,epoch_item_t *ep,setup_params_t *setup);

void
newepoch_clear(epoch_item_t *ep);

int
newepoch_save(char *out,epoch_item_t *ep,setup_params_t * setup);

int
newepoch_load(char *in,epoch_item_t *ep,setup_params_t * setup);

int
claim_new_epoch(char *glb[2],char *epoch[2],char *facc,char *outf,setup_params_t *setup);

/* Witness functions */
int
witness_init(element_t witness,pairing_t params);

int
witness_serialize(uint8_t **buf,element_t witness);

int
witness_deserialize(element_t witness,uint8_t *buf);

int
witness_create(element_t witness,setup_params_t *setup,id_list_t *active,ibeid_t *newid);

int
witness_update(element_t wit,ibeid_t *id,setup_params_t *setup,id_list_t *add,id_list_t *rvk);

void
witness_clear(element_t witness);

/* Action functions */

int
idarray_init(id_list_t *active,id_list_t *revoked,setup_params_t *setup);

int
join_init(action_data_t **join,setup_params_t *setup,prefls_t *pfixlist);

int
do_join(action_data_t *join,setup_params_t *setup);

void
join_clear(action_data_t *join);

int
revoke_init(action_data_t **rvk,setup_params_t *setup);

int
revokation_check(acc_t *acc,element_t wit,mpz_t sign_i, uint32_t id,setup_params_t *setup);

int
do_revoke(action_data_t *rvk,ibeid_t *id);

void
revoke_clear(action_data_t *rvk);

int
join_load(char *in, action_data_t *join);

int
join_save(action_data_t *join);

int
parse_prefix_list(prefls_t **pfixlist,char *str,setup_params_t *setup);

/* Accumulator functions */

int
acc_init(acc_t **acc,pairing_t pairing);

int
acc_create(acc_t *acc);

int
acc_update(acc_t *acc,id_list_t *add,id_list_t *rvk,setup_params_t *setup);

int
acc_load(char *facc,acc_t *acc);

int
acc_save(char *facc,uint32_t nep,acc_t *acc);

void
acc_clear(acc_t *acc);

/* IBE functions */
int
ibe_keypair_gen (ibe_keypair_t *keys);

int
ibe_keypair_savefp(FILE *fp,ibe_keypair_t *keys);

int
ibe_keypair_save(char *fp,ibe_keypair_t *keys);

int
ibe_keypair_loadfp(FILE *fp,ibe_keypair_t *keys);

int
ibe_keypair_load(char *fp,ibe_keypair_t *keys);

int
ibe_keypair_init(ibe_keypair_t **k,setup_params_t *setup);

void
ibe_keypair_clear(ibe_keypair_t *keys);

void
ibe_signature_print(ibe_signature_t *s);

int
ibe_vrfy(ibe_signature_t *sign,setup_params_t *setup ,const uint8_t **m, const size_t *nelem,int *subtime); //XXX: remove subtime

int
ibe_vrfy_single(ibe_signature_t *sign,setup_params_t *setup ,const uint8_t *m, const size_t nelem);

int
ibe_vrfy_hess(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m, const size_t nelem);

int
ibe_sign(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m,const size_t nelem);

void
ibe_sign_hess(ibe_signature_t *sign,ibe_keypair_t *key,const uint8_t *m,const size_t nelem);

int
ibe_signature_init(ibe_signature_t **s,setup_params_t *setup);

int
ibe_signature_serialize(unsigned char **buf,ibe_signature_t *s);

int
ibe_signature_deserialize(ibe_signature_t *s,uint8_t *buf);

int
ibe_signature_init_hess(ibe_signature_t **s,setup_params_t *setup);

void
ibe_signature_clear(ibe_signature_t *s);

void
ibe_signature_clear_hess(ibe_signature_t *s);

#endif
