#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
//#define PBC_DEBUG
#include <pbc.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>

#include "pbgp.h"
#include "pbgp_common.h"

extern char *optarg;
extern int optind, opterr, optopt;


static void
setup_save_pubkey(FILE *fp_pub,setup_params_t *setup_d);
static void
setup_save_privkey(FILE *fp_priv,setup_params_t *setup_d);
static void
setup_save_ascii_param(FILE *fp_param,setup_params_t *setup_d);

static void
setup_load_pubkey(FILE *fp_pub,setup_params_t *setup_d);
static void
setup_load_privkey(FILE *fp_priv,setup_params_t *setup_d);
static void
setup_load_ascii_param(FILE *fp_param,setup_params_t *setup_d);


void
setup_print(setup_params_t *setup)
{
	element_printf("setup->g: %B \n",setup->g);
	element_printf("setup->gamma: %B \n",setup->gamma);
	element_printf("setup->ibePub: %B \n",setup->ibePub);

}

void
setup_clear(setup_params_t *setup_s)
{
      int i = 0;
      int n2 = 0;

      if(!setup_s) return;

      if(setup_s->gamma->data)
            element_clear(setup_s->gamma);
      if(setup_s->gammapow_np1->data)
            element_clear(setup_s->gammapow_np1);

	element_clear(setup_s->g);
      element_clear(setup_s->z);
      element_clear(setup_s->ibePub);

      n2 = setup_s->n * 2;

      if(setup_s->P) {
         for(i=0; i < (n2-1);i++)
            	if(setup_s->P[i])
            		element_clear(setup_s->P[i]);
      }
      if(setup_s->pairing)
            pairing_clear(setup_s->pairing);

      free(setup_s->P);
      free(setup_s);

      return ;
}

static void
setup_save_pubkey(FILE *fp_pub,setup_params_t * setup_d)
{
      int i =0,n2 =0;
      unsigned char *bufelem = NULL;
      uint32_t elem_size = 0;
      struct nettle_buffer pub_buffer;

      //save element g
      elem_size = pairing_length_in_bytes_G1(setup_d->pairing);

      bufelem = (unsigned char *)malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_save_pubkey() :: cannot allocate bufelem");
      }
      element_to_bytes(bufelem,setup_d->g);

      //printf("elem_size: %d\n",elem_size);
      //element_printf("g: %B\n",setup_d->g);
      fwrite(&elem_size,sizeof(uint32_t),1,fp_pub);
      fwrite(bufelem,elem_size,1,fp_pub);

      memset(bufelem,0,elem_size);
      element_to_bytes(bufelem,setup_d->ibePub);
      fwrite(bufelem,elem_size,1,fp_pub);
      free(bufelem);

      //save element z
      elem_size = pairing_length_in_bytes_GT(setup_d->pairing);

      bufelem = (unsigned char *)malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_save_pubkey() :: cannot allocate bufelem");
      }
      element_to_bytes(bufelem,setup_d->z);

      //printf("elem_size: %d\n",elem_size);
      //element_printf("g: %B\n",setup_d->g);
      fwrite(&elem_size,sizeof(uint32_t),1,fp_pub);
      fwrite(bufelem,elem_size,1,fp_pub);
      free(bufelem);

      //save n
      fwrite(&setup_d->n,sizeof(uint32_t),1,fp_pub);

      n2=setup_d->n *2;
      //save P
      for(i=0 ; i < (n2-1); i++) {
            elem_size = pairing_length_in_bytes_G1(setup_d->pairing);

            bufelem = (unsigned char *)malloc(elem_size);
            if(!bufelem) {
                  pbgp_die("setup_save_pubkey() :: cannot allocate bufelem");
            }

            element_to_bytes(bufelem,setup_d->P[i]);
            fwrite(&elem_size,sizeof(uint32_t),1,fp_pub);
            fwrite(bufelem,elem_size,1,fp_pub);
            free(bufelem);
      }
      //save RSA public key
      nettle_buffer_init(&pub_buffer);
      if (!rsa_keypair_to_sexp (&pub_buffer, "rsa-pkcs1-sha1", &setup_d->pub_rsa, NULL)) {
	    pbgp_die ("Formatting public key failed.\n");
      }
      fwrite(pub_buffer.contents,pub_buffer.size,1,fp_pub);
}

static void
setup_load_pubkey(FILE *fp_pub,setup_params_t *setup_d)
{
      unsigned char *bufelem = NULL;
      uint32_t elem_size = 0;
      int i,n2;
      //struct nettle_buffer pub_buffer;


      /* Load g */
      fread(&elem_size,sizeof(uint32_t),1,fp_pub);
      //printf("elem_size: %d\n",elem_size);
      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
      }

      fread(bufelem,elem_size,1,fp_pub);
      element_init_G1(setup_d->g,setup_d->pairing);
      element_from_bytes(setup_d->g,bufelem);

      memset(bufelem,0,elem_size);

      fread(bufelem,elem_size,1,fp_pub);
      element_init_G1(setup_d->ibePub,setup_d->pairing);
      element_from_bytes(setup_d->ibePub,bufelem);

      free(bufelem);

      /* Load z */
      fread(&elem_size,sizeof(uint32_t),1,fp_pub);
      //printf("elem_size: %d\n",elem_size);
      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
      }

      fread(bufelem,elem_size,1,fp_pub);
      element_init_GT(setup_d->z,setup_d->pairing);
      element_from_bytes(setup_d->z,bufelem);
      //element_printf("g: %B\n",setup_d->g);
      free(bufelem);


      //read n
      fread(&setup_d->n,sizeof(uint32_t),1,fp_pub);
      n2 = setup_d->n *2;

      //alloc P
      setup_d->P = pbc_malloc (sizeof (element_t) * n2);

      //read P
      for(i=0; i < (n2-1); i++) {

            fread(&elem_size,sizeof(uint32_t),1,fp_pub);
            //printf("elem_size: %d\n",elem_size);
            bufelem = (unsigned char *) malloc(elem_size);
            if(!bufelem) {
                  pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
            }

            fread(bufelem,elem_size,1,fp_pub);
            element_init_G1(setup_d->P[i],setup_d->pairing);
            element_from_bytes(setup_d->P[i],bufelem);
            //element_printf("g: %B\n",setup_d->g);
            free(bufelem);
      }

      //load RSA public key
      long pos = ftell(fp_pub);
      fseek(fp_pub,0,SEEK_END);
      long end = ftell(fp_pub);
      int len = 0;

      elem_size = end-pos;
      fseek(fp_pub,pos,SEEK_SET);

      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
      }

      len = fread(bufelem,elem_size,1,fp_pub);

      rsa_public_key_init (&setup_d->pub_rsa);
      //rsa_private_key_init (&setup_d->priv_rsa);
      rsa_keypair_from_sexp(&setup_d->pub_rsa,&setup_d->priv_rsa, 0, len,
                                                            (uint8_t *) bufelem);

      free(bufelem);

}

static void
setup_save_privkey(FILE *fp_priv,setup_params_t * setup_d)
{
      uint32_t elem_size =0;
      unsigned char *bufelem= NULL;
      struct nettle_buffer priv_buffer;

      elem_size = element_length_in_bytes(setup_d->gamma);

      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_save_privkey() :: cannot allocate bufelem");
      }

      element_to_bytes(bufelem,setup_d->gamma);
      fwrite(&elem_size,sizeof(uint32_t),1,fp_priv);
      fwrite(bufelem,elem_size,1,fp_priv);
      free(bufelem);

      elem_size = element_length_in_bytes(setup_d->gammapow_np1);

      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_save_privkey() :: cannot allocate bufelem");
      }

      element_to_bytes(bufelem,setup_d->gammapow_np1);
      fwrite(&elem_size,sizeof(uint32_t),1,fp_priv);
      fwrite(bufelem,elem_size,1,fp_priv);
      free(bufelem);

      nettle_buffer_init(&priv_buffer);
      if (!rsa_keypair_to_sexp (&priv_buffer, "rsa-pkcs1-sha1", &setup_d->pub_rsa,
                                                                  &setup_d->priv_rsa)) {
	    pbgp_die ("Formatting private key failed.\n");
      }
      fwrite(priv_buffer.contents,priv_buffer.size,1,fp_priv);
}

static void
setup_load_privkey(FILE *fp_priv,setup_params_t *setup_d)
{
      unsigned char *bufelem = NULL;
      uint32_t elem_size = 0;
      //struct nettle_buffer pub_buffer;

      fread(&elem_size,sizeof(uint32_t),1,fp_priv);
      //printf("elem_size: %d\n",elem_size);
      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
      }

      fread(bufelem,elem_size,1,fp_priv);
      element_init_Zr(setup_d->gamma,setup_d->pairing);
      element_from_bytes(setup_d->gamma,bufelem);
      //element_printf("g: %B\n",setup_d->g);
      free(bufelem);

      fread(&elem_size,sizeof(uint32_t),1,fp_priv);
      //printf("elem_size: %d\n",elem_size);
      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
      }

      fread(bufelem,elem_size,1,fp_priv);
      element_init_GT(setup_d->gammapow_np1,setup_d->pairing);
      element_from_bytes(setup_d->gammapow_np1,bufelem);
      //element_printf("g: %B\n",setup_d->g);
      free(bufelem);

      //load RSA public key
      long pos = ftell(fp_priv);
      fseek(fp_priv,0,SEEK_END);
      long end = ftell(fp_priv);
      int len = 0;

      elem_size = end-pos;
      fseek(fp_priv,pos,SEEK_SET);

      bufelem = (unsigned char *) malloc(elem_size);
      if(!bufelem) {
            pbgp_die("setup_load_pubkey :: malloc for bufelem failed ");
      }

      len = fread(bufelem,elem_size,1,fp_priv);
      //rsa_public_key_init (&setup_d->pub_rsa);
      rsa_private_key_init (&setup_d->priv_rsa);
      rsa_keypair_from_sexp(&setup_d->pub_rsa,&setup_d->priv_rsa, 0, elem_size,
                                                            (uint8_t *) bufelem);

      free(bufelem);
}

static void
setup_save_ascii_param(FILE *fp_param,setup_params_t *setup_d)
{
      pbc_param_out_str(fp_param,setup_d->params);
}

static void
setup_load_ascii_param(FILE *fp_param,setup_params_t *setup_d)
{
      char s[MAX_LOAD_FSIZE];
      size_t count = 0;

      count = fread(s,1,MAX_LOAD_FSIZE,fp_param);
      if(!count) pbgp_die("setup_load_ascii_param :: I/O error");

      pairing_init_set_buf(setup_d->pairing,s,count);
      pbc_param_init_set_buf(setup_d->params, s, count);
}

int
setup_save (char *f_pub, char *f_priv,char *f_param ,setup_params_t * setup_d)
{
	  FILE *fp_pub = NULL,*fp_priv = NULL,*fp_param = NULL;
	  int rv = 0;

      if(!f_param || (!f_priv && !f_pub)) {
            pbgp_error("setup_save :: fp_param missing");
            return -1;
      }

      if(f_pub) {
    	  fp_pub = fopen(f_pub,"wb");
    	  if(!fp_pub) {
			  pbgp_error("setup_save :: fopen %s\n",strerror(errno));
			  return -1;
    	  }
      }
      if(f_priv) {
    	  fp_priv = fopen(f_priv,"wb");
    	  if(!fp_priv){
			  pbgp_error("setup_save :: fopen %s\n",strerror(errno));

			  rv = -1;
			  goto end;
    	  }
      }
      if(f_param) {
    	  fp_param = fopen(f_param,"w");
    	  if(!fp_param){
			  pbgp_error("setup_save :: fopen %s\n",strerror(errno));

			  rv = -1;
			  goto end;
    	  }
      }

      setup_save_ascii_param(fp_param,setup_d);

      if(fp_pub)
            setup_save_pubkey(fp_pub,setup_d);
      if(fp_priv)
            setup_save_privkey(fp_priv,setup_d);

end:
	if(fp_pub)   fclose(fp_pub);
	if(fp_priv)  fclose(fp_priv);
	if(fp_param) fclose(fp_param);

	return rv;
}

int
setup_load (char *f_pub,char *f_priv,char *f_param,setup_params_t **setup_d)
{
	  int rv = 0;
	  setup_params_t * setup;
	  FILE *fp_pub = NULL,*fp_priv = NULL,*fp_param = NULL;

      if(!f_param || (!f_priv && !f_pub)) {
            pbgp_error("setup_load :: param missing\n");
            return -1;
      }

      if(f_pub) {
    	  fp_pub = fopen(f_pub,"rb");
    	  if(!fp_pub) {
			  pbgp_error("setup_load %s :: fopen %s\n",f_pub,strerror(errno));
			  return -1;
    	  }
      }
      if(f_priv) {
    	  fp_priv = fopen(f_priv,"rb");
    	  if(!fp_priv) {
			  pbgp_error("setup_load %s :: fopen %s\n",f_priv,strerror(errno));
			  rv = -1;
			  goto end;
    	  }
      }
      if(f_param) {
    	  fp_param = fopen(f_param,"r");
    	  if(!fp_param) {
			  pbgp_error("setup_load %s :: fopen %s\n",f_param,strerror(errno));
			  rv = -1;
			  goto end;
    	  }
      }

      *setup_d = malloc(sizeof(setup_params_t));
      if(!(*setup_d))
    	  pbgp_die("setup_load() :: malloc() \n");

      setup = *setup_d;

      setup_load_ascii_param(fp_param,setup);

      if(fp_pub)
            setup_load_pubkey(fp_pub,setup);
      else {
          setup->g->data = NULL;
          setup->ibePub->data = NULL;
          setup->z->data = NULL;
          setup->P = NULL;
      }

      if(fp_priv)
            setup_load_privkey(fp_priv,setup);
      else {
    	  setup->gamma->data = NULL;
    	  setup->gammapow_np1->data = NULL;
      }

end:
	if(fp_pub)   fclose(fp_pub);
	if(fp_priv)  fclose(fp_priv);
	if(fp_param) fclose(fp_param);

    return rv;
}

void
setup_init(setup_params_t **setup_s, int rbits, int qbits, uint32_t n)
{

      int i = 0, n2 = 0;
      //element_t gpowgamma;
      element_t *P;

      setup_params_t *setup = NULL;

      *setup_s = malloc(sizeof(setup_params_t));
      if(!setup_s)
    	  	 pbgp_die("setup_init() :: malloc()");

      setup = *setup_s;

      n2 = n * 2;
      setup->n = n;

      //init group parameters
      pbc_param_init_a_gen (setup->params, rbits, qbits);

      //init pairing structure through params
      pairing_init_pbc_param (setup->pairing, setup->params);
      //force symmetric pairing
      setup->pairing->G2 = setup->pairing->G1;

      element_init_Zr (setup->gamma, setup->pairing);
      element_init_G1 (setup->g, setup->pairing);
      element_init_G1 (setup->ibePub,setup->pairing);
      element_init_GT (setup->z,setup->pairing);

      element_init_Zr(setup->gammapow_np1,setup->pairing);

      P = pbc_malloc (sizeof (element_t) * (n2-1));
      for (i = 0; i < (n2-1); i++) {
	    //SAVE VALUE
	    element_init_G1 (P[i], setup->pairing);
      }
      //Initialize PKI data with nettle libs
      yarrow256_init (&setup->yarrow, 0, NULL);

      rsa_public_key_init (&setup->pub_rsa);
      rsa_private_key_init (&setup->priv_rsa);

      setup->P= P;
}

void
setup_random (setup_params_t * setup_s)
{
      int i = 0, j=0, n2 = 0;
      element_t gpowgammai,gammapowi;
      element_t t1;
      mpz_t np1_mpz,tmp_mpz;
      element_pp_t p;

      mpz_init(tmp_mpz);

      n2 = setup_s->n * 2;
      mpz_init(np1_mpz);
      mpz_set_ui(np1_mpz,(setup_s->n) +1);

      element_random (setup_s->gamma);
      element_random (setup_s->g);
      element_mul_zn (setup_s->ibePub,setup_s->g,setup_s->gamma);

      //init to g^gamma
      element_init_G1 (gpowgammai, setup_s->pairing);
      element_init_Zr (gammapowi, setup_s->pairing);

      element_set1(gammapowi);
      element_set(gpowgammai,setup_s->g);

      element_pp_init(p, gpowgammai);
      for (i = 0,j=0; i < n2; i++,j++) {
	     /* g^gamma+1 is a private value and it's stored separately */
          if(i == (setup_s->n + 1)) {
        	  	  element_set (setup_s->gammapow_np1, gpowgammai);
        	  	  element_mul (gammapowi, gammapowi, setup_s->gamma);
	              element_to_mpz(tmp_mpz,gammapowi);
                    element_pp_pow(gpowgammai, tmp_mpz, p);

                    j--;
                    continue;
          }
          //SAVE VALUE
	    element_set (setup_s->P[j], gpowgammai);
	    element_mul (gammapowi, gammapowi, setup_s->gamma);
	    element_to_mpz(tmp_mpz,gammapowi);
          element_pp_pow(gpowgammai, tmp_mpz, p);
      }

      /* Fill z public value*/
      element_init_G1(t1, setup_s->pairing);
      //element_mul(t1,setup_s->g,setup_s->P[setup_s->n]);
      //element_pairing(setup_s->z, setup_s->g, setup_s->g);
      element_pairing(setup_s->z, setup_s->P[1], setup_s->P[setup_s->n]);

      /* Read some data to seed the generator */
      if (!simple_random (&setup_s->yarrow, NULL)) {
	    pbgp_die ("Initialization of randomness generator failed.\n");
      }

      if (!rsa_generate_keypair
	      (&setup_s->pub_rsa, &setup_s->priv_rsa,
	            (void *) &setup_s->yarrow, (nettle_random_func *) yarrow256_random,
	            NULL, NULL, KEYSIZE, ESIZE)) {

	    pbgp_die ("Key generation failed.\n");
      }


      element_clear(t1);
      element_clear(gpowgammai);
      element_clear(gammapowi);
      mpz_clear(tmp_mpz);
      element_pp_clear(p);
}

static void
print_usage(void)
{
      printf("Help is not available!\n");
}


//#define SETUPTEST_MAIN
#ifdef SETUP_MAIN
/* qbit, rbit, n
 * outpriv,outpub,outparam
 *
 */
int
main (int argc, char **argv)
{
      int c = 0,rv = 0;
      int q = 0,r =0,n = 0;

      setup_params_t *setup = NULL;
      char *ca[] = {"key.pub", "key.prv", "key.par"};

      //default values
      q = 512;
      r = 160;
      n = 65536;

      while ((c=getopt (argc,argv,"q:r:n:e:d:p:")) != -1) {
            switch(c) {
                  case 'q':
                        q = strtol(optarg, NULL, 10);
                  break;

                  case 'r':
                        r = strtol(optarg, NULL, 10);
                  break;

                  case 'n':
                        n = strtol(optarg, NULL, 10);
                  break;

                  case 'e':
                        pbgp_die("Option not implemented yet\n");
                  break;

                  case 'd':
                        pbgp_die("Option not implemented yet\n");
                  break;

                  case 'p':
                        pbgp_die("Option not implemented yet\n");
                  break;

                  default:
                        print_usage();
                        exit(EXIT_FAILURE);

            }
      }

      setup_init (&setup, r, q, n);
      setup_random(setup);

      rv = setup_save(ca[0],ca[1],ca[2],setup);
      if(rv < 0)
    	  pbgp_die("Save failed. Abort\n");

      setup_clear(setup);

      return 0;
}

#endif
