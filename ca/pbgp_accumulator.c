#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#define PBC_DEBUG
#include <pbc.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>

#include "pbgp.h"
#include "pbgp_common.h"

//active e revoked devono essere gia inizializzate con fid_load
int
acc_init(acc_t **acc,pairing_t pairing)
{
	acc_t *p = NULL;

	if(!acc) {
		errno = EINVAL;
		return -1;
	}

	p = (acc_t *)malloc(sizeof(acc_t));
	if(!p) {
		pbgp_error("acc_init :: malloc %s",strerror(errno));
		return -1;
	}
	bzero(p,sizeof(acc_t));
    element_init_G1(p->elem,pairing);

    *acc = p;

    return 0;
}

int
acc_create(acc_t *acc)
{
	if(!acc) {
		errno = EINVAL;
		return -1;
	}

	element_set1(acc->elem);
	return 0;
}

int
acc_update(acc_t *acc,id_list_t *add,id_list_t *rvk,setup_params_t *setup)
{
      int i = 0;
      int pos = 0;
      int np1 = 0;
      element_t num,den,acct;

      element_init_G1(num,setup->pairing);
      element_init_G1(den,setup->pairing);
      element_init_G1(acct,setup->pairing);

      element_set1(num);
      element_set1(den);

      np1 = setup->n + 1;

      for(i=0;i < add->size; i++) {
            pos = np1 - add->head[i].asnum;

            if(pos == np1)
                  element_mul(num,num,setup->gammapow_np1);
            else {
                 if(pos > np1) pos--; 
                 element_mul(num,num,setup->P[pos]);
            }
            //printf("acc_update act :: pos: %d\n",pos);
      }

      for(i=0;i < rvk->size; i++) {
            pos = np1 - rvk->head[i].asnum;
            if(pos == np1)
                  element_mul(den,den,setup->gammapow_np1);
            else {
                 if(pos > np1) pos--; 
                 element_mul(den,den,setup->P[pos]);
            }
            //printf("acc_update rvk :: pos: %d\n",pos);
      }
      element_div(acct,num,den);
      element_mul(acc->elem,acc->elem,acct);

      element_clear(num);
      element_clear(den);
      element_clear(acct);

      return 0;
}

int
acc_load(char *facc,acc_t *acc)
{
      FILE *fp = NULL;
      unsigned char *bufelem = NULL;
      uint32_t elem_size =0;

      if(!file_exists(facc)) {
            pbgp_error("acc_load() \n");
            return -1;
      } 
      
      fp = fopen(facc,"rb");
    	if(!fp) {
	      pbgp_error("acc_load :: fopen %s\n",strerror(errno));
	      return -1;
      }

      fread(&elem_size,sizeof(uint32_t),1,fp);
      if(elem_size == 0 ) {
            element_set0(acc->elem);
      }
      else {
            bufelem = (unsigned char *) malloc(elem_size);
            if(!bufelem) {
                  pbgp_error("acc_load() :: cannot allocate bufelem (%s)\n",strerror(errno));
                  fclose(fp);
                  return -1;
            }
            bzero(bufelem,elem_size);

            fread(bufelem,elem_size,1,fp);
            element_from_bytes(acc->elem,bufelem);
      }
      fread(&acc->nep,sizeof(uint32_t),1,fp);

      //TODO: Leggere/Scrivere firma RSA accumulatore

      free(bufelem);
      fclose(fp);

      return 0;
}

int
acc_save(char *facc,uint32_t nep,acc_t *acc)
{
      FILE *fp = NULL;
      unsigned char *bufelem = NULL;
      uint32_t elem_size =0;

      if(!facc) return -1;

      fp = fopen(facc,"wb");
    	if(!fp) {
	      pbgp_error("acc_save :: fopen %s\n",strerror(errno));
	      return -1;
    	}
      
      //workaround to handle acc = 0 case. Maybe a bug in pbc lib? 
      if(element_is0(acc->elem)) {
            elem_size = 0;
            fwrite(&elem_size,sizeof(uint32_t),1,fp);
      }
      else {
            elem_size = element_length_in_bytes(acc->elem);

            bufelem = (unsigned char *) malloc(elem_size);
            if(!bufelem) {
                  pbgp_error("acc_save :: cannot allocate bufelem\n");
                  fclose(fp);
                  return -1;
            }
            memset(bufelem,0,elem_size);
            
            element_to_bytes(bufelem,acc->elem);
            fwrite(&elem_size,sizeof(uint32_t),1,fp);
            fwrite(bufelem,elem_size,1,fp);
      }
      fwrite(&nep,sizeof(uint32_t),1,fp);
      //element_printf("ho scritto: %B\n",acc);

      free(bufelem);
      fclose(fp);

      return 0;
}

void
acc_clear(acc_t *acc)
{
	if(acc) {
      element_clear(acc->elem);
      free(acc);
	}
}


