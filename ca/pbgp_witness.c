#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pbc.h>
#include <gmp.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>

#include "pbgp.h"
#include "pbgp_common.h"

int
witness_init(element_t witness,pairing_t pairing)
{
      element_init_G1(witness,pairing);

      return 0;
}

int
witness_serialize(uint8_t **buf,element_t witness)
{
	uint32_t elem_size = 0;
	uint8_t *rbuf = NULL;

	if(!buf) {
		errno = EINVAL;
		pbgp_error("witness_serialize() :: invalid param sequence\n");
		return -1;
	}

    elem_size = element_length_in_bytes(witness);
    rbuf = (uint8_t *) malloc(elem_size);
    if(!rbuf) {
    	pbgp_error("witness_serialize() :: %s\n",strerror(errno));
    	return -1;
    }
    bzero(rbuf,elem_size);
    element_to_bytes(rbuf,witness);

    *buf = rbuf;

    return elem_size;
}

int
witness_deserialize(element_t witness,uint8_t *buf)
{
	if(!buf) {
		errno = EINVAL;
		pbgp_error("witness_serialize() :: invalid param sequence\n");
		return -1;
	}
	element_from_bytes(witness,buf);

	return 0;
}


int
witness_create(element_t witness,setup_params_t *setup,id_list_t *active,ibeid_t *newid)
{
      int i = 0,pos = 0;
      int np1 = 0;

      np1 = setup->n + 1;

      element_set1(witness);
      
      for(i=0; i < active->size; i++) {
            pos = np1 - active->head[i].asnum +newid->asnum;
            if(pos >= (np1))
                  pos--;
            
            element_mul(witness,witness,setup->P[pos]);
      }
     
 
      return 0;
}

int
witness_update(element_t wit,ibeid_t *id,setup_params_t *setup,id_list_t *add,id_list_t *rvk)
{
      int i = 0, curr = 0;
      int pos = 0;
      int np1 = 0;
      element_t num,den,witt;

      element_init_G1(num,setup->pairing);
      element_init_G1(den,setup->pairing);
      element_init_G1(witt,setup->pairing);

      element_set1(num);
      element_set1(den);

      np1 = setup->n + 1;
      curr = id->asnum;

      for(i=0;i < add->size; i++) {
            if(add->head[i].asnum  ==  curr )
                  continue; 
            
            pos = np1 - add->head[i].asnum + curr;
            if(pos >= (np1))
                  pos--;
            
                   
            element_mul(num,num,setup->P[pos]);
            //printf("witness_update add :: pos: %d\n",pos);
      }

      for(i=0;i < rvk->size; i++) {
            if(rvk->head[i].asnum  ==  curr )
                  continue; 
            
            pos = np1 - rvk->head[i].asnum + curr;
            if(pos >= (np1))
                  pos--;
            element_mul(den,den,setup->P[pos]);
            //printf("witness_update rvk :: pos: %d\n",pos);
      }

      element_div(witt,num,den);
      element_mul(wit,wit,witt);

      element_clear(num);
      element_clear(den);
      element_clear(witt);      
      
      return 0;
}

void
witness_clear(element_t witness)
{
      element_clear(witness);
}


