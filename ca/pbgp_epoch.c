#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pbc.h>
#include <gmp.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>
#include <nettle/sha.h>

#include "pbgp.h"
#include "pbgp_common.h"

int
newepoch_load(char *in,epoch_item_t *ep,setup_params_t * setup)
{
      FILE *fp = NULL;
      uint32_t elem_size = 0;
      int rv = 0;
      unsigned char *buf = NULL;

      fp=fopen(in,"rb");
      if(!fp) {
          pbgp_error("newepoch_load :: %s\n",strerror(errno));
          return -1;
      }

      fread(&elem_size,sizeof(uint32_t),1,fp);

      buf = (unsigned char *) malloc(elem_size);
      if(!buf) {
          pbgp_error("newepoch_load :: cannot allocate buf\n");
          rv = -1;
          goto out;
      }
      
      fread(buf,elem_size,1,fp);
      element_from_bytes(ep->acc->elem,buf);
      mpz_inp_raw (ep->s_acc,fp); 

      ids_load_fp(fp,ep->epls.act);
      mpz_inp_raw(ep->s_new,fp);
      
      ids_load_fp(fp,ep->epls.rvk);
      mpz_inp_raw(ep->s_rvk,fp);

out:
	if(buf)
		free(buf);

	fclose(fp);
	return rv;
}


int
newepoch_save(char *out,epoch_item_t *ep,setup_params_t * setup)
{
      FILE *fp = NULL;
      uint32_t elem_size = 0;
      int rv = 0;
      unsigned char *buf = NULL;

      fp=fopen(out,"wb");
      if(!fp) {
            pbgp_error("newepoch_save :: %s\n",strerror(errno));
            return -1;
      }

      elem_size = element_length_in_bytes(ep->acc->elem);
      buf = (unsigned char *) malloc(elem_size);
      if(!buf) {
            pbgp_error("newepoch_save :: cannot allocate buf\n");
            rv = -1;
            goto out;
      }
      element_to_bytes(buf,ep->acc->elem);
      fwrite(&elem_size,sizeof(uint32_t),1,fp);
      fwrite(buf,elem_size,1,fp);
      mpz_out_raw(fp,ep->s_acc);

      ids_save_fp(fp,ep->epls.act);
      mpz_out_raw(fp,ep->s_new);
      
      ids_save_fp(fp,ep->epls.rvk);
      mpz_out_raw(fp,ep->s_rvk);

out:
      if(buf) 
            free(buf);

      fclose(fp);
      return rv;
}

int
newepoch_gen(char *out,epoch_item_t *ep,setup_params_t *setup)
{
      char *accstr = NULL;
      int elem_size = 0;
      
      //update the accumulator 
      acc_update(ep->acc,ep->epls.act,ep->epls.rvk,setup);
      ep->epoch++;
      //sign epoch revoked list
      sign_list_rsa(ep->s_rvk,setup,ep->epls.rvk);
      //sign epoch added list      
      sign_list_rsa(ep->s_new,setup,ep->epls.act);

      elem_size = element_length_in_bytes(ep->acc->elem);
      accstr = (char *) malloc(elem_size);
      if(!accstr) {
            pbgp_error("newepoch :: %s\n",strerror(errno));
            return -1;
      }

      element_snprintf(accstr,elem_size,"%B",ep->acc->elem);
      //sign accumulator value
      sign_rsa(ep->s_acc,setup,(uint8_t *)accstr);

      //dump envelope
      newepoch_save(out,ep,setup);
      
      free(accstr); 
      return 0;  
}

int
newepoch_init(epoch_item_t **ep, setup_params_t *setup)
{
     epoch_item_t *out = NULL;

      *ep = malloc(sizeof(epoch_item_t));
      out = *ep;

      if(!out) {
            pbgp_error("newepoch_init :: %s\n",strerror(errno));
            return -1;
      }
      bzero(out,sizeof(epoch_item_t));
      acc_init(&out->acc,setup->pairing);
      
      mpz_init(out->s_new); 
      mpz_init(out->s_rvk); 
      mpz_init(out->s_acc); 

      return 0;

}

void
newepoch_clear(epoch_item_t *ep)
{
      if(ep) {
            mpz_clear(ep->s_new);
            mpz_clear(ep->s_rvk);
            mpz_clear(ep->s_acc);

            free(ep);
            ep = NULL;
      }
}

int
claim_new_epoch(char *glb[2],char *epoch[2],char *facc,char *outf,setup_params_t *setup)
{
      int rv = 0, i = 0;
      epoch_item_t *ep = NULL;      
      id_list_t *act = NULL, *rvk = NULL;

      rv = newepoch_init(&ep,setup);
      if(rv < 0) {
            pbgp_error("claim_new_epoch :: Cannot complete initialization process\n");
            goto out1;
      }

      rv = ids_init(&ep->epls.act,&ep->epls.rvk);
      rv -= ids_init(&act,&rvk);
      if (rv < 0) { 
            pbgp_error("claim_new_epoch :: Cannot initialize ids lists\n");

            goto out2;
      }
     
      if (!file_exists(epoch[0]) || !file_exists(epoch[1])) {
            rv = -1;
            pbgp_error("Cannot find epoch files (%s,%s)\n",epoch[0],epoch[1]);
            goto out2;
      } 
 
      rv = ids_load(epoch[0],ep->epls.act);
	rv -= ids_load(epoch[1],ep->epls.rvk);
	rv -= ids_load(glb[0],act);
	rv -= ids_load(glb[1],rvk);
      if(rv < 0) { 
            pbgp_error("claim_new_epoch :: Cannot load ids\n");
            goto out3;
      }
     
      if(ep->epls.act->size == 0 && ep->epls.rvk->size == 0) {
            rv = -1;
            pbgp_error("claim_new_epoch :: There are no entities to join or revoke\n");
            goto out3;

      }
 
      //if first epoch
      if(!file_exists(facc)) {
            acc_create(ep->acc);
            ep->epoch = 0;
      } else {
            rv = acc_load(facc,ep->acc);
            if(rv < 0) {
                  pbgp_error("claim_new_epoch :: Cannot create accumulator\n");
                  goto out4;
            }
      }       
      ep->epoch = ep->acc->nep;
      //element_printf("ACC: %B\n",ep->acc);

      newepoch_gen(outf,ep,setup);
      //save accumulator
      //element_printf("ACC: %B\n",ep->acc);
      if(element_is0(ep->acc->elem)) {
            printf("ACC is 0\n");
            element_set1(ep->acc->elem);
      }
      acc_save(facc,ep->epoch,ep->acc);
      //update global joined entities
      for(i = 0; i < ep->epls.act->size; i++) {
            ids_add(act,&ep->epls.act->head[i]);
      }
      //update global revoked entities
      for(i = 0; i < ep->epls.rvk->size; i++) {
            ids_remove(act,&ep->epls.rvk->head[i]);
            ids_add(rvk,&ep->epls.rvk->head[i]);
      }
      ids_save(glb[0],act);
      ids_save(glb[1],rvk);
      
      //delete old epoch files (or write empty list)
      remove(epoch[0]);
      remove(epoch[1]);

out4:      
      acc_clear(ep->acc);
out3:
      ids_clear(ep->epls.act,ep->epls.rvk);
      ids_clear(act,rvk);
out2:
      newepoch_clear(ep);
out1:
      return rv; 
}

#define EPOCHTEST_MAIN
#ifdef EPOCHTEST_MAIN
int
main()
{
      int rv = 0,res =0,i = 0,j=0;
      char *ca[] = {"key.pub","key.prv","key.par"};
      char *glb[] = {"gbl.act","gbl.rvk"};
      char *epoch[] = {"epc.act","epc.rvk"};
      char *facc = "last.acc";
      char fname[MAX_ENVEL_NAME];

      setup_params_t *setup = NULL;
      epoch_item_t *ep = NULL;
      id_list_t *actls= NULL, *rvkls = NULL;
      action_data_t *join = NULL;
     
      rv = setup_load (ca[0],ca[1],ca[2],&setup);
      if(rv < 0)
            pbgp_die("Cannot initialize setup\n Aborting. \n");

      //genera epoca
      rv = claim_new_epoch(glb,epoch,facc,"last.epc",setup);
      if(rv < 0) 
            pbgp_die("Cannot claim a new epoch\n");

      rv = newepoch_init(&ep,setup);
      if(rv < 0) {
            pbgp_die("claim_new_init :: Cannot complete initialization process\n");
      }
      rv = ids_init(&ep->epls.act,&ep->epls.rvk);
      if(rv < 0) {
            pbgp_die("ids_init :: Cannot create lists\n");
      }
      rv = newepoch_load("last.epc",ep,setup);
      if(rv < 0) {
            pbgp_die("\n");
      }
     

      //da usare per caricare i nomi dei file
      ids_init(&actls,&rvkls);
      ids_load(glb[0],actls);
      ids_load(glb[1],rvkls);
 
      join_init(&join,setup,NULL);
      if(join == NULL)
            pbgp_die("join is null. Abort.");
      
      printf("ACTIVE USER TEST:\n");
      for(i=0; i < actls->size ; i++) {
            char *idstr = NULL;
            //carica join elem
            sprintf(fname,"id-%d.env",actls->head[i].asnum);
            
            join_load(fname,join);

            id_to_string(&idstr, join->ibk->id); 
            printf("Verifying %s\n",idstr);
            id_to_string_clear(idstr);

            //update the witness
            witness_update(join->witness,join->ibk->id,setup,
             		ep->epls.act,ep->epls.rvk);
            //check the presence of the AS into the accumulator
            rv = revokation_check(ep->acc,join->witness,join->signature,
            		join->ibk->id->asnum,setup);

            //check the prefix list signatures TODO!!!!! aaggiusta sto codice -.-
            for(j=0; j < join->pfixlist->size; j++) {
            	const uint8_t *buf_ina = (const uint8_t *) &join->pfixlist->ina[j];
            	size_t sina[1];
            	char as[40];

        		inet_net_ntop (AF_INET, &join->pfixlist->ina[j], join->pfixlist->netmask[j],as, 40);

            	//sina[0] = sizeof(join->pfixlist->ina[j]);
				uint8_t to_vrfy[1][9];
				uint8_t *p = to_vrfy;

				bzero(p,9);
				SERIALIZE_AUTH(p,&join->pfixlist->ina[j],&join->pfixlist->netmask[j],&join->pfixlist->tsca);
				sina[0] = 9;

				res = ibe_vrfy(join->pfixlist->pf_sign[j],
						setup,(const uint8_t **)&p,sina,NULL);



                if(res == SIGN_VALID) printf("The signature is valid! (%s)\n",as);
                else printf("Invalid signature :( \n");
            }

            if(rv != 0) {
                  pbgp_error("revokation_check :: %d have been revoked!\n",join->ibk->id->asnum);
                  rv = -1;
            } else {
                  printf("SUCCESS: User %d is still into the accumulator\n",join->ibk->id->asnum);
                  join_save(join);
            }

            pfix_clear(join->pfixlist);

      }
      join_clear(join);

      // verifica che i revocati non sono nell'accumulatore
      join_init(&join,setup,NULL);
      if(join == NULL)
            pbgp_die("join is null. Abort.");
      
      printf("REVOKED USER TEST:\n");

      for(i=0; i < rvkls->size ; i++) {
            char *idstr = NULL;
            //carica join elem
            sprintf(fname,"id-%d.env",rvkls->head[i].asnum);
            
            join_load(fname,join);

            id_to_string(&idstr, join->ibk->id); 
            printf("Verifying %s\n",idstr);
            //aggiorna il witness
            witness_update(join->witness,join->ibk->id,setup,
             		ep->epls.act,ep->epls.rvk);

            rv = revokation_check(ep->acc,join->witness,join->signature,
            		join->ibk->id->asnum,setup);

            if(rv != 0) {
                  pbgp_error("revokation_check :: %d have been revoked!\n",join->ibk->id->asnum);
                  rv = -1;
            } else {
                  printf("SUCCESS: User %d is still into the accumulator\n",join->ibk->id->asnum);
                  join_save(join);
            }

            id_to_string_clear(idstr);

      }
      join_clear(join);

      ids_clear(actls,rvkls);
      setup_clear(setup);
      return 0;
}
#endif
