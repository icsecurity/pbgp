#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>

//#ifdef BSD
//#include <netinet/in.h>
//#endif

 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>

//#define PBC_DEBUG
#include <pbc.h>
#include <gmp.h>
#include <nettle/yarrow.h>
#include <nettle/rsa.h>
#include <nettle/sexp.h>
#include <nettle/buffer.h>

#include "pbgp.h"
#include "pbgp_common.h"

extern char *optarg;
extern int optind, opterr, optopt;

enum {JOIN,REVOKE,ADDPREFIX};

static int *idarray;

static void
idarray_clear(void );

static int
idarray_getnextid(id_list_t *active,id_list_t *revoked,setup_params_t *setup);

static int
join_action(char *glb[2],char *epoch[2],setup_params_t *setup, ibeid_t *id, prefls_t *pfixlist);

static void
revoke_action(char *glb[2],char *epoch[2],setup_params_t *setup,ibeid_t *id);

int
idarray_init(id_list_t *active,id_list_t *revoked,setup_params_t *setup)
{
      int i =0;

      //alloc and intialize metadata (this is done only once)
      if(!idarray) {
            idarray = malloc(sizeof(int) * setup->n);
            if(!idarray) {
                  pbgp_error("idarray_init() :: malloc %s\n",strerror(errno));
                  return -1;
            }
            memset(idarray,FREE,sizeof(int) * setup->n);
            idarray[0] = BUSY; //reserved to the CA
      }
      //set busy entries
      for(i=0; i < active->size; i++) {
            idarray[active->head[i].asnum] = BUSY; 
      }
      for(i=0; i < revoked->size; i++) {
            idarray[revoked->head[i].asnum] = BUSY; 
      }
      return 0;
}

int
join_load(char *in, action_data_t *join)
{
      FILE *fpin = NULL;
      int rv = 0,i = 0;
      int elem_size = 0,pfix_count = 0;
      unsigned char *buf = NULL;
      unsigned char *sbuf = NULL;

      prefls_t *p = NULL;

      fpin = fopen(in,"rb");
      if(!fpin) {
            goto err;
      }
      
      rv = ibe_keypair_loadfp(fpin,join->ibk);
      if(rv < 0 ) {
            goto err;
      } 
      
      fread(&elem_size,sizeof(uint32_t),1,fpin);    
      buf = (unsigned char *) malloc(elem_size);
      if(!buf) {
            goto err;
      } 
      fread(buf,elem_size,1,fpin);
      element_from_bytes(join->witness,buf); 
      
      fread(&pfix_count,sizeof(uint32_t),1,fpin);    
      rv = pfix_init(&join->pfixlist,pfix_count,join->ibk->setup);
      if(rv < 0)
            goto err;

      p = join->pfixlist;
      //read prefix list + signatures
      for(i = 0; i < p->size; i++) {
            fread(&p->ina[i],sizeof(struct in_addr),1,fpin);
            fread(&p->netmask[i],sizeof(uint8_t),1,fpin);

            fread(&elem_size,sizeof(uint32_t),1,fpin);

            sbuf = (unsigned char *) malloc(elem_size);
            if(!sbuf) {
            	pbgp_error("join_load(), sbuf malloc :: %s\n",strerror(errno));
                goto err;
            }
            fread(sbuf,elem_size,1,fpin);

            rv = ibe_signature_deserialize(p->pf_sign[i],sbuf);
            free(sbuf);

            if(rv < 0)
            	goto err;
      }

      fread(&join->pfixlist->tsca,sizeof(time_t),1,fpin);

      goto out;

err:      
      rv = -1;
      pbgp_error("join_load :: %s\n",strerror(errno));
out:
      if(fpin) fclose(fpin);
      if(buf) free(buf);

      return rv;      

}

int
join_save(action_data_t *join)
{
      FILE *fpout = NULL;
      int rv = 0, i = 0;
      uint32_t elem_size = 0 ;
      uint8_t *buf = NULL;
      char fname[MAX_ENVEL_NAME];
	  unsigned char *sbuf = NULL;


      if(!join) {
    	  errno = EINVAL;
    	  pbgp_error("join_save :: join is null");
    	  return -1;
      }

      sprintf(fname,"id-%d.env",join->ibk->id->asnum);
           
      fpout = fopen(fname,"wb");
      if(!fpout) {
            pbgp_error("join_datasave :: %s\n",strerror(errno));
            return -1;
      }
     
      rv = ibe_keypair_savefp(fpout,join->ibk);
      if(rv < 0 ) {
            pbgp_error("join_datasave :: %s\n",strerror(errno));
            return -1;
      }
 
      elem_size = element_length_in_bytes(join->witness);
      fwrite(&elem_size,sizeof(uint32_t),1,fpout);

      buf = (uint8_t *) malloc(elem_size);
      if(!buf) {
            pbgp_error("join_datasave :: %s\n",strerror(errno));
            return -1;
      } 
      element_to_bytes(buf,join->witness);
      fwrite(buf,elem_size,1,fpout);
      
      fwrite(&join->pfixlist->size,sizeof(uint32_t),1,fpout);
      //write prefix list + signatures
      for(i = 0; i < join->pfixlist->size; i++) {
            fwrite(&join->pfixlist->ina[i],sizeof(struct in_addr),1,fpout);
            fwrite(&join->pfixlist->netmask[i],sizeof(uint8_t),1,fpout);

            elem_size = ibe_signature_serialize(&sbuf,join->pfixlist->pf_sign[i]);

            if(elem_size < 0 ) {
            	rv = -1;
            	break;
            }

            fwrite(&elem_size,sizeof(uint32_t),1,fpout);
            fwrite(sbuf,elem_size,1,fpout);

            free(sbuf);
            sbuf = NULL;
      }

      fwrite(&join->pfixlist->tsca,sizeof(time_t),1,fpout);

      if(sbuf) free(sbuf);
      if(buf)  free(buf);
      fclose(fpout);

      return rv;
}

int
do_join(action_data_t *join,setup_params_t *setup)
{
	  int rv = 0,nextid = 0, i =0;
      char *idstr = NULL;
      
      ibe_keypair_t *ibk = NULL;
      ar_list_t *glb = NULL,*epoch = NULL; 
      prefls_t *pf = NULL;
      
      ibk = join->ibk;
      glb = &join->glb;
      epoch = &join->epoch;
      pf = join->pfixlist;
      
      //command line specified as number
      if(ibk->id->asnum > 0) {
            if(ibk->id->asnum  > setup->n) {
                  pbgp_error ("as number must be lower than %d\n",setup->n);
                  return -1;
            }
            if(idarray[ibk->id->asnum] == BUSY) {
                  pbgp_error ("as number %d is already allocated\n", ibk->id->asnum);
                  return -1;
            } 
      } else {
            //choose from available asnums (not in ID or R_ID)
            nextid = idarray_getnextid (glb->act,glb->rvk,setup);
            if(nextid < 0) {
                  pbgp_error("join() :: id table is full");
                  return -1;
            }
            
            ibk->id->asnum = nextid;
      }
      //gen keypair
      ibe_keypair_gen(ibk);

      pbgp_info("Doing join for %d\n",ibk->id->asnum);
     
      pf->asnum = ibk->id->asnum;
      for(i=0; i < pf->size; i++) { 
    	  //4 bytes for ina + 1 byte for netmask +4 bytes for the timestamp
    	  uint8_t to_sign[9];
    	  bzero(to_sign,9);
    	  SERIALIZE_AUTH(to_sign,&pf->ina[i],&pf->netmask[i],&pf->tsca);

		  ibe_signature_init(&pf->pf_sign[i],ibk->setup);
		  //sign prefix
		  //XXX: questa firma dovrebbe essere fatta con la chiave ibe del RIR!
		  //XXX: richiede di inserire la generazione di una chiave IBE 0 per
		  //XXX: il RIR durante la fase di setup
		  ibe_sign(pf->pf_sign[i],ibk,(const uint8_t *)to_sign,9);
      }      

      //generate the witness for i
      witness_create(join->witness,setup,glb->act,ibk->id);
      
      //update epoch and glb
      ids_add(epoch->act,ibk->id);
      idarray[ibk->id->asnum] = BUSY;      
 
      //dump the envelope
      rv = join_save(join);

      return rv;
}

/* Initialize the action_data_t structur with setup parameters.
 * pfixlist is NULL when the cryptographic data are loaded from file.
 */
int
join_init(action_data_t **join,setup_params_t *setup,prefls_t *pfixlist)
{
      time_t ts;
      char ts_str[MAX_TS_LEN];
      int i = 0,rv =0;
      action_data_t *out = NULL;

      *join = (action_data_t *) malloc(sizeof(action_data_t));
      if(!(*join)) {
            pbgp_error("join_init :: Abort. (%s)\n",strerror(errno));
            return -1;
      }

      out = *join;
      //init ibe
      rv = ibe_keypair_init(&out->ibk,setup);
      if(rv < 0) {
            pbgp_error("join_init :: Abort.\n");
            goto err1;
      }

      //id fiels load and init  
      rv = ids_init(&out->glb.act,&out->glb.rvk);
      rv -= ids_init(&out->epoch.act,&out->epoch.rvk);
      if(rv < 0) {
            pbgp_error("join_init :: Abort.\n");
            goto err2;
      }

      witness_init(out->witness,setup->pairing);

      if(pfixlist) {
          //insert current timestamp inside prefixes
		  ts = time(NULL);
		  pfixlist->tsca = ts;
		  out->pfixlist = pfixlist;
      }

      return 0;

err2:
	ibe_keypair_clear(out->ibk);
	ids_clear(out->glb.act,out->glb.rvk);
	ids_clear(out->epoch.act,out->epoch.rvk);
err1:
	if(out) free(out);

    return rv;
}

void
join_idsdump(action_data_t *join,char *glb[2],char *epoch[2])
{
      //save epoch,glb 
      ids_dump(join->glb.act,join->glb.rvk,glb[0],glb[1]);
      ids_dump(join->epoch.act,join->epoch.rvk,epoch[0],epoch[1]);

}


void
join_clear(action_data_t *join)
{
      if(join) {
            
            //clear all
            ids_clear(join->glb.act,join->glb.rvk);
            ids_clear(join->epoch.act,join->epoch.rvk);

            witness_clear(join->witness);
            ibe_keypair_clear(join->ibk);

            free(join);
            join = NULL;
      }
}

int
revoke_init(action_data_t **rvk,setup_params_t *setup)
{
      action_data_t *out = NULL;

      *rvk = (action_data_t *) malloc(sizeof(action_data_t));
      if(!(*rvk))
            pbgp_die("join_init :: Abort. (%s)\n",strerror(errno));

      out = *rvk;
 
      //id fiels load and init  
      ids_init(&out->glb.act,&out->glb.rvk);
      ids_init(&out->epoch.act,&out->epoch.rvk);
            
      return 0;
}

int
do_revoke(action_data_t *rvk,ibeid_t *id)
{
      if(ids_find(rvk->glb.act,id) < 0) {
            pbgp_error("do_revoke :: %d is not an active entity!\n",id->asnum);
            return -1;
      }

      if(ids_find(rvk->epoch.act,id) > 0) {
            pbgp_error("do_revoke :: you cannot revoke %d during this epoch!\n",id->asnum);
            return -1;
      }

      ids_add(rvk->epoch.rvk,id);

      return 0;
}

void
revoke_clear(action_data_t *rvk)
{
      if(rvk) {
            //clear all
            ids_clear(rvk->glb.act,rvk->glb.rvk);
            ids_clear(rvk->epoch.act,rvk->epoch.rvk);

            free(rvk);
            rvk = NULL;
            
      }

      return ;
}

static void
idarray_clear(void )
{
      if(idarray) free(idarray);
      idarray = NULL;
}

static int
idarray_getnextid(id_list_t *active,id_list_t *revoked,setup_params_t *setup)
{
      int next_id = 0, i = 0;
      int idarraysize = 0;

      if(!active || !revoked) {
            pbgp_error("get_next_id() :: invalid input params");
            return -1;
      }

      idarraysize = setup->n;

      //search first free entry 
      for(i=0; i < idarraysize; i++) {
            if(idarray[i] == FREE) {
                  next_id = i;
                  break;
            }
      }

      if(i == idarraysize) {
            pbgp_error("get_next_id() :: No space left\n");
            return -1;
      }

      return next_id; 
}


static int
join_action(char *glb[2],char *epoch[2],setup_params_t *setup, ibeid_t *id, prefls_t *pfixlist)
{
      int rv=0; 
      action_data_t *act_p = NULL;
      
      if(!setup || !id ||!pfixlist ) {
    	  errno = EINVAL;
    	  return -1;
      }

      //join init
      rv = join_init(&act_p,setup,pfixlist);
      if(rv < 0)
            pbgp_die("join initialization failed. Aborting. \n");

      //ids load
      rv = ids_load(glb[0],act_p->glb.act);
      rv -= ids_load(glb[1],act_p->glb.rvk);
      rv -= ids_load(epoch[0],act_p->epoch.act);
      rv -= ids_load(epoch[1],act_p->epoch.rvk);
      if(rv < 0) 
            pbgp_die("init_ids fid_load \n");
      
      //idarray init
      idarray_init(act_p->glb.act,act_p->glb.rvk,setup);
      idarray_init(act_p->epoch.act,act_p->epoch.rvk,setup);
    
      //set prefix list 
      act_p->ibk->id->asnum=id->asnum;

      //do join
      do_join(act_p,setup);
     
      //id_save
      ids_dump(act_p->epoch.act,act_p->epoch.rvk,epoch[0],epoch[1]);
      
      pbgp_info("%d successfully joined\n",act_p->ibk->id->asnum);

      //join clear
      join_clear(act_p);
      //idarray clear
      idarray_clear();
      pfix_clear(pfixlist);

      return 0;
}

static void
revoke_action(char *glb[2],char *epoch[2],setup_params_t *setup,ibeid_t *id)
{
      int rv = 0;
      action_data_t *act_p = NULL;

      rv = revoke_init(&act_p,setup);
      if(rv < 0)
            pbgp_die("revoke initialization failed. Aborting. \n");

      //ids load
      rv = ids_load(glb[0],act_p->glb.act);
      rv -= ids_load(glb[1],act_p->glb.rvk);
      rv -= ids_load(epoch[0],act_p->epoch.act);
      rv -= ids_load(epoch[1],act_p->epoch.rvk);
      if(rv < 0) 
            pbgp_die("init_ids fid_load \n");
      
      //idarray init
      idarray_init(act_p->glb.act,act_p->glb.rvk,setup);
      idarray_init(act_p->epoch.act,act_p->epoch.rvk,setup);

      rv = do_revoke(act_p,id);
      if(rv < 0) {
            pbgp_die("Revokation failed. Aborting. \n");
      }
      
      ids_dump(act_p->epoch.act,act_p->epoch.rvk,epoch[0],epoch[1]);
      ids_clear(act_p->epoch.act,act_p->epoch.rvk);
      
      pbgp_info("%d successfully revoked\n",id->asnum);

      revoke_clear(act_p);
      idarray_clear();

}

int
parse_prefix_list(prefls_t **pfixlist,char *str,setup_params_t *setup)
{

	int nelem = 0;
	int i = 0,len =0,rv=0;
	char *token = NULL,*bck = NULL;
	prefls_t *p = NULL;

	if(!str || !setup) {
		errno = EINVAL;
		return -1;
	}

	len = strlen(str);
	bck = malloc(len);
	if(!bck) {
		pbgp_error("parse_prefix_list :: %s\n",strerror(errno));
		return -1;
	}
	strncpy(bck,str,len);
	//count tokens
	token = strtok(str,",");
	while(token != NULL) {
		nelem++;
		token = strtok(NULL,",");
	}
	strncpy(str,bck,len);

	rv = pfix_init(pfixlist,nelem,setup);
	if(rv < 0)
		goto out;

	p = *pfixlist;

	token = strtok(str,",");
	while((token != NULL) && (i < MAX_PFIX_NUM)) {
		/*rv = inet_pton(AF_INET,token,&(*pfixlist)->ina[i].sin_addr);*/
		//rv=host(token, &p->ina[i], &p->bitmask[i]);
		if (strrchr(token, '/') != NULL) {
				if ((p->netmask[i] = inet_net_pton(AF_INET, token, &p->ina[i], sizeof(struct in_addr))) == -1)
					rv =-1;
			} else {
				if (inet_pton(AF_INET, token, &p->ina[i]) != 1)
					rv=-1;
			}

		if(rv < 0) {
			pbgp_error("parse_prefix_list :: %s\n",strerror(errno));
			rv = -1;
			goto out;
		}

    	//char as[40];
		//inet_net_ntop (AF_INET, &p->ina[i], p->bitmask[i],as, 40);
    	//printf("addr:%s bitmask: %d\n",as,p->bitmask[i]);

		token = strtok(NULL,",");
		i++;
	}
    
out:
      free(bck);

      return rv;

}


static void 
print_usage(void)
{
      printf("Help is not available!\n");
}

#ifdef ACTIONS_MAIN
/*
 * action [join|revoke]
 * ip netmask [asnum] 
 * file epoch {.rvk,.act} without extension
 * file global {.rvk.act} without extension
 * file setup keypair{.priv,.pub,.par}
 */
int
main(int argc, char **argv)
{
      int rv = 0;
      int c = 0;
      int action = -1;

      char *ca[] = {"key.pub","key.prv","key.par"};
      char *glb[] = {"gbl.act","gbl.rvk"};
      char *epoch[] = {"epc.act","epc.rvk"};

      char *pfixstr = NULL;

      //struct sockaddr_in prefix,netmask;
      setup_params_t *setup = NULL;
      ibeid_t id;
      prefls_t *pfixlist = NULL;

      memset(&id,0,sizeof(ibeid_t));
      while ((c=getopt (argc,argv,"p:a:i:egkrj::")) != -1) {
            switch(c) {
                  case 'p': //ip prefix (ex: 10.0.1.0/24,11.0.0.0/8)
                        pfixstr = malloc(strlen(optarg));
                        if(!pfixstr)
                        	pbgp_die("malloc %s\n",strerror(errno));
                        memcpy(pfixstr,optarg,strlen(optarg));
                  break;

                  case 'i': //as number
                        if(optarg)
                              id.asnum = strtol(optarg, NULL, 10);
                  break;
                  
                  case 'e': //epoch filename prefix
                        pbgp_die("Option not implemented yet\n");
                  break;

                  case 'g': //global filename prefix
                        pbgp_die("Option not implemented yet\n");
                  break;

                  case 'k': //ca keypair filename prefix
                        pbgp_die("Option not implemented yet\n");
                  break;

                  case 'r':
                        if(action <0)
                              action = REVOKE;
                        else {
                              print_usage();
                              pbgp_die("JOIN and REVOKE options are mutually exclusive\n");
                        }
                  break;
                  case 'j':
                        if ( action < 0)
                              action = JOIN;
                        else {
                              print_usage();
                              pbgp_die("JOIN and REVOKE options are mutually exclusive\n");
                        }
                  break;
                  //TODO: addprefix option
                  case 'a':
                        pbgp_die("Option not implemented yet\n");
                  break;                  
                  default:
                        print_usage();
                        pbgp_die("%c is not a valid option\n",c);
            }
      }

      if(action != JOIN && action != REVOKE && action != ADDPREFIX) {
            print_usage();
            pbgp_die("You must specify a valid action to take (join or revoke)\n");
      }
       

      rv = setup_load (ca[0],ca[1],ca[2],&setup);
      if(rv < 0) 
            pbgp_die("setup_load failed, cannot proceed\n");

      if(pfixstr) {
    	  rv = parse_prefix_list(&pfixlist,pfixstr,setup);
    	  free(pfixstr);
    	  if(rv < 0)
              pbgp_die("parse_prefix_list failed, cannot proceed (%s)\n",strerror(errno));

      }
      switch(action) {
            case JOIN:
                  printf(" ****** Join action called ****** \n");
                  
                  rv = join_action(glb,epoch,setup,&id,pfixlist);
                  if(rv < 0) {
                	  pbgp_error("Error during join: %s\n",strerror(errno));

                  }
            break;
            case REVOKE:
                  printf(" ****** Revoke action called ****** \n");
                  if(id.asnum <= 0) {
                        pbgp_die("You must specify the asnum option for revokation\n");
                  }
           
                  revoke_action(glb,epoch,setup,&id);
            break;
            case ADDPREFIX:
                  //TODO
            break;
     }

      setup_clear(setup);
      return 0;
      
}
#endif
