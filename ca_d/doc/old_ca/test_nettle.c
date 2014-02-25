#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>

#include <pbgp.h>
#include <pbgp_common.h>
#include <nettle/rsa.h>
#include <nettle/nettle-meta.h>
#include <nettle/sha.h>

#define MAXASPATHLEN (13)
#define MSG_NUM (MAXASPATHLEN+1)
#define MAXPFIXNUM (50)
#define MAXPFIXLEN (30)
#define MAX_MSG_LEN (1024)
#define MAX_VRFY_LEN (16384)

//RSA
#define KEYSIZE (1024) 
//#define ESIZE 30 

#define RANDOM_DEVICE "/dev/urandom"
#define BUFSIZE 1000

prefls_t *pfixlist = NULL;
uint8_t upvrfy[MAX_VRFY_LEN];
uint8_t rsaupvrfy[MAX_VRFY_LEN];
ibe_keypair_t *as_rir = NULL;

int aspathlen = MAXASPATHLEN;
int pfixnum = MAXPFIXNUM;

static int
out (const char *format, ...)
{
      va_list params;

      va_start (params, format);
      int res = vfprintf (stdout, format, params);

      va_end (params);
      return res;
}

static void
report (const char *prefix, const char *err, va_list params)
{
      char msg[MAX_MSG_LEN];

      vsnprintf (msg, sizeof (msg), err, params);
      out ("%s%s\n", prefix, msg);

}

void
die(const char *err, ...)
{
      va_list params;

      va_start (params, err);
      report ("[FATAL] ", err, params);
      va_end (params);

      exit (EXIT_FAILURE);
}

unsigned
read_file(const char *name, unsigned max_size, char **contents)
{
  unsigned size;
  unsigned done;
  char *buffer;
  FILE *f;
    
  f = fopen(name, "rb");
  if (!f)
    {
      die("Opening `%s' failed: %s\n", name, strerror(errno));
    }
  buffer = NULL;

  if (max_size && max_size < 100)
    size = max_size;
  else
    size = 100;
  
  for (size = 100, done = 0;
       (!max_size || done < max_size) && !feof(f);
       size *= 2)
    {
      char *p;

      if (max_size && size > max_size)
	size = max_size;

      /* Space for terminating NUL */
      p = realloc(buffer, size + 1);

      if (!p)
	{
	fail:
	  fclose(f);
	  free(buffer);
	  *contents = NULL;
	  return 0;
	}

      buffer = p;
      done += fread(buffer + done, 1, size - done, f);

      if (ferror(f))
	goto fail;
    }
  
  fclose(f);

  /* NUL-terminate the data. */
  buffer[done] = '\0';
  *contents = buffer;
  
  return done;
}

int
test_simple_random(struct yarrow256_ctx *ctx, const char *name)
{
  unsigned length;
  uint8_t *buffer;

  if (name)
    length = read_file(name, 0, (char **)&buffer);
  else
    length = read_file(RANDOM_DEVICE, 20, (char **)&buffer);
  
  if (!length)
    return 0;

  yarrow256_seed(ctx, length, buffer);

  free(buffer);

  return 1;
} 
int
create_aslist(ibe_keypair_t **ibk,setup_params_t *setup)
{
	int i = 0;
	int rv = 0 ;
	//ibe_keypair_t *ibk[MAXPATHLEN];
	char pfix[MAXPFIXNUM*MAXPFIXLEN]; //ex: 1.1.1/24
	char *p= NULL;

	bzero(&pfix[0],MAXPFIXNUM*MAXPFIXLEN);

      //create as_rir
      rv = ibe_keypair_init(&as_rir,setup);
      if(rv < 0) {
            die("create_aslist :: ibe_keypair_init %d",i);
      }
      as_rir->id->asnum = 65536;
      ibe_keypair_gen(as_rir);
	
      //create keys for the as
	//printf(">>>> Creating keys for ASes...\n");
      for(i = 0; i < aspathlen ; i++) {
        rv = ibe_keypair_init(&ibk[i],setup);
        if(rv < 0) {
      	      die("create_aslist :: ibe_keypair_init %d",i);
        }
        ibk[i]->id->asnum = i;
        ibe_keypair_gen(ibk[i]);
      }
      //printf(">>>> Done!\n\n");

      p = &pfix[0];
      //assign prefixes to the generator of the announces
	//printf(">>>> Allocating prefixes for the generator AS\n");

      for(i = 0; i < pfixnum ; i++) {

    	      snprintf(p,30,"%d.%d.%d/24",i,i,i);
    	      p+=strlen(p);

    	      if(i < (pfixnum-1)){
    		      snprintf(p,2,",");
    		      p++;
    	      }
      }
      p = &pfix[0];
      //printf("Prefixlist: %s\n",p);
      rv = parse_prefix_list(&pfixlist,&pfix[0],setup);
      if(rv <0) {
    	      die("create_aslist :: parse_prefix_list");
      }

      pfixlist->tsca = time(NULL);

      //printf(">>>> Signing prefixes for generator AS\n");
      for(i=0; i < pfixlist->size; i++) {
  	      //4 bytes for ina + 1 byte for netmask +4 bytes for the timestamp
  	      uint8_t to_sign[9];
  	      bzero(to_sign,9);
  	      SERIALIZE_AUTH(to_sign,&pfixlist->ina[i],&pfixlist->netmask[i],&pfixlist->tsca);

	      ibe_signature_init(&pfixlist->pf_sign[i],setup);
	      //sign prefix
	      //XXX: questa firma dovrebbe essere fatta con la chiave ibe del RIR!
	      //XXX: richiede di inserire la generazione di una chiave IBE 0 per
	      //XXX: il RIR durante la fase di setup
	      ibe_sign(pfixlist->pf_sign[i],as_rir,(const uint8_t *)to_sign,9);
      }
      //printf(">>>> Done!\n\n");

      return 0;
}

void
print_msg(uint8_t *msg)
{
      time_t ts ;
      memcpy(&ts,msg,sizeof(time_t));

      printf("%d %d %d\n",ts,(uint32_t)*(msg+sizeof(time_t)),(uint32_t)*(msg+sizeof(time_t)+4));
            
      return ;
}

int
build_msg_array(uint8_t ** msga,uint8_t *smsg,time_t *tstamps,int prefixnum,setup_params_t *setup)
{
	int i = 0;
	int datalen = 0;
	uint8_t *pmsga = NULL;
      uint8_t *pmsg = NULL;

	datalen = sizeof(time_t) + 2*sizeof(uint32_t);

	pmsga = msga[0];
      pmsg = smsg;

	uint8_t to_sign[9];
	bzero(to_sign,9);
	SERIALIZE_AUTH(to_sign,&pfixlist->ina[prefixnum],&pfixlist->netmask[prefixnum],&pfixlist->tsca);
	memcpy(pmsga,&to_sign[0],9);
      
      //ibe_signature_print(pfixlist->pf_sign[prefixnum]);

	for(i = 0; i < (aspathlen-1) ; i++) {
		pmsga = msga[i+1];
            
		pmsg = smsg + (datalen * pfixnum)*i;
            //print_msg(pmsg);

		memcpy(pmsga,pmsg,sizeof(time_t));
		pmsg +=sizeof(time_t);
		pmsga +=sizeof(time_t);

		memcpy(pmsga,pmsg,sizeof(uint32_t));
		pmsg +=sizeof(uint32_t);
		pmsga +=sizeof(uint32_t);

		memcpy(pmsga,pmsg,sizeof(uint32_t));
		pmsg +=sizeof(uint32_t);
		pmsga +=sizeof(uint32_t);

	}


	return 0;
}

static void
progress(void *ctx, int c)
{
  (void) ctx;
  //fputc(c, stderr);
}
/* Allocate and generate keys */
void
init_rsa_array(struct rsa_public_key **pub,struct rsa_private_key **priv)
{
      int i = 0;
      struct yarrow256_ctx yarrow;
      const char *random_name = NULL;


      for(i=0; i < aspathlen; i++) {
            yarrow256_init(&yarrow, 0, NULL);

            /* Read some data to seed the generator */
            if (!test_simple_random(&yarrow, random_name)) {
                  die("init_rsa_array :: Initialization of randomness generator failed.\n");
            }

            pub[i] = (struct rsa_public_key * ) malloc (sizeof(struct rsa_public_key));
            priv[i] = (struct rsa_private_key *) malloc (sizeof(struct rsa_private_key));
            if(!priv[i] || !pub[i])
                  die("init_rsa_array :: i = %d %s\n",strerror(errno));

            rsa_public_key_init(pub[i]);
            rsa_private_key_init(priv[i]);

            if (!rsa_generate_keypair (pub[i], priv[i],
             (void *) &yarrow, (nettle_random_func *) yarrow256_random,
             NULL, progress,KEYSIZE, ESIZE)) {
                  die("Key generation failed.\n");
            }
      }
     
      return ;      
}


void
rsa_sign_msg(struct rsa_private_key *priv,mpz_t s,  uint8_t *msg, const size_t len)
{
      uint8_t digest[SHA1_DIGEST_SIZE];
      struct sha1_ctx sha1ctx;
      int i = 0,nloop = 0;
      

      if(priv == NULL || msg == NULL || len == 0) {
            die("priv == NULL || msg == NULL || len == 0");
      }

      //printf("\nMSG_LEN: %d\n",len);
      bzero(&sha1ctx,sizeof(struct sha1_ctx));
      bzero(&digest[0],SHA1_DIGEST_SIZE);

      mpz_init(s);
      sha1_init(&sha1ctx);
      sha1_update(&sha1ctx,len,msg);
      sha1_digest(&sha1ctx,SHA1_DIGEST_SIZE,digest);
            
      if (!rsa_sha1_sign_digest(priv, digest, s)) {
      //      out("rsa_sha1_sign...try again\n");
            rsa_sign_msg(priv,s,msg,len);
      }
}

int
rsa_vrfy_msg(struct rsa_public_key *pub,mpz_t sign,const uint8_t *msg,const size_t len)
{
      uint8_t digest[SHA1_DIGEST_SIZE];
      struct sha1_ctx sha1ctx;
      
      bzero(&sha1ctx,sizeof(struct sha1_ctx));
      bzero(&digest[0],SHA1_DIGEST_SIZE);

      sha1_init(&sha1ctx);
      sha1_update(&sha1ctx,len,msg);
      sha1_digest(&sha1ctx,SHA1_DIGEST_SIZE,digest);
  
      //if (!rsa_sha1_verify(pub, &sha1ctx, sign)) {
      if (!rsa_sha1_verify_digest(pub, &digest[0], sign)) {
            return SIGN_INVALID;
      }
    
      return SIGN_VALID;  
}


//#define MAKETEST
#ifdef MAKETEST
int
main(int argc,char **argv)
{
      int rv = 0,i = 0,j=0;
      int datalen = sizeof(time_t) + 2*sizeof(uint32_t);
      int c = 0;

      char *ca[] = {"key.pub","key.prv","key.par"};
      uint8_t *pmsg = NULL,*smsg = NULL;
      uint8_t **msga = NULL,*pmsga = NULL;
     
      //timing vars
      clock_t cstart =0,cend=0;      
      struct timeval start,end;
      int subtime = 0;
      double totsubtime=0.0;

      setup_params_t *setup = NULL;
      ibe_keypair_t *ibk[MAXASPATHLEN]; //one key per as
      ibe_signature_t *signature[MAXPFIXNUM]; //one aggregated signature per prefix
      time_t tstamps[(MAXASPATHLEN+1)*MAXPFIXNUM];
      time_t rsatstamps[(MAXASPATHLEN+1)*MAXPFIXNUM];
      size_t vlen[MAXASPATHLEN +1];

      //RSA
      struct rsa_public_key **rsa_pub = NULL;
      struct rsa_private_key **rsa_priv = NULL;
      mpz_t *vsign = NULL;
      long int nonces[MAXPFIXNUM*MAXPFIXLEN];
      int rsadatalen =sizeof(time_t) + 2*sizeof(uint32_t)+ sizeof(long int) + sizeof(uint8_t) + sizeof(in_addr_t); 

      while ((c=getopt (argc,argv,"a:p:")) != -1) {
            switch(c) {
                  case 'a':
                        aspathlen = strtol(optarg, NULL, 10);
                        if(aspathlen > MAXASPATHLEN) {
                              die("The specified aspathlen execeed MAXASPATHLEN(%d)\n",MAXASPATHLEN);
                        }
                        break;
                  case 'p':
                        pfixnum = strtol(optarg, NULL, 10);
                        if(pfixnum > MAXPFIXNUM) {
                              die("The specified pfixnum execeed MAXPFIXNUM(%d)\n",MAXPFIXNUM);
                        }

                        break;
                  default:
                        die("Invalid input option\n Aborting.\n");
            }

      }
      rv = setup_load (ca[0],ca[1],ca[2],&setup);
      if(rv < 0)
            die("Cannot initialize setup\n Aborting. \n");

      //initialize IBE structures
      bzero(ibk,MAXASPATHLEN*sizeof(ibe_keypair_t *));
      bzero(signature,MAXPFIXNUM*sizeof(ibe_signature_t *));
      bzero(&tstamps,MAXASPATHLEN*MAXPFIXNUM * sizeof(time_t));
      bzero(&rsatstamps,MAXASPATHLEN*MAXPFIXNUM * sizeof(time_t));

      rv = create_aslist(&ibk[0],setup); 
      if(rv < 0)
    	  die("create_aslist");

      msga = (uint8_t **) malloc((MSG_NUM)* sizeof(uint8_t*));
      if(!msga) {
    	  die("malloc msga :: %s",strerror(errno));
      }

      for(i=0; i < MSG_NUM; i++) {
    	  pmsga = (uint8_t * ) malloc(MAX_VRFY_LEN);
    	  if(!pmsga) {
        	  die("malloc msga[%d] :: %s",i,strerror(errno));

    	  }
        bzero(pmsga,MAX_VRFY_LEN);
    	  msga[i] = pmsga;
      }

      vlen[0] = 9;
      for(i = 1; i < (MSG_NUM);i++){ 
    	  vlen[i] = datalen;
      }

      //initialize RSA structures 
      bzero(&nonces,MAXASPATHLEN*MAXPFIXNUM * sizeof(long int));

      rsa_pub = (struct rsa_public_key **) malloc((MSG_NUM)* sizeof(struct rsa_public_key *));
      rsa_priv = (struct rsa_private_key **)malloc((MSG_NUM) * sizeof(struct rsa_private_key *)) ;

      if(!rsa_pub || ! rsa_priv)
            die("init_rsa_array :: %s\n",strerror(errno));
      
      init_rsa_array(rsa_pub,rsa_priv);
      vsign = (mpz_t *) malloc(sizeof(mpz_t) * MSG_NUM * pfixnum);
      if(!vsign)
            die("init_rsa_sign() :: %s\n",strerror(errno));
      
      //----------------- Timing goes here -----------------
      //create the verification message
      //aggregate the signature to assigned prefixes (by AS1)

      //for AS2 to ASn-1
      pmsg = smsg = &upvrfy[0];

      //printf("#TEST SUMMARY\n");
      //printf("#AS path length:%6d\n",aspathlen);
      //printf("#Number of prefixes:%2d\n",pfixnum);
      printf("%d %d ",aspathlen,pfixnum);
      
      //printf("=======================================\n");
      //printf("====== IBE SIGNATURE TIMING TEST ======\n");
      //printf("=======================================\n");
      //for each as
      gettimeofday(&start,NULL);
      //cstart = clock();
      for(j = 0 ; j < (aspathlen-1); j++ ){
        //for each prefix
    	  for(i = 0; i < pfixlist->size; i++) {
              //generate the current timestamp (for prefix + as couple)
    		  tstamps[j*pfixnum + i] = time(NULL);
		  //update the verification message
        	  memcpy(pmsg,&tstamps[j*pfixnum + i],sizeof(time_t));
        	  pmsg+=sizeof(time_t);

        	  memcpy(pmsg,&ibk[j]->id->asnum,sizeof(uint32_t));
        	  //pmsg+=sizeof(ibk[j]->id->asnum);
        	  pmsg+=sizeof(uint32_t);

        	  memcpy(pmsg,&ibk[j+1]->id->asnum,sizeof(uint32_t));
        	  //pmsg+=sizeof(ibk[j+1]->id->asnum);
        	  pmsg+=sizeof(uint32_t);

		  //aggregate signature to prefixes
        	  ibe_sign(pfixlist->pf_sign[i],ibk[j],(const uint8_t * )smsg,pmsg-smsg);
              
              //printf(">> %d %d %d\n",tstamps[j*pfixnum + i],ibk[j]->id->asnum,ibk[j+1]->id->asnum);
              //print_msg(smsg);
        	  smsg = pmsg;
    	  }
      }
      //cend = clock();
      gettimeofday(&end,NULL);
      print_avg_time(start,end,(aspathlen-1));
      //print_time_clock(cstart,cend);
      //printf("=======================================\n");
      //printf("====== RSA SIGNATURE TIMING TEST ======\n");
      //printf("=======================================\n");
      //for each as
      pmsg = smsg = &rsaupvrfy[0];
      gettimeofday(&start,NULL);
      //cstart = clock();
      for(j = 0 ; j < (aspathlen-1); j++ ){
        //for each prefix
    	  for(i = 0; i < pfixlist->size; i++) {
              //add some randomness
              nonces[j*pfixnum +i] = random(); 
              memcpy(pmsg,&nonces[j*pfixnum + i],sizeof(long int));
        	  pmsg+=sizeof(long int);

              //generate the current timestamp (for prefix + as couple)
    		  rsatstamps[j*pfixnum + i] = time(NULL);
		  //update the verification message
        	  memcpy(pmsg,&rsatstamps[j*pfixnum + i],sizeof(time_t));
        	  pmsg+=sizeof(time_t);

        	  memcpy(pmsg,&ibk[j]->id->asnum,sizeof(uint32_t));
        	  pmsg+=sizeof(uint32_t);

        	  memcpy(pmsg,&ibk[j+1]->id->asnum,sizeof(uint32_t));
        	  pmsg+=sizeof(uint32_t);
        	  
              memcpy(pmsg,&pfixlist->ina[i].s_addr,sizeof(in_addr_t));
        	  pmsg+=sizeof(struct in_addr);
              
              memcpy(pmsg,&pfixlist->netmask[i],sizeof(uint8_t));
        	  pmsg+=sizeof(uint8_t);

              //sign prefix
        	  rsa_sign_msg(rsa_priv[j],vsign[j*pfixnum +i],(uint8_t * )smsg,pmsg-smsg);

              smsg = pmsg;
    	  }
      }
      //cend = clock(); 
      gettimeofday(&end,NULL);
      print_avg_time(start,end,(aspathlen-1));
      //print_time(start,end);
      //print_time_clock(cstart,cend);
      
      //printf("==========================================\n");
      //printf("====== IBE VERIFICATION TIMING TEST ======\n");
      //printf("==========================================\n");
      pmsg =  smsg = &upvrfy[0];
      gettimeofday(&start,NULL);
      //cstart = clock();
      //----------------- Timing goes here -----------------
      for(i=0; i < pfixlist->size; i++) {
           //build array of messages
            build_msg_array(msga,smsg,tstamps,i,setup);
            //verfy aggregated message
            rv = ibe_vrfy(pfixlist->pf_sign[i],setup,(const uint8_t **)msga,vlen,&subtime);
            if(rv != SIGN_VALID) printf("Invalid signature :( \n");;
            
            //aggregate signature (by ASn)
            smsg+=datalen;
            totsubtime +=subtime;
      }
      //cend = clock(); 
      gettimeofday(&end,NULL);
      print_time_sub(start,end,totsubtime);
      //print_time_clock(cstart,cend);

      //printf("==========================================\n");
      //printf("====== RSA VERIFICATION TIMING TEST ======\n");
      //printf("==========================================\n");
      //start = clock();
      gettimeofday(&start,NULL);
      //cstart = clock();
      
      int z = 0;
      while(z < 2) {
            pmsg =  smsg = &rsaupvrfy[0];
            //----------------- Timing goes here -----------------
            for(j = 0 ; j < (aspathlen-1); j++ ){
                  for(i=0; i < pfixlist->size; i++) {
                        //vrfy rsa signature
                        rv = rsa_vrfy_msg(rsa_pub[j],vsign[j*pfixnum +i],smsg,rsadatalen);
                        if(rv != SIGN_VALID) printf("Invalid signature :( \n");;

                        //go to next message
                        smsg+=rsadatalen;
                  }
            }
            z++;
      }
      //cend = clock(); 
      gettimeofday(&end,NULL);
      print_time(start,end); 
      //print_time_clock(cstart,cend);
      printf("\n");
      //cleanup
      for(i = 0; i < MAXASPATHLEN ; i++) {
    	  ibe_keypair_clear(ibk[i]);
      }

      for(i=0; i < MAXASPATHLEN; i++) {

    	  if(msga[i])
    		  free(msga[i]);
      }
      free(msga);

      return 0;
}
#endif
