#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
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

//#ifdef TIMING


//#else
//#define START_TIMER(t1) 
//#define END_TIMER(s,t1,t2)
//#endif


static int
out (const char *format, ...);
static void
report (const char *prefix, const char *err, va_list params);
static unsigned
read_file (const char *name, unsigned max_size, char **contents);

void
pbgp_die (const char *err, ...)
{
      va_list params;

      va_start (params, err);
      report ("[FATAL] ", err, params);
      va_end (params);

      exit (EXIT_FAILURE);
}

void
pbgp_info (const char *err, ...)
{
      va_list params;

      va_start (params, err);
      report ("[INFO] ", err, params);
      va_end (params);

}


void
pbgp_error (const char *err, ...)
{
      va_list params;

      va_start (params, err);
      report ("[ERROR] ", err, params);
      va_end (params);

}

int
simple_random (struct yarrow256_ctx *ctx, const char *name)
{
      unsigned length;
      char *buffer;

      if (name)
	    length = read_file (name, 0, &buffer);
      else
	    length = read_file (RANDOM_DEVICE, 20, &buffer);

      if (!length)
	    return 0;

      yarrow256_seed (ctx, length, (uint8_t *)buffer);

      free (buffer);

      return 1;
}

void
hexsha1(char *hexsha1, const uint8_t *message,size_t length)
{

      uint8_t hash[SHA1_DIGEST_SIZE];
      struct sha1_ctx sha1ctx;

      sha1_init(&sha1ctx);
      sha1_update(&sha1ctx,length,message);
      sha1_digest(&sha1ctx,SHA1_DIGEST_SIZE,hash);
      bytestohex(hash,SHA1_DIGEST_SIZE,hexsha1);

}

/** Helper function to convert bytestrings to hex
 * \param in the raw bytestring to convert
 * \param len the length of the string (null characters may be included in in)
 * \param out the result will be put here - len * 2 + 1 should be allocated for this string
 */
void
bytestohex(unsigned char *in, int len, char *out) {
    int i;
    for(i=0; i<len; i++) {
        snprintf(out, 2 ,"%02x", in[i]);
        out += 2;
    }
    *(out-1) = '\0';
}

void
id_to_string(char **s,const ibeid_t *id)
{
      char *p = NULL;

      if(!s) return;

      p = (char *) malloc (MAXIDLEN);
      if(!(p)) {
            pbgp_error("entity_to_string() :: malloc \n");
            return;
      }

      *s = p;
      memset(p,0,MAXIDLEN);
      snprintf(p,MAXIDLEN,"%d",id->asnum);
}

void id_to_string_clear(char *s)
{
      if(s) {
            free(s);
            s = NULL;
      }

      return ;
}

void
ids_clear(id_list_t *active,id_list_t *revoked)
{
      if(active)
            free(active);
      active = NULL;

      if(revoked)
            free(revoked);
      revoked = NULL;

      return ;
}

int
ids_dump(id_list_t *active,id_list_t *revoked, char *idf,char *ridf)
{
      int rv = 0;
      
      rv = ids_save(idf,active);
      rv -= ids_save(ridf,revoked);

      return rv;
}

int
ids_init(id_list_t **active,id_list_t **revoked)
{
      int rv = 0;

      if(active != NULL) { 
            *active = malloc(sizeof(id_list_t));
            if(!(*active)) {
                  pbgp_error("ids_init :: %s\n",strerror(errno));
                  rv = -1;
                  goto out;
            }
            (*active)->head = NULL;
            (*active)->size = 0;
            (*active)->maxsize = 1;
      }
      if(revoked != NULL) {
            *revoked = malloc(sizeof(id_list_t));
            if(!(*revoked)) {
                  pbgp_error("ids_init :: %s\n",strerror(errno));
                  rv = -1;
                  goto out;
            }
            (*revoked)->head = NULL;
            (*revoked)->size = 0;
            (*revoked)->maxsize = 1;
      }


out:
      if(rv < 0) {
            if(*active) free(*active);
            if(*revoked) free(*revoked);
      }
      return rv;
}


int
ids_find(id_list_t *list,ibeid_t *id) 
{
      int i = 0;

      if(!list || !id) return -1;

      for (i=0; i < list->size ; i++) {
            if (id->asnum == list->head[i].asnum)
                    //found    
                    return i;
      }

      return -1;
}

int
ids_remove(id_list_t *list,ibeid_t *id)
{
      int index = 0;
      int  j = 0;

      if(!list) return -1;

      index = ids_find(list,id);
      if(index < 0) {
            pbgp_error("ids_remove() :: element %d not found\n",id->asnum);
            
            return -1;
      }
      
      memset(&list->head[index],0,sizeof(ibeid_t));
      for(j = index; j < (list->size-1); j++) {
            list->head[j] = list->head[j+1];
      }
      list->size--;
      
      return 0;
}

int
ids_add(id_list_t *list,ibeid_t *id)
{
      int offset = 0;
      int index = 0;

      index = ids_find(list,id);
      if(index >= 0) {
            pbgp_error("ids_add () :: element %d already present\n",id->asnum);
            return -1;
      }	
      
      if( (list->size + 1) >= list->maxsize ){
		list->maxsize = list->maxsize*2;
		//realloc
		list->head = realloc(list->head,list->maxsize * sizeof(ibeid_t));
		if(!list->head) {
			pbgp_error("ids_add :: realloc (%s)\n",strerror(errno));
			return -1;
		}

	}
      offset = list->size;
      
	list->head[offset].asnum = id->asnum;
      list->size++;
      
	return 0;
}

int
ids_save_fp(FILE *fp, id_list_t *entities)
{
      uint32_t nwrite = 0;
      uint32_t remaining = 0;
      ibeid_t *p= NULL;

      fwrite(&entities->size,sizeof(uint32_t),1,fp);

      remaining = entities->size;
      p = entities->head;
      while(remaining > 0) {
            nwrite = fwrite(p,sizeof(ibeid_t),remaining,fp);
            remaining -= nwrite;
            p += nwrite;
      }

      return 0;
}

int
ids_load_fp(FILE *fp,id_list_t *entities)
{

      uint32_t nread = 0;
      uint32_t remaining = 0;
      ibeid_t *p= NULL;
      
      if(!fp || !entities) return -1;      

      fread(&entities->size,sizeof(uint32_t),1,fp);

      //prealloc some entries to avoid (realloc) performance issues
      entities->maxsize = 2*(entities->size +1); 

      entities->head = malloc(sizeof(ibeid_t)*entities->maxsize);
      if(!entities->head) {
            pbgp_die("ids_load() :: malloc");
      }
      
      remaining = entities->size;
      p= entities->head;
      //loop til file is read
      while(remaining > 0) {
            nread = fread(p,sizeof(ibeid_t),remaining,fp);
            
            remaining -=nread;
            p+= nread;
      }
      return 0;
}

int
ids_save(char *f, id_list_t *entities)
{
      FILE *fp = NULL;

      fp = fopen(f,"wb");
      if(!fp) {
      	pbgp_error("fid_save :: fopen %s\n",strerror(errno));
      	return -1;
      }
      ids_save_fp(fp,entities);

      fclose(fp);
      return 0;
}

int
ids_load(char *f,id_list_t *entities)
{
      char mode[2] = {'r','b'};      
      FILE *fp = NULL;

      if(!file_exists(f)){
            mode[0] = 'w';
            mode[1] = 'b';
      }

      fp = fopen(f,mode);
      if(!fp) {
      	pbgp_error("ids_load :: fopen %s\n",strerror(errno));
      	return -1;
      }
      ids_load_fp(fp,entities);

      fclose(fp);
      return 0;
}

//TODO: implementare verifica firma envelope
int
revokation_check(acc_t *acc,element_t wit,mpz_t sign_i, uint32_t id,setup_params_t *setup)
{
      int rv= 0;
      element_t num,den,check;

      element_init_GT(num,setup->pairing);
      element_init_GT(den,setup->pairing);
      element_init_GT(check,setup->pairing);
      element_pairing(num, setup->P[id],acc->elem);
      element_pairing(den, setup->g,wit);

      element_div(check,num,den);
      rv = element_cmp(check,setup->z);
      
      element_clear(num);
      element_clear(den);
      element_clear(check);

      return rv;
}

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

static unsigned
read_file (const char *name, unsigned max_size, char **contents)
{
      unsigned size;
      unsigned done;
      char *buffer;
      FILE *f;

      f = fopen (name, "rb");
      if (!f) {
    	  pbgp_error ("Opening `%s' failed: %s\n", name, strerror (errno));
	    return 0;
      }
      buffer = NULL;

      if (max_size && max_size < 100)
	    size = max_size;
      else
	    size = 100;

      for (size = 100, done = 0;
	   (!max_size || done < max_size) && !feof (f); size *= 2) {
	    char *p;

	    if (max_size && size > max_size)
		  size = max_size;

	    /* Space for terminating NUL */
	    p = realloc (buffer, size + 1);

	    if (!p) {
		fail:
		  fclose (f);
		  free (buffer);
		  *contents = NULL;
		  return 0;
	    }

	    buffer = p;
	    done += fread (buffer + done, 1, size - done, f);

	    if (ferror (f))
		  goto fail;
      }

      fclose (f);

      /* NUL-terminate the data. */
      buffer[done] = '\0';
      *contents = buffer;

      return done;
}

int
file_exists(const char * filename)
{
	FILE * f = NULL;
      
      f = fopen(filename, "r");
      if (f) {
        fclose(f);
        return 1;
	}

	return 0;
}


int
vrfy_rsa(mpz_t signature,setup_params_t *setup,uint8_t *msg)
{
    int length = 0;
    length = strlen((char *)msg);

    return vrfy_rsa_len(signature,setup,msg, length);
}

int
vrfy_rsa_len(mpz_t signature,setup_params_t *setup,uint8_t *msg, int length)
{
    struct sha1_ctx sha1ctx;

    sha1_init(&sha1ctx);
    nettle_sha1.update(&sha1ctx,length,msg);
    if(!rsa_sha1_verify(&setup->pub_rsa,&sha1ctx,signature)) {
          pbgp_error("sign_rsa :: invalid signature\n");
          return -1;
    }

    return 0;
}

int
sign_rsa(mpz_t signature,setup_params_t *setup,uint8_t *msg)
{
      int length = 0;
   
      length = strlen((char *)msg);

      return sign_rsa_len(signature,setup,msg,length);
}

int
sign_rsa_len(mpz_t signature,setup_params_t *setup,uint8_t *msg,int length)
{
    struct sha1_ctx sha1ctx;

    sha1_init(&sha1ctx);
    nettle_sha1.update(&sha1ctx,length,msg);
    if(!rsa_sha1_sign(&setup->priv_rsa,&sha1ctx,signature)) {
          pbgp_error("sign_rsa :: signature failed\n");
          return -1;
    }

    return 0;
}

int 
vrfy_list_rsa(mpz_t signature,setup_params_t *setup,id_list_t *list)
{
      int i = 0;
      struct sha1_ctx sha1ctx;
      uint8_t *msg = NULL;

      sha1_init(&sha1ctx);
      for(i = 0; i < list->size ; i++) {
            msg = (uint8_t *) (list->head + i);
            nettle_sha1.update(&sha1ctx,sizeof(ibeid_t),msg);
      }

      if(!rsa_sha1_verify(&setup->pub_rsa,&sha1ctx,signature)) {
            pbgp_error("sign_rsa :: signature failed\n");
            return -1;
      }

      return 0;
}

int
sign_list_rsa(mpz_t signature,setup_params_t *setup,id_list_t *list)
{
      int i = 0;
      struct sha1_ctx sha1ctx;
      uint8_t *msg = NULL;

      sha1_init(&sha1ctx);
      for(i = 0; i < list->size ; i++) {
            msg = (uint8_t *) (list->head + i);
            nettle_sha1.update(&sha1ctx,sizeof(ibeid_t),msg);
      }

      if(!rsa_sha1_sign(&setup->priv_rsa,&sha1ctx,signature)) {
            pbgp_error("sign_rsa :: signature failed\n");
            return -1;
      }

      return 0;
}

void
print_id(ibeid_t *id)
{
      printf("\n-------------\nasnum: %u\n------------\n",
                        id->asnum);
}

int
pfix_init(prefls_t **ls,uint32_t size,setup_params_t *setup)
{
      int i = 0;
      prefls_t *p = NULL;

      if(!ls) {
    	  errno = EINVAL;
    	  return -1;
      }

      *ls = (prefls_t *) malloc(sizeof(prefls_t));
      if(!(*ls)) {
            pbgp_error("pfix_init :: %s\n",strerror(errno));
            return -1;
      }
      p =*ls;

      //cap prefixes to MAX_PFIX_NUM
      p->size = size < MAX_PFIX_NUM ? size : MAX_PFIX_NUM ;
      
      for(i=0; i < p->size; i++) {
    	  	bzero(&p->ina[i],sizeof(struct in_addr));
    	  	p->netmask[i] = 0;
            ibe_signature_init(&p->pf_sign[i],setup);
      }

      p->setup = setup;

      return 0;
}

void
pfix_clear(prefls_t *ls)
{
      int i = 0;

      if(!ls) return;

      for(i=0; i < ls->size ; i++) {
            ibe_signature_clear(ls->pf_sign[i]);
            //free(ls->pfix[i]);
      }
      free(ls);
      ls = NULL;

      return ;
}

void
print_time_clock(clock_t start,clock_t end)
{
  clock_t diff = end - start;
  int msec = diff * 1000 / CLOCKS_PER_SEC;
  
  //printf("Time taken %d.%d sec\n", msec/1000, msec%1000);
  printf("%d,%d ", msec/1000, msec%1000);
}

void
print_time(struct timeval startTime,struct timeval endTime)
{
    // calculate time in microseconds
    double tS = startTime.tv_sec*1000000 + (startTime.tv_usec);
    double tE = endTime.tv_sec*1000000  + (endTime.tv_usec);

    printf("%.0f ", tE-tS);

}

void
print_avg_time(struct timeval startTime,struct timeval endTime,int n)
{
    // calculate time in microseconds
    double tS = startTime.tv_sec*1000000 + (startTime.tv_usec);
    double tE = endTime.tv_sec*1000000  + (endTime.tv_usec);

    printf("%.0f ", (tE-tS)/n);

}

void
print_time_sub(struct timeval startTime,struct timeval endTime,double sub)
{

    // calculate time in microseconds
    double tS = startTime.tv_sec*1000000 + (startTime.tv_usec);
    double tE = endTime.tv_sec*1000000  + (endTime.tv_usec);

    printf("%.0f ", (tE-sub)-tS);

}

      
double
get_time_diff(struct timeval startTime,struct timeval endTime)
{
    double tS = startTime.tv_sec*1000000 + (startTime.tv_usec);
    double tE = endTime.tv_sec*1000000  + (endTime.tv_usec);

    return (tE-tS);
}
/*
static int
host_v4(const char *s, struct bgpd_addr *h, u_int8_t *len)
{
	struct in_addr		 ina;
	int			 bits = 32;

	bzero(&ina, sizeof(struct in_addr));
	if (strrchr(s, '/') != NULL) {
		if ((bits = inet_net_pton(AF_INET, s, &ina, sizeof(ina))) == -1)
			return (0);
	} else {
		if (inet_pton(AF_INET, s, &ina) != 1)
			return (0);
	}

	h->af = AF_INET;
	h->v4.s_addr = ina.s_addr;
	*len = bits;

	return (1);
}

static int
host_v6(const char *s, struct bgpd_addr *h)
{
	struct addrinfo		 hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM; //dummy
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, "0", &hints, &res) == 0) {
		h->af = AF_INET6;
		memcpy(&h->v6,
		    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		    sizeof(h->v6));
		h->scope_id =
		    ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;

		freeaddrinfo(res);
		return (1);
	}

	return (0);
}



 // Convert a string in a struct bgp_addr
int
host(const char *s, struct bgpd_addr *h, u_int8_t *len)
{
	int			 done = 0;
	int			 mask;
	char			*p, *ps;
	const char		*errstr;

	if ((p = strrchr(s, '/')) != NULL) {
#ifdef BSD
		mask = strtonum(p + 1, 0, 128, &errstr);
#else
		mask= strtol(p + 1,NULL, 10);
#endif
		if (errstr) {
			pbgp_error("prefixlen is %s: %s", errstr, p + 1);
			return (0);
		}
		if ((ps = malloc(strlen(s) - strlen(p) + 1)) == NULL)
			pbgp_die("host: malloc %s",strerror(errno));
		strncpy(ps, s, strlen(s) - strlen(p) + 1);
	} else {
		if ((ps = strdup(s)) == NULL)
			pbgp_die("host: strdup");
		mask = 128;
	}

	bzero(h, sizeof(struct bgpd_addr));

	// IPv4 address?
	if (!done)
		done = host_v4(s, h, len);

	// IPv6 address?
	if (!done) {
		done = host_v6(ps, h);
		*len = mask;
	}

	free(ps);

	return (done);
}

*/
