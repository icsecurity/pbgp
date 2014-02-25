#ifndef _H_PBGP_COMMON
#define _H_PBGP_COMMON

#include <stdint.h>
#include <sys/queue.h>

#define MAX_MSG_LEN (1024)
#define RANDOM_DEVICE "/dev/urandom"
#define BUFSIZE (1000)
#define MAXIDLEN (60)
#define MAXLONGLEN (10)
#define MAXIPLEN (15)

#define START_TIMER(t1) gettimeofday(&t1,NULL);
#define END_TIMER(s,t1,t2)\
      gettimeofday(&t2,NULL);\
      printf("%s: ",s);\
      print_time(t1,t2);\
      printf("\n");

void 
pbgp_die (const char *err, ...);

void
pbgp_info (const char *err, ...);

void 
pbgp_error (const char *err, ...);

void
hexsha1(char *hexsha1, const uint8_t *message,size_t length);

void
bytestohex(unsigned char *in, int len, char *out);

void
id_to_string(char **s,const ibeid_t *id);

void 
id_to_string_clear(char *s);

/* Functions to handle AS-id lists */
void
ids_clear(id_list_t *active,id_list_t *revoked);

int
ids_dump(id_list_t *active,id_list_t *revoked, char *idf,char *ridf);

int
ids_init(id_list_t **active,id_list_t **revoked);

int
ids_add(id_list_t *active,ibeid_t *newid);

int
ids_remove(id_list_t *list,ibeid_t *id);

int
ids_find(id_list_t *list,ibeid_t *id);

int
ids_save(char *f, id_list_t *entities);

int
ids_save_fp(FILE *fp, id_list_t *entities);

int
ids_load(char *f,id_list_t *entities);

int
ids_load_fp(FILE *fp,id_list_t *entities);

/* Feed the ctx struct with random data*/
int
simple_random (struct yarrow256_ctx *ctx, const char *name);

int
file_exists(const char * filename);

void
print_id(ibeid_t *id);

/* Helper function to sign/verify an rsa message */
int
vrfy_rsa(mpz_t signature,setup_params_t *setup,uint8_t *msg);
int
sign_rsa(mpz_t signature,setup_params_t *setup,uint8_t *msg);

int
sign_rsa_len(mpz_t signature,setup_params_t *setup,uint8_t *msg,int length);
int
vrfy_rsa_len(mpz_t signature,setup_params_t *setup,uint8_t *msg,int length);

/* Helper function to sign/verify an identity list */
int
vrfy_list_rsa(mpz_t signature,setup_params_t *setup,id_list_t *list);
int 
sign_list_rsa(mpz_t signature,setup_params_t *setup,id_list_t *list);

int
revokation_check(acc_t *acc,element_t wit,mpz_t sign_i, uint32_t id,setup_params_t *setup);

int
pfix_init(prefls_t **ls,uint32_t size,setup_params_t *setup);

void
pfix_clear(prefls_t *ls);

void
print_time_clock(clock_t start,clock_t end);

void
print_time(struct timeval startTime,struct timeval endTime);

void
print_avg_time(struct timeval startTime,struct timeval endTime,int n);

double
get_time_diff(struct timeval startTime,struct timeval endTime);

void
print_time_sub(struct timeval startTime,struct timeval endTime,double sub);

//int
//host(const char *s, struct bgpd_addr *h, u_int8_t *len);

#endif
