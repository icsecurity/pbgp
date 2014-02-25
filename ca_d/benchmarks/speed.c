#include "pbgp.h"
#include <sys/time.h>

/*
 *    valgrind --tool=callgrind --dump-instr=yes --simulate-cache=yes --collect-jumps=yes --dump-after=pbgp_store_put
 *      .libs/lt-speed
 */
#define ITERATIONS 10

#define pbgp_dsa_sign pbgp_rsa_sign
#define pbgp_dsa_verify pbgp_rsa_verify

/*
 * 1         firma
 * 1,2       verifica e firma
 * 1,2,3     verifica e firma...
 *
 *  Per IBE c'è una sola firma aggregata
 *  Per RSA / DSA ve ne è una per ogni segmento
 *
 *  Ma prima devo misurare i tempi delle singole firme / verifiche
 *  su input di diversa lunghezza (senza considerare aggregazione)
 *
 *  Quindi 1...X byte firma e verifica
 *
 */

static int __ibe_time(setup_params_t *setup,
                                    store_t *store,
                                    ibe_signature_t *signature)
{
  pbgp_ibe_verify(setup, signature, store);
  return 0;
}

static EVP_PKEY *pbgp_dsa_generate()
{
  EVP_PKEY *pkey = EVP_PKEY_new();

  if (RAND_status() != 1) {
    pbgp_fatal("RAND_status");
  }

  DSA *dsa = DSA_generate_parameters(1024, NULL, 0, NULL, NULL, NULL, NULL);
  if (!dsa) {
    pbgp_fatal("DSA_new");
  }

  if (DSA_generate_key(dsa) != 1) {
    pbgp_fatal("DSA_generate_key");
  }

  if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
    pbgp_fatal("EVP_PKEY_assign_DSA");
  }
  return pkey;
}

static int __rdsa_time(store_t *store, EVP_PKEY *evp, size_t signature_len, unsigned char *sig)
{
  size_t dsize = 0, ksize =0;
  store_key_t key = STORE_KEY_INIT;
  store_iterator_t *iterator = pbgp_store_iterator_open(store);

  int ret = pbgp_store_iterator_uget_next_size(iterator, &ksize, &dsize);
  ksize -= STORE_KEY_METADATA_LENGTH;

  unsigned char kbuf[ksize];
  memset (kbuf, 0, ksize);

  key.data = kbuf;
  key.dsize = sizeof(kbuf);

  unsigned char message[dsize];
  memset (message, 0, dsize);

  ret = pbgp_store_iterator_uget_next(iterator, &key, message, &dsize);

  ret = pbgp_rsa_verify(evp, (unsigned char *) message, dsize, sig, signature_len);

  if (1 != ret) {
    printf("pbgp_rsa_verify :: err");
  }

  pbgp_store_iterator_close(iterator);
  return 0;
}

/*
 *    microseconds = 1 / 1 000 000 sec.
 */
static double
__timediff(struct timeval startTime, struct timeval endTime)
{
  return (endTime.tv_sec * 1000000  + (endTime.tv_usec)) -
         (startTime.tv_sec * 1000000 + (startTime.tv_usec));
}

int main(void)
{
  store_key_t key = STORE_KEY_INIT;
  setup_params_t *setup = pbgp_setup_init(100);

  pbgp_setup_fill(setup);

  u_int32_t signer_id = 0;

  ibe_keypair_t *ibe_keypair = NULL;
  pbgp_ibe_keypair_init(setup, &ibe_keypair);
  pbgp_ibe_keypair_gen(setup, signer_id, ibe_keypair);

  ibe_signature_t *ibe_signature = NULL;
  pbgp_ibe_signature_clear(ibe_signature);
  pbgp_ibe_signature_init(setup, &ibe_signature);

  EVP_PKEY *rsa_evp = setup->rsa_evp;
  EVP_PKEY *dsa_evp = pbgp_dsa_generate();

  struct timeval start,end;
  gettimeofday(&start, NULL);

  ///////////////

  printf("rsa_sign,rsa_vrfy,dsa_sig,dsa_vrfy,ibe_sig,ibe_vrfy\n");

  int i = ITERATIONS;
  while (i--)
  {
    size_t msg_len = sizeof(u_int32_t) * i;
    unsigned char *sig, msg[msg_len];
    size_t signature_len = 0;

    store_t *store = pbgp_store_open(NULL);
    pbgp_store_put(store, STORE_KEY_SET_DATA(key, MESSAGE, signer_id), (void *) msg, msg_len);

    sig = xmalloc(EVP_PKEY_size(rsa_evp));
    gettimeofday(&start, NULL);
    signature_len = pbgp_rsa_usign(rsa_evp, msg, msg_len, sig);
    gettimeofday(&end, NULL);
    printf("%.0f,", __timediff(start, end));
    gettimeofday(&start, NULL);
    __rdsa_time(store, rsa_evp, signature_len, sig);
    gettimeofday(&end, NULL);
    printf("%.0f,", __timediff(start, end));
    xfree(sig);

    sig = xmalloc(EVP_PKEY_size(dsa_evp));
    gettimeofday(&start, NULL);
    signature_len = pbgp_rsa_usign(dsa_evp, msg, msg_len, sig);
    gettimeofday(&end, NULL);
    printf("%.0f,", __timediff(start, end));
    gettimeofday(&start, NULL);
    __rdsa_time(store, dsa_evp, signature_len, sig);
    gettimeofday(&end, NULL);
    printf("%.0f,", __timediff(start, end));
    xfree(sig);

    pbgp_ibe_signature_init(setup, &ibe_signature);
    gettimeofday(&start, NULL);
    pbgp_ibe_sign(setup, ibe_keypair, (const unsigned char *) msg, msg_len, ibe_signature);
    gettimeofday(&end, NULL);
    printf("%.0f,", __timediff(start, end));
    gettimeofday(&start, NULL);
    __ibe_time(setup, store, ibe_signature);
    gettimeofday(&end, NULL);
    printf("%.0f,", __timediff(start, end));
    pbgp_ibe_signature_clear(ibe_signature);

    printf("\n");
    pbgp_store_close(store);
  }

  ///////////////

  pbgp_ibe_keypair_clear(ibe_keypair);

  //pbgp_store_close(store);
  return (EXIT_SUCCESS);
}

