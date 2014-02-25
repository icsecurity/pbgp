/**
 *
 * gcc -O3 -g -ggdb  -Wall -L/usr/local/lib main.c -I/usr/local/include/pbgp -I/usr/local/include -I/usr/local/include/db4 -lpbgp -o main
 *
 */
#include <pbgp.h>

#define SETUP_PATH          "/etc/pbgp"

#define STORE_SETUP_PUB     "store_setup_pub"
#define STORE_SETUP_PRV     "store_setup_prv"
#define STORE_GLB_ADDED     "store_glb_added"
#define STORE_GLB_REVOKED   "store_glb_revoked"
#define STORE_IBE           "store_ibe"
#define STORE_EPOCH         "store_epoch"

int
main(int argc, char *argv[])
{
  if (chdir(SETUP_PATH)) {
    perror(":: try to mkdir " SETUP_PATH);
    return EXIT_FAILURE;
  }

  struct stat sstat;

  short init_setup = stat(STORE_SETUP_PUB, &sstat),
        init_keys  = stat(STORE_IBE, &sstat)
  ;

  store_t
          // To send to AS
          *store_setup_pub    = pbgp_store_open(STORE_SETUP_PUB),
          *store_epoch        = pbgp_store_open(STORE_EPOCH),

          // CA only storages
          *store_setup_prv    = pbgp_store_open(STORE_SETUP_PRV),
          *store_glb_added    = pbgp_store_open(STORE_GLB_ADDED),
          *store_glb_revoked  = pbgp_store_open(STORE_GLB_REVOKED),
          *store_ibe          = pbgp_store_open(STORE_IBE),

          // Temporary storages, used for inputs
          *store_added        = pbgp_store_open(NULL),
          *store_revoked      = pbgp_store_open(NULL)
  ;

  // epoch added / revoked AS with prefixes

  setup_params_t *setup = pbgp_setup_init(USHRT_MAX);

  if (init_setup) {
    pbgp_setup_fill(setup);
    pbgp_setup_save_privkey(setup, store_setup_prv);
    pbgp_setup_save_pubkey(setup, store_setup_pub);
  }
  else {
    pbgp_setup_load_pubkey(setup, store_setup_pub);
    // the following will overwrite setup->rsa_key
    pbgp_setup_load_privkey(setup, store_setup_prv);
  }
  pbgp_store_close(store_setup_pub);
  pbgp_store_close(store_setup_prv);

  ibe_keypair_t *ibe_keypair;
  pbgp_ibe_keypair_init(setup, &ibe_keypair);

  if (init_keys) {
    pbgp_ibe_keypair_gen(setup, 0, ibe_keypair);
    pbgp_ibe_save_keypair(store_ibe, ibe_keypair);
  }
  else {
    pbgp_ibe_load_keypair(store_ibe, ibe_keypair);
  }
  pbgp_store_close(store_ibe);

  // Generate join envelope for AS
  uint32_t as = 65535;
  while (as--)
  {
    const char cidr_path[128];

    sprintf(cidr_path, "%d.cidr", as);

    FILE * fp = fopen(cidr_path, "r");
    if (fp == NULL) {
      continue ;
    }

    char *store_name = pbgp_generate_envelope_storage_name(as);

    pbgp_debug("env :: %s", store_name);

    store_t *store_cidr_in  = pbgp_store_open(NULL),
            *store_cidr_out = pbgp_store_open(store_name);

    // Parse prefixes and store into cidr_in

    char pfxlist[1024];

    while (fgets(pfxlist, sizeof(pfxlist), fp) != NULL)
    {
      pfxlist[strlen(pfxlist) - 1] = 0;
      pbgp_debug("\tprefix :: %s", pfxlist);
      pbgp_store_parsed_cidr(as, pfxlist, store_cidr_in);
    }

    // Current AS num must not be into glb_added / glb_revoked
    //  or epoch added / revoked !

    // - creates signed witness for this asnum (on empty list of added id)
    // - updates signed epoch asnum storages (store_added / store_revoked)
    // - calls join_save and write the signed envelope to storage (disk)
    // - ibe_keypair (CA) needed only to sign prefix list
    pbgp_action_join(setup,
                     ibe_keypair,
                     as,
                     store_cidr_in,
                     store_cidr_out,
                     store_added,
                     store_revoked,
                     store_glb_added,
                     store_glb_revoked
    );

    // Generate and insert AS private ibe key into envelope
    ibe_keypair_t *client_ibe_keypair;
    pbgp_ibe_keypair_init(setup, &client_ibe_keypair);
    pbgp_ibe_keypair_gen(setup, as, client_ibe_keypair);
    pbgp_ibe_save_keypair(store_cidr_out, client_ibe_keypair);

    pbgp_store_close(store_cidr_out);
    pbgp_store_close(store_cidr_in);
    xfree(store_name);

    pbgp_ibe_keypair_clear(client_ibe_keypair);
    fclose(fp);
  }

  // Only at this point we have the 'real' filled
  // store_added / store_revoked epoch storages.
  // Client *must* update its witness according to these 'new'
  // added / revoked list of as numbers (inside join loop).
  // We send these lists within the epoch (accumulator) storage

  // updates and saves signed accumulator
  // updates CA permanent global storages
  // calls pbgp_epoch_save
  // stores added / revoked lists into permanent store_epoch
  pbgp_epoch_claim_new(setup,
                       store_epoch,
                       store_added,
                       store_revoked,
                       store_glb_added,
                       store_glb_revoked
  );
  pbgp_store_close(store_epoch);

  pbgp_store_close(store_glb_added);
  pbgp_store_close(store_glb_revoked);

  pbgp_store_close(store_added);
  pbgp_store_close(store_revoked);

  return EXIT_SUCCESS;
}
