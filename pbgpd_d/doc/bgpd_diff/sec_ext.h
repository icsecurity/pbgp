#ifndef PI_BGP_SEC_EXT
#define PI_BGP_SEC_EXT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbgp.h>

#include "session.h"
#include "bgpd.h"

enum {VRFY_KO, VRFY_OK};
#define MAX_ASPATH_LEN (13)


struct sec_ext {
    setup_params_t *setup;
    action_data_t *data;
    acc_t *acc;

};
typedef struct sec_ext secext_t;

/* Message for the secure open */
struct msg_sec_open {
    u_int32_t       as_orig;
    u_int32_t       as_dest;
    time_t          ts_orig;
    u_int32_t       witnesslen;
    element_t       witness;
    ibe_signature_t *signature;
};


/*** Crypto Data resources allocation/deallocation  ***/
int
pi_init(char*pubca, char*parca, char*asenv, secext_t **ext);

int
pi_clear(secext_t*);
/*** Crypto Data resources allocation/deallocation  ***/

inline time_t
pi_get_open_timestamp(void);

/*** OPEN ***/
int
pi_serialize_open(u_int8_t** sec_buf, u_int32_t local_asn, u_int32_t remote_asn, secext_t* pi_setup);

int
pi_deserialize_open(struct msg_sec_open**, u_int8_t *, secext_t *pi_setup);

int
pi_verify_as_open(u_int8_t*, int, secext_t*);

/*** UDATE ***/

/*
 * Sign the update message pointed by $update parameter. The output message is a list of N blocks
 * of timestamps where each block is composed by a fixed amount of (k)-timestamps where (k-1) is the
 * aspath length and the +1 is for the RIR timestamp. Each list of timestamps is followed by the
 * IBE signature of the block.
 *
 * output messagge format:
 * -------------------------------------------------------------------------------------
 * | number of blocks || ts11 || ... || ts1k || signature_size || signature(B1) || ...  |
 * 	------------------------------------------------------------------------------------
 *					   |________________________________________________________|
 *											        |
 *								                  Block 1
 *
 * number of blocks is an uint16_t; timestamps are time_t; signature_size is uint16_t
 *
 * @return
 * 	A vector of serialized signature and timestamps into $output parameter
 * 	If no errors return the size of the $output in bytes, -1 otherwise
 */
int
pi_sign_update(uint8_t **output, void *update, size_t datalen,struct peer *s_peer ,secext_t* pi_setup);

int
pi_vrfy_update(u_char *updatesignmsg, size_t len ,void *update, size_t uplen,struct peer *s_peer ,secext_t* pi_setup);



#endif
