#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pbgp.h>

#include "bgpd.h"
#include "sec_ext.h"
#include "session.h"
#include "rde.h"

/* attribute parser specific makros */
#define UPD_READ(t, p, plen, n) \
	do { \
		memcpy(t, p, n); \
		p += n; \
		plen += n; \
	} while (0)

#define CHECK_FLAGS(s, t, m)	\
	(((s) & ~(ATTR_EXTLEN | (m))) == (t))

#define WR_ELEM(where,what,size)\
	memcpy(where,what,size);\
	where += size;\


/** Load cryptographic data into memory */
int
pi_init(char*pubca, char*parca, char*asenv, secext_t **ext) {
  u_int32_t	pathhashsize = 1024;
  secext_t        *pext = NULL;
  setup_params_t  *setup = NULL;
  action_data_t   *env = NULL;
  acc_t *acc = NULL;
  char *facc = "/etc/pi_bgp/last.acc"; //TODO: spostare come parametro

  int rv = 0;
  int i = 0;

  pext = malloc(sizeof (secext_t));
  if (!pext) {
    log_warn("pi_init :: malloc failed. Aborting.\n");
    return -1;
  }

  //setup load
  rv = setup_load (pubca, NULL, parca, &setup);
  if (rv < 0) {
    log_warn("pi_init :: setup_load failed. Aborting.\n");
    goto err1;
  }

  rv = join_init(&env, setup, NULL);
  if (rv < 0) {
    log_warn("pi_init :: can't initialize the join structure. Aborting.\n");
    goto err2;
  }

  rv = join_load(asenv, env);
  if (rv < 0) {
    log_warn("pi_init :: cannot load the join structure. Aborting.\n");
    goto err3;
  }

  //load the accumulator
  rv = acc_init(&acc, setup->pairing);
  if (rv < 0) {
    log_warn("pi_init :: cannot initialize the accumulator. Aborting. (%s)\n", strerror(errno));
    goto err3;
  }
  rv = acc_load(facc, acc);
  if (rv < 0) {
    log_warn("pi_init :: cannot load the accumulator structure. Aborting.\n");
    goto err4;
  }

  pext->setup     = setup;
  pext->data      = env;
  pext->acc		= acc;
  //set the structure for the caller
  *ext            = pext;


  rv = revokation_check(pext->acc, env->witness, NULL, env->ibk->id->asnum, pext->setup);
  if (rv != 0) {
    log_warnx("pi_verify_as_open:: Revocation check failed. %d have been revoked. \
				  Check if your accumulator is up to date", env->ibk->id);
    rv = VRFY_KO;
    goto err4;
  }
  log_warnx("pi_verify_as_open:: Verification SUCCESS for %d!", env->ibk->id->asnum);

  /* Initialize structure for aspath parsing */
  aspath_init(pathhashsize);

  return 0;


err4:
  acc_clear(acc);
err3:
  join_clear(env);
err2:
  setup_clear(setup);
err1:
  free(pext);

  return -1;
}

/**
 * Release data memory
 * Input: Destination Buffer, Local AS, Remote AS, Timestamp
 * Output: -1 on Error, 0 on succeful
 */
int
pi_clear(secext_t *ext) {
  if (ext) {
    if (ext->setup) {
      setup_clear(ext->setup);
    }
    /*if(ext->ibk) {
      ibe_keypair_clear(ext->ibk);
    }*/
    if (ext->data) {
      join_clear(ext->data);
    }
  }
  return 0;
}

/**
 * Get Timestamp for secure Open
 * Input: NULL
 * Output: timestamp (man 3 time)
 */
static inline time_t
pi_get_open_timestamp() {
  return time(NULL);
}

/**
 * Serialize Secure Open message
 * Input: Destination Buffer, Local AS, Remote AS
 * Output: -1 on Error, 0 on succeful
 */
int
pi_serialize_open(u_int8_t** sec_buf, u_int32_t local_asn, u_int32_t remote_asn, secext_t* pi_setup) {
  int         sec_buf_len     = 0;
  u_int8_t    *cryptobuf      = NULL;
  u_int8_t    *witnessbuf     = NULL;
  u_int8_t    *p              = NULL;
  u_int32_t   witnesslen      = 0;
  int         cryptobuflen    = 0;
  int         offset          = 0;
  int         rv              = 0;
  time_t      timestamp       = 0;

  ibe_signature_t         *signature  = NULL;
  ibe_keypair_t           *ibk        = NULL;

  /** Get Current Timestamp */
  timestamp = pi_get_open_timestamp();

  /** SERIALIZE WITNESS */
  witnesslen = witness_serialize( &witnessbuf, pi_setup->data->witness);
  if (witnesslen <= 0) {
    log_warn("pi_serialize_open::witness_serialize::Aborting.");
    return -1;
  }

  /** Fill destination buffer with ORIG_AS, DEST_AS, TIMESTAMP */
  sec_buf_len += (2 * sizeof (u_int32_t));     // Adding space for Source and Destination AS NUM
  sec_buf_len += (sizeof (time_t));            // Adding space for Timestamp
  sec_buf_len += (sizeof (witnesslen));        // Adding space witness size
  sec_buf_len += witnesslen;                  // Adding space for Witness

  *sec_buf = (u_int8_t*) malloc( sec_buf_len );

  if (!*sec_buf) {
    log_warn("pi_serialize_open :: malloc failed. Aborting.");
    goto err1;
  }

  p = *sec_buf;

  bzero(p, sec_buf_len);

  memcpy(p + offset, &local_asn, sizeof (local_asn) );
  offset += sizeof (local_asn);

  memcpy(p + offset, &remote_asn, sizeof (remote_asn) );
  offset += sizeof (remote_asn);

  memcpy(p + offset, &timestamp, sizeof (timestamp) );
  offset += sizeof (timestamp);

  memcpy(p + offset, &witnesslen, sizeof (witnesslen) );
  offset += sizeof (witnesslen);

  memcpy(p + offset, witnessbuf, witnesslen );
  offset += witnesslen;


  /* Begin Signature Procedure */
  ibk = pi_setup->data->ibk;
  rv = ibe_signature_init(&signature, pi_setup->setup);
  if (rv < 0) {
    log_warn("pi_serialize_open::ibe_signature_init::Aborting.");
    return -1;
  }

  /* Sign Message m */
  ibe_sign(signature, ibk, p, sec_buf_len);

  cryptobuflen = ibe_signature_serialize(&cryptobuf, signature);
  if ( cryptobuflen <= 0  ) {
    log_warn("pi_serialize_open :: ibe_signature_serialize failed. Aborting.");
    goto err1;
  }

  /* Serialize Signature */
  *sec_buf = realloc(*sec_buf, sec_buf_len + cryptobuflen);
  if (!*sec_buf) {
    log_warn("pi_serialize_open::ibe_signature_init::Aborting.");
    goto err2;
  }
  sec_buf_len += cryptobuflen;
  p = *sec_buf;

  bzero(p + offset, cryptobuflen);
  memcpy(p + offset, cryptobuf, cryptobuflen );
  offset += cryptobuflen;

  ibe_signature_clear(signature);

  return sec_buf_len;

err2:
  if (sec_buf) free(sec_buf);
err1:
  if (witnessbuf) free(witnessbuf);
  ibe_signature_clear(signature);
  return -1;

}

/**
 * DESerialize Secure Open message
 * Input:
 * Output:
 */
int
pi_deserialize_open(struct msg_sec_open** dst, u_int8_t *sec_buffer, secext_t *pi_setup) {
  struct msg_sec_open     *ret        = NULL;
  int                     offset = 0 ;
  uint8_t *bwit = NULL;

  // Controllare la sturttura per verificare l'allocazione
  ret = malloc( sizeof (struct msg_sec_open) );
  if ( ! ret ) {
    log_warn("pi_deserialize_open::malloc error");
    goto err;
  }
  bzero(ret, sizeof (struct msg_sec_open) );

  memcpy(&(ret->as_orig), sec_buffer + offset, sizeof (u_int32_t));
  offset += sizeof (u_int32_t);

  memcpy(&(ret->as_dest), sec_buffer + offset, sizeof (u_int32_t));
  offset += sizeof (u_int32_t);

  memcpy(&(ret->ts_orig), sec_buffer + offset, sizeof (time_t));
  offset += sizeof (time_t);

  memcpy(&(ret->witnesslen), sec_buffer + offset, sizeof (u_int32_t));
  offset += sizeof (u_int32_t);

  if ( ret->witnesslen == 0 ) {
    log_warn("pi_deserialize_open::witnesss lenght error.");
    goto err;
  }

  //WITNESS init e deserialize
  bwit = (uint8_t * ) malloc (ret->witnesslen);
  if (!bwit) {
    log_warn("pi_deserialize_open:: bwit malloc %s", strerror(errno));
    goto err;
  }
  bzero(bwit, ret->witnesslen);
  memcpy(bwit, sec_buffer + offset, ret->witnesslen);
  witness_init(ret->witness, pi_setup->setup->pairing);
  witness_deserialize(ret->witness, bwit);
  free(bwit);

  offset += ret->witnesslen;

  ibe_signature_init(&(ret->signature), pi_setup->setup);
  ibe_signature_deserialize( ret->signature, sec_buffer + offset);

  *dst = ret;

  return offset;

err:
  if (ret)
    free( ret );

  return 0;
}

/**
 * Verify OpenMsg
 * Input: Peer reference, Secure (OPEN) message
 * Output: TRUE or FALSE
 */
int
pi_verify_as_open(u_int8_t* sec_msg, int datalen, secext_t *pi_setup) {
  struct msg_sec_open *sec_open   = NULL;
  int                 sign_offset_init = 0;
  int                 ret = 0;

  if (! pi_deserialize_open(&sec_open, sec_msg, pi_setup) ) {
    log_warnx("pi_verify_as_open:: error");
    return VRFY_KO;
  }

  /** Evaluate start point of signature */
  sign_offset_init = ( 3 * sizeof (u_int32_t) ) + sizeof (time_t) + sec_open->witnesslen;

  ret = ibe_vrfy_single(sec_open->signature, pi_setup->setup, sec_msg , sign_offset_init);
  if (ret == SIGN_INVALID) {
    ret = VRFY_KO;
    goto out;
  }

  log_warnx("pi_verify_as_open:: Running revocation check for %d....", sec_open->as_orig);
  ret = revokation_check(pi_setup->acc, sec_open->witness, NULL, sec_open->as_orig, pi_setup->setup);
  if (ret != 0) {
    log_warnx("pi_verify_as_open:: Revocation check failed. %d have been revoked. \
        		  Check if your accumulator is up to date", sec_open->as_orig);
    ret = VRFY_KO;
    goto out;
  }
  log_warnx("pi_verify_as_open:: Verification SUCCESS for %d!", sec_open->as_orig);

  ret = VRFY_OK;
out:
  //TODO:CLEANUP DI SERIALIZE!!!
  return ret;
}

struct rde_aspath *
pi_get_aspath(void *update, int len, int attrpath_len, struct peer *s_peer ) {
  int as4byte_flag = 0;
  int acc_flag = 0;
  int plen = 0 ;
  u_int32_t	 tmp32 = 0;
  u_int32_t	 tmp16 = 0;
  u_int16_t	 attr_len = 0;
  u_int16_t	 nlen = 0;
  u_int8_t	 flags = 0;
  u_int8_t	 type = 0;
  u_int8_t	 tmp8 = 0;
  u_char		*npath = NULL;

  struct rde_aspath *asp = NULL;
  //set the cursor for the update message
  uint8_t *p = (uint8_t*) update;

  asp = path_get();

  while (len > 0) {
    as4byte_flag = 0;
    plen = 0;

    UPD_READ(&flags, p, plen, 1);
    UPD_READ(&type, p, plen, 1);

    if (flags & ATTR_EXTLEN) {
      UPD_READ(&attr_len, p, plen, 2);
      attr_len = ntohs(attr_len);
    }
    else {
      UPD_READ(&tmp8, p, plen, 1);
      attr_len = tmp8;
    }

    //Warning: case statements are not ordered!!
    switch (type) {
      case ATTR_UNDEF:
        /* ignore and drop path attributes with a type code of 0 */
        break;
      case ATTR_ORIGIN:
        UPD_READ(&tmp8, p, plen, 1);
        acc_flag |= F_ATTR_ORIGIN;
        break;
        // Don't need any verification here
        // Assume that the update's code have already done it
      case ATTR_ASPATH:
        as4byte_flag = (s_peer->capa.ann.as4byte && s_peer->capa.peer.as4byte);

        if (aspath_verify(p, attr_len, as4byte_flag) != 0) {
          log_warnx("aspath_verify()");
          return NULL;
        }

        if (as4byte_flag) {
          npath = p;
          nlen = attr_len;
        }
        else {
          npath = aspath_inflate(p, attr_len, &nlen);
        }
        acc_flag |= F_ATTR_ASPATH;

        asp->aspath = aspath_get(npath, nlen);
        if (npath != p)
          free(npath);

        plen += attr_len;
        p += attr_len;
        break;
      case ATTR_NEXTHOP:
      case ATTR_MED:
        UPD_READ(&tmp32, p, plen, 4);
        break;

      case ATTR_LOCALPREF:
        if (s_peer->conf.ebgp) {
          // ignore local-pref attr on non ibgp peers
          plen += 4;
          p += attr_len;
          break;
        }

        UPD_READ(&tmp32, p, plen, 4);
        break;
      case ATTR_AGGREGATOR:
        if (!as4byte_flag) {
          UPD_READ(&tmp16, p, plen, 2);
          UPD_READ(&tmp32, p, plen, 4);

          break;
        }
        break;

      case ATTR_MP_REACH_NLRI:
      case ATTR_MP_UNREACH_NLRI:
        plen += attr_len;
        p += attr_len;
        break;
      case ATTR_ATOMIC_AGGREGATE:
      case ATTR_COMMUNITIES:
      case ATTR_ORIGINATOR_ID:
      case ATTR_CLUSTER_LIST:
      case ATTR_AS4_AGGREGATOR:
      case ATTR_AS4_PATH:
        break;
      default:
        log_warnx("An unknown as type found! (%d)", type);
        plen += attr_len;
        p += attr_len;
        break;
    }

    if (plen < 0)
      break;
    len -= plen;
  }

  return asp;
}

int
pi_vrfy_update(u_char *updatesignmsg, size_t lenvrf , void *update, size_t uplen, struct peer *s_peer , secext_t* pi_setup) {
  ibe_signature_t *sign = NULL;
  int withdrawn_len = 0 ,
    attrpath_len = 0,
    len = 0;
  struct rde_aspath *asp = NULL;

  uint8_t *p = NULL;

  ibe_signature_init(&sign, pi_setup->setup);
  ibe_signature_deserialize( sign, updatesignmsg);

  //set the cursor for the update message
  p = (uint8_t*) update;
  //move the cursor to the path attribute
  memcpy(&len, p, 2);
  withdrawn_len = ntohs(len);
  p += 2 + withdrawn_len;
  memcpy(&len, p, 2);
  attrpath_len = len = ntohs(len);
  p += 2;

  if (attrpath_len != 0) { /* 0 = no NLRI information in this message */
    /* Extract the aspath from the update */
    asp = pi_get_aspath(p, len, attrpath_len, s_peer);

    if (asp == NULL || asp->aspath == NULL) {
      log_warnx("pi_sign_update() :: Unable to get ASPath ");
      return SIGN_INVALID;
    }
  }

  return ibe_vrfy_single(sign, pi_setup->setup, asp->aspath->data, asp->aspath->len);
}

/**
 * Input: update message
 * Output: serialized update verification message
 */
int
pi_sign_update(uint8_t **vrfupd, void *update, size_t datalen, struct peer *s_peer , secext_t* pi_setup) {
  int rv = 0, pos = 0 ;
  int len = 0, tlen = 0;
  int i = 0, ii = 0;
  int withdrawn_len = 0 ,
    attrpath_len = 0,
    nlri_len = 0;
  int vrfupd_size = 0;
  struct rde_aspath *asp = NULL;

  uint8_t *p = NULL;
  uint8_t *asp_curs = NULL;
  uint8_t *vrfp = NULL;
  uint16_t    pfix_count = 0;
  uint16_t sign_size = 0;
  ibe_signature_t         *signature  = NULL;
  ibe_keypair_t           *ibk        = NULL;

  u_int8_t    *cryptobuf      = NULL;
  int         cryptobuflen    = 0;

  //set the cursor for the update message
  p = (uint8_t*) update;
  //move the cursor to the path attribute
  memcpy(&len, p, 2);
  withdrawn_len = ntohs(len);
  p += 2 + withdrawn_len;
  memcpy(&len, p, 2);
  attrpath_len = len = ntohs(len);
  p += 2;
  nlri_len = tlen = datalen - (4 + withdrawn_len + attrpath_len);

  if (attrpath_len != 0) { /* 0 = no NLRI information in this message */
    /* Extract the aspath from the update */
    asp = pi_get_aspath(p, len, attrpath_len, s_peer);

    if (asp == NULL || asp->aspath == NULL) {
      log_warnx("pi_sign_update() :: Unable to get ASPath ");
      goto err;
    }

    /* Move the cursor to the begin of NLRI attributes */
    p += attrpath_len;
    len = nlri_len;

    /* Calculate the number of announced prefixes */
    while (tlen > 0 ) {
      struct bgpd_addr prefix;
      u_int8_t prefixlen = 0;
      uint tpos = 0;

      tpos = rde_update_get_prefix(p + pos, nlri_len, &prefix, &prefixlen);
      pfix_count++;

      tlen -= tpos;
      pos += tpos;
    }


    /* Begin Signature Procedure */
    ibk = pi_setup->data->ibk;
    rv = ibe_signature_init(&signature, pi_setup->setup);
    if (rv < 0) {
      log_warn("pi_sign_update::ibe_signature_init::Aborting.");
      return -1;
    }

    //TODO: cooncatenare firme degli update per ogni prefisso!!!!
    for (ii = 0; ii < pfix_count; ii++)
      /* Sign Message m */
      ibe_sign(signature, ibk, asp->aspath->data, asp->aspath->len);

    cryptobuflen = ibe_signature_serialize(&cryptobuf, signature);
    if ( cryptobuflen <= 0  ) {
      log_warn("pi_sign_update :: ibe_signature_serialize failed. Aborting.");
      goto err;
    }

    *vrfupd = cryptobuf;

  }


  return cryptobuflen;

  //XXX: set different labels for cleanup!!!!!!!!!
err:
  return -1;
}
