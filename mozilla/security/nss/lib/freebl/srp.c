/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Initial Developer of the Original Code is
 * Steffen Schulz - pepe (at) cbg.dyndns.org
 *
 * Portions created by the Initial Developer are Copyright (C) 2007
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/*
 * This file implements the core SRP algorithms described in rfc 5054
 * for enabling secure password based authentication in TLS via SRP.
 *
 * See also:
 * Wu, T., "SRP-6: Improvements and Refinements to the Secure
 *                 Remote Password Protocol", October 2002,
 *                 <http://srp.stanford.edu/srp6.ps>.
 */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "secerr.h"
#include "blapi.h"
#include "mpi.h"
#include "secmpi.h"
#include "secitem.h"
#include "keythi.h"
#include "plbase64.h"

#include "srp_groups.h"

/* length of srp secret keys in byte */
#define SRP_SECRET_KEY_LEN 32


/* check if (N,g) are among the known-good group params */
static SECStatus check_srp_group(const mp_int *N, const mp_int *g) {
    int i;
    char *N_str;
    char *g_str;
    mp_err err;
    SECStatus rv = SECFailure;

    N_str = PORT_Alloc(mp_radix_size(N, 16));
    g_str = PORT_Alloc(mp_radix_size(g, 16));

    CHECK_MPI_OK(mp_toradix(N, N_str, 16));
    CHECK_MPI_OK(mp_toradix(g, g_str, 16));

    /* compare bytes and length */
    for ( i=0; i < SRP_KNOWN_GROUPS; i++)
        if (PORT_Strcmp(N_str, known_srp_groups[i].modulus))
            if (PORT_Strcmp(g_str, known_srp_groups[i].generator)) {
                rv = SECSuccess;
                break;
            }

    if (rv !=SECSuccess)
        PORT_SetError(SEC_ERROR_SRP_UNSUPPORTED_GROUP);

cleanup:
    PORT_Free(N_str);
    PORT_Free(g_str);
    if (err) {
    	MP_TO_SEC_ERROR(err);
	    rv = SECFailure;
    }

    return rv;
}

/* check if B%N = 0  -> trapdoor */
static SECStatus srp_backdoor_check(const mp_int *N, const mp_int *B) {

    mp_int  res;
    mp_err  err;

    CHECK_MPI_OK(mp_init(&res));
    CHECK_MPI_OK(mp_mod(B, N, &res));
    

    if ( mp_cmp_z(&res) == 0) {
        PORT_SetError(SEC_ERROR_SRP_ILLEGAL_PARAMETER);
	    return SECFailure;
    }
cleanup:
    mp_clear(&res);
    if (err) {
    	MP_TO_SEC_ERROR(err);
	    return SECFailure;
    }
    return SECSuccess;
}

/* SRP_DeriveKey computes common key 'pms'
 *
 * The pre-master secret is calculated as follows:
 *
 *   u = SHA1(PAD(A) | PAD(B))
 *   k = SHA1(N | PAD(g))
 * pms = (A * v^u) ^ b % N
 *
 * PAD() left-paddes with \0 until length of N
 */

SECStatus SRP_ServerDerive(SRPPrivateKey *prvKey, SRPDeriveParams *srp,
                                                SECItem *pms) {
    mp_int  mp_pms, mp_res;
    mp_int	mp_A, mp_b, mp_v;
    mp_int  mp_N, mp_g, mp_u, mp_k;
    SECItem *it_u, *it_k;
    unsigned char   *zero;
    unsigned int     len   = srp->N.len;
    SHA1Context     *ctx   = SHA1_NewContext();
    SECStatus        rv    = SECFailure;
    mp_err           err   = MP_OKAY;
    
    CHECK_MPI_OK(mp_init(&mp_N));
    CHECK_MPI_OK(mp_init(&mp_g));
    CHECK_MPI_OK(mp_init(&mp_u));
    CHECK_MPI_OK(mp_init(&mp_k));
    CHECK_MPI_OK(mp_init(&mp_v));
    CHECK_MPI_OK(mp_init(&mp_b));
    CHECK_MPI_OK(mp_init(&mp_A));
    CHECK_MPI_OK(mp_init(&mp_res));
    CHECK_MPI_OK(mp_init(&mp_pms));

    zero = PORT_ZAlloc(len);
    it_u = SECITEM_AllocItem(NULL, NULL, SHA1_LENGTH);
    it_k = SECITEM_AllocItem(NULL, NULL, SHA1_LENGTH);

    if (!zero || !it_u || !it_k) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        goto cleanup;
    }
    
    /*  u = SHA1( PAD(A) | PAD(B) ) */
    SHA1_Begin(ctx);
    SHA1_Update(ctx, zero, len - srp->ppub.len);
    SHA1_Update(ctx, srp->ppub.data, srp->ppub.len);
    SHA1_Update(ctx, zero, len - prvKey->pubKey.len);
    SHA1_Update(ctx, prvKey->pubKey.data, prvKey->pubKey.len);
    SHA1_End(ctx, it_u->data, &it_u->len, SHA1_LENGTH);
    
    /*  k = SHA1( N | PAD(g) ) */
    SHA1_Begin(ctx);
    SHA1_Update(ctx, srp->N.data, srp->N.len);
    SHA1_Update(ctx, zero, len - srp->g.len);
    SHA1_Update(ctx, srp->g.data, srp->g.len);
    SHA1_End(ctx, it_k->data, &it_k->len, SHA1_LENGTH);
    
    /* 
     * calculate pms = (A * v^u) ^ b % N
     */

    SECITEM_TO_MPINT(*it_u,    &mp_u);
    SECITEM_TO_MPINT(*it_k,    &mp_k);
    SECITEM_TO_MPINT(srp->N,   &mp_N);
    SECITEM_TO_MPINT(srp->g,   &mp_g);
    SECITEM_TO_MPINT(srp->ppub,&mp_A);
    SECITEM_TO_MPINT(prvKey->secret, &mp_v);
    SECITEM_TO_MPINT(prvKey->prvKey, &mp_b);

    CHECK_MPI_OK(mp_exptmod(&mp_v, &mp_u, &mp_N, &mp_res));
    CHECK_MPI_OK(mp_mulmod(&mp_A, &mp_res, &mp_N, &mp_res));
    CHECK_MPI_OK(mp_exptmod(&mp_res, &mp_b, &mp_N, &mp_pms));

    MPINT_TO_SECITEM(&mp_pms, pms, NULL);
    
    rv = SECSuccess;
cleanup:
    PORT_Free(zero);
    SECITEM_FreeItem(it_u, PR_TRUE);
    SECITEM_FreeItem(it_k, PR_TRUE);
    SHA1_DestroyContext(ctx, PR_TRUE);
    mp_clear(&mp_N);
    mp_clear(&mp_g);
    mp_clear(&mp_b);
    mp_clear(&mp_A);
    mp_clear(&mp_k);
    mp_clear(&mp_u);
    mp_clear(&mp_v);
    mp_clear(&mp_pms);
    mp_clear(&mp_res);
    if (err) {
    	MP_TO_SEC_ERROR(err);
	    rv = SECFailure;
    }
    return rv;
}

/* SRP_ClientDerive, computes common key 'pms'
 *
 * The pre-master secret is calculated as follows:
 *
 *   u = SHA1(PAD(A) | PAD(B))
 *   k = SHA1(N | PAD(g))
 *   x = SHA1(s | SHA1(I | ":" | P))
 * pms = (B - (k * g^x)) ^ (a + (u * x)) % N
 *
 * PAD() left-paddes with \0 until length of N
 */
SECStatus SRP_ClientDerive(SRPPrivateKey *prvKey, SRPDeriveParams *srp,
                                                SECItem * pms) {

    /* mp_int use pointers*/
    unsigned char *zero = NULL;
    mp_int  mp_pms, mp_res1, mp_res2;
    mp_int	mp_B, mp_a, mp_A;
    mp_int  mp_N,   mp_g,	mp_u;
    mp_int	mp_k,   mp_x;
    mp_err  err = MP_OKAY;
    SECItem *it_u = NULL;
    SECItem *it_k = NULL;
    SECItem *it_x = NULL;
    SHA1Context   *ctx   = SHA1_NewContext();
    unsigned int   len   = srp->N.len;
    SECStatus rv = SECFailure;
    
    if (prvKey->secret.len == 0) {
        /* XXX this error is probably meant for token passwords
         * anyway, we use it to show missing password in bypass mode*/
        PORT_SetError(SEC_ERROR_BAD_PASSWORD);
        return SECFailure;
    }

    CHECK_MPI_OK(mp_init(&mp_N));
    CHECK_MPI_OK(mp_init(&mp_g));
    CHECK_MPI_OK(mp_init(&mp_u));
    CHECK_MPI_OK(mp_init(&mp_k));
    CHECK_MPI_OK(mp_init(&mp_x));
    CHECK_MPI_OK(mp_init(&mp_A));
    CHECK_MPI_OK(mp_init(&mp_a));
    CHECK_MPI_OK(mp_init(&mp_B));
    CHECK_MPI_OK(mp_init(&mp_res1));
    CHECK_MPI_OK(mp_init(&mp_res2));
    CHECK_MPI_OK(mp_init(&mp_pms));
    
    /* check server-supplied parameters */
    SECITEM_TO_MPINT(srp->N,   &mp_N);
    SECITEM_TO_MPINT(srp->g,   &mp_g);
    SECITEM_TO_MPINT(srp->ppub,&mp_B);

    CHECK_SEC_OK(srp_backdoor_check(&mp_N, &mp_B));

    /*
     * create hashed variables u, k, x
     */

    zero = PORT_ZAlloc(len);
    it_u = SECITEM_AllocItem(NULL, NULL, SHA1_LENGTH);
    it_k = SECITEM_AllocItem(NULL, NULL, SHA1_LENGTH);
    it_x = SECITEM_AllocItem(NULL, NULL, SHA1_LENGTH);

    if (!zero || !it_u || !it_k || !it_x) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        goto cleanup;
    }

    /*  u = SHA1( PAD(A) | PAD(B) ) */
    SHA1_Begin(ctx);
    SHA1_Update(ctx, zero, len - prvKey->pubKey.len);
    SHA1_Update(ctx, prvKey->pubKey.data, prvKey->pubKey.len);
    SHA1_Update(ctx, zero, len - srp->ppub.len);
    SHA1_Update(ctx, srp->ppub.data, srp->ppub.len);
    SHA1_End(ctx, it_u->data, &it_u->len, SHA1_LENGTH);
    
    /*  k = SHA1( N | PAD(g) ) */
    SHA1_Begin(ctx);
    SHA1_Update(ctx, srp->N.data, srp->N.len);
    SHA1_Update(ctx, zero, len - srp->g.len);
    SHA1_Update(ctx, srp->g.data, srp->g.len);
    SHA1_End(ctx, it_k->data, &it_k->len, SHA1_LENGTH);
    
    /*  x = SHA1(s | SHA1(I | ":" | P)) */
    SHA1_Begin(ctx);
    SHA1_Update(ctx, srp->u.data, srp->u.len);
    SHA1_Update(ctx,(unsigned char *)":",1);
    SHA1_Update(ctx, prvKey->secret.data, prvKey->secret.len);
    SHA1_End(ctx, it_x->data, &it_x->len, SHA1_LENGTH);
    
    SHA1_Begin(ctx);
    SHA1_Update(ctx, srp->s.data, srp->s.len);
    SHA1_Update(ctx, it_x->data, it_x->len);
    SHA1_End(ctx, it_x->data, &it_x->len, SHA1_LENGTH);

    /*
     * compute pms = (B - (k * g^x)) ^ (a + (u * x)) % N
     */
    
    SECITEM_TO_MPINT(*it_u, &mp_u);
    SECITEM_TO_MPINT(*it_k, &mp_k);
    SECITEM_TO_MPINT(*it_x, &mp_x);
    SECITEM_TO_MPINT(prvKey->prvKey, &mp_a);

    CHECK_MPI_OK(mp_exptmod(&mp_g,&mp_x,&mp_N,&mp_res2));
    CHECK_MPI_OK(mp_mulmod(&mp_res2,&mp_k,&mp_N,&mp_res2));
    CHECK_MPI_OK(mp_submod(&mp_B,&mp_res2,&mp_N,&mp_res2));
    CHECK_MPI_OK(mp_mul(&mp_u, &mp_x, &mp_res1));
    CHECK_MPI_OK(mp_add(&mp_res1,&mp_a,&mp_res1));
    CHECK_MPI_OK(mp_exptmod(&mp_res2,&mp_res1,&mp_N,&mp_pms));

    MPINT_TO_SECITEM(&mp_pms, pms, NULL);
    rv = SECSuccess;
cleanup:
    PORT_Free(zero);
    SECITEM_FreeItem(it_u, PR_TRUE);
    SECITEM_FreeItem(it_k, PR_TRUE);
    SECITEM_FreeItem(it_x, PR_TRUE);
    SHA1_DestroyContext(ctx, PR_TRUE);
    mp_clear(&mp_N);
    mp_clear(&mp_g);
    mp_clear(&mp_a);
    mp_clear(&mp_A);
    mp_clear(&mp_B);
    mp_clear(&mp_k);
    mp_clear(&mp_u);
    mp_clear(&mp_x);
    mp_clear(&mp_pms);
    mp_clear(&mp_res1);
    mp_clear(&mp_res2);
    if (err) {
    	MP_TO_SEC_ERROR(err);
	    rv = SECFailure;
    }
    return rv;
}


/* SRP_NewServerKeyPair
 * creates a new srp key pair for the server
 *
 * k = SHA1(N | PAD(g))
 * pubKey = k*v + g^prvKey % N 
 */
SECStatus SRP_NewServerKeyPair(SRPPrivateKey **prvKey, SRPKeyPairParams *srp) {

    mp_int	mp_N, mp_g, mp_pub, mp_prv, mp_k, mp_v, mp_res;
    PRArenaPool *arena;
    SRPPrivateKey *key;
    SECItem         *it_k;
    unsigned char   *zero;
    mp_err           err = MP_OKAY;
    SECStatus        rv  = SECFailure;
    SHA1Context     *ctx = SHA1_NewContext();
    
    
    if (!srp || !prvKey) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE);
    if (!arena) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    key = (SRPPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(SRPPrivateKey));
    if (!key) {
        PORT_FreeArena(arena, PR_TRUE);
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    key->arena = arena;

    /* prv=rand() */
    SECITEM_AllocItem(arena, &key->prvKey, SRP_SECRET_KEY_LEN);
    rv = RNG_GenerateGlobalRandomBytes(key->prvKey.data, key->prvKey.len);
    
    if (rv != SECSuccess || !(&key->prvKey)) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        PORT_FreeArena(arena, PR_TRUE);
        return SECFailure;
    }

    it_k = SECITEM_AllocItem(NULL, NULL, SHA1_LENGTH);
    zero = PORT_ZAlloc(srp->N.len);

    if (!zero || !it_k) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        goto cleanup;
    }

    /*  k = SHA1( N | PAD(g) ) */
    SHA1_Begin(ctx);
    SHA1_Update(ctx, srp->N.data, srp->N.len);
    SHA1_Update(ctx, zero, srp->N.len - srp->g.len);
    SHA1_Update(ctx, srp->g.data, srp->g.len);
    SHA1_End(ctx, it_k->data, &it_k->len, SHA1_LENGTH);

    /*
     * create key pair
     */
    CHECK_MPI_OK( mp_init(&mp_N)  );
    CHECK_MPI_OK( mp_init(&mp_g)  );
    CHECK_MPI_OK( mp_init(&mp_k)  );
    CHECK_MPI_OK( mp_init(&mp_v)  );
    CHECK_MPI_OK( mp_init(&mp_pub));
    CHECK_MPI_OK( mp_init(&mp_prv));
    CHECK_MPI_OK( mp_init(&mp_res));
    SECITEM_TO_MPINT(*it_k,       &mp_k);
    SECITEM_TO_MPINT(srp->N,      &mp_N);
    SECITEM_TO_MPINT(srp->g,      &mp_g);
    SECITEM_TO_MPINT(srp->secret, &mp_v);
    SECITEM_TO_MPINT(key->prvKey, &mp_prv);
    
    char *N_str;
    char *g_str;
    printf("X\n");
        N_str = PORT_ZAlloc(mp_radix_size(&mp_N,16));
        mp_toradix(&mp_N,N_str,16);
        printf("%s\n",N_str);
        g_str = PORT_ZAlloc(mp_radix_size(&mp_g,16));
        mp_toradix(&mp_g,g_str,16);
        printf("%s\n",g_str);
    printf("X\n");


    /* pub = k*v + g^prv % N */
    CHECK_MPI_OK(mp_exptmod(&mp_g, &mp_prv, &mp_N, &mp_pub));
    CHECK_MPI_OK(mp_mulmod(&mp_k, &mp_v, &mp_N, &mp_res));
    CHECK_MPI_OK(mp_addmod(&mp_res, &mp_pub, &mp_N, &mp_pub));

    MPINT_TO_SECITEM(&mp_pub, &key->pubKey, arena);
    CHECK_SEC_OK(SECITEM_CopyItem(arena, &key->secret, &srp->secret));
    *prvKey = key;

cleanup:
    PORT_Free(zero);
    SECITEM_FreeItem(it_k,PR_TRUE);
    SHA1_DestroyContext(ctx, PR_TRUE);
    mp_clear(&mp_N);
    mp_clear(&mp_g);
    mp_clear(&mp_k);
    mp_clear(&mp_v);
    mp_clear(&mp_pub);
    mp_clear(&mp_prv);
    mp_clear(&mp_res);
    if (err) {
        PORT_FreeArena(arena, PR_TRUE); /* not zeroized!! */
        MP_TO_SEC_ERROR(err);
        rv = SECFailure;
    }
    return rv;
}

/* SRP_NewClientKeyPair
 * creates a new srp key pair for the client
 *
 * prv = rand()
 * pub = g^prv % N, with prv at least 256bit random
 * prvKey->secret = srp->secret
 */

SECStatus SRP_NewClientKeyPair(SRPPrivateKey **prvKey, SRPKeyPairParams *srp) {


    SRPPrivateKey *key;
    PRArenaPool *arena;
    mp_int	mp_N, mp_g, mp_prv, mp_pub;
    mp_err      err  = MP_OKAY;
    SECStatus   rv = SECFailure;
    
    if (!srp || !prvKey) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    
    arena = PORT_NewArena(NSS_FREEBL_DEFAULT_CHUNKSIZE);
    if (!arena) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    
    key = (SRPPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(SRPPrivateKey));
    if (!key) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        PORT_FreeArena(arena, PR_TRUE);
        return SECFailure;
    }
    key->arena = arena;

    /* prv=rand() */
    SECITEM_AllocItem(arena, &key->prvKey, SRP_SECRET_KEY_LEN);
    rv = RNG_GenerateGlobalRandomBytes(key->prvKey.data, key->prvKey.len);

    if (rv != SECSuccess || !(&key->prvKey)) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        PORT_FreeArena(arena, PR_TRUE);
        return SECFailure;
    }

    /* pub = g^prv % N */
    CHECK_MPI_OK( mp_init(&mp_N)  );
    CHECK_MPI_OK( mp_init(&mp_g)  );
    CHECK_MPI_OK( mp_init(&mp_pub));
    CHECK_MPI_OK( mp_init(&mp_prv));
    SECITEM_TO_MPINT(srp->N,      &mp_N);
    SECITEM_TO_MPINT(srp->g,      &mp_g);
    SECITEM_TO_MPINT(key->prvKey, &mp_prv);

    if (SECSuccess != check_srp_group(&mp_N, &mp_g))
        goto cleanup;

    CHECK_MPI_OK( mp_exptmod(&mp_g, &mp_prv, &mp_N, &mp_pub) );
    
    MPINT_TO_SECITEM(&mp_pub, &key->pubKey, key->arena);
    CHECK_SEC_OK( SECITEM_CopyItem(arena, &key->secret, &srp->secret) );
    *prvKey = key;

cleanup:
    mp_clear(&mp_g);
    mp_clear(&mp_N);
    mp_clear(&mp_pub);
    mp_clear(&mp_prv);
    if (err) {
        PORT_FreeArena(arena, PR_TRUE); /* not zeroized!! */
        MP_TO_SEC_ERROR(err);
        rv = SECFailure;
    }
    return rv;
}
