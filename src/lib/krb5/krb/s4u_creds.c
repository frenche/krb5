/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/s4u_creds.c */
/*
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"
#include "int-proto.h"
#include "fast.h"


/*
 * Implements S4U2Self, by which a service can request a ticket to
 * itself on behalf of an arbitrary principal.
 */

enum s4u2self_state {
    STATE_BEGIN,
    STATE_GET_TGT_TO_CLIENT_REALM,
    STATE_CHASE_BACK_REFERRALS_TO_SELF,
    STATE_COMPLETE
};

typedef struct _referral_tgts {
    krb5_creds *tgts[KRB5_REFERRAL_MAXHOPS];
    unsigned int count;
} referral_tgts;

static void
clean_referral_tgts(krb5_context context, referral_tgts *refs)
{
    int i;

    for (i = 0; i < KRB5_REFERRAL_MAXHOPS; i++) {
        krb5_free_creds(context, refs->tgts[i]);
        refs->tgts[i] = NULL;
        refs->count = 0;
    }
}

typedef struct _single_request {
    krb5_principal server;      /* The requested server name (storage) */
    referral_tgts *refs;        /* */
    krb5_creds tgs_in_creds;    /* Input credentials of request (alias) */
    krb5_timestamp timestamp;   /* Timestamp of request */
    krb5_int32 nonce;           /* Nonce of request */
    int kdcopt;                 /* KDC options of request */
    krb5_keyblock *subkey;      /* subkey of request */
    struct krb5int_fast_request_state *fast_state;
    krb5_pa_data **in_padata;
    krb5_data previous_request; /* Encoded request (for TCP retransmission) */

    k5_pacb_fn build_pa_s4u_cb;
    void *build_pa_s4u_data;

    krb5_creds *reply_creds;    /* Creds from TGS reply */
    krb5_pa_data **reply_padata;
    krb5_pa_data **reply_enc_padata;
} single_request;

struct _krb5_s4u2s_creds_context {
    enum s4u2self_state state; /* What we should do with the next reply */

    k5_tkt_creds_in_data in;    /* Caller-provided initialization data */

    referral_tgts referral_storage;

    krb5_pa_s4u_x509_user s4u_user;

    single_request req;
};

inline static krb5_creds *request_tgt(single_request *req)
{
    return req->refs->tgts[req->refs->count -1];
}

static krb5_error_code
make_request(krb5_context context, single_request *req, int extra_options)
{
    krb5_error_code code;
    krb5_data request = empty_data();

    req->kdcopt = FLAGS2OPTS(request_tgt(req)->ticket_flags) |
                          extra_options;

    /* Create a new FAST state structure to store this request's armor key. */
    krb5int_fast_free_state(context, req->fast_state);
    req->fast_state = NULL;
    code = krb5int_fast_make_state(context, &req->fast_state);
    if (code)
        return code;

    krb5_free_keyblock(context, req->subkey);
    req->subkey = NULL;
    code = k5_make_tgs_req(context, req->fast_state,
                           request_tgt(req), req->kdcopt,
                           request_tgt(req)->addresses,
                           req->in_padata,
                           &req->tgs_in_creds,
                           req->build_pa_s4u_cb, req->build_pa_s4u_data,
                           &request, &req->timestamp,
                           &req->nonce, &req->subkey);
    if (code)
        return code;

    krb5_free_data_contents(context, &req->previous_request);
    req->previous_request = request;

    return 0;
}

/* Return an error if server is present in referral_list. */
static krb5_error_code
check_referral_path(krb5_context context, krb5_principal server,
                    krb5_creds **referral_list, int referral_count)
{
    int i;

    for (i = 0; i < referral_count; i++) {
        if (krb5_principal_compare(context, server, referral_list[i]->server))
            return KRB5_KDC_UNREACH;
    }
    return 0;
}

static krb5_error_code
set_principal_realm(krb5_context context, krb5_principal princ,
                    krb5_data *realm)
{
    krb5_free_data_contents(context, &princ->realm);
    return krb5int_copy_data_contents(context, realm, &princ->realm);
}

static krb5_error_code
follow_referral(krb5_context context, single_request *req, int req_kdcopt)
{
    krb5_error_code code;

    if (req->refs->count == KRB5_REFERRAL_MAXHOPS)
        return KRB5_KDCREP_MODIFIED;

    if (!IS_TGS_PRINC(req->reply_creds->server))
        return KRB5KRB_AP_WRONG_PRINC;

    if (data_eq(request_tgt(req)->server->data[1],
                req->reply_creds->server->data[1]))
        return KRB5_ERR_HOST_REALM_UNKNOWN;

    code = check_referral_path(context, req->reply_creds->server,
                               req->refs->tgts, req->refs->count);
    if (code)
        return code;

    req->refs->tgts[req->refs->count] = req->reply_creds;
    req->reply_creds = NULL;
    req->refs->count++;

    code = set_principal_realm(context, req->server,
                               &request_tgt(req)->server->data[1]);
    if (code)
        return code;

    return make_request(context, req, req_kdcopt);
}


/*
 * Make AS requests with the canonicalize flag set, stopping when we get a
 * message indicating which realm the client principal is in.  Set *client_out
 * to a copy of client with the canonical realm.  If subject_cert is non-null,
 * include PA_S4U_X509_USER pa-data with the subject certificate each request.
 * (See [MS-SFU] 3.1.5.1.1.1 and 3.1.5.1.1.2.)
 */

static krb5_error_code
identify_realm(krb5_context context, krb5_principal client,
               const krb5_data *subject_cert, krb5_principal *realm)
{
    krb5_error_code ret;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_init_creds_context ctx = NULL;
    int use_master = 0;

    *realm = NULL;

    ret = krb5_get_init_creds_opt_alloc(context, &opts);
    if (ret)
        goto cleanup;
    krb5_get_init_creds_opt_set_tkt_life(opts, 15);
    krb5_get_init_creds_opt_set_renew_life(opts, 0);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);
    krb5_get_init_creds_opt_set_canonicalize(opts, 1);
    krb5_get_init_creds_opt_set_identify_realm(opts, 1);
    krb5_get_init_creds_opt_set_id_cert(opts, subject_cert);

    ret = krb5_init_creds_init(context, client, NULL, NULL, 0, opts, &ctx);
    if (ret)
        goto cleanup;

    ret = k5_init_creds_get(context, ctx, &use_master);
    if (ret)
        goto cleanup;

    ret = krb5_init_creds_get_req_client_realm(context, ctx, realm);

cleanup:
    krb5_get_init_creds_opt_free(context, opts);
    krb5_init_creds_free(context, ctx);
    return ret;
}

static krb5_error_code
s4u_identify_realm(krb5_context context,
                   krb5_creds *in_creds,
                   krb5_data *subject_cert,
                   krb5_principal *realm)
{
    krb5_principal_data client;
    krb5_data empty_name = empty_data();

    *realm = NULL;

    if (in_creds->client == NULL && subject_cert == NULL) {
        return EINVAL;
    }

    if (in_creds->client != NULL &&
        in_creds->client->type != KRB5_NT_ENTERPRISE_PRINCIPAL) {
        int anonymous;

        anonymous = krb5_principal_compare(context, in_creds->client,
                                           krb5_anonymous_principal());

        return krb5_copy_principal(context,
                                   anonymous ? in_creds->server
                                   : in_creds->client,
                                   realm);
    }

    if (in_creds->client != NULL) {
        client = *in_creds->client;
        client.realm = in_creds->server->realm;

        /* Don't send subject_cert if we have an enterprise principal. */
        return identify_realm(context, &client, NULL, realm);
    }

    client.magic = KV5M_PRINCIPAL;
    client.realm = in_creds->server->realm;

    /*
     * Windows clients send the certificate subject as the client name.
     * However, Windows KDC seem to be happy with an empty string as long as
     * the name-type is NT-X500-PRINCIPAL.
     */
    client.data = &empty_name;
    client.length = 1;
    client.type = KRB5_NT_X500_PRINCIPAL;

    return identify_realm(context, &client, subject_cert, realm);
}

static krb5_error_code
s4u_identify_user(krb5_context context,
                  krb5_creds *in_creds,
                  krb5_data *subject_cert,
                  krb5_principal *canon_user)
{
    krb5_error_code code;
    krb5_principal realm;

    code = s4u_identify_realm(context, in_creds, subject_cert, &realm);
    if (code)
        return code;

    if (in_creds->client == NULL) {
        *canon_user = realm;
        return 0;
    }

    code = krb5_copy_principal(context, in_creds->client, canon_user);
    if (code) {
        krb5_free_principal(context, realm);
        return code;
    }

    krb5_free_data_contents(context, &(*canon_user)->realm);
    (*canon_user)->realm = realm->realm;
    realm->realm = empty_data();
    krb5_free_principal(context, realm);

    return 0;
}

static krb5_error_code
make_pa_for_user_checksum(krb5_context context,
                          krb5_keyblock *key,
                          krb5_pa_for_user *req,
                          krb5_checksum *cksum)
{
    krb5_error_code code;
    int i;
    char *p;
    krb5_data data;

    data.length = 4;
    for (i = 0; i < req->user->length; i++)
        data.length += req->user->data[i].length;
    data.length += req->user->realm.length;
    data.length += req->auth_package.length;

    p = data.data = malloc(data.length);
    if (data.data == NULL)
        return ENOMEM;

    p[0] = (req->user->type >> 0) & 0xFF;
    p[1] = (req->user->type >> 8) & 0xFF;
    p[2] = (req->user->type >> 16) & 0xFF;
    p[3] = (req->user->type >> 24) & 0xFF;
    p += 4;

    for (i = 0; i < req->user->length; i++) {
        if (req->user->data[i].length > 0)
            memcpy(p, req->user->data[i].data, req->user->data[i].length);
        p += req->user->data[i].length;
    }

    if (req->user->realm.length > 0)
        memcpy(p, req->user->realm.data, req->user->realm.length);
    p += req->user->realm.length;

    if (req->auth_package.length > 0)
        memcpy(p, req->auth_package.data, req->auth_package.length);

    /* Per spec, use hmac-md5 checksum regardless of key type. */
    code = krb5_c_make_checksum(context, CKSUMTYPE_HMAC_MD5_ARCFOUR, key,
                                KRB5_KEYUSAGE_APP_DATA_CKSUM, &data,
                                cksum);

    free(data.data);

    return code;
}

static krb5_error_code
build_pa_for_user(krb5_context context,
                  krb5_creds *tgt,
                  krb5_s4u_userid *userid,
                  krb5_pa_data **out_padata)
{
    krb5_error_code code;
    krb5_pa_data *padata;
    krb5_pa_for_user for_user;
    krb5_data *for_user_data = NULL;
    char package[] = "Kerberos";

    if (userid->user == NULL)
        return EINVAL;

    memset(&for_user, 0, sizeof(for_user));
    for_user.user = userid->user;
    for_user.auth_package.data = package;
    for_user.auth_package.length = sizeof(package) - 1;

    code = make_pa_for_user_checksum(context, &tgt->keyblock,
                                     &for_user, &for_user.cksum);
    if (code != 0)
        goto cleanup;

    code = encode_krb5_pa_for_user(&for_user, &for_user_data);
    if (code != 0)
        goto cleanup;

    padata = malloc(sizeof(*padata));
    if (padata == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    padata->magic = KV5M_PA_DATA;
    padata->pa_type = KRB5_PADATA_FOR_USER;
    padata->length = for_user_data->length;
    padata->contents = (krb5_octet *)for_user_data->data;

    free(for_user_data);
    for_user_data = NULL;

    *out_padata = padata;

cleanup:
    if (for_user.cksum.contents != NULL)
        krb5_free_checksum_contents(context, &for_user.cksum);
    krb5_free_data(context, for_user_data);

    return code;
}

/*
 * This function is invoked by krb5int_make_tgs_request_ext() just before the
 * request is encoded; it gives us access to the nonce and subkey without
 * requiring them to be generated by the caller.
 */
static krb5_error_code
build_pa_s4u_x509_user(krb5_context context,
                       krb5_keyblock *subkey,
                       krb5_kdc_req *tgsreq,
                       void *gcvt_data)
{
    krb5_error_code code;
    krb5_pa_s4u_x509_user *s4u_user = (krb5_pa_s4u_x509_user *)gcvt_data;
    krb5_data *data = NULL;
    krb5_cksumtype cksumtype;
    int i;

    assert(s4u_user->cksum.contents == NULL);

    s4u_user->user_id.nonce = tgsreq->nonce;

    code = encode_krb5_s4u_userid(&s4u_user->user_id, &data);
    if (code != 0)
        goto cleanup;

    /* [MS-SFU] 2.2.2: unusual to say the least, but enc_padata secures it */
    if (subkey->enctype == ENCTYPE_ARCFOUR_HMAC ||
        subkey->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
        cksumtype = CKSUMTYPE_RSA_MD4;
    } else {
        code = krb5int_c_mandatory_cksumtype(context, subkey->enctype,
                                             &cksumtype);
    }
    if (code != 0)
        goto cleanup;

    code = krb5_c_make_checksum(context, cksumtype, subkey,
                                KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST, data,
                                &s4u_user->cksum);
    if (code != 0)
        goto cleanup;

    krb5_free_data(context, data);
    data = NULL;

    code = encode_krb5_pa_s4u_x509_user(s4u_user, &data);
    if (code != 0)
        goto cleanup;

    /* Find the empty PA-S4U-X509-USER element placed in the TGS request padata
     * XXX by krb5_get_self_cred_from_kdc() and replace it with the encoding. */
    assert(tgsreq->padata != NULL);
    for (i = 0; tgsreq->padata[i] != NULL; i++) {
        if (tgsreq->padata[i]->pa_type == KRB5_PADATA_S4U_X509_USER)
            break;
    }
    assert(tgsreq->padata[i] != NULL);
    free(tgsreq->padata[i]->contents);
    tgsreq->padata[i]->length = data->length;
    tgsreq->padata[i]->contents = (krb5_octet *)data->data;
    free(data);
    data = NULL;

cleanup:
    if (code != 0 && s4u_user->cksum.contents != NULL) {
        krb5_free_checksum_contents(context, &s4u_user->cksum);
        s4u_user->cksum.contents = NULL;
    }
    krb5_free_data(context, data);

    return code;
}

/*
 * Validate the S4U2Self padata in the KDC reply.  If update_req_user is true
 * and the KDC sent S4U-X509-USER padata, replace req_s4u_user->user_id.user
 * with the checksum-protected client name from the KDC.  If update_req_user is
 * false, verify that the client name has not changed.
 */
static krb5_error_code
verify_s4u2self_reply(krb5_context context,
                      krb5_keyblock *subkey,
                      krb5_pa_s4u_x509_user *req_s4u_user,
                      krb5_pa_data **rep_padata,
                      krb5_pa_data **enc_padata,
                      krb5_boolean update_req_user)
{
    krb5_error_code code;
    krb5_pa_data *rep_s4u_padata, *enc_s4u_padata;
    krb5_pa_s4u_x509_user *rep_s4u_user = NULL;
    krb5_data data, *datap = NULL;
    krb5_keyusage usage;
    krb5_boolean valid;
    krb5_boolean not_newer;

    assert(req_s4u_user != NULL);

    switch (subkey->enctype) {
    case ENCTYPE_DES3_CBC_SHA1:
    case ENCTYPE_DES3_CBC_RAW:
    case ENCTYPE_ARCFOUR_HMAC:
    case ENCTYPE_ARCFOUR_HMAC_EXP :
        not_newer = TRUE;
        break;
    default:
        not_newer = FALSE;
        break;
    }

    enc_s4u_padata = krb5int_find_pa_data(context,
                                          enc_padata,
                                          KRB5_PADATA_S4U_X509_USER);

    /* XXX this will break newer enctypes with a MIT 1.7 KDC */
    rep_s4u_padata = krb5int_find_pa_data(context,
                                          rep_padata,
                                          KRB5_PADATA_S4U_X509_USER);
    if (rep_s4u_padata == NULL) {
        if (not_newer == FALSE || enc_s4u_padata != NULL)
            return KRB5_KDCREP_MODIFIED;
        else
            return 0;
    }

    data.length = rep_s4u_padata->length;
    data.data = (char *)rep_s4u_padata->contents;

    code = decode_krb5_pa_s4u_x509_user(&data, &rep_s4u_user);
    if (code != 0)
        goto cleanup;

    if (rep_s4u_user->user_id.nonce != req_s4u_user->user_id.nonce) {
        code = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

    code = encode_krb5_s4u_userid(&rep_s4u_user->user_id, &datap);
    if (code != 0)
        goto cleanup;

    if (rep_s4u_user->user_id.options & KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE)
        usage = KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY;
    else
        usage = KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST;

    code = krb5_c_verify_checksum(context, subkey, usage, datap,
                                  &rep_s4u_user->cksum, &valid);
    if (code != 0)
        goto cleanup;
    if (valid == FALSE) {
        code = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

    if (rep_s4u_user->user_id.user == NULL ||
        rep_s4u_user->user_id.user->length == 0) {
        code = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

    if (update_req_user) {
        krb5_free_principal(context, req_s4u_user->user_id.user);
        req_s4u_user->user_id.user = NULL;
        code = krb5_copy_principal(context, rep_s4u_user->user_id.user,
                                   &req_s4u_user->user_id.user);
        if (code != 0)
            goto cleanup;
    } else if (!krb5_principal_compare(context, rep_s4u_user->user_id.user,
                                       req_s4u_user->user_id.user)) {
        code = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

    /*
     * KDCs that support KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE also return
     * S4U enc_padata for older (pre-AES) encryption types only.
     */
    if (not_newer) {
        if (enc_s4u_padata == NULL) {
            if (rep_s4u_user->user_id.options &
                KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE) {
                code = KRB5_KDCREP_MODIFIED;
                goto cleanup;
            }
        } else {
            if (enc_s4u_padata->length !=
                req_s4u_user->cksum.length + rep_s4u_user->cksum.length) {
                code = KRB5_KDCREP_MODIFIED;
                goto cleanup;
            }
            if (memcmp(enc_s4u_padata->contents,
                       req_s4u_user->cksum.contents,
                       req_s4u_user->cksum.length) ||
                memcmp(&enc_s4u_padata->contents[req_s4u_user->cksum.length],
                       rep_s4u_user->cksum.contents,
                       rep_s4u_user->cksum.length)) {
                code = KRB5_KDCREP_MODIFIED;
                goto cleanup;
            }
        }
    } else if (!krb5_c_is_keyed_cksum(rep_s4u_user->cksum.checksum_type)) {
        code = KRB5KRB_AP_ERR_INAPP_CKSUM;
        goto cleanup;
    }

cleanup:
    krb5_free_pa_s4u_x509_user(context, rep_s4u_user);
    krb5_free_data(context, datap);

    return code;
}

/* Unparse princ and re-parse it as an enterprise principal. */
static krb5_error_code
convert_to_enterprise(krb5_context context, krb5_principal princ,
                      krb5_principal *eprinc_out)
{
    krb5_error_code code;
    char *str;

    *eprinc_out = NULL;
    code = krb5_unparse_name(context, princ, &str);
    if (code != 0)
        return code;
    code = krb5_parse_name_flags(context, str,
                                 KRB5_PRINCIPAL_PARSE_ENTERPRISE |
                                 KRB5_PRINCIPAL_PARSE_IGNORE_REALM,
                                 eprinc_out);
    krb5_free_unparsed_name(context, str);
    return code;
}


/* Decode and decrypt a TGS reply, and set the reply_code or return error. */
static krb5_error_code
get_creds_from_tgs_reply(krb5_context context, single_request *req,
                         krb5_data *reply)
{
    krb5_error_code code;

    krb5_free_creds(context, req->reply_creds);
    req->reply_creds = NULL;

    krb5_free_pa_data(context, req->reply_padata);
    req->reply_padata = NULL;

    krb5_free_pa_data(context, req->reply_enc_padata);
    req->reply_enc_padata = NULL;

    code = krb5int_process_tgs_reply(context, req->fast_state,
                                     reply, request_tgt(req),
                                     req->kdcopt,
                                     request_tgt(req)->addresses,
                                     req->in_padata,
                                     &req->tgs_in_creds,
                                     req->timestamp,
                                     req->nonce, req->subkey,
                                     &req->reply_padata,
                                     &req->reply_enc_padata,
                                     &req->reply_creds);

    return code;
}

/*
 * Fill in the caller out, realm, and flags output variables.  out is filled in
 * with ctx->previous_request, which the caller should set, and realm is filled
 * in with the realm of ctx->cur_tgt.
 */
static krb5_error_code
set_caller_request(krb5_context context, single_request *req,
                   krb5_data *caller_out, krb5_data *caller_realm)
{
    krb5_error_code code;
    const krb5_data *previous_request = &req->previous_request;
    const krb5_data *realm = &request_tgt(req)->server->data[1];
    krb5_data out_copy = empty_data(), realm_copy = empty_data();

    code = krb5int_copy_data_contents(context, previous_request, &out_copy);
    if (code != 0)
        return code;
    code = krb5int_copy_data_contents(context, realm, &realm_copy);
    if (code != 0)
        return code;

    *caller_out = out_copy;
    *caller_realm = realm_copy;
    return 0;
}

static void
complete(krb5_context context, single_request *req, k5_tkt_creds_in_data in)
{
    //TRACE_TKT_CREDS_COMPLETE(context, ctx->reply_creds->server);

    /* Put the requested server principal in the output creds. */
    krb5_free_principal(context, req->reply_creds->server);
    req->reply_creds->server = in->req_server;
    in->req_server = NULL;

    /* Note the authdata we asked for in the output creds. */
    req->reply_creds->authdata = in->authdata;
    in->authdata = NULL;

    if (!(in->req_options & KRB5_GC_NO_STORE)) {
        /* Try to cache the credential. */
        (void) krb5_cc_store_cred(context, in->ccache, req->reply_creds);
    }
}

/* S4U2Self step Functions */

static krb5_error_code
make_s4u2self_padata(krb5_context context, krb5_creds *tgt,
                     krb5_pa_s4u_x509_user *s4u_user,
                     krb5_pa_data ***padata)
{
    krb5_error_code code;
    krb5_pa_data **in_padata = NULL;

    *padata = NULL;

    in_padata = k5calloc(3, sizeof(krb5_pa_data *), &code);
    if (in_padata == NULL)
       return code;

    in_padata[0] = k5alloc(sizeof(krb5_pa_data), &code);
    if (in_padata[0] == NULL) {
        krb5_free_pa_data(context, in_padata);
        return code;
    }

    in_padata[0]->magic = KV5M_PA_DATA;
    in_padata[0]->pa_type = KRB5_PADATA_S4U_X509_USER;
    in_padata[0]->length = 0;
    in_padata[0]->contents = NULL;

    if (s4u_user->user_id.user->length) {
        code = build_pa_for_user(context, tgt, &s4u_user->user_id,
                                 &in_padata[1]);
        if (code != 0) {
            krb5_free_pa_data(context, in_padata);
            return code;
        }
    }

    *padata = in_padata;
    return 0;
}

static krb5_error_code
make_initial_s4u2s_request(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    krb5_error_code code;

    krb5_free_principal(context, ctx->req.server);
    ctx->req.server = NULL;

    code = krb5_copy_principal(context, ctx->in->in_creds->server,
                               &ctx->req.server);
    if (code)
        return code;

    ctx->req.tgs_in_creds = *ctx->in->in_creds;
    ctx->req.tgs_in_creds.server = ctx->req.server;

    code = krb5_copy_principal(context, ctx->in->impersonate,
                               &ctx->s4u_user.user_id.user);
    if (code)
        return code;

    ctx->s4u_user.user_id.subject_cert = ctx->in->impersonate_cert;
    ctx->s4u_user.user_id.options = KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE;

    ctx->req.build_pa_s4u_cb = build_pa_s4u_x509_user;
    ctx->req.build_pa_s4u_data = &ctx->s4u_user;

    code = make_s4u2self_padata(context, request_tgt(&ctx->req),
                                &ctx->s4u_user, &ctx->req.in_padata);
    if (code)
        return code;

    code = make_request(context, &ctx->req, ctx->in->req_kdcopt);
    if (code)
        return code;

    ctx->state = STATE_CHASE_BACK_REFERRALS_TO_SELF;
    return 0;
}

static krb5_error_code
begin(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    krb5_error_code code;

    if (krb5_is_referral_realm(&ctx->in->in_creds->server->realm)) {
        krb5_free_data_contents(context, &ctx->in->in_creds->server->realm);
        code = krb5int_copy_data_contents(context,
                                          &ctx->in->impersonate->realm,
                                          &ctx->in->in_creds->server->realm);
        if (code)
            return code;
    }

    ctx->req.refs = &ctx->referral_storage;

    code = k5_get_cached_local_tgt(context, ctx->in->in_creds->client, 0,
                                   ctx->in->ccache, &ctx->req.refs->tgts[0]);
    if (code)
        return code;

    ctx->req.refs->count = 1;

    if (krb5_realm_compare(context, ctx->in->in_creds->client,
                           ctx->in->impersonate))
        return make_initial_s4u2s_request(context, ctx);

    /* XXX check if we got cached foreign tgt ? */

    /* First, acquire a TGT to the user's realm. */
    code = krb5int_tgtname(context, &ctx->in->impersonate->realm,
                           &ctx->in->in_creds->client->realm,
                           &ctx->req.server);
    if (code != 0)
        return code;

    ctx->req.tgs_in_creds.client = ctx->in->in_creds->client;
    ctx->req.tgs_in_creds.server = ctx->req.server;

    code = make_request(context, &ctx->req, ctx->in->req_kdcopt);
    if (code)
        return code;

    ctx->state = STATE_GET_TGT_TO_CLIENT_REALM;
    return 0;
}

static krb5_error_code
get_tgt_to_client_realm(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    /* XXX save in cache and use ? */
    if (!krb5_principal_compare_any_realm(context, ctx->req.server,
                                          ctx->req.reply_creds->server))
        return follow_referral(context, &ctx->req, ctx->in->req_kdcopt);

    clean_referral_tgts(context, ctx->req.refs);

    ctx->req.refs->tgts[0] = ctx->req.reply_creds;
    ctx->req.reply_creds = NULL;
    ctx->req.refs->count = 1;

    return make_initial_s4u2s_request(context, ctx);
}

static krb5_error_code
chase_back_referrals_to_self(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    krb5_error_code code;

    /* Update s4u_user.user_id.user if this is the initial request to the
     * client realm; otherwise verify that it doesn't change. */
    code = verify_s4u2self_reply(context, ctx->req.subkey, &ctx->s4u_user,
                                 ctx->req.reply_padata, ctx->req.reply_enc_padata,
                                 ctx->req.refs->count == 1);
    if (code)
        return code;

    if (krb5_principal_compare_any_realm(context, ctx->req.server,
                                         ctx->req.reply_creds->server)) {
        /* Verify that the unprotected client name in the reply matches the
         * checksum-protected one from the client realm's KDC padata. */
        if (!krb5_principal_compare(context, ctx->req.reply_creds->client,
                                    ctx->s4u_user.user_id.user))
            return KRB5_KDCREP_MODIFIED;

        complete(context, &ctx->req, ctx->in);
        ctx->state = STATE_COMPLETE;
        return 0;
    }

    /* Only include a cert in the initial request to the client realm. */
    ctx->s4u_user.user_id.subject_cert = empty_data();

    krb5_free_checksum_contents(context, &ctx->s4u_user.cksum);
    krb5_free_pa_data(context, ctx->req.in_padata);
    ctx->req.in_padata = NULL;

    code = make_s4u2self_padata(context, request_tgt(&ctx->req),
                                &ctx->s4u_user, &ctx->req.in_padata);
    if (code)
        return code;

    return follow_referral(context, &ctx->req, ctx->in->req_kdcopt);
}


/***** API functions *****/

krb5_error_code
k5_gc_s4u2s_init(krb5_context context, k5_tkt_creds_in_data in_data,
              krb5_s4u2s_creds_context *out_ctx)
{
    krb5_error_code code;
    krb5_s4u2s_creds_context ctx;

    *out_ctx = NULL;

    //TRACE_TKT_CREDS(context, in_data->in_creds, in_data->ccache);
    ctx = k5alloc(sizeof(*ctx), &code);
    if (ctx == NULL)
        return code;

    ctx->state = STATE_BEGIN;

    ctx->in = in_data;

    *out_ctx = ctx;
    ctx = NULL;

    return 0;
}

krb5_error_code
k5_gc_s4u2s_step(krb5_context context, krb5_s4u2s_creds_context ctx,
                 krb5_data *in, krb5_data *out, krb5_data *realm,
                 krb5_boolean *need_continue, krb5_creds **reply_creds)
{
    krb5_error_code code;
    krb5_boolean no_input = (in == NULL || in->length == 0);

    *out = empty_data();
    *realm = empty_data();
    *need_continue = FALSE;
    *reply_creds = NULL;

    /* We should receive an empty input on the first step only, and should not
     * get called after completion. */
    if (no_input != (ctx->state == STATE_BEGIN) ||
        ctx->state == STATE_COMPLETE)
        return EINVAL;

    if (!no_input) {
        /* Convert the input token into a credential and store it in ctx. */
        code = get_creds_from_tgs_reply(context, &ctx->req, in);
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG) {
            code = set_caller_request(context, &ctx->req, out, realm);
            if (code != 0)
                return code;
            /* Instruct the caller to re-send the request with TCP. */
            *need_continue = TRUE;
            return KRB5KRB_ERR_RESPONSE_TOO_BIG;
        }
        if (code != 0)
            return code;
    }

    if (ctx->state == STATE_BEGIN)
        code = begin(context, ctx);
    else if (ctx->state == STATE_GET_TGT_TO_CLIENT_REALM)
        code = get_tgt_to_client_realm(context, ctx);
    else if (ctx->state == STATE_CHASE_BACK_REFERRALS_TO_SELF)
        code = chase_back_referrals_to_self(context, ctx);
    else
        code = EINVAL;

    if (code != 0)
        return code;

    if (ctx->state != STATE_COMPLETE) {
        code = set_caller_request(context, &ctx->req, out, realm);
        if (code)
            return code;
        *need_continue = TRUE;
    } else {
        *reply_creds = ctx->req.reply_creds;
        ctx->req.reply_creds = NULL;
    }

    return 0;
}

void
k5_gc_s4u2s_free(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    if (ctx == NULL)
        return;
    k5_tkt_creds_in_data_free(context, ctx->in);
    clean_referral_tgts(context, ctx->req.refs);
    krb5_free_principal(context, ctx->s4u_user.user_id.user);
    krb5_free_checksum_contents(context, &ctx->s4u_user.cksum);
    krb5int_fast_free_state(context, ctx->req.fast_state);
    krb5_free_principal(context, ctx->req.server);
    krb5_free_keyblock(context, ctx->req.subkey);
    krb5_free_data_contents(context, &ctx->req.previous_request);
    krb5_free_creds(context, ctx->req.reply_creds);
    krb5_free_pa_data(context, ctx->req.in_padata);
    krb5_free_pa_data(context, ctx->req.reply_padata);
    krb5_free_pa_data(context, ctx->req.reply_enc_padata);
    free(ctx);
}

static krb5_error_code
krb5_get_self_cred_from_kdc(krb5_context context,
                            krb5_flags options,
                            krb5_ccache ccache,
                            krb5_creds *in_creds,
                            krb5_principal impersonate,
                            krb5_data *subject_cert,
                            krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds *out = NULL;
    krb5_tkt_creds_context ctx = NULL;

    code = krb5_tkt_creds_init(context, ccache, in_creds, options, &ctx); 
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_set_impersonate(context, ctx, impersonate);
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_set_impersonate_cert(context, ctx, subject_cert);
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_get(context, ctx);
    if (code)
        goto cleanup;

    /* Allocate a container. */
    out = k5alloc(sizeof(krb5_creds), &code);
    if (out == NULL)
        goto cleanup;

    code = krb5_tkt_creds_get_creds(context, ctx, out);
    if (code) {
        free(out);
        goto cleanup;
    }

    *out_creds = out;

cleanup:
    krb5_tkt_creds_free(context, ctx);
    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_get_credentials_for_user(krb5_context context, krb5_flags options,
                              krb5_ccache ccache, krb5_creds *in_creds,
                              krb5_data *subject_cert,
                              krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds s4u_creds, *reply = NULL;
    krb5_principal canon = NULL;
    krb5_principal server = NULL;
    krb5_principal enterprise_server = NULL;

    *out_creds = NULL;

    if (in_creds->client != NULL) {
        /* Uncanonicalised check */
        code = krb5_get_credentials(context, options | KRB5_GC_CACHED,
                                    ccache, in_creds, out_creds);
        if (code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
            goto cleanup;

        if ((options & KRB5_GC_CACHED) && !(options & KRB5_GC_CANONICALIZE))
            goto cleanup;
    }

    code = s4u_identify_user(context, in_creds, subject_cert, &canon);
    if (code != 0)
        goto cleanup;

    if (in_creds->client != NULL &&
        in_creds->client->type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
        /* Post-canonicalisation check for enterprise principals */
        krb5_creds mcreds = *in_creds;
        mcreds.client = canon;
        code = krb5_get_credentials(context, options | KRB5_GC_CACHED,
                                    ccache, &mcreds, &reply);
        if ((code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
            || (options & KRB5_GC_CACHED))
            goto cleanup;
    }

    server = in_creds->server;
    s4u_creds = *in_creds;
    s4u_creds.client = server;

    if (!krb5_realm_compare(context, s4u_creds.server, canon)) {
        code = convert_to_enterprise(context, s4u_creds.server,
                                     &enterprise_server);
        if (code)
            goto cleanup;

        krb5_free_data_contents(context, &enterprise_server->realm);
        code = krb5int_copy_data_contents(context, &canon->realm,
                                          &enterprise_server->realm);
        if (code)
            goto cleanup;

        s4u_creds.server = enterprise_server;
    }

    /* XXX: TEMP */
    options |= KRB5_GC_CANONICALIZE;

    code = krb5_get_self_cred_from_kdc(context, options | KRB5_GC_NO_STORE,
                                       ccache, &s4u_creds,
                                       canon, subject_cert, &reply);
    if (code != 0)
        goto cleanup;

    if (enterprise_server != NULL) {
        krb5_free_principal(context, reply->server);
        reply->server = NULL;

        code = krb5_copy_principal(context, server, &reply->server);
        if (code != 0)
            goto cleanup;
    }

    /* If we canonicalized the client name or discovered it using subject_cert,
     * check if we had cached credentials and return them if found. */
    if (in_creds->client == NULL ||
        !krb5_principal_compare(context, canon, reply->client)) {
        krb5_creds *old_creds;
        krb5_creds mcreds = *in_creds;
        mcreds.client = reply->client;
        code = krb5_get_credentials(context, options | KRB5_GC_CACHED, ccache,
                                    &mcreds, &old_creds);
        if (code == 0) {
            krb5_free_creds(context, reply);
            reply = old_creds;
            options |= KRB5_GC_NO_STORE;
        } else if (code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE) {
            goto cleanup;
        }
        code = 0;
    }

    if ((options & KRB5_GC_NO_STORE) == 0) {
        code = krb5_cc_store_cred(context, ccache, reply);
        if (code != 0)
            goto cleanup;
    }

    *out_creds = reply;
    reply = NULL;

cleanup:
    krb5_free_creds(context, reply);
    krb5_free_principal(context, canon);
    krb5_free_principal(context, enterprise_server);

    return code;
}

/*
 * Exported API for constrained delegation (S4U2Proxy).
 *
 * This is preferable to using krb5_get_credentials directly because
 * it can perform some additional checks.
 */
krb5_error_code KRB5_CALLCONV
krb5_get_credentials_for_proxy(krb5_context context,
                               krb5_flags options,
                               krb5_ccache ccache,
                               krb5_creds *in_creds,
                               krb5_ticket *evidence_tkt,
                               krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds mcreds;
    krb5_creds *ncreds = NULL;
    krb5_flags fields;
    krb5_data *evidence_tkt_data = NULL;
    krb5_creds s4u_creds;

    *out_creds = NULL;

    if (in_creds == NULL || in_creds->client == NULL || evidence_tkt == NULL) {
        code = EINVAL;
        goto cleanup;
    }

    /*
     * Caller should have set in_creds->client to match evidence
     * ticket client.  If we can, verify it before issuing the request.
     */
    if (evidence_tkt->enc_part2 != NULL &&
        !krb5_principal_compare(context, evidence_tkt->enc_part2->client,
                                in_creds->client)) {
        code = EINVAL;
        goto cleanup;
    }

    code = krb5int_construct_matching_creds(context, options, in_creds,
                                            &mcreds, &fields);
    if (code != 0)
        goto cleanup;

    ncreds = calloc(1, sizeof(*ncreds));
    if (ncreds == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    ncreds->magic = KV5M_CRED;

    code = krb5_cc_retrieve_cred(context, ccache, fields, &mcreds, ncreds);
    if (code != 0) {
        free(ncreds);
        ncreds = in_creds;
    } else {
        *out_creds = ncreds;
    }

    if ((code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
        || options & KRB5_GC_CACHED)
        goto cleanup;

    code = encode_krb5_ticket(evidence_tkt, &evidence_tkt_data);
    if (code != 0)
        goto cleanup;

    s4u_creds = *in_creds;
    s4u_creds.client = evidence_tkt->server;
    s4u_creds.second_ticket = *evidence_tkt_data;

    code = krb5_get_credentials(context,
                                options | KRB5_GC_CONSTRAINED_DELEGATION,
                                ccache, &s4u_creds, out_creds);
    if (code != 0)
        goto cleanup;

    /*
     * Check client name because we couldn't compare that inside
     * krb5_get_credentials() (enc_part2 is unavailable in clear)
     */
    if (!krb5_principal_compare(context, in_creds->client,
                                (*out_creds)->client)) {
        code = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

cleanup:
    if (*out_creds != NULL && code != 0) {
        krb5_free_creds(context, *out_creds);
        *out_creds = NULL;
    }
    if (evidence_tkt_data != NULL)
        krb5_free_data(context, evidence_tkt_data);

    return code;
}

