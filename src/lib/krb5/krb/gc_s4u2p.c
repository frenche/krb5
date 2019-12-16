/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/gc_s4u2p.c */
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


enum s4u2proxy_state {
    STATE_BEGIN,
    STATE_GET_TICKET_OR_REFERRAL,
    STATE_CHASE_SERVICE_TGT,
    STATE_CHASE_PROXY_TGT,
    STATE_GET_XREALM_TICKET,
    STATE_COMPLETE
};

struct _krb5_s4u2p_creds_context {
    enum s4u2proxy_state state; /* What we should do with the next reply */

    k5_tkt_creds_in_data in;    /* Caller-provided initialization data */

    krb5_creds *service_tgts[KRB5_REFERRAL_MAXHOPS];
    unsigned int service_tgts_count;
    krb5_creds *proxy_tgts[KRB5_REFERRAL_MAXHOPS];
    unsigned int proxy_tgts_count;

    struct {
        krb5_principal req_server;  /* The requested server name (storage) */
        krb5_creds *req_tgt;        /* The tgt used for the request (alias) */
        krb5_creds tgs_in_creds;    /* Input credentials of request (alias) */
        krb5_timestamp timestamp;   /* Timestamp of request */
        krb5_int32 nonce;           /* Nonce of request */
        int kdcopt;                 /* KDC options of request */
        krb5_keyblock *subkey;      /* subkey of request */
        struct krb5int_fast_request_state *fast_state;
        krb5_data previous_request; /* Encoded request (for TCP retransmission) */
    } request;

    krb5_creds *reply_creds;    /* Creds from TGS reply */
    krb5_pa_data **reply_enc_padata;
};

static krb5_error_code
check_rbcd_support(krb5_context context, krb5_pa_data **padata)
{
    krb5_error_code code;
    krb5_pa_data *pa;
    krb5_pa_pac_options *pac_options;
    krb5_data der_pac_options;

    pa = krb5int_find_pa_data(context, padata, KRB5_PADATA_PAC_OPTIONS);
    if (pa == NULL)
        return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    der_pac_options = make_data(pa->contents, pa->length);
    code = decode_krb5_pa_pac_options(&der_pac_options, &pac_options);
    if (code)
        return code;

    if (!(pac_options->options & KRB5_PA_PAC_OPTIONS_RBCD))
        code = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    free(pac_options);
    return code;
}

static krb5_error_code
add_rbcd_padata(krb5_context context, krb5_pa_data ***in_padata)
{
    krb5_error_code code;
    krb5_pa_pac_options pac_options;
    krb5_data *der_pac_options = NULL;

    memset(&pac_options, 0, sizeof(pac_options));
    pac_options.options |= KRB5_PA_PAC_OPTIONS_RBCD;

    code = encode_krb5_pa_pac_options(&pac_options, &der_pac_options);
    if (code)
        return code;

    code = k5_add_pa_data_from_data(in_padata, KRB5_PADATA_PAC_OPTIONS,
                                    der_pac_options);
    krb5_free_data(context, der_pac_options);
    return code;
}

/*
 * Copy req_server to *out_server.  If req_server has the referral realm, set
 * the realm of *out_server to realm.  Otherwise the S4U2Proxy request will
 * fail unless the specified realm is the same as the TGT (or an alias to it).
 */
static krb5_error_code
normalize_server_princ(krb5_context context, const krb5_data *realm,
                       krb5_principal req_server, krb5_principal *out_server)
{
    krb5_error_code code;
    krb5_principal server;

    *out_server = NULL;

    code = krb5_copy_principal(context, req_server, &server);
    if (code)
        return code;

    if (krb5_is_referral_realm(&server->realm)) {
        krb5_free_data_contents(context, &server->realm);
        code = krb5int_copy_data_contents(context, realm, &server->realm);
        if (code) {
            krb5_free_principal(context, server);
            return code;
        }
    }

    *out_server = server;
    return 0;
}

/*caller should set request.req_tgt and request.tgs_in_creds */
static krb5_error_code
make_request(krb5_context context, krb5_s4u2p_creds_context ctx,
             int extra_options, krb5_pa_data **in_padata)
{
    krb5_error_code code;
    krb5_data request = empty_data();

    ctx->request.kdcopt = extra_options | ctx->in->req_kdcopt |
        FLAGS2OPTS(ctx->request.req_tgt->ticket_flags);

    /* Create a new FAST state structure to store this request's armor key. */
    krb5int_fast_free_state(context, ctx->request.fast_state);
    ctx->request.fast_state = NULL;
    code = krb5int_fast_make_state(context, &ctx->request.fast_state);
    if (code)
        return code;

    krb5_free_keyblock(context, ctx->request.subkey);
    ctx->request.subkey = NULL;
    code = k5_make_tgs_req(context, ctx->request.fast_state,
                           ctx->request.req_tgt, ctx->request.kdcopt,
                           ctx->request.req_tgt->addresses, in_padata,
                           &ctx->request.tgs_in_creds, NULL, NULL, &request,
                           &ctx->request.timestamp, &ctx->request.nonce,
                           &ctx->request.subkey);
    if (code)
        return code;

    krb5_free_data_contents(context, &ctx->request.previous_request);
    ctx->request.previous_request = request;

    return 0;
}

static krb5_error_code
begin(krb5_context context, krb5_s4u2p_creds_context ctx)
{
    krb5_error_code code;
    krb5_pa_data **in_padata = NULL;

    code = k5_get_cached_local_tgt(context, ctx->in->in_creds->client, 0,
                                   ctx->in->ccache, &ctx->service_tgts[0]);
    if (code)
        return code;

    ctx->service_tgts_count = 1;

    code = normalize_server_princ(context, &ctx->in->in_creds->client->realm,
                                  ctx->in->in_creds->server,
                                  &ctx->request.req_server);
    if (code)
        return code;

    ctx->request.tgs_in_creds = *ctx->in->in_creds;
    ctx->request.tgs_in_creds.server = ctx->request.req_server;
    ctx->request.req_tgt = ctx->service_tgts[0];

    code = add_rbcd_padata(context, &in_padata);
    if (code)
        return code;

    code = make_request(context, ctx, KDC_OPT_CNAME_IN_ADDL_TKT, in_padata);
    krb5_free_pa_data(context, in_padata);
    if (code)
        return code;

    /* why free, move to ctx->authdata, get rid of in->authdata and in->req_server ! */
    krb5_free_authdata(context, ctx->in->in_creds->authdata);
    ctx->in->in_creds->authdata = NULL;
    ctx->request.tgs_in_creds.authdata = NULL;

    ctx->state = STATE_GET_TICKET_OR_REFERRAL;
    return 0;
}

static krb5_error_code
complete(krb5_context context, krb5_s4u2p_creds_context ctx)
{
    //TRACE_TKT_CREDS_COMPLETE(context, ctx->reply_creds->server);

    /* Put the requested server principal in the output creds. */
    krb5_free_principal(context, ctx->reply_creds->server);
    ctx->reply_creds->server = ctx->in->req_server;
    ctx->in->req_server = NULL;

    /* Note the authdata we asked for in the output creds. */
    ctx->reply_creds->authdata = ctx->in->authdata;
    ctx->in->authdata = NULL;

    if (!(ctx->in->req_options & KRB5_GC_NO_STORE)) {
        /* Try to cache the credential. */
        (void) krb5_cc_store_cred(context, ctx->in->ccache, ctx->reply_creds);
    }

    ctx->state = STATE_COMPLETE;
    return 0;
}

static krb5_error_code
get_ticket_or_referral(krb5_context context,
                       krb5_s4u2p_creds_context ctx)
{
    krb5_error_code code;

    if (krb5_principal_compare_any_realm(context, ctx->request.req_server,
                                         ctx->reply_creds->server))
        return complete(context, ctx);

    if (!IS_TGS_PRINC(ctx->reply_creds->server))
        return KRB5KRB_AP_WRONG_PRINC;

    code = check_rbcd_support(context, ctx->reply_enc_padata);
    if (code)
        return code;

    ctx->proxy_tgts[0] = ctx->reply_creds;
    ctx->reply_creds = NULL;
    ctx->proxy_tgts_count = 1;

    ctx->request.tgs_in_creds.second_ticket = empty_data();

    code = make_request(context, ctx, 0, NULL);
    if (code)
        return code;

    ctx->state = STATE_CHASE_SERVICE_TGT;
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
check_referral(krb5_context context, krb5_creds *tgt, krb5_creds *ref,
               krb5_creds **referral_list, int referral_count)
{
    if (referral_count == KRB5_REFERRAL_MAXHOPS)
        return KRB5_KDCREP_MODIFIED;

    if (!IS_TGS_PRINC(ref->server))
        return KRB5KRB_AP_WRONG_PRINC;

    if (data_eq(tgt->server->data[1], ref->server->data[1]))
        return KRB5_ERR_HOST_REALM_UNKNOWN;

    return check_referral_path(context, ref->server, referral_list,
                               referral_count);
}

static krb5_error_code
set_principal_realm(krb5_context context, krb5_principal princ,
                    krb5_data *realm)
{
    krb5_free_data_contents(context, &princ->realm);
    return krb5int_copy_data_contents(context, realm, &princ->realm);
}

static krb5_error_code
make_xrealm_s4u2proxy_request(krb5_context context,
                              krb5_s4u2p_creds_context ctx)
{
    krb5_error_code code;
    krb5_creds *proxy;
    krb5_pa_data **in_padata = NULL;

    krb5_free_principal(context, ctx->request.req_server);
    ctx->request.req_server = NULL;

    code = krb5_copy_principal(context, ctx->in->in_creds->server,
                               &ctx->request.req_server);
    if (code)
        return code;

    ctx->request.req_tgt = ctx->service_tgts[ctx->service_tgts_count -1];

    code = set_principal_realm(context, ctx->request.req_server,
                               &ctx->request.req_tgt->server->data[1]);
    if (code)
        return code;

    ctx->request.tgs_in_creds = *ctx->in->in_creds;
    ctx->request.tgs_in_creds.server = ctx->request.req_server;

    proxy = ctx->proxy_tgts[ctx->proxy_tgts_count -1];
    ctx->request.tgs_in_creds.second_ticket = proxy->ticket;

    code = add_rbcd_padata(context, &in_padata);
    if (code)
        return code;

    code = make_request(context, ctx, KDC_OPT_CNAME_IN_ADDL_TKT, in_padata);
    krb5_free_pa_data(context, in_padata);
    if (code)
        return code;

    ctx->state = STATE_GET_XREALM_TICKET;
    return 0;
}

static krb5_error_code
chase_service_tgt(krb5_context context,
                  krb5_s4u2p_creds_context ctx)
{
    krb5_error_code code;
    krb5_creds *tgt, *proxy;

    if (!krb5_principal_compare_any_realm(context, ctx->request.req_server,
                                          ctx->reply_creds->server)) {

        code = check_referral(context, ctx->request.req_tgt, ctx->reply_creds,
                              ctx->service_tgts, ctx->service_tgts_count);
        if (code)
            return code;

        ctx->service_tgts[ctx->service_tgts_count] = ctx->reply_creds;
        ctx->reply_creds = NULL;
        ctx->service_tgts_count++;

        ctx->request.req_tgt = ctx->service_tgts[ctx->service_tgts_count -1];

        code = set_principal_realm(context, ctx->request.req_server,
                                   &ctx->request.req_tgt->server->data[1]);
        if (code)
            return code;

        return make_request(context, ctx, 0, NULL);
    }

    krb5_free_creds(context, ctx->reply_creds);
    ctx->reply_creds = NULL;

    tgt = ctx->service_tgts[ctx->service_tgts_count -1];
    proxy = ctx->proxy_tgts[ctx->proxy_tgts_count -1];

    if (data_eq(tgt->server->data[1], (proxy->server->data[1])))
        return make_xrealm_s4u2proxy_request(context, ctx);

    /* Transitive trust */
    ctx->request.req_tgt = ctx->proxy_tgts[ctx->proxy_tgts_count -1];

    krb5_free_principal(context, ctx->request.req_server);
    ctx->request.req_server = NULL;
    code = krb5int_tgtname(context, &tgt->server->data[1],
                           &proxy->server->data[1], &ctx->request.req_server);
    if (code)
        return code;

    memset(&ctx->request.tgs_in_creds, 0, sizeof(krb5_creds));
    ctx->request.tgs_in_creds.client = ctx->in->in_creds->client;
    ctx->request.tgs_in_creds.server = ctx->request.req_server;

    ctx->state = STATE_CHASE_PROXY_TGT;
    return make_request(context, ctx, 0, NULL);;
}

static krb5_error_code
chase_proxy_tgt(krb5_context context,
                      krb5_s4u2p_creds_context ctx)
{
    krb5_error_code code;

    if (!krb5_principal_compare_any_realm(context, ctx->request.req_server,
                                          ctx->reply_creds->server)) {

        code = check_referral(context, ctx->request.req_tgt, ctx->reply_creds,
                              ctx->proxy_tgts, ctx->proxy_tgts_count);
        if (code)
            return code;

        ctx->proxy_tgts[ctx->proxy_tgts_count] = ctx->reply_creds;
        ctx->reply_creds = NULL;
        ctx->proxy_tgts_count++;

        ctx->request.req_tgt = ctx->proxy_tgts[ctx->proxy_tgts_count -1];

        code = set_principal_realm(context, ctx->request.req_server,
                                   &ctx->request.req_tgt->server->data[1]);
        if (code)
            return code;

        return make_request(context, ctx, 0, NULL);
    }

    return make_xrealm_s4u2proxy_request(context, ctx);
}

static krb5_error_code
get_xrealm_ticket(krb5_context context,
                  krb5_s4u2p_creds_context ctx)
{
    krb5_error_code code;

    if (!krb5_principal_compare(context, ctx->request.req_server,
                                ctx->reply_creds->server))
        return KRB5KRB_AP_WRONG_PRINC;

    code = check_rbcd_support(context, ctx->reply_enc_padata);
    if (code)
        return code;

    return complete(context, ctx);
}

/* Decode and decrypt a TGS reply, and set the reply_code or return error. */
static krb5_error_code
get_creds_from_tgs_reply(krb5_context context, krb5_s4u2p_creds_context ctx,
                         krb5_data *reply)
{
    krb5_error_code code;

    krb5_free_creds(context, ctx->reply_creds);
    ctx->reply_creds = NULL;

    krb5_free_pa_data(context, ctx->reply_enc_padata);
    ctx->reply_enc_padata = NULL;

    code = krb5int_process_tgs_reply(context, ctx->request.fast_state,
                                     reply, ctx->request.req_tgt,
                                     ctx->request.kdcopt,
                                     ctx->request.req_tgt->addresses, NULL,
                                     &ctx->request.tgs_in_creds,
                                     ctx->request.timestamp,
                                     ctx->request.nonce, ctx->request.subkey,
                                     NULL, &ctx->reply_enc_padata,
                                     &ctx->reply_creds);

    return code;
}

/*
 * Fill in the caller out, realm, and flags output variables.  out is filled in
 * with ctx->previous_request, which the caller should set, and realm is filled
 * in with the realm of ctx->cur_tgt.
 */
static krb5_error_code
set_caller_request(krb5_context context, krb5_s4u2p_creds_context ctx,
                   krb5_data *caller_out, krb5_data *caller_realm)
{
    krb5_error_code code;
    const krb5_data *req = &ctx->request.previous_request;
    const krb5_data *realm = &ctx->request.req_tgt->server->data[1];
    krb5_data out_copy = empty_data(), realm_copy = empty_data();

    code = krb5int_copy_data_contents(context, req, &out_copy);
    if (code != 0)
        goto cleanup;
    code = krb5int_copy_data_contents(context, realm, &realm_copy);
    if (code != 0)
        goto cleanup;

    *caller_out = out_copy;
    *caller_realm = realm_copy;
    return 0;

cleanup:
    krb5_free_data_contents(context, &out_copy);
    krb5_free_data_contents(context, &realm_copy);
    return code;
}

/***** API functions *****/

krb5_error_code
k5_gc_s4u2p_init(krb5_context context, k5_tkt_creds_in_data in_data,
              krb5_s4u2p_creds_context *out_ctx)
{
    krb5_error_code code;
    krb5_s4u2p_creds_context ctx;

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
k5_gc_s4u2p_step(krb5_context context, krb5_s4u2p_creds_context ctx,
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
        code = get_creds_from_tgs_reply(context, ctx, in);
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG) {
            code = set_caller_request(context, ctx, out, realm);
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
    else if (ctx->state == STATE_GET_TICKET_OR_REFERRAL)
        code = get_ticket_or_referral(context, ctx);
    else if (ctx->state == STATE_CHASE_SERVICE_TGT)
        code = chase_service_tgt(context, ctx);
    else if (ctx->state == STATE_CHASE_PROXY_TGT)
        code = chase_proxy_tgt(context, ctx);
    else if (ctx->state == STATE_GET_XREALM_TICKET)
        code = get_xrealm_ticket(context, ctx);
    else
        code = EINVAL;

    if (code != 0)
        return code;

    if (ctx->state != STATE_COMPLETE) {
        code = set_caller_request(context, ctx, out, realm);
        if (code)
            return code;
        *need_continue = TRUE;
    } else {
        *reply_creds = ctx->reply_creds;
        ctx->reply_creds = NULL;
    }

    return 0;
}

void
k5_gc_s4u2p_free(krb5_context context, krb5_s4u2p_creds_context ctx)
{
    int i;

    if (ctx == NULL)
        return;
    for (i = 0; i < KRB5_REFERRAL_MAXHOPS; i++) {
        krb5_free_creds(context, ctx->service_tgts[i]);
        krb5_free_creds(context, ctx->proxy_tgts[i]);
    }
    k5_tkt_creds_in_data_free(context, ctx->in);
    krb5int_fast_free_state(context, ctx->request.fast_state);
    krb5_free_principal(context, ctx->request.req_server);
    krb5_free_keyblock(context, ctx->request.subkey);
    krb5_free_data_contents(context, &ctx->request.previous_request);
    krb5_free_creds(context, ctx->reply_creds);
    krb5_free_pa_data(context, ctx->reply_enc_padata);
    free(ctx);

}
