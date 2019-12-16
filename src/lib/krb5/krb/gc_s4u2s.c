
#include "k5-int.h"
#include "int-proto.h"
#include "fast.h"

enum s4u2self_state {
    STATE_BEGIN,
    STATE_AS_CANON_CLIENT_REALM,
    STATE_GET_TGT_TO_CLIENT_REALM,
    STATE_CHASE_BACK_REFERRALS_TO_SELF,
    STATE_COMPLETE
};

struct _krb5_s4u2s_creds_context {
    enum s4u2self_state state; /* What we should do with the next reply */

    k5_tkt_creds_in_data in;    /* Caller-provided initialization data */

    krb5_creds *referral_tgts[KRB5_REFERRAL_MAXHOPS];
    unsigned int referral_tgts_count;

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
complete(krb5_context context, krb5_s4u2s_creds_context ctx)
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
begin(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    return EINVAL;
}

static krb5_error_code
as_canon_client_realm(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    return EINVAL;
}

static krb5_error_code
get_tgt_to_client_realm(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    return EINVAL;
}

static krb5_error_code
chase_back_referrals_to_self(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    return EINVAL;
}

/* Decode and decrypt a TGS reply, and set the reply_code or return error. */
static krb5_error_code
get_creds_from_tgs_reply(krb5_context context, krb5_s4u2s_creds_context ctx,
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
set_caller_request(krb5_context context, krb5_s4u2s_creds_context ctx,
                   krb5_data *caller_out, krb5_data *caller_realm)
{
    krb5_error_code code;
    const krb5_data *req = &ctx->request.previous_request;
    const krb5_data *realm = &ctx->request.req_tgt->server->data[1];
    krb5_data out_copy = empty_data(), realm_copy = empty_data();

    code = krb5int_copy_data_contents(context, req, &out_copy);
    if (code != 0)
        return code;
    code = krb5int_copy_data_contents(context, realm, &realm_copy);
    if (code != 0)
        return code;

    *caller_out = out_copy;
    *caller_realm = realm_copy;
    return 0;
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
    else if (ctx->state == STATE_AS_CANON_CLIENT_REALM)
        code = as_canon_client_realm(context, ctx);
    else if (ctx->state == STATE_GET_TGT_TO_CLIENT_REALM)
        code = get_tgt_to_client_realm(context, ctx);
    else if (ctx->state == STATE_CHASE_BACK_REFERRALS_TO_SELF)
        code = chase_back_referrals_to_self(context, ctx);
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
k5_gc_s4u2s_free(krb5_context context, krb5_s4u2s_creds_context ctx)
{
    int i;

    if (ctx == NULL)
        return;
    for (i = 0; i < KRB5_REFERRAL_MAXHOPS; i++) {
        krb5_free_creds(context, ctx->referral_tgts[i]);
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
