/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Portions Copyright (C) 2008 Novell Inc.
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "gssapiP_krb5.h"

OM_uint32
krb5_gss_inquire_context(minor_status, context_handle, initiator_name,
                         acceptor_name, lifetime_rec, mech_type, ret_flags,
                         locally_initiated, opened)
    OM_uint32 *minor_status;
    gss_ctx_id_t context_handle;
    gss_name_t *initiator_name;
    gss_name_t *acceptor_name;
    OM_uint32 *lifetime_rec;
    gss_OID *mech_type;
    OM_uint32 *ret_flags;
    int *locally_initiated;
    int *opened;
{
    krb5_context context;
    krb5_error_code code;
    krb5_gss_ctx_id_rec *ctx;
    krb5_principal initiator, acceptor;
    krb5_timestamp now;
    krb5_deltat lifetime;

    if (initiator_name)
        *initiator_name = (gss_name_t) NULL;
    if (acceptor_name)
        *acceptor_name = (gss_name_t) NULL;

    /* validate the context handle */
    if (! kg_validate_ctx_id(context_handle)) {
        *minor_status = (OM_uint32) G_VALIDATE_FAILED;
        return(GSS_S_NO_CONTEXT);
    }

    ctx = (krb5_gss_ctx_id_rec *) context_handle;

    if (! ctx->established) {
        *minor_status = KG_CTX_INCOMPLETE;
        return(GSS_S_NO_CONTEXT);
    }

    initiator = NULL;
    acceptor = NULL;
    context = ctx->k5_context;

    if ((code = krb5_timeofday(context, &now))) {
        *minor_status = code;
        save_error_info(*minor_status, context);
        return(GSS_S_FAILURE);
    }

    if ((lifetime = ctx->endtime - now) < 0)
        lifetime = 0;

    if (initiator_name) {
        if ((code = krb5_copy_principal(context,
                                        ctx->initiate?ctx->here:ctx->there,
                                        &initiator))) {
            *minor_status = code;
            save_error_info(*minor_status, context);
            return(GSS_S_FAILURE);
        }
        if (! kg_save_name((gss_name_t) initiator)) {
            krb5_free_principal(context, initiator);
            *minor_status = (OM_uint32) G_VALIDATE_FAILED;
            return(GSS_S_FAILURE);
        }
    }

    if (acceptor_name) {
        if ((code = krb5_copy_principal(context,
                                        ctx->initiate?ctx->there:ctx->here,
                                        &acceptor))) {
            if (initiator) krb5_free_principal(context, initiator);
            *minor_status = code;
            save_error_info(*minor_status, context);
            return(GSS_S_FAILURE);
        }
        if (! kg_save_name((gss_name_t) acceptor)) {
            krb5_free_principal(context, acceptor);
            if (initiator) {
                kg_delete_name((gss_name_t) initiator);
                krb5_free_principal(context, initiator);
            }
            *minor_status = (OM_uint32) G_VALIDATE_FAILED;
            return(GSS_S_FAILURE);
        }
    }

    if (initiator_name)
        *initiator_name = (gss_name_t) initiator;

    if (acceptor_name)
        *acceptor_name = (gss_name_t) acceptor;

    if (lifetime_rec)
        *lifetime_rec = lifetime;

    if (mech_type)
        *mech_type = (gss_OID) ctx->mech_used;

    if (ret_flags)
        *ret_flags = ctx->gss_flags;

    if (locally_initiated)
        *locally_initiated = ctx->initiate;

    if (opened)
        *opened = ctx->established;

    *minor_status = 0;
    return((lifetime == 0)?GSS_S_CONTEXT_EXPIRED:GSS_S_COMPLETE);
}

OM_uint32 KRB5_CALLCONV
gss_krb5int_get_subkey(
   const gss_ctx_id_t context_handle,
   krb5_keyblock **key)
{
   krb5_gss_ctx_id_rec *ctx;
   int code;

   *key = NULL;

   /* validate the context handle */
   if (! kg_validate_ctx_id(context_handle)) {
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (! ctx->established) {
      return(GSS_S_NO_CONTEXT);
   }

   code = krb5_copy_keyblock(ctx->k5_context,
			     ctx->have_acceptor_subkey ?
				ctx->acceptor_subkey : ctx->subkey,
			     key);
   if (code) {
     return (GSS_S_FAILURE);
   }

   return (GSS_S_COMPLETE);
}

OM_uint32 KRB5_CALLCONV
gss_krb5int_extract_authz_data_from_sec_context(
   OM_uint32 *minor_status,
   const gss_ctx_id_t context_handle,
   int ad_type,
   gss_buffer_set_t ad_data)
{
   OM_uint32 major_status;
   krb5_gss_ctx_id_rec *ctx;
   krb5_authdata **p;
   gss_buffer_t tmp;

   /* validate the context handle */
   if (!kg_validate_ctx_id(context_handle)) {
      return (GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (!ctx->established) {
      return (GSS_S_NO_CONTEXT);
   }

   major_status = GSS_S_FAILURE;
   *minor_status = ENOENT;

   ad_data->count = 0;
   ad_data->elements = NULL;

   /*
    * This is an internal API so let's just return a pointer
    * into the data and have the shim copy it.
    */
   if (ctx->authdata != NULL) {
      major_status = GSS_S_COMPLETE;
      *minor_status = 0;
      for (p = ctx->authdata; *p != NULL; p++) {
	 if ((*p)->ad_type == ad_type) {
	    ad_data->count++;
	    tmp = (gss_buffer_desc *)realloc(ad_data->elements,
					     ad_data->count * sizeof(gss_buffer_desc));
	    if (tmp == NULL) {
		if (ad_data->elements != NULL)
		    free(ad_data->elements);
		ad_data->count = 0;
		ad_data->elements = NULL;
		*minor_status = ENOMEM;
		major_status = GSS_S_FAILURE;
		break;
	    }
	    ad_data->elements = tmp;
	    ad_data->elements[ad_data->count-1].length = (*p)->length;
	    ad_data->elements[ad_data->count-1].value = (*p)->contents;
	 }
      }
   }
       
   return (major_status);
}
