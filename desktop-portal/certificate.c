/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
 */

#include "config.h"

#include "certificate.h"

#include <string.h>

#include <gio/gio.h>

#include "xdp-app-info.h"
#include "xdp-context.h"
#include "xdp-experimental-dbus.h"
#include "xdp-impl-experimental-dbus.h"
#include "xdp-permissions.h"
#include "xdp-portal-config.h"
#include "xdp-request-dex.h"
#include "xdp-session-dex.h"
#include "xdp-utils.h"

/* A grant always expires. The application asks for a lifetime, the portal
 * decides one: the request is a ceiling, never a floor. */
#define CERTIFICATE_DEFAULT_GRANT_LIFETIME 300
#define CERTIFICATE_MAX_GRANT_LIFETIME 3600

/* And renewal has an end. RenewGrant sets the expiry relative to now, so
 * without an absolute deadline a caller renewing every few minutes keeps one
 * consent alive forever. Eight hours from the moment the user consented, which
 * is eight times the per-renewal ceiling and one working day. */
#define CERTIFICATE_MAX_GRANT_TOTAL_LIFETIME (8 * CERTIFICATE_MAX_GRANT_LIFETIME)

static uint32_t
certificate_max_total_lifetime (void)
{
  const char *env =
    g_getenv ("XDG_DESKTOP_PORTAL_TEST_CERTIFICATE_MAX_TOTAL_LIFETIME");
  uint64_t seconds;

  if (env && g_ascii_string_to_unsigned (env, 10, 1, G_MAXUINT32, &seconds, NULL))
    return (uint32_t) seconds;

  return CERTIFICATE_MAX_GRANT_TOTAL_LIFETIME;
}

/* Signing or decrypting a whole file through the bus is not what this is for. */
#define CERTIFICATE_MAX_DATA_SIZE (1024 * 1024)

/* What the portal accepts as a purpose. There is deliberately no purpose
 * meaning "anything". */
static const char * const certificate_purposes[] = {
  "client_auth",
  "signing",
  "email",
  "ssh",
  NULL,
};

static const char * const certificate_operations[] = {
  "sign",
  "decrypt",
  NULL,
};

/* The portal's mechanism allow list. A grant's mechanisms are this list
 * intersected with what the backend said the key can do. */
static const char * const certificate_mechanisms[] = {
  "RSA_PKCS1_V1_5",
  "RSA_PSS",
  "RSA_OAEP",
  "ECDSA",
  NULL,
};

static const char * const certificate_sign_mechanisms[] = {
  "RSA_PKCS1_V1_5",
  "RSA_PSS",
  "ECDSA",
  NULL,
};

/* PKCS#1 v1.5 decryption is a Bleichenbacher oracle over the card's key: the
 * caller learns from the response alone whether the padding was well formed,
 * and can recover a plaintext, or forge a signature, one query at a time.
 * There is no rate limit here that would make that safe, so v1.5 is a signing
 * mechanism only and OAEP is the only way to decrypt. */
static const char * const certificate_decrypt_mechanisms[] = {
  "RSA_OAEP",
  NULL,
};

/* The digest sizes are the point rather than a detail: 'data' is a digest of
 * the named hash, so its length is not a free parameter, and a caller that
 * cannot name the hash is not signing a digest. */
typedef struct _CertificateHash
{
  const char *name;
  size_t digest_size;
} CertificateHash;

static const CertificateHash certificate_hashes[] = {
  { "SHA1", 20 },
  { "SHA224", 28 },
  { "SHA256", 32 },
  { "SHA384", 48 },
  { "SHA512", 64 },
};

static const CertificateHash *
certificate_hash_lookup (const char *name)
{
  if (!name)
    return NULL;

  for (size_t i = 0; i < G_N_ELEMENTS (certificate_hashes); i++)
    {
      /* "SHA-256" and "SHA256" are both in wide use; refusing one of the two
       * spellings is a papercut, not a check. */
      g_autofree char *dashed =
        g_strdup_printf ("SHA-%s", certificate_hashes[i].name + 3);

      if (g_ascii_strcasecmp (name, certificate_hashes[i].name) == 0 ||
          g_ascii_strcasecmp (name, dashed) == 0)
        return &certificate_hashes[i];
    }

  return NULL;
}

static const char * const certificate_interaction_modes[] = {
  "required",
  "allowed",
  "forbidden",
  NULL,
};

/* Everything the frontend knows about a live grant. None of it grows after
 * AcquireCredential. */
typedef struct _CertificateGrant
{
  gboolean acquired;
  char *grant_id;
  uint64_t expires_at;
  /* The absolute end of this consent. Set once, when the user consented, and
   * never moved by RenewGrant. */
  uint64_t consent_deadline;
  GStrv permitted_operations;
  GStrv supported_mechanisms;
} CertificateGrant;

static void
certificate_grant_free (CertificateGrant *grant)
{
  g_clear_pointer (&grant->grant_id, g_free);
  g_clear_pointer (&grant->permitted_operations, g_strfreev);
  g_clear_pointer (&grant->supported_mechanisms, g_strfreev);
  g_free (grant);
}

struct _XdpCertificate
{
  XdpDbusExperimentalCertificateSkeleton parent_instance;

  XdpContext *context;
  XdpDbusExperimentalImplCertificate *impl;
  XdpSessionDexStore *sessions;
  GHashTable *grants; /* char *session_handle -> CertificateGrant */
};

#define XDP_TYPE_CERTIFICATE (xdp_certificate_get_type ())
G_DECLARE_FINAL_TYPE (XdpCertificate,
                      xdp_certificate,
                      XDP, CERTIFICATE,
                      XdpDbusExperimentalCertificateSkeleton)

static void xdp_certificate_iface_init (XdpDbusExperimentalCertificateIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (XdpCertificate,
                               xdp_certificate,
                               XDP_DBUS_EXPERIMENTAL_TYPE_CERTIFICATE_SKELETON,
                               G_IMPLEMENT_INTERFACE (XDP_DBUS_EXPERIMENTAL_TYPE_CERTIFICATE,
                                                      xdp_certificate_iface_init))

static gboolean
strv_contains (const char * const *strv,
               const char         *needle)
{
  return strv != NULL && needle != NULL && g_strv_contains (strv, needle);
}

/* Keep only the values which are in both lists, in the order of the allow
 * list. A backend that returns more than it may does not get more. */
static GStrv
strv_intersect (const char * const *allowed,
                const char * const *reported)
{
  g_autoptr(GStrvBuilder) builder = g_strv_builder_new ();

  for (size_t i = 0; allowed[i]; i++)
    {
      if (reported && g_strv_contains (reported, allowed[i]))
        g_strv_builder_add (builder, allowed[i]);
    }

  return g_strv_builder_end (builder);
}

static XdpSessionDex *
lookup_session (XdpCertificate  *certificate,
                const char      *session_handle,
                XdpAppInfo      *app_info,
                GError         **error)
{
  XdpSessionDex *session;

  session = xdp_session_dex_store_lookup_session (certificate->sessions,
                                                  session_handle,
                                                  app_info);
  if (!session || xdp_session_dex_is_closed (session))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_NOT_FOUND,
                           "Invalid session");
      return NULL;
    }

  return session;
}

/* Everything the frontend owns about a live grant is checked here: that the
 * grant exists, that it has not expired, that it permits this operation and
 * this mechanism. */
static gboolean
check_grant (CertificateGrant  *grant,
             const char        *operation,
             const char        *mechanism,
             GError           **error)
{
  if (!grant || !grant->acquired)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                           "The session does not hold a credential");
      return FALSE;
    }

  if (grant->expires_at <= (uint64_t) (g_get_real_time () / G_USEC_PER_SEC))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                           "The grant has expired");
      return FALSE;
    }

  if (operation &&
      !strv_contains ((const char * const *) grant->permitted_operations,
                      operation))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                   "The grant does not permit '%s'", operation);
      return FALSE;
    }

  if (mechanism &&
      !strv_contains ((const char * const *) grant->supported_mechanisms,
                      mechanism))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                   "The grant does not permit the mechanism '%s'", mechanism);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_purpose (const char  *key,
                  GVariant    *value,
                  GVariant    *options,
                  gpointer     user_data,
                  GError     **error)
{
  const char *purpose = g_variant_get_string (value, NULL);

  if (!strv_contains (certificate_purposes, purpose))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown purpose '%s'", purpose);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_interaction_mode (const char  *key,
                           GVariant    *value,
                           GVariant    *options,
                           gpointer     user_data,
                           GError     **error)
{
  const char *mode = g_variant_get_string (value, NULL);

  if (!strv_contains (certificate_interaction_modes, mode))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown interaction_mode '%s'", mode);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_reason (const char  *key,
                 GVariant    *value,
                 GVariant    *options,
                 gpointer     user_data,
                 GError     **error)
{
  const char *reason = g_variant_get_string (value, NULL);

  if (g_utf8_strlen (reason, -1) > 256)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Not accepting overly long reasons");
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_operation_mechanism (const char          *mechanism,
                              const char * const  *allowed,
                              const char          *operation,
                              GError             **error)
{
  if (!strv_contains (certificate_mechanisms, mechanism))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown mechanism '%s'", mechanism);
      return FALSE;
    }

  if (!strv_contains (allowed, mechanism))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The mechanism '%s' may not be used to %s",
                   mechanism, operation);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_sign_mechanism (const char  *key,
                         GVariant    *value,
                         GVariant    *options,
                         gpointer     user_data,
                         GError     **error)
{
  return validate_operation_mechanism (g_variant_get_string (value, NULL),
                                       certificate_sign_mechanisms,
                                       "sign", error);
}

static gboolean
validate_decrypt_mechanism (const char  *key,
                            GVariant    *value,
                            GVariant    *options,
                            gpointer     user_data,
                            GError     **error)
{
  return validate_operation_mechanism (g_variant_get_string (value, NULL),
                                       certificate_decrypt_mechanisms,
                                       "decrypt", error);
}

static gboolean
validate_data (const char  *key,
               GVariant    *value,
               GVariant    *options,
               gpointer     user_data,
               GError     **error)
{
  if (g_variant_get_size (value) > CERTIFICATE_MAX_DATA_SIZE)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Not accepting overly large data");
      return FALSE;
    }

  return TRUE;
}

static XdpOptionKey create_session_options[] = {
};

static XdpOptionKey acquire_credential_options[] = {
  { "activation_token", G_VARIANT_TYPE_STRING, NULL },
  { "purpose", G_VARIANT_TYPE_STRING, validate_purpose },
  { "certificate_filter", G_VARIANT_TYPE_VARDICT, NULL },
  { "operation_policy", G_VARIANT_TYPE_VARDICT, NULL },
  { "interaction_mode", G_VARIANT_TYPE_STRING, validate_interaction_mode },
  { "reason", G_VARIANT_TYPE_STRING, validate_reason },
};

static XdpOptionKey sign_options[] = {
  { "mechanism", G_VARIANT_TYPE_STRING, validate_sign_mechanism },
  { "parameters", G_VARIANT_TYPE_VARDICT, NULL },
  { "data", G_VARIANT_TYPE_BYTESTRING, validate_data },
};

static XdpOptionKey decrypt_options[] = {
  { "mechanism", G_VARIANT_TYPE_STRING, validate_decrypt_mechanism },
  { "parameters", G_VARIANT_TYPE_VARDICT, NULL },
  { "ciphertext", G_VARIANT_TYPE_BYTESTRING, validate_data },
};

/* An OAEP label is a domain separator, not a payload. */
#define CERTIFICATE_MAX_LABEL_SIZE 256

static const char * const certificate_signature_encodings[] = {
  "raw",
  "der",
  NULL,
};

/* 'data' is a digest and nothing else: the caller names the hash, and the
 * length has to agree with it. That refuses a signature over bytes the caller
 * did not hash, and refuses raw v1.5 padding of an arbitrary blob; it does not
 * make Sign anything less than a signing capability over whatever the caller
 * hashes. The backend enforces this too, but it is a property of the interface
 * rather than of one backend, so it is enforced here as well. */
static gboolean
check_sign_parameters (GVariant  *options,
                       GError   **error)
{
  g_autoptr(GVariant) parameters = NULL;
  g_autoptr(GVariant) data = NULL;
  const CertificateHash *hash;
  const char *hash_name = NULL;
  const char *encoding = NULL;

  parameters = g_variant_lookup_value (options, "parameters",
                                       G_VARIANT_TYPE_VARDICT);

  if (!parameters ||
      !g_variant_lookup (parameters, "hash", "&s", &hash_name))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "A 'hash' parameter is required: 'data' is a "
                           "digest, and the portal has to know which one");
      return FALSE;
    }

  hash = certificate_hash_lookup (hash_name);
  if (!hash)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown hash '%s'", hash_name);
      return FALSE;
    }

  data = g_variant_lookup_value (options, "data", G_VARIANT_TYPE_BYTESTRING);
  if (data && g_variant_get_size (data) != hash->digest_size)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The 'data' must be a %s digest of %" G_GSIZE_FORMAT
                   " bytes, not %" G_GSIZE_FORMAT,
                   hash->name, hash->digest_size, g_variant_get_size (data));
      return FALSE;
    }

  /* PRESENT WITH THE WRONG TYPE IS AN ERROR, NEVER ABSENT.
   * g_variant_lookup (..., "&s", ...) returns FALSE for a key that is there
   * holding a uint32, and the caller would then get the default encoding it
   * did not ask for. 'label' below is already checked this way. */
  if (!g_variant_lookup (parameters, "signature_encoding", "&s", &encoding) &&
      xdp_variant_contains_key (parameters, "signature_encoding"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Expected type 's' for parameter 'signature_encoding'");
      return FALSE;
    }

  if (encoding && !strv_contains (certificate_signature_encodings, encoding))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown signature_encoding '%s'", encoding);
      return FALSE;
    }

  return TRUE;
}

/* RSA_OAEP is the only decryption mechanism, and its parameters decide what
 * the card is asked to do, so they are checked here rather than forwarded and
 * hoped about. The backend checks them again against the key. */
static gboolean
check_decrypt_parameters (GVariant  *options,
                          GError   **error)
{
  g_autoptr(GVariant) parameters = NULL;
  g_autoptr(GVariant) label = NULL;
  const CertificateHash *hash;
  const char *hash_name = NULL;
  const char *mgf1_hash_name = NULL;

  parameters = g_variant_lookup_value (options, "parameters",
                                       G_VARIANT_TYPE_VARDICT);

  if (!parameters ||
      !g_variant_lookup (parameters, "hash", "&s", &hash_name))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "RSA_OAEP needs a 'hash' parameter");
      return FALSE;
    }

  hash = certificate_hash_lookup (hash_name);
  if (!hash)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown hash '%s'", hash_name);
      return FALSE;
    }

  /* PKCS#1 lets MGF1 use a different hash than OAEP itself. Nothing asks for
   * that on purpose, and the value goes into the module's mechanism
   * parameter, so the two have to agree. */
  if (!g_variant_lookup (parameters, "mgf1_hash", "&s", &mgf1_hash_name) &&
      xdp_variant_contains_key (parameters, "mgf1_hash"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Expected type 's' for parameter 'mgf1_hash'");
      return FALSE;
    }

  if (mgf1_hash_name && certificate_hash_lookup (mgf1_hash_name) != hash)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The 'mgf1_hash' must name the same hash as 'hash', "
                   "not '%s'", mgf1_hash_name);
      return FALSE;
    }

  label = g_variant_lookup_value (parameters, "label",
                                  G_VARIANT_TYPE_BYTESTRING);
  if (!label && xdp_variant_contains_key (parameters, "label"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Expected type 'ay' for parameter 'label'");
      return FALSE;
    }

  if (label && g_variant_get_size (label) > CERTIFICATE_MAX_LABEL_SIZE)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Not accepting an overly large 'label'");
      return FALSE;
    }

  return TRUE;
}

static void
on_session_closed (XdpSessionDex *session,
                   gpointer       user_data)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (user_data);

  g_hash_table_remove (certificate->grants,
                       xdp_session_dex_get_object_path (session));
}

static gboolean
handle_create_session (XdpDbusExperimentalCertificate *object,
                       GDBusMethodInvocation          *invocation,
                       GVariant                       *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(XdpSessionDex) session = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;

  {
    g_auto(GVariantBuilder) options_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);

    if (!xdp_filter_options (arg_options,
                             &options_builder,
                             create_session_options,
                             G_N_ELEMENTS (create_session_options),
                             NULL,
                             &error))
      {
        g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                                error);
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }

    options = g_variant_ref_sink (g_variant_builder_end (&options_builder));
  }

  request = dex_await_object (xdp_request_dex_new (certificate->context,
                                                   app_info,
                                                   G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (certificate->impl),
                                                   arg_options),
                              &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!xdp_request_dex_export (request, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  session = dex_await_object (xdp_session_dex_new (certificate->context,
                                                   app_info,
                                                   G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (certificate->impl),
                                                   arg_options),
                              &error);
  if (!session)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  xdp_dbus_experimental_certificate_complete_create_session (
    object,
    g_steal_pointer (&invocation),
    xdp_request_dex_get_object_path (request));

  {
    g_autoptr(XdpDbusExperimentalImplCertificateCreateSessionResult) result = NULL;
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    XdgDesktopPortalResponseEnum response;

    result = dex_await_boxed (
      xdp_dbus_experimental_impl_certificate_call_create_session_future (
        certificate->impl,
        xdp_request_dex_get_object_path (request),
        xdp_session_dex_get_object_path (session),
        xdp_app_info_get_id (app_info),
        options),
      &error);

    if (result && result->response == XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
      {
        const char *session_handle = xdp_session_dex_get_object_path (session);

        response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;

        g_variant_builder_add (&results_builder, "{sv}",
                               "session_handle",
                               g_variant_new_object_path (session_handle));

        g_hash_table_insert (certificate->grants,
                             g_strdup (session_handle),
                             g_new0 (CertificateGrant, 1));

        g_signal_connect_object (session, "session-closed",
                                 G_CALLBACK (on_session_closed),
                                 certificate,
                                 G_CONNECT_DEFAULT);

        xdp_session_dex_store_take_session (certificate->sessions,
                                            g_steal_pointer (&session));
      }
    else if (result)
      {
        response = result->response;
      }
    else
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }

    xdp_request_dex_emit_response (request,
                                   response,
                                   g_variant_builder_end (&results_builder));
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* How much the app id can be trusted. The backend is expected to make the
 * difference visible; it never re-derives it. */
static const char *
app_identity_level (XdpAppInfo *app_info)
{
  if (!xdp_app_info_is_host (app_info))
    return "verified_sandboxed";

  if (g_strcmp0 (xdp_app_info_get_id (app_info), "") != 0)
    return "derived_host";

  return "unidentified";
}

static GVariant *
acquire_credential_validate_options (XdpAppInfo  *app_info,
                                     GVariant    *arg_options,
                                     uint32_t    *out_lifetime,
                                     gboolean    *out_selection_memory,
                                     GError     **error)
{
  g_auto(GVariantBuilder) options =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  uint32_t lifetime = CERTIFICATE_DEFAULT_GRANT_LIFETIME;
  gboolean allow_selection_memory = FALSE;

  if (!xdp_variant_contains_key (arg_options, "purpose"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "A purpose is required");
      return NULL;
    }

  if (!xdp_filter_options (arg_options,
                           &options,
                           acquire_credential_options,
                           G_N_ELEMENTS (acquire_credential_options),
                           NULL,
                           error))
    return NULL;

  if (g_variant_lookup (arg_options, "requested_lifetime", "u", &lifetime))
    {
      if (lifetime == 0)
        {
          g_set_error_literal (error,
                               XDG_DESKTOP_PORTAL_ERROR,
                               XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                               "A requested_lifetime of zero is not a lifetime");
          return NULL;
        }

      /* A ceiling request, not a floor. */
      lifetime = MIN (lifetime, CERTIFICATE_MAX_GRANT_LIFETIME);
    }
  else if (xdp_variant_contains_key (arg_options, "requested_lifetime"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Expected type 'u' for option 'requested_lifetime'");
      return NULL;
    }

  if (!g_variant_lookup (arg_options, "allow_selection_memory", "b",
                         &allow_selection_memory) &&
      xdp_variant_contains_key (arg_options, "allow_selection_memory"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Expected type 'b' for option 'allow_selection_memory'");
      return NULL;
    }

  /* Selection memory needs an identity to key on. An application whose
   * identity could not be verified does not get one. */
  if (g_strcmp0 (app_identity_level (app_info), "unidentified") == 0)
    allow_selection_memory = FALSE;

  /* The backend is told what the frontend decided, not what was asked for. */
  g_variant_builder_add (&options, "{sv}",
                         "lifetime", g_variant_new_uint32 (lifetime));
  g_variant_builder_add (&options, "{sv}",
                         "app_identity_level",
                         g_variant_new_string (app_identity_level (app_info)));
  /* Whether the backend may offer to remember the selection at all. The
   * frontend is the only one that can know: it holds the permission store
   * and it is the one that applied the identity rule above. A backend that
   * offers the choice anyway makes a promise nothing here will keep. */
  g_variant_builder_add (&options, "{sv}",
                         "allow_selection_memory",
                         g_variant_new_boolean (allow_selection_memory));

  *out_lifetime = lifetime;
  *out_selection_memory = allow_selection_memory;

  return g_variant_ref_sink (g_variant_builder_end (&options));
}

static GVariant *
options_with_preselect (GVariant   *options,
                        const char *certificate_id)
{
  g_auto(GVariantBuilder) builder =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  GVariantIter iter;
  const char *key;
  GVariant *value;

  g_variant_iter_init (&iter, options);
  while (g_variant_iter_next (&iter, "{&sv}", &key, &value))
    {
      g_variant_builder_add (&builder, "{sv}", key, value);
      g_variant_unref (value);
    }

  g_variant_builder_add (&builder, "{sv}",
                         "preselect_certificate",
                         g_variant_new_string (certificate_id));

  return g_variant_ref_sink (g_variant_builder_end (&builder));
}

static gboolean
handle_acquire_credential (XdpDbusExperimentalCertificate *object,
                           GDBusMethodInvocation          *invocation,
                           const char                     *arg_session_handle,
                           const char                     *arg_parent_window,
                           GVariant                       *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  CertificateGrant *grant;
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  gboolean allow_selection_memory = FALSE;
  uint32_t lifetime = CERTIFICATE_DEFAULT_GRANT_LIFETIME;

  options = acquire_credential_validate_options (app_info,
                                                 arg_options,
                                                 &lifetime,
                                                 &allow_selection_memory,
                                                 &error);
  if (!options)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!lookup_session (certificate, arg_session_handle, app_info, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (allow_selection_memory)
    {
      g_auto(GStrv) permissions = NULL;

      permissions = dex_await_boxed (
        xdp_permissions_get_future (app_info,
                                    CERTIFICATE_PERMISSION_TABLE,
                                    xdp_app_info_get_id (app_info)),
        NULL);

      if (permissions && permissions[0])
        {
          g_autoptr(GVariant) old_options = g_steal_pointer (&options);

          options = options_with_preselect (old_options, permissions[0]);
        }
    }

  request = dex_await_object (xdp_request_dex_new (certificate->context,
                                                   app_info,
                                                   G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (certificate->impl),
                                                   arg_options),
                              &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!xdp_request_dex_export (request, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  xdp_dbus_experimental_certificate_complete_acquire_credential (
    object,
    g_steal_pointer (&invocation),
    xdp_request_dex_get_object_path (request));

  {
    g_autoptr(XdpDbusExperimentalImplCertificateAcquireCredentialResult) result = NULL;
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    XdgDesktopPortalResponseEnum response;

    result = dex_await_boxed (
      xdp_dbus_experimental_impl_certificate_call_acquire_credential_future (
        certificate->impl,
        xdp_request_dex_get_object_path (request),
        arg_session_handle,
        xdp_app_info_get_id (app_info),
        arg_parent_window,
        options),
      &error);

    /* The session can have gone away while the user was making up their
     * mind. */
    grant = g_hash_table_lookup (certificate->grants, arg_session_handle);

    if (!result)
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else if (result->response != XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
      {
        response = result->response;
      }
    else if (!grant)
      {
        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else
      {
        static const char *passthrough_keys[] = {
          "certificate_der", "chain_der", "chain_status", "token_display",
          "key_type", "key_size", "key_curve", "may_prompt_later",
        };
        g_auto(GStrv) reported_mechanisms = NULL;
        g_auto(GStrv) reported_operations = NULL;
        const char *certificate_id = NULL;
        gboolean remember_selection = FALSE;

        for (size_t i = 0; i < G_N_ELEMENTS (passthrough_keys); i++)
          {
            g_autoptr(GVariant) value = NULL;

            value = g_variant_lookup_value (result->results,
                                            passthrough_keys[i],
                                            NULL);
            if (value)
              g_variant_builder_add (&results_builder, "{sv}",
                                     passthrough_keys[i], value);
          }

        g_variant_lookup (result->results, "supported_mechanisms", "^as",
                          &reported_mechanisms);
        g_variant_lookup (result->results, "permitted_operations", "^as",
                          &reported_operations);

        g_clear_pointer (&grant->supported_mechanisms, g_strfreev);
        g_clear_pointer (&grant->permitted_operations, g_strfreev);
        grant->supported_mechanisms =
          strv_intersect (certificate_mechanisms,
                          (const char * const *) reported_mechanisms);
        grant->permitted_operations =
          strv_intersect (certificate_operations,
                          (const char * const *) reported_operations);

        {
          uint64_t now = (uint64_t) (g_get_real_time () / G_USEC_PER_SEC);

          grant->acquired = TRUE;
          grant->consent_deadline = now + certificate_max_total_lifetime ();
          grant->expires_at = MIN (now + lifetime, grant->consent_deadline);
        }
        g_clear_pointer (&grant->grant_id, g_free);
        grant->grant_id = g_uuid_string_random ();

        g_variant_builder_add (&results_builder, "{sv}",
                               "grant_id",
                               g_variant_new_string (grant->grant_id));
        g_variant_builder_add (&results_builder, "{sv}",
                               "supported_mechanisms",
                               g_variant_new_strv (
                                 (const char * const *) grant->supported_mechanisms,
                                 -1));
        g_variant_builder_add (&results_builder, "{sv}",
                               "permitted_operations",
                               g_variant_new_strv (
                                 (const char * const *) grant->permitted_operations,
                                 -1));
        g_variant_builder_add (&results_builder, "{sv}",
                               "expires_at",
                               g_variant_new_uint64 (grant->expires_at));

        /* certificate_id and remember_selection are the backend's half of
         * selection memory. Whether anything is remembered is ours. */
        g_variant_lookup (result->results, "remember_selection", "b",
                          &remember_selection);
        if (allow_selection_memory && remember_selection &&
            g_variant_lookup (result->results, "certificate_id", "&s",
                              &certificate_id))
          {
            const char *permissions[] = { certificate_id, NULL };

            dex_await (xdp_permissions_set_future (app_info,
                                                   CERTIFICATE_PERMISSION_TABLE,
                                                   xdp_app_info_get_id (app_info),
                                                   permissions),
                       NULL);
          }

        response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;
      }

    xdp_request_dex_emit_response (request,
                                   response,
                                   g_variant_builder_end (&results_builder));
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

typedef enum _XdpCertificateOperation
{
  XDP_CERTIFICATE_OPERATION_SIGN,
  XDP_CERTIFICATE_OPERATION_DECRYPT,
} XdpCertificateOperation;

static gboolean
handle_key_operation (XdpDbusExperimentalCertificate *object,
                      GDBusMethodInvocation          *invocation,
                      XdpCertificateOperation         operation,
                      const char                     *arg_session_handle,
                      const char                     *arg_parent_window,
                      GVariant                       *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  gboolean is_sign = operation == XDP_CERTIFICATE_OPERATION_SIGN;
  const char *operation_name = is_sign ? "sign" : "decrypt";
  const char *data_key = is_sign ? "data" : "ciphertext";
  const char *result_key = is_sign ? "signature" : "plaintext";
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  const char *mechanism = NULL;
  const char *operation_id = NULL;

  {
    g_auto(GVariantBuilder) options_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);

    if (!xdp_filter_options (arg_options,
                             &options_builder,
                             is_sign ? sign_options : decrypt_options,
                             is_sign ? G_N_ELEMENTS (sign_options)
                                     : G_N_ELEMENTS (decrypt_options),
                             NULL,
                             &error))
      {
        g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                                error);
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }

    options = g_variant_ref_sink (g_variant_builder_end (&options_builder));
  }

  if (!g_variant_lookup (options, "mechanism", "&s", &mechanism))
    {
      g_dbus_method_invocation_return_error_literal (g_steal_pointer (&invocation),
                                                     XDG_DESKTOP_PORTAL_ERROR,
                                                     XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                                                     "A mechanism is required");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!xdp_variant_contains_key (options, data_key))
    {
      g_dbus_method_invocation_return_error (g_steal_pointer (&invocation),
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                                             "No '%s' given", data_key);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (is_sign ? !check_sign_parameters (options, &error)
              : !check_decrypt_parameters (options, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!lookup_session (certificate, arg_session_handle, app_info, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!check_grant (g_hash_table_lookup (certificate->grants,
                                         arg_session_handle),
                    operation_name, mechanism, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_lookup (arg_options, "operation_id", "&s", &operation_id);

  request = dex_await_object (xdp_request_dex_new (certificate->context,
                                                   app_info,
                                                   G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (certificate->impl),
                                                   arg_options),
                              &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!xdp_request_dex_export (request, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (is_sign)
    xdp_dbus_experimental_certificate_complete_sign (
      object,
      g_steal_pointer (&invocation),
      xdp_request_dex_get_object_path (request));
  else
    xdp_dbus_experimental_certificate_complete_decrypt (
      object,
      g_steal_pointer (&invocation),
      xdp_request_dex_get_object_path (request));

  {
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    g_autoptr(GVariant) impl_results = NULL;
    XdgDesktopPortalResponseEnum response;
    uint32_t impl_response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;

    if (is_sign)
      {
        g_autoptr(XdpDbusExperimentalImplCertificateSignResult) result = NULL;

        result = dex_await_boxed (
          xdp_dbus_experimental_impl_certificate_call_sign_future (
            certificate->impl,
            xdp_request_dex_get_object_path (request),
            arg_session_handle,
            xdp_app_info_get_id (app_info),
            arg_parent_window,
            options),
          &error);

        if (result)
          {
            impl_response = result->response;
            impl_results = g_variant_ref (result->results);
          }
      }
    else
      {
        g_autoptr(XdpDbusExperimentalImplCertificateDecryptResult) result = NULL;

        result = dex_await_boxed (
          xdp_dbus_experimental_impl_certificate_call_decrypt_future (
            certificate->impl,
            xdp_request_dex_get_object_path (request),
            arg_session_handle,
            xdp_app_info_get_id (app_info),
            arg_parent_window,
            options),
          &error);

        if (result)
          {
            impl_response = result->response;
            impl_results = g_variant_ref (result->results);
          }
      }

    if (!impl_results)
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else
      {
        response = impl_response;

        if (response == XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
          {
            g_autoptr(GVariant) value = NULL;

            value = g_variant_lookup_value (impl_results, result_key,
                                            G_VARIANT_TYPE_BYTESTRING);
            if (value)
              {
                g_variant_builder_add (&results_builder, "{sv}",
                                       result_key, value);
              }
            else
              {
                g_warning ("Backend did not return '%s'", result_key);
                response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
              }
          }
      }

    if (operation_id)
      g_variant_builder_add (&results_builder, "{sv}",
                             "operation_id",
                             g_variant_new_string (operation_id));

    xdp_request_dex_emit_response (request,
                                   response,
                                   g_variant_builder_end (&results_builder));
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_sign (XdpDbusExperimentalCertificate *object,
             GDBusMethodInvocation          *invocation,
             const char                     *arg_session_handle,
             const char                     *arg_parent_window,
             GVariant                       *arg_options)
{
  return handle_key_operation (object, invocation,
                               XDP_CERTIFICATE_OPERATION_SIGN,
                               arg_session_handle, arg_parent_window,
                               arg_options);
}

static gboolean
handle_decrypt (XdpDbusExperimentalCertificate *object,
                GDBusMethodInvocation          *invocation,
                const char                     *arg_session_handle,
                const char                     *arg_parent_window,
                GVariant                       *arg_options)
{
  return handle_key_operation (object, invocation,
                               XDP_CERTIFICATE_OPERATION_DECRYPT,
                               arg_session_handle, arg_parent_window,
                               arg_options);
}

/* Renewal is decided entirely here: no window is shown, the backend is not
 * asked, and the grant never gains operations or mechanisms it did not have. */
static gboolean
handle_renew_grant (XdpDbusExperimentalCertificate *object,
                    GDBusMethodInvocation          *invocation,
                    const char                     *arg_session_handle,
                    GVariant                       *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  CertificateGrant *grant;
  g_autoptr(GError) error = NULL;
  uint32_t lifetime = CERTIFICATE_DEFAULT_GRANT_LIFETIME;

  if (g_variant_lookup (arg_options, "requested_lifetime", "u", &lifetime))
    lifetime = MIN (lifetime, CERTIFICATE_MAX_GRANT_LIFETIME);

  if (!lookup_session (certificate, arg_session_handle, app_info, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  grant = g_hash_table_lookup (certificate->grants, arg_session_handle);

  /* Before the ordinary checks, because the expiry a passed deadline produces
   * would otherwise report itself as "expired" — which invites another
   * renewal. A renewal past the deadline is refused rather than clamped: the
   * caller has to acquire a credential again, which means asking the user. */
  if (grant && grant->acquired &&
      (uint64_t) (g_get_real_time () / G_USEC_PER_SEC) >= grant->consent_deadline)
    {
      g_dbus_method_invocation_return_error_literal (
        g_steal_pointer (&invocation),
        XDG_DESKTOP_PORTAL_ERROR,
        XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
        "The grant has reached the maximum total lifetime of its consent");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!check_grant (grant, NULL, NULL, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  grant->expires_at =
    MIN ((uint64_t) (g_get_real_time () / G_USEC_PER_SEC) + lifetime,
         grant->consent_deadline);

  xdp_dbus_experimental_certificate_complete_renew_grant (
    object,
    g_steal_pointer (&invocation),
    grant->expires_at);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_release_grant (XdpDbusExperimentalCertificate *object,
                      GDBusMethodInvocation          *invocation,
                      const char                     *arg_session_handle)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  XdpSessionDex *session;

  /* Releasing a grant which is already gone succeeds. */
  session = xdp_session_dex_store_lookup_session (certificate->sessions,
                                                  arg_session_handle,
                                                  app_info);
  if (session && !xdp_session_dex_is_closed (session))
    {
      g_autoptr(XdpSessionDex) held = g_object_ref (session);

      xdp_dbus_experimental_certificate_emit_grant_invalidated (
        object, arg_session_handle, "released");

      /* Closing the session drops the grant through on_session_closed() */
      xdp_session_dex_close (held, TRUE);
    }

  xdp_dbus_experimental_certificate_complete_release_grant (
    object, g_steal_pointer (&invocation));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_get_capabilities (XdpDbusExperimentalCertificate *object,
                         GDBusMethodInvocation          *invocation,
                         GVariant                       *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_autoptr(XdpDbusExperimentalImplCertificateGetCapabilitiesResult) result = NULL;
  g_auto(GVariantBuilder) capabilities =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_auto(GVariantBuilder) impl_options =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_auto(GStrv) backend_purposes = NULL;
  g_auto(GStrv) backend_operations = NULL;
  g_auto(GStrv) backend_mechanisms = NULL;
  g_auto(GStrv) purposes = NULL;
  g_auto(GStrv) operations = NULL;
  g_auto(GStrv) mechanisms = NULL;
  g_autoptr(GError) error = NULL;
  gboolean protected_authentication_path = FALSE;

  result = dex_await_boxed (
    xdp_dbus_experimental_impl_certificate_call_get_capabilities_future (
      certificate->impl,
      xdp_app_info_get_id (app_info),
      g_variant_builder_end (&impl_options)),
    &error);

  if (!result)
    {
      g_dbus_error_strip_remote_error (error);
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_lookup (result->capabilities, "purposes", "^as", &backend_purposes);
  g_variant_lookup (result->capabilities, "operations", "^as", &backend_operations);
  g_variant_lookup (result->capabilities, "mechanisms", "^as", &backend_mechanisms);
  g_variant_lookup (result->capabilities, "protected_authentication_path", "b",
                    &protected_authentication_path);

  purposes = strv_intersect (certificate_purposes,
                             (const char * const *) backend_purposes);
  operations = strv_intersect (certificate_operations,
                               (const char * const *) backend_operations);
  mechanisms = strv_intersect (certificate_mechanisms,
                               (const char * const *) backend_mechanisms);

  g_variant_builder_add (&capabilities, "{sv}", "purposes",
                         g_variant_new_strv ((const char * const *) purposes, -1));
  g_variant_builder_add (&capabilities, "{sv}", "operations",
                         g_variant_new_strv ((const char * const *) operations, -1));
  g_variant_builder_add (&capabilities, "{sv}", "mechanisms",
                         g_variant_new_strv ((const char * const *) mechanisms, -1));
  g_variant_builder_add (&capabilities, "{sv}", "selection_memory",
                         g_variant_new_boolean (TRUE));
  g_variant_builder_add (&capabilities, "{sv}", "protected_authentication_path",
                         g_variant_new_boolean (protected_authentication_path));
  g_variant_builder_add (&capabilities, "{sv}", "max_grant_lifetime",
                         g_variant_new_uint32 (CERTIFICATE_MAX_GRANT_LIFETIME));
  g_variant_builder_add (&capabilities, "{sv}", "max_grant_total_lifetime",
                         g_variant_new_uint32 (certificate_max_total_lifetime ()));

  xdp_dbus_experimental_certificate_complete_get_capabilities (
    object,
    g_steal_pointer (&invocation),
    g_variant_builder_end (&capabilities));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* The token signals are broadcast: every client on the session bus receives
 * them, sandboxed or not, before anything has been consented to. So they say
 * that a token is there, and nothing about whose it is. A token label is
 * routinely the cardholder's name or an employee number, and the reader name
 * names the hardware; both stay in the AcquireCredential results, which only
 * an application that was granted a credential ever sees. */
static GVariant *
token_presence (GVariant *token)
{
  g_auto(GVariantBuilder) builder =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  const char *token_id = NULL;
  gboolean protected_authentication_path = FALSE;

  if (g_variant_lookup (token, "token_id", "&s", &token_id))
    g_variant_builder_add (&builder, "{sv}",
                           "token_id", g_variant_new_string (token_id));

  if (g_variant_lookup (token, "protected_authentication_path", "b",
                        &protected_authentication_path))
    g_variant_builder_add (&builder, "{sv}",
                           "protected_authentication_path",
                           g_variant_new_boolean (protected_authentication_path));

  return g_variant_ref_sink (g_variant_builder_end (&builder));
}

static void
on_impl_token_added (XdpDbusExperimentalImplCertificate *impl,
                     GVariant                           *token,
                     gpointer                            user_data)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (user_data);
  g_autoptr(GVariant) presence = token_presence (token);

  xdp_dbus_experimental_certificate_emit_token_added (
    XDP_DBUS_EXPERIMENTAL_CERTIFICATE (certificate), presence);
}

static void
on_impl_token_removed (XdpDbusExperimentalImplCertificate *impl,
                       GVariant                           *token,
                       gpointer                            user_data)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (user_data);
  g_autoptr(GVariant) presence = token_presence (token);

  xdp_dbus_experimental_certificate_emit_token_removed (
    XDP_DBUS_EXPERIMENTAL_CERTIFICATE (certificate), presence);
}

static void
on_impl_session_invalidated (XdpDbusExperimentalImplCertificate *impl,
                             const char                         *session_handle,
                             const char                         *reason,
                             gpointer                            user_data)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (user_data);
  XdpSessionDex *session;

  if (!g_hash_table_contains (certificate->grants, session_handle))
    return;

  xdp_dbus_experimental_certificate_emit_grant_invalidated (
    XDP_DBUS_EXPERIMENTAL_CERTIFICATE (certificate), session_handle, reason);

  session = xdp_session_dex_store_lookup_session (certificate->sessions,
                                                  session_handle,
                                                  NULL);
  if (session && !xdp_session_dex_is_closed (session))
    {
      g_autoptr(XdpSessionDex) held = g_object_ref (session);

      xdp_session_dex_close (held, TRUE);
    }
  else
    {
      g_hash_table_remove (certificate->grants, session_handle);
    }
}

static void
xdp_certificate_iface_init (XdpDbusExperimentalCertificateIface *iface)
{
  iface->handle_create_session = handle_create_session;
  iface->handle_acquire_credential = handle_acquire_credential;
  iface->handle_sign = handle_sign;
  iface->handle_decrypt = handle_decrypt;
  iface->handle_renew_grant = handle_renew_grant;
  iface->handle_release_grant = handle_release_grant;
  iface->handle_get_capabilities = handle_get_capabilities;
}

static void
xdp_certificate_dispose (GObject *object)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);

  g_clear_object (&certificate->impl);
  g_clear_object (&certificate->sessions);
  g_clear_pointer (&certificate->grants, g_hash_table_unref);

  G_OBJECT_CLASS (xdp_certificate_parent_class)->dispose (object);
}

static void
xdp_certificate_init (XdpCertificate *certificate)
{
  certificate->sessions = xdp_session_dex_store_new ();
  certificate->grants =
    g_hash_table_new_full (g_str_hash, g_str_equal,
                           g_free,
                           (GDestroyNotify) certificate_grant_free);
}

static void
xdp_certificate_class_init (XdpCertificateClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = xdp_certificate_dispose;
}

static XdpCertificate *
xdp_certificate_new (XdpContext                         *context,
                     XdpDbusExperimentalImplCertificate *impl)
{
  XdpCertificate *certificate;

  certificate = g_object_new (XDP_TYPE_CERTIFICATE, NULL);
  certificate->context = context;
  certificate->impl = g_object_ref (impl);

  g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (certificate->impl), G_MAXINT);

  g_signal_connect_object (certificate->impl, "token-added",
                           G_CALLBACK (on_impl_token_added),
                           certificate, G_CONNECT_DEFAULT);
  g_signal_connect_object (certificate->impl, "token-removed",
                           G_CALLBACK (on_impl_token_removed),
                           certificate, G_CONNECT_DEFAULT);
  g_signal_connect_object (certificate->impl, "session-invalidated",
                           G_CALLBACK (on_impl_session_invalidated),
                           certificate, G_CONNECT_DEFAULT);

  xdp_dbus_experimental_certificate_set_version (
    XDP_DBUS_EXPERIMENTAL_CERTIFICATE (certificate), 1);

  return certificate;
}

DexFuture *
init_certificate (gpointer user_data)
{
  XdpContext *context = XDP_CONTEXT (user_data);
  g_autoptr(XdpCertificate) certificate = NULL;
  GDBusConnection *connection = xdp_context_get_connection (context);
  XdpPortalConfig *config = xdp_context_get_config (context);
  XdpImplConfig *impl_config;
  g_autoptr(XdpDbusExperimentalImplCertificate) impl = NULL;
  g_autoptr(GError) error = NULL;

  impl_config = xdp_portal_config_find (config,
                                        CERTIFICATE_EXPERIMENTAL_DBUS_IMPL_IFACE);
  if (impl_config == NULL)
    return dex_future_new_true ();

  impl = dex_await_object (
    xdp_dbus_experimental_impl_certificate_proxy_new_future (
      connection,
      G_DBUS_PROXY_FLAGS_NONE,
      impl_config->dbus_name,
      DESKTOP_DBUS_PATH),
    &error);

  if (impl == NULL)
    {
      g_warning ("Failed to create certificate proxy: %s", error->message);
      return dex_future_new_false ();
    }

  certificate = xdp_certificate_new (context, impl);

  xdp_context_take_and_export_portal (
    context,
    G_DBUS_INTERFACE_SKELETON (g_steal_pointer (&certificate)),
    XDP_CONTEXT_EXPORT_FLAGS_RUN_IN_FIBER);

  return dex_future_new_true ();
}
