/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
 */

#include "config.h"

#include "certificate.h"

#include <string.h>

#include <gio/gio.h>

#include "xdp-app-info.h"
#include "xdp-context.h"
#include "xdp-dbus-experimental.h"
#include "xdp-impl-dbus-experimental.h"
#include "xdp-portal-config.h"
#include "xdp-request-dex.h"
#include "xdp-session-dex.h"
#include "xdp-utils.h"

#define CERTIFICATE_DEFAULT_GRANT_LIFETIME 300
#define CERTIFICATE_MAX_GRANT_LIFETIME 3600

#define CERTIFICATE_MAX_REASON_LENGTH 256

static const char * const certificate_operations[] = {
  "sign",
  NULL,
};

static const char * const certificate_mechanisms[] = {
  "RSA_PKCS1_V1_5",
  "RSA_PSS",
  "ECDSA",
  NULL,
};

static const char * const certificate_interaction_modes[] = {
  "required",
  "allowed",
  "forbidden",
  NULL,
};

static const char * const certificate_signature_encodings[] = {
  "raw",
  "der",
  NULL,
};

static const char * const certificate_piv_slots[] = {
  "authentication",
  "signature",
  "key_management",
  "card_authentication",
  NULL,
};

static const char * const certificate_purposes[] = {
  "client_auth",
  "signing",
  "email",
  "ssh",
  NULL,
};

/* Sign accepts a digest with the length of the named hash. */
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

struct _XdpCertificate
{
  XdpDbusExperimentalCertificate1Skeleton parent_instance;

  XdpContext *context;
  XdpDbusExperimentalImplCertificate1 *impl;
  XdpSessionDexStore *sessions;
};

#define XDP_TYPE_CERTIFICATE (xdp_certificate_get_type ())
G_DECLARE_FINAL_TYPE (XdpCertificate,
                      xdp_certificate,
                      XDP, CERTIFICATE,
                      XdpDbusExperimentalCertificate1Skeleton)

static void xdp_certificate_iface_init (XdpDbusExperimentalCertificate1Iface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (XdpCertificate,
                               xdp_certificate,
                               XDP_DBUS_EXPERIMENTAL_TYPE_CERTIFICATE1_SKELETON,
                               G_IMPLEMENT_INTERFACE (XDP_DBUS_EXPERIMENTAL_TYPE_CERTIFICATE1,
                                                      xdp_certificate_iface_init))

/* Grant state belongs to the session object, whose path can be reused. */
struct _CertificateGrant
{
  GObject parent_instance;

  XdpCertificate *certificate;
  XdpSessionDex *session;

  gboolean acquiring;
  gboolean acquired;

  /* deadline is monotonic; expires_at is wall clock time for display. */
  int64_t deadline;
  uint64_t expires_at;
  unsigned int expiry_id;

  GStrv permitted_operations;
  GStrv supported_mechanisms;
};

#define CERTIFICATE_TYPE_GRANT (certificate_grant_get_type ())
G_DECLARE_FINAL_TYPE (CertificateGrant,
                      certificate_grant,
                      CERTIFICATE, GRANT,
                      GObject)

G_DEFINE_FINAL_TYPE (CertificateGrant, certificate_grant, G_TYPE_OBJECT)

static void
certificate_grant_dispose (GObject *object)
{
  CertificateGrant *grant = CERTIFICATE_GRANT (object);

  g_clear_handle_id (&grant->expiry_id, g_source_remove);
  g_clear_object (&grant->session);
  g_clear_pointer (&grant->permitted_operations, g_strfreev);
  g_clear_pointer (&grant->supported_mechanisms, g_strfreev);

  G_OBJECT_CLASS (certificate_grant_parent_class)->dispose (object);
}

static void
certificate_grant_init (CertificateGrant *grant)
{
}

static void
certificate_grant_class_init (CertificateGrantClass *klass)
{
  G_OBJECT_CLASS (klass)->dispose = certificate_grant_dispose;
}

static gboolean
strv_contains (const char * const *strv,
               const char         *needle)
{
  return strv != NULL && needle != NULL && g_strv_contains (strv, needle);
}

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

static const CertificateHash *
certificate_hash_lookup (const char *name)
{
  if (!name)
    return NULL;

  for (size_t i = 0; i < G_N_ELEMENTS (certificate_hashes); i++)
    {
      g_autofree char *dashed =
        g_strdup_printf ("SHA-%s", certificate_hashes[i].name + 3);

      if (g_ascii_strcasecmp (name, certificate_hashes[i].name) == 0 ||
          g_ascii_strcasecmp (name, dashed) == 0)
        return &certificate_hashes[i];
    }

  return NULL;
}

/* Identity levels use the vocabulary shared by the impl interfaces. */
static const char *
app_identity_level (XdpAppInfo *app_info)
{
  if (!xdp_app_info_is_host (app_info))
    return "sandboxed";

  if (g_strcmp0 (xdp_app_info_get_id (app_info), "") != 0)
    return "host";

  return "unidentified";
}

static CertificateGrant *
lookup_session (XdpCertificate  *certificate,
                const char      *session_handle,
                XdpAppInfo      *app_info,
                GError         **error)
{
  CertificateGrant *grant;

  grant = xdp_session_dex_store_lookup_session (certificate->sessions,
                                                session_handle,
                                                app_info);
  if (!grant || xdp_session_dex_is_closed (grant->session))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_NOT_FOUND,
                           "Invalid session");
      return NULL;
    }

  return grant;
}

/* After an await, the same path may refer to a different session. */
static gboolean
session_is_current (XdpCertificate   *certificate,
                    CertificateGrant *held,
                    const char       *session_handle,
                    XdpAppInfo       *app_info)
{
  return xdp_session_dex_store_lookup_session (certificate->sessions,
                                               session_handle,
                                               app_info) == held &&
         !xdp_session_dex_is_closed (held->session);
}

/* Grant validity must be checked across awaits. */
static gboolean
check_grant (CertificateGrant  *grant,
             const char        *operation,
             const char        *mechanism,
             GError           **error)
{
  if (!grant->acquired)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                           "Session has no credential");
      return FALSE;
    }

  if (g_get_monotonic_time () >= grant->deadline)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                           "Grant has expired");
      return FALSE;
    }

  if (operation &&
      !strv_contains ((const char * const *) grant->permitted_operations,
                      operation))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                   "Grant does not permit '%s'", operation);
      return FALSE;
    }

  if (mechanism &&
      !strv_contains ((const char * const *) grant->supported_mechanisms,
                      mechanism))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                   "Grant does not permit mechanism '%s'", mechanism);
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

  if (g_utf8_strlen (reason, -1) > CERTIFICATE_MAX_REASON_LENGTH)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "reason exceeds the maximum length");
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_lifetime (const char  *key,
                   GVariant    *value,
                   GVariant    *options,
                   gpointer     user_data,
                   GError     **error)
{
  if (g_variant_get_uint32 (value) == 0)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "requested_lifetime must be greater than zero");
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_piv_slot (const char  *key,
                   GVariant    *value,
                   GVariant    *options,
                   gpointer     user_data,
                   GError     **error)
{
  const char *slot = g_variant_get_string (value, NULL);

  if (!strv_contains (certificate_piv_slots, slot))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown piv_slot '%s'", slot);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_mechanism (const char  *key,
                    GVariant    *value,
                    GVariant    *options,
                    gpointer     user_data,
                    GError     **error)
{
  const char *mechanism = g_variant_get_string (value, NULL);

  if (!strv_contains (certificate_mechanisms, mechanism))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown mechanism '%s'", mechanism);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_hash (const char  *key,
               GVariant    *value,
               GVariant    *options,
               gpointer     user_data,
               GError     **error)
{
  const char *hash = g_variant_get_string (value, NULL);

  if (!certificate_hash_lookup (hash))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown hash '%s'", hash);
      return FALSE;
    }

  return TRUE;
}

/* Unqualified MGF1 uses the signature hash. */
static gboolean
validate_mgf (const char  *key,
              GVariant    *value,
              GVariant    *options,
              gpointer     user_data,
              GError     **error)
{
  const char *mgf = g_variant_get_string (value, NULL);

  if (g_strcmp0 (mgf, "MGF1") != 0 &&
      !(g_str_has_prefix (mgf, "MGF1-") && certificate_hash_lookup (mgf + 5)))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown mgf '%s'", mgf);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_signature_encoding (const char  *key,
                             GVariant    *value,
                             GVariant    *options,
                             gpointer     user_data,
                             GError     **error)
{
  const char *encoding = g_variant_get_string (value, NULL);

  if (!strv_contains (certificate_signature_encodings, encoding))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown signature_encoding '%s'", encoding);
      return FALSE;
    }

  return TRUE;
}

static XdpOptionKey acquire_credential_options[] = {
  { "activation_token", G_VARIANT_TYPE_STRING, NULL },
  { "purpose", G_VARIANT_TYPE_STRING, validate_purpose },
  { "certificate_filter", G_VARIANT_TYPE_VARDICT, NULL },
  { "operation_policy", G_VARIANT_TYPE_VARDICT, NULL },
  { "interaction_mode", G_VARIANT_TYPE_STRING, validate_interaction_mode },
  { "reason", G_VARIANT_TYPE_STRING, validate_reason },
};

/* These options are consumed by the frontend. */
static XdpOptionKey acquire_credential_local_options[] = {
  { "requested_lifetime", G_VARIANT_TYPE_UINT32, validate_lifetime },
};

static XdpOptionKey certificate_filter_options[] = {
  { "issuers", G_VARIANT_TYPE_BYTESTRING_ARRAY, NULL },
  { "key_usage", G_VARIANT_TYPE_STRING_ARRAY, NULL },
  { "eku", G_VARIANT_TYPE_STRING_ARRAY, NULL },
  { "key_algorithms", G_VARIANT_TYPE_STRING_ARRAY, NULL },
  { "token_label", G_VARIANT_TYPE_STRING, NULL },
  { "piv_slot", G_VARIANT_TYPE_STRING, validate_piv_slot },
};

static XdpOptionKey operation_policy_options[] = {
  { "sign", G_VARIANT_TYPE_BOOLEAN, NULL },
};

static XdpOptionKey sign_options[] = {
  { "mechanism", G_VARIANT_TYPE_STRING, validate_mechanism },
  { "parameters", G_VARIANT_TYPE_VARDICT, NULL },
  { "data", G_VARIANT_TYPE_BYTESTRING, NULL },
};

static XdpOptionKey sign_local_options[] = {
  { "operation_id", G_VARIANT_TYPE_STRING, NULL },
};

static XdpOptionKey sign_parameters_options[] = {
  { "hash", G_VARIANT_TYPE_STRING, validate_hash },
  { "mgf", G_VARIANT_TYPE_STRING, validate_mgf },
  { "salt_length", G_VARIANT_TYPE_UINT32, NULL },
  { "signature_encoding", G_VARIANT_TYPE_STRING, validate_signature_encoding },
};

/* Unknown filter or policy keys must not broaden the requested access. */
static gboolean
filter_nested_options (GVariant            *options,
                       const char          *key,
                       const XdpOptionKey  *supported,
                       int                  n_supported,
                       GVariant           **out_nested,
                       GError             **error)
{
  g_auto(GVariantBuilder) builder =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autoptr(GVariant) nested = NULL;
  GVariantIter iter;
  const char *name;
  GVariant *value;

  *out_nested = NULL;

  nested = g_variant_lookup_value (options, key, G_VARIANT_TYPE_VARDICT);
  if (!nested)
    return TRUE;

  g_variant_iter_init (&iter, nested);
  while (g_variant_iter_next (&iter, "{&sv}", &name, &value))
    {
      g_autoptr(GVariant) owned = value;
      gboolean known = FALSE;

      for (int i = 0; i < n_supported; i++)
        known = known || g_strcmp0 (name, supported[i].key) == 0;

      if (!known)
        {
          g_set_error (error,
                       XDG_DESKTOP_PORTAL_ERROR,
                       XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                       "Unknown key '%s' in '%s'", name, key);
          return FALSE;
        }
    }

  if (!xdp_filter_options (nested, &builder, supported, n_supported, NULL,
                           error))
    return FALSE;

  *out_nested = g_variant_ref_sink (g_variant_builder_end (&builder));
  return TRUE;
}

/* Omitted operations default to enabled. */
static GStrv
requested_operations (GVariant *policy)
{
  g_autoptr(GStrvBuilder) builder = g_strv_builder_new ();

  for (size_t i = 0; certificate_operations[i]; i++)
    {
      gboolean wanted = TRUE;

      if (policy)
        g_variant_lookup (policy, certificate_operations[i], "b", &wanted);

      if (wanted)
        g_strv_builder_add (builder, certificate_operations[i]);
    }

  return g_strv_builder_end (builder);
}

static GVariant *
acquire_credential_validate_options (XdpAppInfo  *app_info,
                                     GVariant    *arg_options,
                                     uint32_t    *out_lifetime,
                                     GStrv       *out_operations,
                                     GError     **error)
{
  g_auto(GVariantBuilder) filtered =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_auto(GVariantBuilder) discarded =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GVariant) certificate_filter = NULL;
  g_autoptr(GVariant) operation_policy = NULL;
  g_auto(GStrv) operations = NULL;
  uint32_t lifetime = CERTIFICATE_DEFAULT_GRANT_LIFETIME;
  GVariantDict dict;

  if (!xdp_variant_contains_key (arg_options, "purpose"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "purpose is required");
      return NULL;
    }

  if (!xdp_filter_options (arg_options,
                           &filtered,
                           acquire_credential_options,
                           G_N_ELEMENTS (acquire_credential_options),
                           NULL,
                           error))
    return NULL;

  if (!xdp_filter_options (arg_options,
                           &discarded,
                           acquire_credential_local_options,
                           G_N_ELEMENTS (acquire_credential_local_options),
                           NULL,
                           error))
    return NULL;

  if (!filter_nested_options (arg_options, "certificate_filter",
                              certificate_filter_options,
                              G_N_ELEMENTS (certificate_filter_options),
                              &certificate_filter, error))
    return NULL;

  if (!filter_nested_options (arg_options, "operation_policy",
                              operation_policy_options,
                              G_N_ELEMENTS (operation_policy_options),
                              &operation_policy, error))
    return NULL;

  operations = requested_operations (operation_policy);
  if (!operations[0])
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "operation_policy permits no operation");
      return NULL;
    }

  if (g_variant_lookup (arg_options, "requested_lifetime", "u", &lifetime))
    lifetime = MIN (lifetime, CERTIFICATE_MAX_GRANT_LIFETIME);

  options = g_variant_ref_sink (g_variant_builder_end (&filtered));

  g_variant_dict_init (&dict, options);
  if (certificate_filter)
    g_variant_dict_insert_value (&dict, "certificate_filter",
                                 certificate_filter);
  if (operation_policy)
    g_variant_dict_insert_value (&dict, "operation_policy", operation_policy);
  g_variant_dict_insert (&dict, "lifetime", "u", lifetime);
  g_variant_dict_insert (&dict, "app_identity_level", "s",
                         app_identity_level (app_info));

  *out_lifetime = lifetime;
  *out_operations = g_steal_pointer (&operations);

  return g_variant_ref_sink (g_variant_dict_end (&dict));
}

static gboolean
sign_validate_options (GVariant  *arg_options,
                       GVariant **out_options,
                       GError   **error)
{
  g_auto(GVariantBuilder) filtered =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_auto(GVariantBuilder) discarded =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GVariant) parameters = NULL;
  g_autoptr(GVariant) data = NULL;
  const CertificateHash *hash;
  const char *hash_name = NULL;
  GVariantDict dict;

  if (!xdp_filter_options (arg_options, &filtered, sign_options,
                           G_N_ELEMENTS (sign_options), NULL, error))
    return FALSE;

  if (!xdp_filter_options (arg_options, &discarded, sign_local_options,
                           G_N_ELEMENTS (sign_local_options), NULL, error))
    return FALSE;

  if (!filter_nested_options (arg_options, "parameters",
                              sign_parameters_options,
                              G_N_ELEMENTS (sign_parameters_options),
                              &parameters, error))
    return FALSE;

  options = g_variant_ref_sink (g_variant_builder_end (&filtered));

  if (!xdp_variant_contains_key (options, "mechanism"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "mechanism is required");
      return FALSE;
    }

  data = g_variant_lookup_value (options, "data", G_VARIANT_TYPE_BYTESTRING);
  if (!data)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "data is required");
      return FALSE;
    }

  if (!parameters ||
      !g_variant_lookup (parameters, "hash", "&s", &hash_name))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "hash is required");
      return FALSE;
    }

  hash = certificate_hash_lookup (hash_name);
  g_assert (hash != NULL);

  if (g_variant_get_size (data) != hash->digest_size)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "data must be a %s digest of %" G_GSIZE_FORMAT
                   " bytes; received %" G_GSIZE_FORMAT,
                   hash->name, hash->digest_size, g_variant_get_size (data));
      return FALSE;
    }

  g_variant_dict_init (&dict, options);
  g_variant_dict_insert_value (&dict, "parameters", parameters);

  *out_options = g_variant_ref_sink (g_variant_dict_end (&dict));
  return TRUE;
}

/* Sent only to the session owner. */
static void
emit_grant_invalidated (CertificateGrant *grant,
                        const char       *reason)
{
  GDBusConnection *connection;

  connection = g_dbus_interface_skeleton_get_connection (
    G_DBUS_INTERFACE_SKELETON (grant->certificate));
  if (!connection)
    return;

  g_dbus_connection_emit_signal (
    connection,
    xdp_app_info_get_sender (xdp_session_dex_get_app_info (grant->session)),
    DESKTOP_DBUS_PATH,
    CERTIFICATE_DBUS_IFACE,
    "GrantInvalidated",
    g_variant_new ("(os)",
                   xdp_session_dex_get_object_path (grant->session),
                   reason),
    NULL);
}

static void
invalidate_grant (CertificateGrant *grant,
                  const char       *reason)
{
  g_autoptr(CertificateGrant) held = g_object_ref (grant);

  if (xdp_session_dex_is_closed (held->session))
    return;

  if (held->acquired)
    emit_grant_invalidated (held, reason);

  xdp_session_dex_close (held->session);
}

static gboolean
on_grant_expired (gpointer user_data)
{
  CertificateGrant *grant = user_data;

  grant->expiry_id = 0;
  invalidate_grant (grant, "expired");

  return G_SOURCE_REMOVE;
}

static void
on_impl_session_invalidated (XdpDbusExperimentalImplCertificate1 *impl,
                             const char                          *session_handle,
                             const char                          *reason,
                             gpointer                             user_data)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (user_data);
  CertificateGrant *grant;

  grant = xdp_session_dex_store_lookup_session (certificate->sessions,
                                                session_handle,
                                                NULL);
  if (grant)
    invalidate_grant (grant, reason);
}

static void
on_impl_name_owner_changed (GObject    *object,
                            GParamSpec *pspec,
                            gpointer    user_data)
{
  g_autofree char *owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));

  if (owner)
    return;

  invalidate_grant (CERTIFICATE_GRANT (user_data), "backend_gone");
}

static CertificateGrant *
certificate_grant_new (XdpCertificate *certificate,
                       XdpSessionDex  *session)
{
  CertificateGrant *grant = g_object_new (CERTIFICATE_TYPE_GRANT, NULL);

  grant->certificate = certificate;
  grant->session = g_object_ref (session);

  g_signal_connect_object (certificate->impl, "notify::g-name-owner",
                           G_CALLBACK (on_impl_name_owner_changed),
                           grant,
                           G_CONNECT_DEFAULT);

  return grant;
}

static XdgDesktopPortalResponseEnum
checked_response (uint32_t response)
{
  if (response > XDG_DESKTOP_PORTAL_RESPONSE_OTHER)
    {
      g_warning ("Invalid backend response: %u", response);
      return XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
    }

  return response;
}

static void
add_reason (GVariantBuilder *builder,
            const char      *reason)
{
  g_variant_builder_add (builder, "{sv}", "reason",
                         g_variant_new_string (reason));
}

static void
forward_reason (GVariantBuilder *builder,
                GVariant        *results)
{
  const char *reason = NULL;

  if (g_variant_lookup (results, "reason", "&s", &reason))
    add_reason (builder, reason);
}

static gboolean
handle_create_session (XdpDbusExperimentalCertificate1 *object,
                       GDBusMethodInvocation           *invocation,
                       GVariant                        *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_auto(GVariantBuilder) options_builder =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(XdpSessionDex) session = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;

  options = g_variant_ref_sink (g_variant_builder_end (&options_builder));

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

  xdp_dbus_experimental_certificate1_complete_create_session (
    object,
    g_steal_pointer (&invocation),
    xdp_request_dex_get_object_path (request));

  {
    g_autoptr(XdpDbusExperimentalImplCertificate1CreateSessionResult) result = NULL;
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    XdgDesktopPortalResponseEnum response;

    result = dex_await_boxed (
      xdp_dbus_experimental_impl_certificate1_call_create_session_future (
        certificate->impl,
        xdp_request_dex_get_object_path (request),
        xdp_session_dex_get_object_path (session),
        xdp_app_info_get_id (app_info),
        options),
      &error);

    if (!result)
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else if (result->response != XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
      {
        response = checked_response (result->response);
      }
    else if (xdp_request_dex_is_closed (request))
      {
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }
    else
      {
        const char *session_handle = xdp_session_dex_get_object_path (session);
        g_autoptr(CertificateGrant) grant = NULL;

        grant = certificate_grant_new (certificate, session);
        xdp_session_dex_store_take_session (certificate->sessions,
                                            g_object_ref (grant));

        /* The store rejects sessions that closed during the backend call. */
        if (xdp_session_dex_store_lookup_session (certificate->sessions,
                                                  session_handle,
                                                  app_info) != grant)
          {
            add_reason (&results_builder, "session_closed");
            response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
          }
        else
          {
            response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;

            g_variant_builder_add (&results_builder, "{sv}",
                                   "session_handle",
                                   g_variant_new_object_path (session_handle));
          }
      }

    xdp_request_dex_emit_response (request,
                                   response,
                                   g_variant_builder_end (&results_builder));
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

typedef struct _CertificateResultKey
{
  const char *key;
  const GVariantType *type;
  gboolean required;
} CertificateResultKey;

static const CertificateResultKey acquire_credential_results[] = {
  { "certificate_der", G_VARIANT_TYPE_BYTESTRING, TRUE },
  { "chain_der", G_VARIANT_TYPE_BYTESTRING_ARRAY, FALSE },
  { "chain_status", G_VARIANT_TYPE_STRING, FALSE },
  { "token_display", G_VARIANT_TYPE_VARDICT, FALSE },
  { "key_type", G_VARIANT_TYPE_STRING, FALSE },
  { "key_size", G_VARIANT_TYPE_UINT32, FALSE },
  { "key_curve", G_VARIANT_TYPE_STRING, FALSE },
  { "may_prompt_later", G_VARIANT_TYPE_BOOLEAN, FALSE },
};

static gboolean
forward_acquire_credential_results (GVariant        *results,
                                    GVariantBuilder *builder)
{
  for (size_t i = 0; i < G_N_ELEMENTS (acquire_credential_results); i++)
    {
      const char *key = acquire_credential_results[i].key;
      g_autoptr(GVariant) value = NULL;

      value = g_variant_lookup_value (results, key,
                                      acquire_credential_results[i].type);
      if (value)
        g_variant_builder_add (builder, "{sv}", key, value);
      else if (acquire_credential_results[i].required ||
               xdp_variant_contains_key (results, key))
        return FALSE;
    }

  return TRUE;
}

static gboolean
handle_acquire_credential (XdpDbusExperimentalCertificate1 *object,
                           GDBusMethodInvocation           *invocation,
                           const char                      *arg_session_handle,
                           const char                      *arg_parent_window,
                           GVariant                        *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_autoptr(CertificateGrant) grant = NULL;
  CertificateGrant *session_grant;
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(GVariant) options = NULL;
  g_auto(GStrv) operations = NULL;
  g_autoptr(GError) error = NULL;
  uint32_t lifetime = CERTIFICATE_DEFAULT_GRANT_LIFETIME;

  options = acquire_credential_validate_options (app_info,
                                                 arg_options,
                                                 &lifetime,
                                                 &operations,
                                                 &error);
  if (!options)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  session_grant = lookup_session (certificate, arg_session_handle, app_info,
                                  &error);
  if (!session_grant)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  /* Keep the original session alive across awaits for identity checks. */
  grant = g_object_ref (session_grant);

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

  xdp_dbus_experimental_certificate1_complete_acquire_credential (
    object,
    g_steal_pointer (&invocation),
    xdp_request_dex_get_object_path (request));

  {
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);

    if (!session_is_current (certificate, grant, arg_session_handle, app_info))
      {
        add_reason (&results_builder, "grant_gone");
        xdp_request_dex_emit_response (request,
                                       XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                       g_variant_builder_end (&results_builder));
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }

    if (grant->acquired || grant->acquiring)
      {
        add_reason (&results_builder, "grant_already_held");
        xdp_request_dex_emit_response (request,
                                       XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                       g_variant_builder_end (&results_builder));
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }
  }

  grant->acquiring = TRUE;

  {
    g_autoptr(XdpDbusExperimentalImplCertificate1AcquireCredentialResult) result = NULL;
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    XdgDesktopPortalResponseEnum response;

    result = dex_await_boxed (
      xdp_dbus_experimental_impl_certificate1_call_acquire_credential_future (
        certificate->impl,
        xdp_request_dex_get_object_path (request),
        arg_session_handle,
        xdp_app_info_get_id (app_info),
        arg_parent_window,
        options),
      &error);

    grant->acquiring = FALSE;

    /* A closed request must not leave a grant behind. */
    if (xdp_request_dex_is_closed (request))
      {
        if (result &&
            result->response == XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
          xdp_session_dex_close (grant->session);

        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }

    if (!result)
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else if (result->response != XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
      {
        forward_reason (&results_builder, result->results);
        response = checked_response (result->response);
      }
    else if (!session_is_current (certificate, grant, arg_session_handle,
                                  app_info))
      {
        add_reason (&results_builder, "grant_gone");
        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else
      {
        g_auto(GStrv) reported_mechanisms = NULL;
        g_auto(GStrv) reported_operations = NULL;
        g_auto(GStrv) mechanisms = NULL;
        g_auto(GStrv) permitted = NULL;

        g_variant_lookup (result->results, "supported_mechanisms", "^as",
                          &reported_mechanisms);
        g_variant_lookup (result->results, "permitted_operations", "^as",
                          &reported_operations);

        mechanisms =
          strv_intersect (certificate_mechanisms,
                          (const char * const *) reported_mechanisms);
        permitted =
          strv_intersect ((const char * const *) operations,
                          (const char * const *) reported_operations);

        if (!forward_acquire_credential_results (result->results,
                                                 &results_builder) ||
            !mechanisms[0] || !permitted[0])
          {
            g_auto(GVariantBuilder) failure =
              G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);

            g_warning ("Backend returned an invalid credential grant");

            add_reason (&failure, "backend_protocol_error");
            xdp_request_dex_emit_response (request,
                                           XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                           g_variant_builder_end (&failure));
            return G_DBUS_METHOD_INVOCATION_HANDLED;
          }

        grant->acquired = TRUE;
        grant->deadline =
          g_get_monotonic_time () + (int64_t) lifetime * G_USEC_PER_SEC;
        grant->expires_at =
          (uint64_t) (g_get_real_time () / G_USEC_PER_SEC) + lifetime;
        grant->supported_mechanisms = g_steal_pointer (&mechanisms);
        grant->permitted_operations = g_steal_pointer (&permitted);
        grant->expiry_id = g_timeout_add_seconds (lifetime, on_grant_expired,
                                                  grant);

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

        response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;
      }

    xdp_request_dex_emit_response (request,
                                   response,
                                   g_variant_builder_end (&results_builder));
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_sign (XdpDbusExperimentalCertificate1 *object,
             GDBusMethodInvocation           *invocation,
             const char                      *arg_session_handle,
             const char                      *arg_parent_window,
             GVariant                        *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_autoptr(CertificateGrant) grant = NULL;
  CertificateGrant *session_grant;
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree char *operation_id = NULL;
  g_autofree char *mechanism = NULL;

  if (!sign_validate_options (arg_options, &options, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_lookup (options, "mechanism", "s", &mechanism);
  g_variant_lookup (arg_options, "operation_id", "s", &operation_id);

  session_grant = lookup_session (certificate, arg_session_handle, app_info,
                                  &error);
  if (!session_grant ||
      !check_grant (session_grant, "sign", mechanism, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  /* Keep the original session alive across awaits for identity checks. */
  grant = g_object_ref (session_grant);

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

  xdp_dbus_experimental_certificate1_complete_sign (
    object,
    g_steal_pointer (&invocation),
    xdp_request_dex_get_object_path (request));

  {
    g_autoptr(XdpDbusExperimentalImplCertificate1SignResult) result = NULL;
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    g_autoptr(GError) grant_error = NULL;
    XdgDesktopPortalResponseEnum response;

    if (!session_is_current (certificate, grant, arg_session_handle,
                             app_info) ||
        !check_grant (grant, "sign", mechanism, &grant_error))
      {
        add_reason (&results_builder, "grant_gone");

        if (operation_id)
          g_variant_builder_add (&results_builder, "{sv}", "operation_id",
                                 g_variant_new_string (operation_id));

        xdp_request_dex_emit_response (request,
                                       XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                       g_variant_builder_end (&results_builder));
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }

    result = dex_await_boxed (
      xdp_dbus_experimental_impl_certificate1_call_sign_future (
        certificate->impl,
        xdp_request_dex_get_object_path (request),
        arg_session_handle,
        xdp_app_info_get_id (app_info),
        arg_parent_window,
        options),
      &error);

    if (!session_is_current (certificate, grant, arg_session_handle,
                             app_info) ||
        !check_grant (grant, "sign", mechanism, &grant_error))
      {
        add_reason (&results_builder, "grant_gone");
        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else if (!result)
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else if (result->response != XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
      {
        forward_reason (&results_builder, result->results);
        response = checked_response (result->response);
      }
    else
      {
        g_autoptr(GVariant) signature = NULL;

        signature = g_variant_lookup_value (result->results, "signature",
                                            G_VARIANT_TYPE_BYTESTRING);
        if (signature)
          {
            g_variant_builder_add (&results_builder, "{sv}",
                                   "signature", signature);
            response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;
          }
        else
          {
            g_warning ("Backend response is missing a signature");
            add_reason (&results_builder, "backend_protocol_error");
            response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
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
handle_get_capabilities (XdpDbusExperimentalCertificate1 *object,
                         GDBusMethodInvocation           *invocation,
                         GVariant                        *arg_options)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_autoptr(XdpDbusExperimentalImplCertificate1GetCapabilitiesResult) result = NULL;
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
  gboolean has_display = FALSE;

  result = dex_await_boxed (
    xdp_dbus_experimental_impl_certificate1_call_get_capabilities_future (
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
  g_variant_lookup (result->capabilities, "has_display", "b", &has_display);

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
  g_variant_builder_add (&capabilities, "{sv}", "protected_authentication_path",
                         g_variant_new_boolean (protected_authentication_path));
  g_variant_builder_add (&capabilities, "{sv}", "has_display",
                         g_variant_new_boolean (has_display));
  g_variant_builder_add (&capabilities, "{sv}", "max_grant_lifetime",
                         g_variant_new_uint32 (CERTIFICATE_MAX_GRANT_LIFETIME));

  xdp_dbus_experimental_certificate1_complete_get_capabilities (
    object,
    g_steal_pointer (&invocation),
    g_variant_builder_end (&capabilities));

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static void
xdp_certificate_iface_init (XdpDbusExperimentalCertificate1Iface *iface)
{
  iface->handle_create_session = handle_create_session;
  iface->handle_acquire_credential = handle_acquire_credential;
  iface->handle_sign = handle_sign;
  iface->handle_get_capabilities = handle_get_capabilities;
}

static void
xdp_certificate_dispose (GObject *object)
{
  XdpCertificate *certificate = XDP_CERTIFICATE (object);

  g_clear_object (&certificate->impl);
  g_clear_object (&certificate->sessions);

  G_OBJECT_CLASS (xdp_certificate_parent_class)->dispose (object);
}

static void
xdp_certificate_init (XdpCertificate *certificate)
{
  certificate->sessions =
    xdp_session_dex_store_new_wrapped (CertificateGrant, session);
}

static void
xdp_certificate_class_init (XdpCertificateClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = xdp_certificate_dispose;
}

static XdpCertificate *
xdp_certificate_new (XdpContext                          *context,
                     XdpDbusExperimentalImplCertificate1 *impl)
{
  XdpCertificate *certificate;

  certificate = g_object_new (XDP_TYPE_CERTIFICATE, NULL);
  certificate->context = context;
  certificate->impl = g_object_ref (impl);

  g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (certificate->impl), G_MAXINT);

  g_signal_connect_object (certificate->impl, "session-invalidated",
                           G_CALLBACK (on_impl_session_invalidated),
                           certificate, G_CONNECT_DEFAULT);

  xdp_dbus_experimental_certificate1_set_version (
    XDP_DBUS_EXPERIMENTAL_CERTIFICATE1 (certificate), 1);

  return certificate;
}

DexFuture *
init_certificate (gpointer user_data)
{
  XdpContext *context = XDP_CONTEXT (user_data);
  g_autoptr(XdpCertificate) certificate = NULL;
  GDBusConnection *connection;
  XdpPortalConfig *config;
  XdpImplConfig *impl_config;
  g_autoptr(XdpDbusExperimentalImplCertificate1) impl = NULL;
  g_autoptr(GError) error = NULL;

  if (!xdp_context_is_experimental_portal_enabled (context, "Certificate1"))
    return dex_future_new_true ();

  connection = xdp_context_get_connection (context);
  config = xdp_context_get_config (context);
  impl_config = xdp_portal_config_find (config,
                                        CERTIFICATE_DBUS_IMPL_IFACE);
  if (impl_config == NULL)
    return dex_future_new_true ();

  impl = dex_await_object (
    xdp_dbus_experimental_impl_certificate1_proxy_new_future (
      connection,
      G_DBUS_PROXY_FLAGS_NONE,
      impl_config->dbus_name,
      DESKTOP_DBUS_PATH),
    &error);

  if (impl == NULL)
    {
      g_warning ("Certificate proxy creation failed: %s", error->message);
      return dex_future_new_false ();
    }

  certificate = xdp_certificate_new (context, impl);

  xdp_context_take_and_export_portal (
    context,
    G_DBUS_INTERFACE_SKELETON (g_steal_pointer (&certificate)),
    XDP_CONTEXT_EXPORT_FLAGS_RUN_IN_FIBER);

  return dex_future_new_true ();
}
