/* SPDX-License-Identifier: LGPL-2.1-or-later
 * SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
 */

#include "config.h"

#include "web-authentication.h"

#include <string.h>

#include <gio/gio.h>

#include "xdp-app-info.h"
#include "xdp-context.h"
#include "xdp-experimental-dbus.h"
#include "xdp-impl-experimental-dbus.h"
#include "xdp-portal-config.h"
#include "xdp-request-dex.h"
#include "xdp-utils.h"

/* The application may only shorten the deadline, never extend it. */
#define WEB_AUTHENTICATION_DEFAULT_TIMEOUT 300
#define WEB_AUTHENTICATION_MAX_TIMEOUT 900

#define WEB_AUTHENTICATION_MAX_URI_LENGTH 4096
#define WEB_AUTHENTICATION_MAX_TITLE_LENGTH 256

struct _XdpWebAuthentication
{
  XdpDbusExperimentalWebAuthenticationSkeleton parent_instance;

  XdpContext *context;
  XdpDbusExperimentalImplWebAuthentication *impl;
};

#define XDP_TYPE_WEB_AUTHENTICATION (xdp_web_authentication_get_type ())
G_DECLARE_FINAL_TYPE (XdpWebAuthentication,
                      xdp_web_authentication,
                      XDP, WEB_AUTHENTICATION,
                      XdpDbusExperimentalWebAuthenticationSkeleton)

static void xdp_web_authentication_iface_init (XdpDbusExperimentalWebAuthenticationIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (XdpWebAuthentication,
                               xdp_web_authentication,
                               XDP_DBUS_EXPERIMENTAL_TYPE_WEB_AUTHENTICATION_SKELETON,
                               G_IMPLEMENT_INTERFACE (XDP_DBUS_EXPERIMENTAL_TYPE_WEB_AUTHENTICATION,
                                                      xdp_web_authentication_iface_init))

/* GLib does not expose the default port of a scheme, and we only ever accept
 * schemes with a host, so a short table is enough. Custom schemes have no
 * default port, which is what -1 means here. */
static int
default_port_for_scheme (const char *scheme)
{
  if (g_ascii_strcasecmp (scheme, "https") == 0)
    return 443;
  if (g_ascii_strcasecmp (scheme, "http") == 0)
    return 80;

  return -1;
}

static int
effective_port (GUri *uri)
{
  int port = g_uri_get_port (uri);

  if (port != -1)
    return port;

  return default_port_for_scheme (g_uri_get_scheme (uri));
}

static GUri *
parse_uri (const char  *uri_string,
           const char  *what,
           GError     **error)
{
  g_autoptr(GUri) uri = NULL;

  if (uri_string == NULL || *uri_string == '\0')
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "No %s given", what);
      return NULL;
    }

  if (strlen (uri_string) > WEB_AUTHENTICATION_MAX_URI_LENGTH)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The %s is too long", what);
      return NULL;
    }

  for (size_t i = 0; uri_string[i]; i++)
    {
      if ((guchar) uri_string[i] < 0x20 || (guchar) uri_string[i] == 0x7f)
        {
          g_set_error (error,
                       XDG_DESKTOP_PORTAL_ERROR,
                       XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                       "The %s contains control characters", what);
          return NULL;
        }

      if (uri_string[i] == '\\')
        {
          g_set_error (error,
                       XDG_DESKTOP_PORTAL_ERROR,
                       XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                       "The %s contains a backslash", what);
          return NULL;
        }
    }

  /* Keep the URI as it was written: we hand the very same string to the
   * backend, and we compare what comes back against it. */
  uri = g_uri_parse (uri_string, G_URI_FLAGS_ENCODED, NULL);
  if (!uri)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The %s is not a valid URI", what);
      return NULL;
    }

  if (g_uri_get_host (uri) == NULL || *g_uri_get_host (uri) == '\0')
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The %s has no host", what);
      return NULL;
    }

  if (g_uri_get_userinfo (uri) != NULL)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "The %s carries userinfo", what);
      return NULL;
    }

  return g_steal_pointer (&uri);
}

/* The one completion matching rule. Exact, on the parsed URI: scheme and host
 * case insensitively, effective ports with defaults normalised, path exactly.
 * Query and fragment carry the result and take no part in matching. */
static gboolean
completion_uri_matches (GUri *requested,
                        GUri *candidate)
{
  const char *requested_path;
  const char *candidate_path;

  if (g_ascii_strcasecmp (g_uri_get_scheme (requested),
                          g_uri_get_scheme (candidate)) != 0)
    return FALSE;

  if (g_ascii_strcasecmp (g_uri_get_host (requested),
                          g_uri_get_host (candidate)) != 0)
    return FALSE;

  if (effective_port (requested) != effective_port (candidate))
    return FALSE;

  if (g_uri_get_userinfo (candidate) != NULL)
    return FALSE;

  requested_path = g_uri_get_path (requested);
  candidate_path = g_uri_get_path (candidate);

  if (g_strcmp0 (requested_path, candidate_path) != 0)
    return FALSE;

  return TRUE;
}

static gboolean
validate_session_mode (const char  *key,
                       GVariant    *value,
                       GVariant    *options,
                       gpointer     user_data,
                       GError     **error)
{
  const char *mode = g_variant_get_string (value, NULL);

  /* Silently falling back from ephemeral to shared would be a security
   * decision made by a typo. */
  if (g_strcmp0 (mode, "shared") != 0 && g_strcmp0 (mode, "ephemeral") != 0)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Unknown session_mode '%s'", mode);
      return FALSE;
    }

  return TRUE;
}

static gboolean
validate_title (const char  *key,
                GVariant    *value,
                GVariant    *options,
                gpointer     user_data,
                GError     **error)
{
  const char *title = g_variant_get_string (value, NULL);

  if (g_utf8_strlen (title, -1) > WEB_AUTHENTICATION_MAX_TITLE_LENGTH)
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Not accepting overly long titles");
      return FALSE;
    }

  if (strchr (title, '\n'))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Not accepting multi-line titles");
      return FALSE;
    }

  return TRUE;
}

static XdpOptionKey start_options[] = {
  { "activation_token", G_VARIANT_TYPE_STRING, NULL },
  { "session_mode", G_VARIANT_TYPE_STRING, validate_session_mode },
  { "title", G_VARIANT_TYPE_STRING, validate_title },
};

/* How much the app id can be trusted. The backend renders the difference; it
 * never re-derives it. */
static const char *
app_id_kind (XdpAppInfo *app_info)
{
  if (!xdp_app_info_is_host (app_info))
    return "sandboxed";

  if (g_strcmp0 (xdp_app_info_get_id (app_info), "") != 0)
    return "cgroup";

  return "host";
}

static GVariant *
start_validate_options (XdpAppInfo  *app_info,
                        GVariant    *arg_options,
                        GError     **error)
{
  g_auto(GVariantBuilder) options =
    G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  uint32_t timeout = WEB_AUTHENTICATION_DEFAULT_TIMEOUT;

  if (!xdp_filter_options (arg_options,
                           &options,
                           start_options,
                           G_N_ELEMENTS (start_options),
                           NULL,
                           error))
    return NULL;

  if (g_variant_lookup (arg_options, "timeout", "u", &timeout))
    {
      if (timeout == 0)
        {
          g_set_error_literal (error,
                               XDG_DESKTOP_PORTAL_ERROR,
                               XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                               "A timeout of zero is not a timeout");
          return NULL;
        }

      /* The application may only shorten the deadline. */
      timeout = MIN (timeout, WEB_AUTHENTICATION_MAX_TIMEOUT);
    }
  else if (xdp_variant_contains_key (arg_options, "timeout"))
    {
      g_set_error_literal (error,
                           XDG_DESKTOP_PORTAL_ERROR,
                           XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                           "Expected type 'u' for option 'timeout'");
      return NULL;
    }

  g_variant_builder_add (&options, "{sv}",
                         "timeout", g_variant_new_uint32 (timeout));

  g_variant_builder_add (&options, "{sv}",
                         "app_id_kind",
                         g_variant_new_string (app_id_kind (app_info)));

  return g_variant_ref_sink (g_variant_builder_end (&options));
}

static gboolean
handle_start (XdpDbusExperimentalWebAuthentication *object,
              GDBusMethodInvocation                *invocation,
              const char                           *arg_parent_window,
              const char                           *arg_start_uri,
              const char                           *arg_completion_uri,
              GVariant                             *arg_options)
{
  XdpWebAuthentication *web_authentication = XDP_WEB_AUTHENTICATION (object);
  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  g_autoptr(XdpRequestDex) request = NULL;
  g_autoptr(GVariant) options = NULL;
  g_autoptr(GUri) start_uri = NULL;
  g_autoptr(GUri) completion_uri = NULL;
  g_autoptr(GError) error = NULL;

  /* A malformed request is an error from Start(), before any backend is woken
   * and any window is opened. */
  start_uri = parse_uri (arg_start_uri, "start_uri", &error);
  if (!start_uri)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (g_ascii_strcasecmp (g_uri_get_scheme (start_uri), "https") != 0)
    {
      g_dbus_method_invocation_return_error_literal (g_steal_pointer (&invocation),
                                                     XDG_DESKTOP_PORTAL_ERROR,
                                                     XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                                                     "The start_uri must be an https URI");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  completion_uri = parse_uri (arg_completion_uri, "completion_uri", &error);
  if (!completion_uri)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  options = start_validate_options (app_info, arg_options, &error);
  if (!options)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation),
                                              error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  request = dex_await_object (xdp_request_dex_new (web_authentication->context,
                                                   app_info,
                                                   G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (web_authentication->impl),
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

  xdp_dbus_experimental_web_authentication_complete_start (
    object,
    g_steal_pointer (&invocation),
    xdp_request_dex_get_object_path (request));

  {
    g_autoptr(XdpDbusExperimentalImplWebAuthenticationStartResult) result = NULL;
    g_auto(GVariantBuilder) results_builder =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
    XdgDesktopPortalResponseEnum response;

    result = dex_await_boxed (
      xdp_dbus_experimental_impl_web_authentication_call_start_future (
        web_authentication->impl,
        xdp_request_dex_get_object_path (request),
        xdp_app_info_get_id (app_info),
        arg_parent_window,
        arg_start_uri,
        arg_completion_uri,
        options),
      &error);

    if (!result)
      {
        g_dbus_error_strip_remote_error (error);
        g_warning ("Backend call failed: %s", error->message);

        g_variant_builder_add (&results_builder, "{sv}",
                               "reason",
                               g_variant_new_string ("backend_disappeared"));
        response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
      }
    else if (result->response == XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS)
      {
        const char *returned = NULL;
        g_autoptr(GUri) returned_uri = NULL;

        /* The Response we emit is a statement we make, on the bus name the
         * application trusts. A backend that answers with a URI the
         * application did not ask for does not get to hand that URI on. */
        if (!g_variant_lookup (result->results, "completion_uri", "&s", &returned))
          {
            g_warning ("Backend did not return a completion_uri");
            g_variant_builder_add (&results_builder, "{sv}",
                                   "reason",
                                   g_variant_new_string ("backend_protocol_error"));
            response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
          }
        else if (!(returned_uri = parse_uri (returned, "completion_uri", NULL)) ||
                 !completion_uri_matches (completion_uri, returned_uri))
          {
            g_warning ("Backend returned a completion_uri which is not the "
                       "one that was requested");
            g_variant_builder_add (&results_builder, "{sv}",
                                   "reason",
                                   g_variant_new_string ("backend_completion_mismatch"));
            response = XDG_DESKTOP_PORTAL_RESPONSE_OTHER;
          }
        else
          {
            g_variant_builder_add (&results_builder, "{sv}",
                                   "completion_uri",
                                   g_variant_new_string (returned));
            response = XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS;
          }
      }
    else
      {
        const char *reason = NULL;

        if (g_variant_lookup (result->results, "reason", "&s", &reason))
          g_variant_builder_add (&results_builder, "{sv}",
                                 "reason", g_variant_new_string (reason));

        response = result->response;
      }

    xdp_request_dex_emit_response (request,
                                   response,
                                   g_variant_builder_end (&results_builder));
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static void
xdp_web_authentication_iface_init (XdpDbusExperimentalWebAuthenticationIface *iface)
{
  iface->handle_start = handle_start;
}

static void
xdp_web_authentication_dispose (GObject *object)
{
  XdpWebAuthentication *web_authentication = XDP_WEB_AUTHENTICATION (object);

  g_clear_object (&web_authentication->impl);

  G_OBJECT_CLASS (xdp_web_authentication_parent_class)->dispose (object);
}

static void
xdp_web_authentication_init (XdpWebAuthentication *web_authentication)
{
}

static void
xdp_web_authentication_class_init (XdpWebAuthenticationClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = xdp_web_authentication_dispose;
}

static XdpWebAuthentication *
xdp_web_authentication_new (XdpContext                               *context,
                            XdpDbusExperimentalImplWebAuthentication *impl)
{
  XdpWebAuthentication *web_authentication;

  web_authentication = g_object_new (XDP_TYPE_WEB_AUTHENTICATION, NULL);
  web_authentication->context = context;
  web_authentication->impl = g_object_ref (impl);

  g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (web_authentication->impl),
                                    G_MAXINT);

  xdp_dbus_experimental_web_authentication_set_version (
    XDP_DBUS_EXPERIMENTAL_WEB_AUTHENTICATION (web_authentication), 1);

  return web_authentication;
}

DexFuture *
init_web_authentication (gpointer user_data)
{
  XdpContext *context = XDP_CONTEXT (user_data);
  g_autoptr(XdpWebAuthentication) web_authentication = NULL;
  GDBusConnection *connection = xdp_context_get_connection (context);
  XdpPortalConfig *config = xdp_context_get_config (context);
  XdpImplConfig *impl_config;
  g_autoptr(XdpDbusExperimentalImplWebAuthentication) impl = NULL;
  g_autoptr(GError) error = NULL;

  impl_config = xdp_portal_config_find (config,
                                        WEB_AUTHENTICATION_EXPERIMENTAL_DBUS_IMPL_IFACE);
  if (impl_config == NULL)
    return dex_future_new_true ();

  impl = dex_await_object (
    xdp_dbus_experimental_impl_web_authentication_proxy_new_future (
      connection,
      G_DBUS_PROXY_FLAGS_NONE,
      impl_config->dbus_name,
      DESKTOP_DBUS_PATH),
    &error);

  if (impl == NULL)
    {
      g_warning ("Failed to create web authentication proxy: %s",
                 error->message);
      return dex_future_new_false ();
    }

  web_authentication = xdp_web_authentication_new (context, impl);

  xdp_context_take_and_export_portal (
    context,
    G_DBUS_INTERFACE_SKELETON (g_steal_pointer (&web_authentication)),
    XDP_CONTEXT_EXPORT_FLAGS_RUN_IN_FIBER);

  return dex_future_new_true ();
}
