# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black

import dbus
import pytest

import tests.xdp_utils as xdp

INTERFACE = "org.freedesktop.portal.experimental.WebAuthentication"

START_URI = "https://login.example.com/authorize?client_id=test"
COMPLETION_URI = "https://example.com/callback"


@pytest.fixture
def required_templates():
    return {"webauthentication": {}}


@pytest.fixture
def xdp_overwrite_env():
    return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": "web-authentication"}


def start(dbus_con, intf, completion_uri=COMPLETION_URI, options=None):
    request = xdp.Request(dbus_con, intf)
    return request.call(
        "Start",
        parent_window="",
        start_uri=START_URI,
        completion_uri=completion_uri,
        options=options if options is not None else {},
    )


class TestWebAuthentication:
    def test_version(self, portals, dbus_con):
        properties = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Properties"
        )
        assert int(properties.Get(INTERFACE, "version")) == 1

    def test_basic(self, portals, dbus_con, xdp_app_info):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        response = start(
            dbus_con,
            intf,
            options={"title": "Sign in", "session_mode": "ephemeral"},
        )

        assert response
        assert response.response == 0
        assert response.results["completion_uri"] == f"{COMPLETION_URI}?code=secret"

        # Check the impl portal was called with the right args
        method_calls = mock_intf.GetMethodCalls("Start")
        assert len(method_calls) > 0
        _, args = method_calls[-1]
        assert args[1] == xdp_app_info.app_id
        assert args[3] == START_URI
        assert args[4] == COMPLETION_URI
        options = args[5]
        assert options["session_mode"] == "ephemeral"
        assert options["title"] == "Sign in"
        # The frontend decides these, not the app
        assert options["timeout"] == 300
        assert options["app_identity_level"] in ("sandboxed", "host", "unidentified")
        # handle_token is never forwarded
        assert "handle_token" not in options

    def test_timeout_is_clamped(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        response = start(dbus_con, intf, options={"timeout": dbus.UInt32(100000)})

        assert response
        assert response.response == 0

        _, args = mock_intf.GetMethodCalls("Start")[-1]
        assert args[5]["timeout"] == 900

    @pytest.mark.parametrize(
        "template_params", ({"webauthentication": {"expect-close": True}},)
    )
    def test_close(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        request.schedule_close(300)
        request.call(
            "Start",
            parent_window="",
            start_uri=START_URI,
            completion_uri=COMPLETION_URI,
            options={},
        )

        # Only true if the impl.Request was closed too
        assert request.closed

    @pytest.mark.parametrize(
        "template_params",
        ({"webauthentication": {"response": 1, "reason": "user_cancelled"}},),
    )
    def test_cancel(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        response = start(dbus_con, intf)

        assert response
        assert response.response == 1
        assert response.results["reason"] == "user_cancelled"
        assert "completion_uri" not in response.results

    @pytest.mark.parametrize(
        "options,error_fragment",
        [
            ({"session_mode": "shred"}, "session_mode"),
            ({"session_mode": dbus.UInt32(1)}, "session_mode"),
            ({"timeout": "soon"}, "timeout"),
            ({"title": "one\ntwo"}, "title"),
        ],
    )
    def test_invalid_option_rejected(self, portals, dbus_con, options, error_fragment):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            start(dbus_con, intf, options=options)

        assert error_fragment in str(excinfo.value)
        # No backend was woken and no window was opened
        assert len(mock_intf.GetMethodCalls("Start")) == 0

    @pytest.mark.parametrize(
        "start_uri,completion_uri",
        [
            ("http://example.com/start", COMPLETION_URI),
            ("file:///etc/passwd", COMPLETION_URI),
            ("not a uri", COMPLETION_URI),
            ("https:///nohost", COMPLETION_URI),
            (START_URI, "https://user:pw@example.com/callback"),
            (START_URI, "relative/path"),
            # A wildcard is not a pattern here, and is not matched literally
            (START_URI, "https://*.example.com/callback"),
            (START_URI, "com.example.app://*/callback"),
            # A private-use scheme with neither a host nor a path has nothing
            # to match on
            (START_URI, "com.example.app:"),
        ],
    )
    def test_invalid_uri_rejected(self, portals, dbus_con, start_uri, completion_uri):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException):
            request.call(
                "Start",
                parent_window="",
                start_uri=start_uri,
                completion_uri=completion_uri,
                options={},
            )

        assert len(mock_intf.GetMethodCalls("Start")) == 0

    @pytest.mark.parametrize(
        "template_params",
        (
            {
                "webauthentication": {
                    "completion-uri": "https://evil.invalid/callback",
                }
            },
        ),
    )
    def test_completion_mismatch_rejected(self, portals, dbus_con):
        """
        A backend which answers with a URI the application did not ask for does
        not get to hand that URI on: the frontend re-checks it.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        response = start(dbus_con, intf)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "backend_completion_mismatch"
        assert "completion_uri" not in response.results

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            # scheme and host are compared case insensitively, and the default
            # port of the scheme is filled in before the ports are compared
            (
                {"webauthentication": {"completion-uri": "HTTPS://EXAMPLE.COM:443/cb"}},
                "https://example.com/cb",
            ),
            # an escape that does not have to be one is decoded
            (
                {"webauthentication": {"completion-uri": "https://example.com/%63b"}},
                "https://example.com/cb",
            ),
            # an escape that does have to be one keeps uppercase hex
            (
                {"webauthentication": {"completion-uri": "https://example.com/c%2fb"}},
                "https://example.com/c%2Fb",
            ),
            # dot segments are resolved
            (
                {
                    "webauthentication": {
                        "completion-uri": "https://example.com/x/../cb"
                    }
                },
                "https://example.com/cb",
            ),
            (
                {"webauthentication": {"completion-uri": "https://example.com/./cb"}},
                "https://example.com/cb",
            ),
            # a host is converted to punycode
            (
                {"webauthentication": {"completion-uri": "https://exämple.com/cb"}},
                "https://xn--exmple-cua.com/cb",
            ),
        ],
    )
    def test_completion_normalisation_accepted(
        self, portals, dbus_con, template_params, requested
    ):
        """
        The two URIs are compared on their parsed components, so the
        equivalences GLib's parser applies are equivalences here.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)
        answered = template_params["webauthentication"]["completion-uri"]

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 0
        assert response.results["completion_uri"] == f"{answered}?code=secret"

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            # an empty path and '/' are different paths
            (
                {"webauthentication": {"completion-uri": "https://example.com/"}},
                "https://example.com",
            ),
            # and a trailing dot is a different host
            (
                {"webauthentication": {"completion-uri": "https://example.com./cb"}},
                "https://example.com/cb",
            ),
        ],
    )
    def test_completion_near_miss_refused(self, portals, dbus_con, requested):
        """
        The two spellings that look like equivalences are not, and they fail
        closed.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "backend_completion_mismatch"

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            # RFC 8252 section 7.1: a private-use scheme redirect has no
            # authority, and is matched on its scheme and its path
            (
                {
                    "webauthentication": {
                        "completion-uri": "com.example.app:/oauth2redirect"
                    }
                },
                "com.example.app:/oauth2redirect",
            ),
            # the scheme is lowercased and the path normalised, as for https
            (
                {
                    "webauthentication": {
                        "completion-uri": "COM.EXAMPLE.APP:/x/../oauth2%72edirect"
                    }
                },
                "com.example.app:/oauth2redirect",
            ),
        ],
    )
    def test_private_use_scheme_accepted(
        self, portals, dbus_con, template_params, requested
    ):
        """
        A completion URI whose scheme is not http or https needs no host.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)
        answered = template_params["webauthentication"]["completion-uri"]

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 0
        assert response.results["completion_uri"] == f"{answered}?code=secret"

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            # a different path is a different URI
            (
                {"webauthentication": {"completion-uri": "com.example.app:/other"}},
                "com.example.app:/oauth2redirect",
            ),
            # and a URI with a host never matches one without
            (
                {
                    "webauthentication": {
                        "completion-uri": "com.example.app://host/oauth2redirect"
                    }
                },
                "com.example.app:/oauth2redirect",
            ),
        ],
    )
    def test_private_use_scheme_mismatch_refused(self, portals, dbus_con, requested):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "backend_completion_mismatch"
        assert "completion_uri" not in response.results

    @pytest.mark.parametrize(
        "template_params", ({"webauthentication": {"expect-close": True}},)
    )
    def test_timeout(self, portals, dbus_con):
        """
        The deadline is the frontend's: a backend that never answers is
        answered for, and its request is closed so the window goes away.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        impl_closed: list[str] = []
        dbus_con.add_signal_receiver(
            lambda handle: impl_closed.append(str(handle)),
            "RequestClosed",
            dbus_interface="org.freedesktop.impl.portal.Mock",
        )

        response = start(dbus_con, intf, options={"timeout": dbus.UInt32(1)})

        assert response
        assert response.response == 2
        assert response.results["reason"] == "timeout"
        assert "completion_uri" not in response.results

        xdp.wait_for(lambda: len(impl_closed) > 0)
        # and it is closed once, however many ways the request ends
        assert len(impl_closed) == 1


NO_NETWORK_METADATA = b"""
[Application]
name=org.example.Test
runtime=org.freedesktop.Platform/x86_64/23.08
sdk=org.freedesktop.Sdk/x86_64/23.08
command=org.example.Test

[Instance]
instance-id=1234567890

[Context]
sockets=x11;wayland;
"""


class TestWebAuthenticationWithoutNetwork:
    """
    A sandbox with no network access cannot reach the network through this
    portal either.
    """

    @pytest.fixture
    def xdp_app_info(self):
        return xdp.AppInfoFlatpak(metadata=NO_NETWORK_METADATA)

    def test_start_is_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            start(dbus_con, intf)

        assert "sandbox" in str(excinfo.value)
        assert len(mock_intf.GetMethodCalls("Start")) == 0


class TestWebAuthenticationExperimentalGate:
    """
    Without XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL the interface is not on the
    bus at all.
    """

    @pytest.fixture
    def xdp_overwrite_env(self):
        # Explicitly empty: an inherited value would make this pass or fail
        # depending on the developer's environment.
        return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": ""}

    def test_interface_is_absent(self, portals, dbus_con):
        properties = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Properties"
        )

        with pytest.raises(dbus.exceptions.DBusException):
            properties.Get(INTERFACE, "version")

    def test_interface_is_not_introspected(self, portals, dbus_con):
        introspectable = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Introspectable"
        )

        assert INTERFACE not in introspectable.Introspect()
