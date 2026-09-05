# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black

import dbus
import pytest

import tests.xdp_utils as xdp

INTERFACE = "org.freedesktop.portal.experimental.WebAuthentication1"

START_URI = "https://login.example.com/authorize?client_id=test"
COMPLETION_URI = "https://example.com/callback"


@pytest.fixture(
    params=[
        xdp.AppInfoHost(),
        xdp.AppInfoFlatpak(),
    ]
    + (
        [
            xdp.AppInfoSnap(metadata=b"""
[Snap Info]
InstanceName=test
AppName=test
CommonID=org.example.Test
DesktopFile=test_test.desktop
HasNetworkStatus=true
"""),
            xdp.AppInfoLinyaps(),
        ]
        if xdp.run_long_tests()
        else []
    )
)
def xdp_app_info(request) -> xdp.AppInfo:
    return request.param


@pytest.fixture
def xdp_overwrite_env():
    return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": "WebAuthentication1"}


@pytest.fixture
def required_templates():
    return {"webauthentication": {}}


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
        xdp.check_version(dbus_con, "experimental.WebAuthentication1", 1)

    def test_start_returns_completion_uri(self, portals, dbus_con, xdp_app_info):
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

        method_calls = mock_intf.GetMethodCalls("Start")
        assert len(method_calls) == 1
        _, args = method_calls[-1]
        assert args[1] == xdp_app_info.app_id
        assert args[3] == START_URI
        assert args[4] == COMPLETION_URI
        options = args[5]
        assert options["session_mode"] == "ephemeral"
        assert options["title"] == "Sign in"
        assert options["timeout"] == 300
        if isinstance(xdp_app_info, xdp.AppInfoHost):
            assert options["app_identity_level"] == "host"
        else:
            assert options["app_identity_level"] == "sandboxed"
        assert "handle_token" not in options

    def test_timeout_is_clamped(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        response = start(dbus_con, intf, options={"timeout": dbus.UInt32(100000)})

        assert response
        assert response.response == 0

        method_calls = mock_intf.GetMethodCalls("Start")
        assert len(method_calls) == 1
        _, args = method_calls[-1]
        assert args[5]["timeout"] == 900

    @pytest.mark.parametrize(
        "template_params", ({"webauthentication": {"expect-close": True}},)
    )
    def test_close_reaches_backend(self, portals, dbus_con):
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

        assert request.closed

    @pytest.mark.parametrize(
        "template_params",
        ({"webauthentication": {"response": 1, "reason": "user_cancelled"}},),
    )
    def test_cancellation_reason_forwarded(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        response = start(dbus_con, intf)

        assert response
        assert response.response == 1
        assert response.results["reason"] == "user_cancelled"
        assert "completion_uri" not in response.results

    @pytest.mark.parametrize(
        "options,error_fragment",
        [
            ({"session_mode": "shred"}, "Invalid session_mode 'shred'"),
            ({"session_mode": dbus.UInt32(1)}, "session_mode"),
            ({"timeout": "soon"}, "timeout must have type 'u'"),
            ({"title": "one\ntwo"}, "title must be a single line"),
        ],
    )
    def test_invalid_option_rejected(self, portals, dbus_con, options, error_fragment):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            start(dbus_con, intf, options=options)

        e = excinfo.value
        assert e.get_dbus_name() == "org.freedesktop.portal.Error.InvalidArgument"
        assert error_fragment in e.get_dbus_message()
        assert len(mock_intf.GetMethodCalls("Start")) == 0

    @pytest.mark.parametrize(
        "start_uri,completion_uri,error_fragment",
        [
            (
                "http://example.com/start",
                COMPLETION_URI,
                "start_uri must use https",
            ),
            ("not a uri", COMPLETION_URI, "start_uri must be a valid URI"),
            ("https:///nohost", COMPLETION_URI, "start_uri must have a host"),
            (
                START_URI,
                "https://user:pw@example.com/callback",
                "completion_uri must not contain userinfo",
            ),
            (START_URI, "relative/path", "completion_uri must be a valid URI"),
            (
                START_URI,
                "https://*.example.com/callback",
                "completion_uri host contains a wildcard",
            ),
            (
                START_URI,
                "com.example.app://*/callback",
                "completion_uri host contains a wildcard",
            ),
            (
                START_URI,
                "com.example.app:",
                "completion_uri must have a host or path",
            ),
        ],
    )
    def test_invalid_uri_rejected(
        self, portals, dbus_con, start_uri, completion_uri, error_fragment
    ):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            request.call(
                "Start",
                parent_window="",
                start_uri=start_uri,
                completion_uri=completion_uri,
                options={},
            )

        e = excinfo.value
        assert e.get_dbus_name() == "org.freedesktop.portal.Error.InvalidArgument"
        assert error_fragment in e.get_dbus_message()
        assert len(mock_intf.GetMethodCalls("Start")) == 0

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            (
                {
                    "webauthentication": {
                        "completion-uri": "https://evil.invalid/callback"
                    }
                },
                COMPLETION_URI,
            ),
            (
                {"webauthentication": {"completion-uri": "https://example.com/"}},
                "https://example.com",
            ),
            (
                {"webauthentication": {"completion-uri": "https://example.com./cb"}},
                "https://example.com/cb",
            ),
            (
                {"webauthentication": {"completion-uri": "com.example.app:/other"}},
                "com.example.app:/oauth2redirect",
            ),
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
    def test_completion_mismatch_rejected(self, portals, dbus_con, requested):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "backend_completion_mismatch"
        assert "completion_uri" not in response.results

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            (
                {"webauthentication": {"completion-uri": "HTTPS://EXAMPLE.COM:443/cb"}},
                "https://example.com/cb",
            ),
            (
                {"webauthentication": {"completion-uri": "https://example.com/%63b"}},
                "https://example.com/cb",
            ),
            (
                {"webauthentication": {"completion-uri": "https://example.com/c%2fb"}},
                "https://example.com/c%2Fb",
            ),
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
            (
                {"webauthentication": {"completion-uri": "https://exämple.com/cb"}},
                "https://xn--exmple-cua.com/cb",
            ),
        ],
    )
    def test_completion_normalisation_accepted(
        self, portals, dbus_con, template_params, requested
    ):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        answered = template_params["webauthentication"]["completion-uri"]

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 0
        assert response.results["completion_uri"] == f"{answered}?code=secret"

    @pytest.mark.parametrize(
        "template_params,requested",
        [
            (
                {
                    "webauthentication": {
                        "completion-uri": "com.example.app:/oauth2redirect"
                    }
                },
                "com.example.app:/oauth2redirect",
            ),
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
        intf = xdp.get_iface(dbus_con, INTERFACE)
        answered = template_params["webauthentication"]["completion-uri"]

        response = start(dbus_con, intf, completion_uri=requested)

        assert response
        assert response.response == 0
        assert response.results["completion_uri"] == f"{answered}?code=secret"

    @pytest.mark.parametrize(
        "template_params", ({"webauthentication": {"expect-close": True}},)
    )
    def test_timeout_closes_backend_request(self, portals, dbus_con):
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
    @pytest.fixture
    def xdp_app_info(self):
        return xdp.AppInfoFlatpak(metadata=NO_NETWORK_METADATA)

    def test_start_requires_network_access(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            start(dbus_con, intf)

        e = excinfo.value
        assert e.get_dbus_name() == "org.freedesktop.portal.Error.NotAllowed"
        assert "Application sandbox has no network access" in e.get_dbus_message()
        assert len(mock_intf.GetMethodCalls("Start")) == 0


class TestWebAuthenticationDisabled:
    @pytest.fixture
    def xdp_overwrite_env(self, monkeypatch):
        monkeypatch.delenv("XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL", raising=False)
        return {}

    def test_interface_not_exported(self, portals, dbus_con):
        introspectable = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Introspectable"
        )
        assert INTERFACE not in introspectable.Introspect()
