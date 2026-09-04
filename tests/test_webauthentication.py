# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black

import dbus
import pytest

import tests.xdp_utils as xdp

INTERFACE = "org.freedesktop.portal.experimental.WebAuthentication"
IMPL_INTERFACE = "org.freedesktop.impl.portal.experimental.WebAuthentication"

START_URI = "https://login.example.com/authorize?client_id=test"
COMPLETION_URI = "https://example.com/callback"


@pytest.fixture
def required_templates():
    return {"webauthentication": {}}


@pytest.fixture
def xdp_overwrite_env():
    return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": "web-authentication"}


@pytest.fixture
def xdg_desktop_portal_dir_files(xdg_desktop_portal_dir_default_files):
    files = dict(xdg_desktop_portal_dir_default_files)
    portal = files["test.portal"].decode("utf-8")
    portal = portal.replace("Interfaces=", f"Interfaces={IMPL_INTERFACE};")
    files["test.portal"] = portal.encode("utf-8")
    return files


class TestWebAuthentication:
    def test_version(self, portals, dbus_con):
        properties = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Properties"
        )
        assert int(properties.Get(INTERFACE, "version")) == 1

    def test_basic(self, portals, dbus_con, xdp_app_info):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "Start",
            parent_window="",
            start_uri=START_URI,
            completion_uri=COMPLETION_URI,
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
        assert "app_id_kind" in options
        # handle_token is never forwarded
        assert "handle_token" not in options

    def test_timeout_is_clamped(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "Start",
            parent_window="",
            start_uri=START_URI,
            completion_uri=COMPLETION_URI,
            options={"timeout": dbus.UInt32(100000)},
        )

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

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "Start",
            parent_window="",
            start_uri=START_URI,
            completion_uri=COMPLETION_URI,
            options={},
        )

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

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            request.call(
                "Start",
                parent_window="",
                start_uri=START_URI,
                completion_uri=COMPLETION_URI,
                options=options,
            )

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

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "Start",
            parent_window="",
            start_uri=START_URI,
            completion_uri=COMPLETION_URI,
            options={},
        )

        assert response
        assert response.response == 2
        assert response.results["reason"] == "backend_completion_mismatch"
        assert "completion_uri" not in response.results

    @pytest.mark.parametrize(
        "template_params",
        (
            {
                "webauthentication": {
                    # Same URI, spelled differently: case and default port
                    # normalise, so this one does match.
                    "completion-uri": "https://EXAMPLE.COM:443/callback",
                }
            },
        ),
    )
    def test_completion_normalisation_accepted(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "Start",
            parent_window="",
            start_uri=START_URI,
            completion_uri=COMPLETION_URI,
            options={},
        )

        assert response
        assert response.response == 0
        assert (
            response.results["completion_uri"]
            == "https://EXAMPLE.COM:443/callback?code=secret"
        )


class TestWebAuthenticationExperimentalGate:
    """
    Without XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL the interface is not on the
    bus at all.
    """

    @pytest.fixture
    def xdp_overwrite_env(self):
        return {}

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
