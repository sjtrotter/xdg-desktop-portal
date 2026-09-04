# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black

import dbus
import pytest

import tests.xdp_utils as xdp

INTERFACE = "org.freedesktop.portal.experimental.Certificate"
IMPL_INTERFACE = "org.freedesktop.impl.portal.experimental.Certificate"


@pytest.fixture
def required_templates():
    return {"certificate": {}}


@pytest.fixture
def xdp_overwrite_env():
    return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": "certificate"}


@pytest.fixture
def xdg_desktop_portal_dir_files(xdg_desktop_portal_dir_default_files):
    files = dict(xdg_desktop_portal_dir_default_files)
    portal = files["test.portal"].decode("utf-8")
    portal = portal.replace("Interfaces=", f"Interfaces={IMPL_INTERFACE};")
    files["test.portal"] = portal.encode("utf-8")
    return files


def create_session(dbus_con, intf):
    request = xdp.Request(dbus_con, intf)
    response = request.call("CreateSession", options={})
    assert response
    assert response.response == 0
    return xdp.Session.from_response(dbus_con, response)


def acquire_credential(dbus_con, intf, session, options=None):
    if options is None:
        options = {"purpose": "client_auth"}
    request = xdp.Request(dbus_con, intf)
    return request.call(
        "AcquireCredential",
        session_handle=session.handle,
        parent_window="",
        options=options,
    )


class TestCertificate:
    def test_version(self, portals, dbus_con):
        properties = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Properties"
        )
        assert int(properties.Get(INTERFACE, "version")) == 1

    def test_create_session(self, portals, dbus_con, xdp_app_info):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert session.handle

        _, args = mock_intf.GetMethodCalls("CreateSession")[-1]
        assert args[1] == session.handle
        assert args[2] == xdp_app_info.app_id

    def test_acquire_credential(self, portals, dbus_con, xdp_app_info):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        response = acquire_credential(
            dbus_con,
            intf,
            session,
            options={
                "purpose": "client_auth",
                "reason": "To connect to the corporate VPN",
                "requested_lifetime": dbus.UInt32(120),
            },
        )

        assert response
        assert response.response == 0
        assert bytes(response.results["certificate_der"]) == b"certificate"
        assert response.results["grant_id"]
        assert response.results["expires_at"] > 0
        assert list(response.results["supported_mechanisms"]) == ["ECDSA"]
        assert list(response.results["permitted_operations"]) == ["sign"]

        _, args = mock_intf.GetMethodCalls("AcquireCredential")[-1]
        assert args[1] == session.handle
        assert args[2] == xdp_app_info.app_id
        options = args[4]
        assert options["purpose"] == "client_auth"
        # The frontend decides the lifetime, the app only asks
        assert options["lifetime"] == 120
        assert "app_identity_level" in options
        assert "requested_lifetime" not in options
        assert "handle_token" not in options

    def test_lifetime_is_clamped(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        response = acquire_credential(
            dbus_con,
            intf,
            session,
            options={
                "purpose": "signing",
                "requested_lifetime": dbus.UInt32(1000000),
            },
        )

        assert response
        assert response.response == 0

        _, args = mock_intf.GetMethodCalls("AcquireCredential")[-1]
        assert args[4]["lifetime"] == 3600

    def test_sign(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "Sign",
            session_handle=session.handle,
            parent_window="",
            options={
                "mechanism": "ECDSA",
                "data": dbus.ByteArray(b"digest"),
                "operation_id": "op-1",
            },
        )

        assert response
        assert response.response == 0
        assert bytes(response.results["signature"]) == b"signature"
        assert response.results["operation_id"] == "op-1"

    def test_sign_without_grant_is_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            request.call(
                "Sign",
                session_handle=session.handle,
                parent_window="",
                options={"mechanism": "ECDSA", "data": dbus.ByteArray(b"digest")},
            )

        assert "credential" in str(excinfo.value)
        assert len(mock_intf.GetMethodCalls("Sign")) == 0

    def test_decrypt_not_permitted_by_grant(self, portals, dbus_con):
        """
        The backend only granted 'sign', so Decrypt never reaches it.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            request.call(
                "Decrypt",
                session_handle=session.handle,
                parent_window="",
                options={
                    "mechanism": "ECDSA",
                    "ciphertext": dbus.ByteArray(b"ciphertext"),
                },
            )

        assert "decrypt" in str(excinfo.value)
        assert len(mock_intf.GetMethodCalls("Decrypt")) == 0

    @pytest.mark.parametrize(
        "template_params",
        (
            {
                "certificate": {
                    "credential": dbus.Dictionary(
                        {
                            "certificate_der": dbus.ByteArray(b"certificate"),
                            # A backend which claims more than the portal allows
                            "supported_mechanisms": dbus.Array(
                                ["ECDSA", "MAGIC_BEANS"], signature="s"
                            ),
                            "permitted_operations": dbus.Array(
                                ["sign", "decrypt", "exfiltrate"], signature="s"
                            ),
                        },
                        signature="sv",
                    )
                }
            },
        ),
    )
    def test_backend_results_are_clamped(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        response = acquire_credential(dbus_con, intf, session)

        assert response
        assert response.response == 0
        assert list(response.results["supported_mechanisms"]) == ["ECDSA"]
        assert list(response.results["permitted_operations"]) == ["sign", "decrypt"]

        # And the mechanism the portal does not know is refused, not forwarded
        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException):
            request.call(
                "Sign",
                session_handle=session.handle,
                parent_window="",
                options={
                    "mechanism": "MAGIC_BEANS",
                    "data": dbus.ByteArray(b"digest"),
                },
            )

    @pytest.mark.parametrize(
        "options,error_fragment",
        [
            ({}, "purpose"),
            ({"purpose": "world_domination"}, "purpose"),
            ({"purpose": dbus.UInt32(1)}, "purpose"),
            ({"purpose": "signing", "interaction_mode": "maybe"}, "interaction_mode"),
            (
                {"purpose": "signing", "requested_lifetime": "long"},
                "requested_lifetime",
            ),
        ],
    )
    def test_invalid_option_rejected(self, portals, dbus_con, options, error_fragment):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            request.call(
                "AcquireCredential",
                session_handle=session.handle,
                parent_window="",
                options=options,
            )

        assert error_fragment in str(excinfo.value)
        assert len(mock_intf.GetMethodCalls("AcquireCredential")) == 0

    def test_unknown_session_rejected(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            request.call(
                "AcquireCredential",
                session_handle="/org/freedesktop/portal/desktop/session/x/y",
                parent_window="",
                options={"purpose": "signing"},
            )

        assert "session" in str(excinfo.value).lower()

    @pytest.mark.parametrize(
        "template_params", ({"certificate": {"expect-close": True}},)
    )
    def test_close(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        request.schedule_close(300)
        request.call("CreateSession", options={})

        # Only true if the impl.Request was closed too
        assert request.closed

    @pytest.mark.parametrize("template_params", ({"certificate": {"response": 1}},))
    def test_cancel(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        # CreateSession succeeds only because response is per-template; use a
        # separate response for AcquireCredential by cancelling it there.
        request = xdp.Request(dbus_con, intf)
        response = request.call("CreateSession", options={})

        assert response
        assert response.response == 1
        assert "session_handle" not in response.results

    def test_renew_and_release_grant(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        response = acquire_credential(dbus_con, intf, session)
        assert response
        assert response.response == 0

        expires_at = intf.RenewGrant(
            session.handle, {"requested_lifetime": dbus.UInt32(600)}
        )
        assert expires_at > response.results["expires_at"]

        # Renewal is decided in the frontend, the backend is never asked
        assert len(mock_intf.GetMethodCalls("RenewGrant")) == 0

        intf.ReleaseGrant(session.handle)
        # Releasing a grant which is already gone succeeds
        intf.ReleaseGrant(session.handle)

    def test_get_capabilities(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        capabilities = intf.GetCapabilities({})

        assert list(capabilities["purposes"]) == ["client_auth", "signing"]
        assert list(capabilities["operations"]) == ["sign"]
        # Intersected with the portal's own allow list, in its order
        assert list(capabilities["mechanisms"]) == ["RSA_PSS", "ECDSA"]
        assert capabilities["max_grant_lifetime"] == 3600
        assert capabilities["selection_memory"]


class TestCertificateExperimentalGate:
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
