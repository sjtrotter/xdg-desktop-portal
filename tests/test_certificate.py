# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black

import os
import xml.etree.ElementTree as ET

import dbus
import pytest

import tests.xdp_utils as xdp

INTERFACE = "org.freedesktop.portal.experimental.Certificate1"

# A 32 byte SHA256 digest, which is what Sign takes
DIGEST = dbus.ByteArray(b"0123456789abcdef0123456789abcdef")

SIGN_OPTIONS = {
    "mechanism": "ECDSA",
    "parameters": dbus.Dictionary({"hash": "SHA256"}, signature="sv"),
    "data": DIGEST,
}


def credential(remove=(), **overrides):
    results = {
        "certificate_der": dbus.ByteArray(b"certificate"),
        "supported_mechanisms": dbus.Array(["ECDSA"], signature="s"),
        "permitted_operations": dbus.Array(["sign"], signature="s"),
    }
    for key in remove:
        del results[key]
    results.update(overrides)

    return dbus.Dictionary(results, signature="sv")


@pytest.fixture
def xdp_overwrite_env():
    return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": "Certificate1"}


@pytest.fixture
def required_templates():
    return {"certificate": {}}


def create_session(dbus_con, intf):
    request = xdp.Request(dbus_con, intf)
    response = request.call("CreateSession", options={})
    assert response
    assert response.response == 0
    assert isinstance(response.results["session_handle"], dbus.ObjectPath)
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


def sign(dbus_con, intf, session, options=None):
    request = xdp.Request(dbus_con, intf)
    return request.call(
        "Sign",
        session_handle=session.handle,
        parent_window="",
        # Request.call() adds handle_token to the options.
        options=dict(SIGN_OPTIONS if options is None else options),
    )


class TestCertificate:
    def test_version(self, portals, dbus_con):
        xdp.check_version(dbus_con, "experimental.Certificate1", 1)

    def test_create_session(self, portals, dbus_con, xdp_app_info):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert session.handle

        method_calls = mock_intf.GetMethodCalls("CreateSession")
        assert len(method_calls) == 1
        _, args = method_calls[-1]
        assert args[1] == session.handle
        assert args[2] == xdp_app_info.app_id

    @pytest.mark.parametrize(
        "template_params",
        ({"certificate": {"credential": credential(grant_id="backend-grant-id")}},),
    )
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
                "certificate_filter": dbus.Dictionary(
                    {"piv_slot": "authentication"}, signature="sv"
                ),
            },
        )

        assert response
        assert response.response == 0
        assert bytes(response.results["certificate_der"]) == b"certificate"
        assert response.results["expires_at"] > 0
        assert list(response.results["supported_mechanisms"]) == ["ECDSA"]
        assert list(response.results["permitted_operations"]) == ["sign"]
        assert "grant_id" not in response.results

        method_calls = mock_intf.GetMethodCalls("AcquireCredential")
        assert len(method_calls) == 1
        _, args = method_calls[-1]
        assert args[1] == session.handle
        assert args[2] == xdp_app_info.app_id
        options = args[4]
        assert options["lifetime"] == 120
        if isinstance(xdp_app_info, xdp.AppInfoHost):
            assert options["app_identity_level"] == "host"
        else:
            assert options["app_identity_level"] == "sandboxed"
        assert options["certificate_filter"]["piv_slot"] == "authentication"
        assert options["reason"] == "To connect to the corporate VPN"
        assert "handle_token" not in options
        assert "requested_lifetime" not in options

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

        method_calls = mock_intf.GetMethodCalls("AcquireCredential")
        assert len(method_calls) == 1
        _, args = method_calls[-1]
        assert args[4]["lifetime"] == 3600

    def test_second_acquisition_is_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        response = acquire_credential(dbus_con, intf, session)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "grant_already_held"
        assert len(mock_intf.GetMethodCalls("AcquireCredential")) == 1

    @pytest.mark.parametrize(
        "template_params",
        (
            {
                "certificate": {
                    "credential": credential(
                        supported_mechanisms=dbus.Array(
                            ["ECDSA", "RSA_PSS", "MAGIC_BEANS"], signature="s"
                        ),
                        permitted_operations=dbus.Array(
                            ["sign", "decrypt"], signature="s"
                        ),
                    )
                }
            },
        ),
    )
    def test_grant_is_bounded_by_the_request(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        response = acquire_credential(dbus_con, intf, session)

        assert response
        assert response.response == 0
        assert list(response.results["supported_mechanisms"]) == ["RSA_PSS", "ECDSA"]
        assert list(response.results["permitted_operations"]) == ["sign"]

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(
                dbus_con,
                intf,
                session,
                options=dict(SIGN_OPTIONS, mechanism="RSA_PKCS1_V1_5"),
            )

        assert (
            excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotAllowed"
        )
        assert "RSA_PKCS1_V1_5" in excinfo.value.get_dbus_message()

    def test_sign(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        response = sign(
            dbus_con,
            intf,
            session,
            options={
                "mechanism": "ECDSA",
                "parameters": dbus.Dictionary(
                    {"hash": "SHA256", "signature_encoding": "der"}, signature="sv"
                ),
                "data": DIGEST,
                "operation_id": "op-1",
            },
        )

        assert response
        assert response.response == 0
        assert bytes(response.results["signature"]) == b"signature"
        assert response.results["operation_id"] == "op-1"

        method_calls = mock_intf.GetMethodCalls("Sign")
        assert len(method_calls) == 1
        _, args = method_calls[-1]
        assert "operation_id" not in args[4]
        assert args[4]["parameters"]["signature_encoding"] == "der"

    def test_sign_without_grant_is_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session)

        assert (
            excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotAllowed"
        )
        assert "credential" in excinfo.value.get_dbus_message()
        assert len(mock_intf.GetMethodCalls("Sign")) == 0

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
            (
                {"purpose": "signing", "requested_lifetime": dbus.UInt32(0)},
                "requested_lifetime must be greater than zero",
            ),
            (
                {
                    "purpose": "signing",
                    "certificate_filter": dbus.Dictionary(
                        {"colour": "blue"}, signature="sv"
                    ),
                },
                "certificate_filter",
            ),
            (
                {
                    "purpose": "signing",
                    "certificate_filter": dbus.Dictionary(
                        {"piv_slot": "glovebox"}, signature="sv"
                    ),
                },
                "piv_slot",
            ),
            (
                {
                    "purpose": "signing",
                    "certificate_filter": dbus.Dictionary(
                        {"token_label": dbus.UInt32(1)}, signature="sv"
                    ),
                },
                "token_label",
            ),
            (
                {
                    "purpose": "signing",
                    "operation_policy": dbus.Dictionary(
                        {"decrypt": True}, signature="sv"
                    ),
                },
                "operation_policy",
            ),
            (
                {
                    "purpose": "signing",
                    "operation_policy": dbus.Dictionary(
                        {"sign": False}, signature="sv"
                    ),
                },
                "permits no operation",
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

        assert (
            excinfo.value.get_dbus_name()
            == "org.freedesktop.portal.Error.InvalidArgument"
        )
        assert error_fragment in excinfo.value.get_dbus_message()
        assert len(mock_intf.GetMethodCalls("AcquireCredential")) == 0

    @pytest.mark.parametrize(
        "options,error_fragment",
        [
            ({"mechanism": "ECDSA", "data": DIGEST}, "hash is required"),
            (
                dict(SIGN_OPTIONS, parameters=dbus.Dictionary({"hash": "MD5"}, "sv")),
                "MD5",
            ),
            (
                dict(
                    SIGN_OPTIONS, parameters=dbus.Dictionary({"hash": "SHA512"}, "sv")
                ),
                "digest",
            ),
            (dict(SIGN_OPTIONS, data=dbus.ByteArray(b"not a digest")), "digest"),
            (
                dict(
                    SIGN_OPTIONS,
                    parameters=dbus.Dictionary(
                        {"hash": "SHA256", "signature_encoding": dbus.UInt32(1)}, "sv"
                    ),
                ),
                "signature_encoding",
            ),
            (
                dict(
                    SIGN_OPTIONS,
                    parameters=dbus.Dictionary(
                        {"hash": "SHA256", "signature_encoding": "asn1"}, "sv"
                    ),
                ),
                "signature_encoding",
            ),
            (
                dict(
                    SIGN_OPTIONS,
                    parameters=dbus.Dictionary({"hash": "SHA256", "mgf": "MGF2"}, "sv"),
                ),
                "mgf",
            ),
            (
                dict(
                    SIGN_OPTIONS,
                    parameters=dbus.Dictionary({"hash": "SHA256", "salt": 32}, "sv"),
                ),
                "parameters",
            ),
            ({"mechanism": "MAGIC_BEANS", "data": DIGEST}, "mechanism"),
            (dict(SIGN_OPTIONS, operation_id=dbus.UInt32(1)), "operation_id"),
        ],
    )
    def test_sign_invalid_option_rejected(
        self, portals, dbus_con, options, error_fragment
    ):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session, options=options)

        assert (
            excinfo.value.get_dbus_name()
            == "org.freedesktop.portal.Error.InvalidArgument"
        )
        assert error_fragment in excinfo.value.get_dbus_message()
        assert len(mock_intf.GetMethodCalls("Sign")) == 0

    @pytest.mark.parametrize(
        "template_params",
        (
            {"certificate": {"credential": credential(remove=["certificate_der"])}},
            {"certificate": {"credential": credential(certificate_der="certificate")}},
            {"certificate": {"credential": credential(key_size="2048")}},
            {
                "certificate": {
                    "credential": credential(
                        supported_mechanisms=dbus.Array(["MAGIC_BEANS"], signature="s")
                    )
                }
            },
            {
                "certificate": {
                    "credential": credential(
                        permitted_operations=dbus.Array(["decrypt"], signature="s")
                    )
                }
            },
        ),
    )
    def test_unusable_backend_results_are_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        response = acquire_credential(dbus_con, intf, session)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "backend_protocol_error"
        assert "certificate_der" not in response.results

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session)

        assert (
            excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotAllowed"
        )
        assert "credential" in excinfo.value.get_dbus_message()

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

        assert excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotFound"
        assert "session" in excinfo.value.get_dbus_message().lower()

    def test_closed_session_has_no_grant(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        session.close()

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session)

        assert excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotFound"
        assert "Invalid session" in excinfo.value.get_dbus_message()

    @pytest.mark.parametrize(
        "template_params", ({"certificate": {"expect-close": True}},)
    )
    def test_close(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        request.schedule_close(300)
        request.call("CreateSession", options={})

        assert request.closed

    @pytest.mark.parametrize("template_params", ({"certificate": {"response": 1}},))
    def test_cancel(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        response = request.call("CreateSession", options={})

        assert response
        assert response.response == 1
        assert "session_handle" not in response.results

    def test_grant_invalidated_reaches_the_owner_only(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        owner_signals = []
        intf.connect_to_signal(
            "GrantInvalidated", lambda h, r: owner_signals.append((str(h), str(r)))
        )

        onlooker = dbus.bus.BusConnection(os.environ["DBUS_SESSION_BUS_ADDRESS"])
        onlooker_signals = []
        onlooker.add_signal_receiver(
            lambda h, r: onlooker_signals.append((str(h), str(r))),
            signal_name="GrantInvalidated",
            dbus_interface=INTERFACE,
        )

        try:
            mock_intf.InvalidateSession(session.handle, "token_removed")
            xdp.wait_for(lambda: len(owner_signals) == 1)

            versions = []
            errors = []
            properties = dbus.Interface(
                xdp.get_xdp_dbus_object(onlooker), "org.freedesktop.DBus.Properties"
            )
            properties.Get(
                INTERFACE,
                "version",
                reply_handler=versions.append,
                error_handler=errors.append,
            )
            xdp.wait_for(lambda: versions or errors)
            assert not errors
            assert versions == [1]
            assert owner_signals[0] == (session.handle, "token_removed")
            assert onlooker_signals == []
            xdp.wait_for(lambda: session.closed)
        finally:
            onlooker.close()

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session)

        assert excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotFound"
        assert "Invalid session" in excinfo.value.get_dbus_message()

    @pytest.mark.parametrize("template_params", ({"certificate": {"hold": True}},))
    def test_concurrent_acquisition_is_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        first = xdp.Request(dbus_con, intf)
        second = xdp.Request(dbus_con, intf)
        errors = []
        completed = []
        mock_intf.connect_to_signal("AcquireCredentialDone", completed.append)

        for request in (first, second):
            intf.AcquireCredential(
                session.handle,
                "",
                {"handle_token": request.handle_token, "purpose": "client_auth"},
                reply_handler=lambda handle: None,
                error_handler=errors.append,
            )
            if request is first:
                xdp.wait_for(
                    lambda: errors or mock_intf.GetMethodCalls("AcquireCredential")
                )

        xdp.wait_for(lambda: errors or second.response)
        assert not errors
        assert not completed
        assert first.response is None
        assert second.response.response == 2
        assert second.response.results["reason"] == "grant_already_held"

        mock_intf.ReleaseAcquireCredential()
        xdp.wait_for(lambda: errors or first.response)
        assert not errors
        assert first.response.response == 0
        assert len(mock_intf.GetMethodCalls("AcquireCredential")) == 1

    @pytest.mark.parametrize("template_params", ({"certificate": {"delay": 300}},))
    def test_closed_request_does_not_acquire_grant(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        request = xdp.Request(dbus_con, intf)
        completed = []
        mock_intf.connect_to_signal("AcquireCredentialDone", completed.append)
        intf.AcquireCredential(
            session.handle,
            "",
            {"handle_token": request.handle_token, "purpose": "client_auth"},
        )
        request.close()

        xdp.wait_for(lambda: completed)
        assert completed == [request.handle]

        def acquired():
            response = acquire_credential(dbus_con, intf, session)
            assert response
            if response.response == 0:
                return True
            assert response.response == 2
            assert response.results["reason"] == "grant_already_held"
            return False

        xdp.wait_for(acquired)
        assert request.response is None

    def test_reused_session_path_has_no_grant(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "CreateSession", options={"session_handle_token": "reused"}
        )
        first = xdp.Session.from_response(dbus_con, response)
        assert acquire_credential(dbus_con, intf, first).response == 0
        first.close()
        xdp.wait_for(lambda: first.closed)

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "CreateSession", options={"session_handle_token": "reused"}
        )
        second = xdp.Session.from_response(dbus_con, response)

        assert second.handle == first.handle
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, second)
        assert (
            excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotAllowed"
        )
        assert "credential" in excinfo.value.get_dbus_message()
        assert acquire_credential(dbus_con, intf, second).response == 0

    def test_grant_expires(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)

        signals = []
        intf.connect_to_signal(
            "GrantInvalidated", lambda h, r: signals.append((str(h), str(r)))
        )

        response = acquire_credential(
            dbus_con,
            intf,
            session,
            options={
                "purpose": "client_auth",
                "requested_lifetime": dbus.UInt32(1),
            },
        )
        assert response
        assert response.response == 0

        xdp.wait_for(lambda: signals)
        assert signals[0] == (session.handle, "expired")
        xdp.wait_for(lambda: session.closed)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session)

        assert excinfo.value.get_dbus_name() == "org.freedesktop.portal.Error.NotFound"
        assert "Invalid session" in excinfo.value.get_dbus_message()

    @pytest.mark.parametrize("template_params", ({"certificate": {"hold-sign": True}},))
    def test_expiry_during_sign(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        signals = []
        intf.connect_to_signal(
            "GrantInvalidated", lambda h, r: signals.append((str(h), str(r)))
        )
        assert (
            acquire_credential(
                dbus_con,
                intf,
                session,
                options={
                    "purpose": "client_auth",
                    "requested_lifetime": dbus.UInt32(1),
                },
            ).response
            == 0
        )

        request = xdp.Request(dbus_con, intf)
        errors = []
        intf.Sign(
            session.handle,
            "",
            dict(SIGN_OPTIONS, handle_token=request.handle_token),
            reply_handler=lambda handle: None,
            error_handler=errors.append,
        )
        xdp.wait_for(
            lambda: errors or request.response or mock_intf.GetMethodCalls("Sign")
        )
        assert not errors
        assert len(mock_intf.GetMethodCalls("Sign")) == 1
        assert request.response is None

        xdp.wait_for(lambda: signals)
        assert signals == [(session.handle, "expired")]
        assert request.response is None
        mock_intf.ReleaseSign()
        xdp.wait_for(lambda: errors or request.response)
        assert not errors
        assert len(mock_intf.GetMethodCalls("Sign")) == 1
        response = request.response

        assert response
        assert response.response == 2
        assert response.results["reason"] == "grant_gone"
        assert "signature" not in response.results

    def test_backend_disconnect_invalidates_grant(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        granted = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, granted).response == 0
        empty = create_session(dbus_con, intf)

        signals = []
        intf.connect_to_signal(
            "GrantInvalidated", lambda h, r: signals.append((str(h), str(r)))
        )

        mock_intf.ReleaseName()

        xdp.wait_for(lambda: granted.closed and empty.closed)

        assert signals == [(granted.handle, "backend_gone")]

    @pytest.mark.parametrize("template_params", ({"certificate": {"response": 5}},))
    def test_invalid_backend_response_rejected(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        response = request.call("CreateSession", options={})

        assert response
        assert response.response == 2
        assert "session_handle" not in response.results

    def test_get_capabilities(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        capabilities = intf.GetCapabilities({})

        assert list(capabilities["purposes"]) == ["client_auth", "signing"]
        assert list(capabilities["operations"]) == ["sign"]
        assert list(capabilities["mechanisms"]) == ["RSA_PSS", "ECDSA"]
        assert capabilities["max_grant_lifetime"] == 3600
        assert not capabilities["protected_authentication_path"]
        assert capabilities["has_display"]


class TestCertificateDisabled:
    @pytest.fixture
    def xdp_overwrite_env(self, monkeypatch):
        monkeypatch.delenv("XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL", raising=False)
        return {}

    def test_interface_not_exported(self, portals, dbus_con):
        introspectable = dbus.Interface(
            xdp.get_xdp_dbus_object(dbus_con), "org.freedesktop.DBus.Introspectable"
        )
        node = ET.fromstring(introspectable.Introspect())
        assert INTERFACE not in {
            iface.attrib["name"] for iface in node.findall("interface")
        }
