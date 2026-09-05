# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black

import os

import dbus
import pytest
from gi.repository import GLib

import tests.xdp_utils as xdp

INTERFACE = "org.freedesktop.portal.experimental.Certificate"

# A 32 byte SHA256 digest, which is what Sign takes
DIGEST = dbus.ByteArray(b"0123456789abcdef0123456789abcdef")

SIGN_OPTIONS = {
    "mechanism": "ECDSA",
    "parameters": dbus.Dictionary({"hash": "SHA256"}, signature="sv"),
    "data": DIGEST,
}


def credential(remove=(), **overrides):
    """
    What the backend answers AcquireCredential with, as D-Bus types.
    """
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
def required_templates():
    return {"certificate": {}}


@pytest.fixture
def xdp_overwrite_env():
    return {"XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL": "certificate"}


def create_session(dbus_con, intf):
    request = xdp.Request(dbus_con, intf)
    response = request.call("CreateSession", options={})
    assert response
    assert response.response == 0
    # The XML types session_handle as an object path, not a string.
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
        # A copy: Request.call() fills its handle_token into whatever it is
        # given, and every call needs its own
        options=dict(SIGN_OPTIONS if options is None else options),
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
        # There is no renewal, so nothing hands back a grant id to renew with
        assert "grant_id" not in response.results

        _, args = mock_intf.GetMethodCalls("AcquireCredential")[-1]
        assert args[1] == session.handle
        assert args[2] == xdp_app_info.app_id
        options = args[4]
        # The frontend decides these, not the app
        assert options["lifetime"] == 120
        assert options["app_identity_level"] in ("sandboxed", "host", "unidentified")
        assert options["certificate_filter"]["piv_slot"] == "authentication"
        assert options["reason"] == "To connect to the corporate VPN"
        # handle_token and the frontend-only options are never forwarded
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

        _, args = mock_intf.GetMethodCalls("AcquireCredential")[-1]
        assert args[4]["lifetime"] == 3600

    def test_second_acquisition_is_refused(self, portals, dbus_con):
        """
        A session acquires at most once: the way to a second credential is a
        second session, which means asking the user again.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        response = acquire_credential(dbus_con, intf, session)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "grant_already_held"
        # and the user was asked exactly once
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
        """
        What the backend reports is intersected with what the portal allows and
        with what the application asked for. A backend that reports more than
        it may does not get more.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        response = acquire_credential(dbus_con, intf, session)

        assert response
        assert response.response == 0
        assert list(response.results["supported_mechanisms"]) == ["RSA_PSS", "ECDSA"]
        assert list(response.results["permitted_operations"]) == ["sign"]

        # And a mechanism the portal allows but this grant does not have is
        # refused rather than forwarded
        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(
                dbus_con,
                intf,
                session,
                options=dict(SIGN_OPTIONS, mechanism="RSA_PKCS1_V1_5"),
            )

        assert "RSA_PKCS1_V1_5" in str(excinfo.value)

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

        # operation_id is the application's correlation handle, not the
        # backend's business
        _, args = mock_intf.GetMethodCalls("Sign")[-1]
        assert "operation_id" not in args[4]
        assert args[4]["parameters"]["signature_encoding"] == "der"

    def test_sign_without_grant_is_refused(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        with pytest.raises(dbus.exceptions.DBusException) as excinfo:
            sign(dbus_con, intf, session)

        assert "credential" in str(excinfo.value)
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
            ({"purpose": "signing", "requested_lifetime": dbus.UInt32(0)}, "lifetime"),
            # the nested vardicts are closed vocabularies, and typed
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

        assert error_fragment in str(excinfo.value)
        assert len(mock_intf.GetMethodCalls("AcquireCredential")) == 0

    @pytest.mark.parametrize(
        "options,error_fragment",
        [
            # 'data' is a digest, so the portal has to be told which one
            ({"mechanism": "ECDSA", "data": DIGEST}, "hash"),
            (
                dict(SIGN_OPTIONS, parameters=dbus.Dictionary({"hash": "MD5"}, "sv")),
                "MD5",
            ),
            # and a digest has exactly one length
            (
                dict(
                    SIGN_OPTIONS, parameters=dbus.Dictionary({"hash": "SHA512"}, "sv")
                ),
                "digest",
            ),
            (dict(SIGN_OPTIONS, data=dbus.ByteArray(b"not a digest")), "digest"),
            # present with the wrong type is an error, never absent
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

        assert error_fragment in str(excinfo.value)
        assert len(mock_intf.GetMethodCalls("Sign")) == 0

    @pytest.mark.parametrize(
        "template_params",
        (
            # no certificate_der at all
            {"certificate": {"credential": credential(remove=["certificate_der"])}},
            # certificate_der with the wrong type
            {"certificate": {"credential": credential(certificate_der="certificate")}},
            # an optional result with the wrong type
            {"certificate": {"credential": credential(key_size="2048")}},
            # no mechanism the portal allows
            {
                "certificate": {
                    "credential": credential(
                        supported_mechanisms=dbus.Array(["MAGIC_BEANS"], signature="s")
                    )
                }
            },
            # nothing that was asked for
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

        # and the session did not become a grant
        with pytest.raises(dbus.exceptions.DBusException):
            sign(dbus_con, intf, session)

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

    def test_closed_session_has_no_grant(self, portals, dbus_con):
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
        assert acquire_credential(dbus_con, intf, session).response == 0

        session.close()

        with pytest.raises(dbus.exceptions.DBusException):
            sign(dbus_con, intf, session)

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

        request = xdp.Request(dbus_con, intf)
        response = request.call("CreateSession", options={})

        assert response
        assert response.response == 1
        assert "session_handle" not in response.results

    def test_grant_invalidated_reaches_the_owner_only(self, portals, dbus_con):
        """
        A session object path carries the owning peer's unique bus name, so the
        signal goes to that peer and to nobody else.
        """
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

            assert owner_signals[0] == (session.handle, "token_removed")
            assert onlooker_signals == []
            # the session ends with the grant
            xdp.wait_for(lambda: session.closed)
        finally:
            onlooker.close()

        with pytest.raises(dbus.exceptions.DBusException):
            sign(dbus_con, intf, session)

    @pytest.mark.parametrize("template_params", ({"certificate": {"delay": 400}},))
    def test_concurrent_acquisition_is_refused(self, portals, dbus_con):
        """
        The second AcquireCredential arrives while the first is still in
        front of the user, and is refused without asking again.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)
        mock_intf = xdp.get_mock_iface(dbus_con)

        session = create_session(dbus_con, intf)

        second = xdp.Request(dbus_con, intf)

        def start_second():
            intf.AcquireCredential(
                session.handle,
                "",
                {
                    "handle_token": second.handle_token,
                    "purpose": "client_auth",
                },
                reply_handler=lambda handle: None,
                error_handler=lambda error: None,
            )
            return GLib.SOURCE_REMOVE

        GLib.timeout_add(100, start_second)

        first = acquire_credential(dbus_con, intf, session)

        assert first
        assert first.response == 0

        xdp.wait_for(lambda: second.response is not None)
        assert second.response.response == 2
        assert second.response.results["reason"] == "grant_already_held"
        # and the user was asked exactly once
        assert len(mock_intf.GetMethodCalls("AcquireCredential")) == 1

    @pytest.mark.parametrize("template_params", ({"certificate": {"delay": 300}},))
    def test_closed_request_commits_nothing(self, portals, dbus_con):
        """
        The application closes the Request before the backend answers. The
        credential arrives afterwards and is dropped: a response nobody
        receives must not leave a grant behind.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)

        request = xdp.Request(dbus_con, intf)
        intf.AcquireCredential(
            session.handle,
            "",
            {"handle_token": request.handle_token, "purpose": "client_auth"},
        )
        request.close()

        # Long enough for the backend's answer to arrive, because what is
        # being checked is that nothing happens when it does
        xdp.wait(600)

        assert request.response is None
        # A session that held a grant would refuse this
        second = acquire_credential(dbus_con, intf, session)
        assert second
        assert second.response == 0

    def test_recreating_a_session_carries_nothing_over(self, portals, dbus_con):
        """
        A closed session gives its object path back, and the next session can
        be given the same one. It starts empty.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "CreateSession", options={"session_handle_token": "reused"}
        )
        first = xdp.Session.from_response(dbus_con, response)
        assert acquire_credential(dbus_con, intf, first).response == 0
        first.close()

        request = xdp.Request(dbus_con, intf)
        response = request.call(
            "CreateSession", options={"session_handle_token": "reused"}
        )
        second = xdp.Session.from_response(dbus_con, response)

        assert second.handle == first.handle
        with pytest.raises(dbus.exceptions.DBusException):
            sign(dbus_con, intf, second)
        # and it can acquire, which a session carrying the old grant could not
        assert acquire_credential(dbus_con, intf, second).response == 0

    def test_grant_expires(self, portals, dbus_con):
        """
        A grant that reaches its deadline is announced and its session
        closed, rather than the application finding out at its next Sign.
        """
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

        with pytest.raises(dbus.exceptions.DBusException):
            sign(dbus_con, intf, session)

    @pytest.mark.parametrize(
        "template_params", ({"certificate": {"sign-delay": 1500}},)
    )
    def test_expiry_during_sign(self, portals, dbus_con):
        """
        The grant is re-checked after every await, so a signature made for a
        grant that expired while the token was busy is not handed over.
        """
        intf = xdp.get_iface(dbus_con, INTERFACE)

        session = create_session(dbus_con, intf)
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

        response = sign(dbus_con, intf, session)

        assert response
        assert response.response == 2
        assert response.results["reason"] == "grant_gone"
        assert "signature" not in response.results

    def test_grant_ends_with_the_backend(self, portals, dbus_con):
        """
        A grant is the backend's promise as much as the user's consent. A
        session which never acquired one has no grant to invalidate and is
        closed without the signal.
        """
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
    def test_response_outside_the_contract_is_refused(self, portals, dbus_con):
        """
        Request's response is 0, 1 or 2. Anything else is not a response.
        """
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
        # Intersected with the portal's own allow list, in its order
        assert list(capabilities["mechanisms"]) == ["RSA_PSS", "ECDSA"]
        assert capabilities["max_grant_lifetime"] == 3600
        assert not capabilities["protected_authentication_path"]
        # forwarded from the backend, because an application that cannot be
        # shown a chooser needs to know before it asks for one
        assert capabilities["has_display"]


class TestCertificateExperimentalGate:
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
