# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black
# mypy: disable-error-code="misc"

from dataclasses import dataclass

import dbus
import dbus.service
from dbusmock import MOCK_IFACE, DBusMockObject
from gi.repository import GLib

from tests.templates.xdp_utils import ImplRequest, Response, init_logger

BUS_NAME = "org.freedesktop.impl.portal.Test"
MAIN_OBJ = "/org/freedesktop/portal/desktop"
SYSTEM_BUS = False
MAIN_IFACE = "org.freedesktop.impl.portal.experimental.Certificate1"
VERSION = 1


logger = init_logger(__name__)


DEFAULT_CREDENTIAL = {
    "certificate_der": dbus.ByteArray(b"certificate"),
    "chain_status": "leaf_only",
    "key_type": "EC",
    "key_size": dbus.UInt32(256),
    "key_curve": "P-256",
    "supported_mechanisms": dbus.Array(["ECDSA"], signature="s"),
    "permitted_operations": dbus.Array(["sign"], signature="s"),
    "may_prompt_later": False,
}

DEFAULT_CAPABILITIES = {
    "purposes": dbus.Array(["client_auth", "signing"], signature="s"),
    "operations": dbus.Array(["sign"], signature="s"),
    "mechanisms": dbus.Array(["ECDSA", "RSA_PSS"], signature="s"),
    "protected_authentication_path": False,
    "has_display": True,
}


@dataclass
class CertificateParameters:
    delay: int
    sign_delay: int
    hold: bool
    hold_sign: bool
    hold_close: bool
    response: int
    expect_close: bool
    credential: dict
    signature: bytes
    capabilities: dict


class CertificateSession(DBusMockObject):
    @dbus.service.method(
        "org.freedesktop.impl.portal.Session",
        in_signature="",
        out_signature="",
        async_callbacks=("cb_success", "cb_error"),
    )
    def Close(self, cb_success, cb_error):
        mock = self.mock_data
        mock.grants.discard(self.path)
        mock.sessions.remove(self.path)
        mock.RemoveObject(self.path)
        mock.EmitSignal(
            "org.freedesktop.impl.portal.Mock", "SessionClosed", "s", [self.path]
        )

        if mock.certificate_params.hold_close:
            mock.session_close_replies[self.path] = (cb_success, cb_error)
            mock.EmitSignal(MOCK_IFACE, "SessionClosePending", "o", [self.path])
        else:
            cb_success()


def load(mock, parameters=None):
    parameters = parameters or {}

    logger.debug(f"Loading parameters: {parameters}")

    assert not hasattr(mock, "certificate_params")
    mock.certificate_params = CertificateParameters(
        delay=parameters.get("delay", 0),
        sign_delay=parameters.get("sign-delay", parameters.get("delay", 0)),
        hold=parameters.get("hold", False),
        hold_sign=parameters.get("hold-sign", False),
        hold_close=parameters.get("hold-close", False),
        response=parameters.get("response", 0),
        expect_close=parameters.get("expect-close", False),
        credential=parameters.get("credential", DEFAULT_CREDENTIAL),
        signature=parameters.get("signature", b"signature"),
        capabilities=parameters.get("capabilities", DEFAULT_CAPABILITIES),
    )

    mock.AddProperties(
        MAIN_IFACE,
        dbus.Dictionary(
            {
                "version": dbus.UInt32(parameters.get("version", VERSION)),
            }
        ),
    )
    mock.sessions: set[str] = set()
    mock.grants: set[str] = set()
    mock.session_close_replies = {}


@dbus.service.method(
    MAIN_IFACE,
    in_signature="oosa{sv}",
    out_signature="ua{sv}",
    async_callbacks=("cb_success", "cb_error"),
)
def CreateSession(self, handle, session_handle, app_id, options, cb_success, cb_error):
    logger.debug(f"CreateSession({handle}, {session_handle}, {app_id}, {options})")
    params = self.certificate_params

    self.AddObject(
        session_handle,
        "org.freedesktop.impl.portal.Session",
        {},
        [],
        mock_class=CertificateSession,
        mock_data=self,
    )
    self.sessions.add(session_handle)

    request = ImplRequest(self, BUS_NAME, handle, logger, cb_success, cb_error)

    if params.expect_close:
        request.wait_for_close()
    else:
        request.respond(Response(params.response, {}), delay=params.delay)


@dbus.service.method(
    MAIN_IFACE,
    in_signature="oossa{sv}",
    out_signature="ua{sv}",
    async_callbacks=("cb_success", "cb_error"),
)
def AcquireCredential(
    self, handle, session_handle, app_id, parent_window, options, cb_success, cb_error
):
    logger.debug(
        f"AcquireCredential({handle}, {session_handle}, {app_id}, "
        f"{parent_window}, {options})"
    )
    params = self.certificate_params

    assert session_handle in self.sessions

    request = ImplRequest(self, BUS_NAME, handle, logger, cb_success, cb_error)

    if params.expect_close:
        request.wait_for_close()
    else:
        if params.response == 0:
            self.grants.add(session_handle)

        def done():
            self.EmitSignal(MOCK_IFACE, "AcquireCredentialDone", "o", [handle])

        def reply():
            request.respond(
                Response(params.response, dict(params.credential)),
                delay=params.delay,
                done_cb=done,
            )

        if params.hold:
            request._export()

            def release():
                request._unexport()
                reply()

            self.acquire_credential_reply = release
            self.AddMethod(
                MOCK_IFACE,
                "ReleaseAcquireCredential",
                "",
                "",
                "self.acquire_credential_reply()",
            )
        else:
            reply()


@dbus.service.method(
    MAIN_IFACE,
    in_signature="oossa{sv}",
    out_signature="ua{sv}",
    async_callbacks=("cb_success", "cb_error"),
)
def Sign(
    self, handle, session_handle, app_id, parent_window, options, cb_success, cb_error
):
    logger.debug(f"Sign({handle}, {session_handle}, {app_id}, {options})")
    params = self.certificate_params

    assert session_handle in self.sessions
    assert session_handle in self.grants

    request = ImplRequest(self, BUS_NAME, handle, logger, cb_success, cb_error)

    if params.expect_close:
        request.wait_for_close()
    else:

        def reply():
            request.respond(
                Response(
                    params.response, {"signature": dbus.ByteArray(params.signature)}
                ),
                delay=params.sign_delay,
            )

        if params.hold_sign:
            self.sign_reply = reply
            self.AddMethod(MOCK_IFACE, "ReleaseSign", "", "", "self.sign_reply()")
        else:
            reply()


@dbus.service.method(
    MAIN_IFACE,
    in_signature="sa{sv}",
    out_signature="a{sv}",
)
def GetCapabilities(self, app_id, options):
    logger.debug(f"GetCapabilities({app_id}, {options})")

    return dbus.Dictionary(self.certificate_params.capabilities, signature="sv")


@dbus.service.method(MOCK_IFACE, in_signature="o", out_signature="b")
def HasGrant(self, session_handle):
    return session_handle in self.grants


@dbus.service.method(MOCK_IFACE, in_signature="ob", out_signature="")
def ReleaseSessionClose(self, session_handle, fail):
    cb_success, cb_error = self.session_close_replies.pop(session_handle)
    if fail:
        cb_error(
            dbus.exceptions.DBusException(
                "Session close failed", name="org.freedesktop.DBus.Error.Failed"
            )
        )
    else:
        cb_success()


@dbus.service.method(
    MOCK_IFACE,
    in_signature="",
    out_signature="",
)
def ReleaseName(self):
    logger.debug("ReleaseName()")

    def release():
        self.connection.release_name(BUS_NAME)
        return GLib.SOURCE_REMOVE

    # Release the name after replying to this call.
    GLib.idle_add(release)


@dbus.service.method(
    MOCK_IFACE,
    in_signature="os",
    out_signature="",
)
def InvalidateSession(self, session_handle, reason):
    logger.debug(f"InvalidateSession({session_handle}, {reason})")

    self.EmitSignal(MAIN_IFACE, "SessionInvalidated", "os", [session_handle, reason])
