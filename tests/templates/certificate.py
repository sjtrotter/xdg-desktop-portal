# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black
# mypy: disable-error-code="misc"

from dataclasses import dataclass

import dbus
import dbus.service

from tests.templates.xdp_utils import ImplRequest, ImplSession, Response, init_logger

BUS_NAME = "org.freedesktop.impl.portal.Test"
MAIN_OBJ = "/org/freedesktop/portal/desktop"
SYSTEM_BUS = False
MAIN_IFACE = "org.freedesktop.impl.portal.experimental.Certificate"
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
    response: int
    expect_close: bool
    credential: dict
    certificate_id: str
    signature: bytes
    plaintext: bytes
    capabilities: dict


def load(mock, parameters=None):
    parameters = parameters or {}

    logger.debug(f"Loading parameters: {parameters}")

    assert not hasattr(mock, "certificate_params")
    mock.certificate_params = CertificateParameters(
        delay=parameters.get("delay", 0),
        response=parameters.get("response", 0),
        expect_close=parameters.get("expect-close", False),
        credential=parameters.get("credential", DEFAULT_CREDENTIAL),
        certificate_id=parameters.get("certificate_id", "cert-1"),
        signature=parameters.get("signature", b"signature"),
        plaintext=parameters.get("plaintext", b"plaintext"),
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
    mock.sessions: dict[str, ImplSession] = {}


@dbus.service.method(
    MAIN_IFACE,
    in_signature="oosa{sv}",
    out_signature="ua{sv}",
    async_callbacks=("cb_success", "cb_error"),
)
def CreateSession(self, handle, session_handle, app_id, options, cb_success, cb_error):
    logger.debug(f"CreateSession({handle}, {session_handle}, {app_id}, {options})")
    params = self.certificate_params

    session = ImplSession(self, BUS_NAME, session_handle, app_id).export()
    self.sessions[session_handle] = session

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

    results = dict(params.credential)

    # A well behaved backend only offers to remember the selection when the
    # frontend said it may, and only then reports that the user asked for it.
    if options.get("allow_selection_memory", False):
        results["certificate_id"] = params.certificate_id
        results["remember_selection"] = True

    if params.expect_close:
        request.wait_for_close()
    else:
        request.respond(Response(params.response, results), delay=params.delay)


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

    request = ImplRequest(self, BUS_NAME, handle, logger, cb_success, cb_error)

    if params.expect_close:
        request.wait_for_close()
    else:
        request.respond(
            Response(params.response, {"signature": dbus.ByteArray(params.signature)}),
            delay=params.delay,
        )


@dbus.service.method(
    MAIN_IFACE,
    in_signature="oossa{sv}",
    out_signature="ua{sv}",
    async_callbacks=("cb_success", "cb_error"),
)
def Decrypt(
    self, handle, session_handle, app_id, parent_window, options, cb_success, cb_error
):
    logger.debug(f"Decrypt({handle}, {session_handle}, {app_id}, {options})")
    params = self.certificate_params

    assert session_handle in self.sessions

    request = ImplRequest(self, BUS_NAME, handle, logger, cb_success, cb_error)

    if params.expect_close:
        request.wait_for_close()
    else:
        request.respond(
            Response(params.response, {"plaintext": dbus.ByteArray(params.plaintext)}),
            delay=params.delay,
        )


@dbus.service.method(
    MAIN_IFACE,
    in_signature="sa{sv}",
    out_signature="a{sv}",
)
def GetCapabilities(self, app_id, options):
    logger.debug(f"GetCapabilities({app_id}, {options})")

    return dbus.Dictionary(self.certificate_params.capabilities, signature="sv")
