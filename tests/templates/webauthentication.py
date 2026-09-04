# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: Copyright © the xdg-desktop-portal contributors
#
# This file is formatted with Python Black
# mypy: disable-error-code="misc"

from dataclasses import dataclass

import dbus
import dbus.service

from tests.templates.xdp_utils import ImplRequest, Response, init_logger

BUS_NAME = "org.freedesktop.impl.portal.Test"
MAIN_OBJ = "/org/freedesktop/portal/desktop"
SYSTEM_BUS = False
MAIN_IFACE = "org.freedesktop.impl.portal.experimental.WebAuthentication"
VERSION = 1


logger = init_logger(__name__)


@dataclass
class WebAuthenticationParameters:
    delay: int
    response: int
    expect_close: bool
    # When set, the backend answers with this URI instead of the one it was
    # asked to watch for. Used to check that the frontend re-checks.
    completion_uri: str | None
    reason: str | None


def load(mock, parameters=None):
    parameters = parameters or {}

    logger.debug(f"Loading parameters: {parameters}")

    assert not hasattr(mock, "webauthentication_params")
    mock.webauthentication_params = WebAuthenticationParameters(
        delay=parameters.get("delay", 0),
        response=parameters.get("response", 0),
        expect_close=parameters.get("expect-close", False),
        completion_uri=parameters.get("completion-uri", None),
        reason=parameters.get("reason", None),
    )

    mock.AddProperties(
        MAIN_IFACE,
        dbus.Dictionary(
            {
                "version": dbus.UInt32(parameters.get("version", VERSION)),
            }
        ),
    )


@dbus.service.method(
    MAIN_IFACE,
    in_signature="ossssa{sv}",
    out_signature="ua{sv}",
    async_callbacks=("cb_success", "cb_error"),
)
def Start(
    self,
    handle,
    app_id,
    parent_window,
    start_uri,
    completion_uri,
    options,
    cb_success,
    cb_error,
):
    logger.debug(
        f"Start({handle}, {app_id}, {parent_window}, {start_uri}, "
        f"{completion_uri}, {options})"
    )
    params = self.webauthentication_params

    request = ImplRequest(self, BUS_NAME, handle, logger, cb_success, cb_error)

    if params.expect_close:
        request.wait_for_close()
        return

    results = {}
    if params.response == 0:
        answered = params.completion_uri or completion_uri
        # The web engine hands back the URI it actually navigated to, query
        # and fragment included.
        results["completion_uri"] = f"{answered}?code=secret"
    elif params.reason:
        results["reason"] = params.reason

    request.respond(Response(params.response, results), delay=params.delay)
