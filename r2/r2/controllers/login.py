# The contents of this file are subject to the Common Public Attribution
# License Version 1.0. (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://code.reddit.com/LICENSE. The License is based on the Mozilla Public
# License Version 1.1, but Sections 14 and 15 have been added to cover use of
# software over a computer network and provide for limited attribution for the
# Original Developer. In addition, Exhibit A has been modified to be consistent
# with Exhibit B.
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
# the specific language governing rights and limitations under the License.
#
# The Original Code is reddit.
#
# The Original Developer is the Initial Developer.  The Initial Developer of
# the Original Code is reddit Inc.
#
# All portions of the code written by reddit are Copyright (c) 2006-2015 reddit
# Inc. All Rights Reserved.
###############################################################################
from pylons import request
from pylons import tmpl_context as c
from pylons import app_globals as g

from r2.lib.validator import VRatelimit
from r2.lib import amqp
from r2.lib import emailer
from r2.lib import hooks
from r2.lib import newsletter
from r2.lib.base import abort
from r2.lib.errors import errors, reddit_http_error

from r2.models.account import register, AccountExists


def handle_login(
    controller, form, responder, user, rem=None, signature=None, **kwargs
):
    def _event(error):
        g.events.login_event(
            'login_attempt',
            error_msg=error,
            user_name=request.urlvars.get('url_user'),
            remember_me=rem,
            signature=signature,
            request=request,
            context=c)

    if signature and not signature.is_valid():
        _event(error="SIGNATURE")
        abort(403)

    hook_error = hooks.get_hook("account.login").call_until_return(
        responder=responder,
        request=request,
        context=c,
    )
    # if any of the hooks returned an error, abort the login.  The
    # set_error in this case also needs to exist in the hook.
    if hook_error:
        _event(error=hook_error)
        return

    exempt_ua = (request.user_agent and
                 any(ua in request.user_agent for ua
                     in g.config.get('exempt_login_user_agents', ())))
    if (errors.LOGGED_IN, None) in c.errors:
        if user == c.user or exempt_ua:
            # Allow funky clients to re-login as the current user.
            c.errors.remove((errors.LOGGED_IN, None))
        else:
            _event(error='LOGGED_IN')
            abort(reddit_http_error(409, errors.LOGGED_IN))

    if responder.has_errors("ratelimit", errors.RATELIMIT):
        _event(error='RATELIMIT')

    elif responder.has_errors("passwd", errors.WRONG_PASSWORD):
        _event(error='WRONG_PASSWORD')

    else:
        controller._login(responder, user, rem)
        _event(error=None)
