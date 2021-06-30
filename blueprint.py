from flask_dance.consumer import OAuth2ConsumerBlueprint
from functools import partial
from flask.globals import LocalProxy, _lookup_app_object

from flask import _app_ctx_stack as stack

def make_42_blueprint(
    client_id=None,
    client_secret=None,
    *,
    scope=None,
    redirect_url=None,
    redirect_to=None,
    login_url=None,
    authorized_url=None,
    session_class=None,
    storage=None,
    rule_kwargs=None,
):

    blueprint = OAuth2ConsumerBlueprint(
            "fortytwo",
            __name__,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            base_url="https://api.intra.42.fr/v2/",
            authorization_url="https://api.intra.42.fr/oauth/authorize",
            token_url="https://api.intra.42.fr/oauth/token",
            redirect_url=redirect_url,
            redirect_to=redirect_to,
            login_url=login_url,
            authorized_url=authorized_url,
            session_class=session_class,
            storage=storage,
            rule_kwargs=rule_kwargs)

    @blueprint.before_app_request
    def set_applocal_session():
        ctx = stack.top
        ctx.oauth_42 = blueprint.session

    return blueprint;

fortytwo = LocalProxy(partial(_lookup_app_object, "oauth_42"))
