from flask import render_template, session, redirect
from flask_dance.contrib import azure, github
import flask_dance.contrib

from CTFd.auth import confirm, register, reset_password, login
from CTFd.models import db, Users
from CTFd.utils import set_config
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user

from CTFd import utils

from .blueprint import fortytwo, make_42_blueprint

def load(app):
    ########################
    # Plugin Configuration #
    ########################
    authentication_url_prefix = "/auth"
    oauth_client_id = utils.get_app_config('OAUTHLOGIN_CLIENT_ID')
    oauth_client_secret = utils.get_app_config('OAUTHLOGIN_CLIENT_SECRET')
    oauth_provider = 'fortytwo' #utils.get_app_config('OAUTHLOGIN_PROVIDER')
    create_missing_user = True #utils.get_app_config('OAUTHLOGIN_CREATE_MISSING_USER')

    ##################
    # User Functions #
    ##################
    def retrieve_user_from_database(email):
        print("mdr_two")
        user = Users.query.filter_by(email=email).first()
        if user is not None:
            log('logins', "[{date}] {ip} - " + user.name + " - OAuth2 bridged user found")
            return user
    def create_user(username, email):
        print("mdr_one")
        with app.app_context():
            print("test_one")
            user = Users(email=email, name=username)
            print("test_two")
            log('logins', "[{date}] {ip} - " + username + " - No OAuth2 bridged user found, creating user")
            print("test_three")
            db.session.add(user)
            print("test_four")
            db.session.commit()
            print("test_five")
            db.session.flush()
            print("test_six")
            user = Users.query.filter_by(email=email).first()
            return user
    def create_or_get_user(username, email):
        print("lol_one")
        user = retrieve_user_from_database(email)
        print("lol_two")
        if user is not None:
            print("lol_three")
            return user
        if create_missing_user:
            print("lol_four")
            return create_user(username, email)
        else:
            print("lol_five")
            log('logins', "[{date}] {ip} - " + username + " - No OAuth2 bridged user found and not configured to create missing users")
            return None

    ##########################
    # Provider Configuration #
    ##########################
    provider_blueprints = {
        'fortytwo': lambda: make_42_blueprint(
            login_url='/fortytwo',
            client_id='CLIENT_ID',
            client_secret='CLIENT_SECRET',
            redirect_url=authentication_url_prefix + "/fortytwo/confirm")
        #'azure': lambda: flask_dance.contrib.azure.make_azure_blueprint(
        #    login_url='/azure',
        #    client_id=oauth_client_id,
        #    client_secret=oauth_client_secret,
        #    redirect_url=authentication_url_prefix + "/azure/confirm"),
        #'github': lambda: flask_dance.contrib.github.make_github_blueprint(
        #    login_url='/github',
        #    client_id=oauth_client_id,
        #    client_secret=oauth_client_secret,
        #    redirect_url=authentication_url_prefix + "/github/confirm")
    }

    def get_fortytwo_user():
        r = fortytwo.get("/v2/me")

        # print(r.url)
        # print(r.status_code)
        # print(r.text)

        user_info = r.json()
        return create_or_get_user(
            username=user_info["login"],
            email=user_info["email"])

    #def get_azure_user():
    #    user_info = flask_dance.contrib.azure.azure.get("/v1.0/me").json()
    #    return create_or_get_user(
    #        username=user_info["userPrincipalName"],
    #        displayName=user_info["displayName"])
    #def get_github_user():
    #    user_info = flask_dance.contrib.github.github.get("/user").json()
    #    return create_or_get_user(
    #        username=user_info["email"],
    #        displayName=user_info["name"])

    provider_users = {
        #'azure': lambda: get_azure_user(),
        #'github': lambda: get_github_user()
        'fortytwo': lambda: get_fortytwo_user()
    }

    provider_blueprint = provider_blueprints[oauth_provider]() # Resolved lambda
    
    #######################
    # Blueprint Functions #
    #######################
    @provider_blueprint.route('/<string:auth_provider>/confirm', methods=['GET'])
    def confirm_auth_provider(auth_provider):
        print("confirm_auth_provider")

        if auth_provider not in provider_users:
            return redirect('/')

        print("debug_one")

        provider_user = provider_users[oauth_provider]() # Resolved lambda

        print("debug_two")

        session.regenerate()

        print("debug_three")
        if provider_user is not None:
            print("debug_four")
            with app.app_context():
                print("debug_five")
                login_user(provider_user)
        print("debug_six")
        return redirect('/')

    app.register_blueprint(provider_blueprint, url_prefix=authentication_url_prefix)

    ###############################
    # Application Reconfiguration #
    ###############################
    # ('', 204) is "No Content" code
    set_config('registration_visibility', False)
    app.view_functions['auth.login'] = lambda: redirect(authentication_url_prefix + "/" + oauth_provider)
    app.view_functions['auth.register'] = lambda: ('', 204)
    app.view_functions['auth.reset_password'] = lambda: ('', 204)
    app.view_functions['auth.confirm'] = lambda: ('', 204)     
