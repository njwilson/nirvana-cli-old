#!/usr/bin/env python

"""High-level library for Nirvana's API.

Example:
    user, password_md5 = # [user's credentials]
    nirv = Nirvana(app_id='my-app', app_version='1.0')
    nirv.username = user
    nirv.password_md5 = password_md5
    nirv.authenticate()

"""

import logging
import sys

import rest_client

__all__ = ['Error', 'AuthenticationError', 'ApiCommunicationError', 'Nirvana']

# Silence invalid "Redefining attribute" from @property decorator
__pychecker__ = 'no-reuseattr'

log = logging.getLogger(__name__)


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class AuthenticationError(Error):
    """Exception raised for authentication errors."""


class ApiCommunicationError(Error):
    """Exception raised for API communication errors."""


class Nirvana(object):
    """Provides high-level access to the Nirvana API.

    Attributes:
        username: A string containing the user's username.
        password_md5: A string containing the MD5 hash of the user's
                password
        auth_token: The user's authentication token string.
        app_id: A string containing your application's name.
        app_version: A string containing your application's version.
        api_url: A string containing the URL of the API's entry point.

    """
    def __init__(
            self, username=None, password_md5=None, auth_token=None,
            app_id=None, app_version=None, api_url=None):
        """Initialize a Nirvana client.

        Args:
            username: A string containing the user's username.
            password_md5: A string containing the MD5 hash of the user's
                    password.
            auth_token: The user's authentication token string. Can be
                    passed in if the user has already been authenticated,
                    otherwise leave it empty and provide the user's
                    username and password.
            app_id: A string containing your application's name. Defaults
                    to rest_client DEFAULT_APP_ID but should be set to
                    identify your app to the API.
            app_version: A string containing your application's version.
                    Defaults to rest_client.DEFAULT_APP_VERSION but should
                    be set along with app_id to identify your app to the
                    API.
            api_url: A string containing the URL for the API's entry
                    point. Defaults to rest_client.DEFAULT_API_URL.

        """
        self.username = username
        self.password_md5 = password_md5
        self._rest_client = rest_client.RestClient(
                auth_token=auth_token, app_id=app_id,
                app_version=app_version, api_url=api_url)
        log.info(
                ("Initialized Nirvana for application %s version %s, user %s, "
                 "using API URL %s"),
                self.app_id, self.app_version, self.username, self.api_url)

    @property
    def auth_token(self):
        """The user's authentication token string."""
        return self._rest_client.auth_token

    @auth_token.setter
    def auth_token(self, value):
        self._rest_client.auth_token = value

    @property
    def api_url(self):
        """A string containing the URL of the API's entry point."""
        return self._rest_client.api_url

    @api_url.setter
    def api_url(self, value):
        self._rest_client.api_url = value

    @property
    def app_id(self):
        """A string containing your application's name."""
        return self._rest_client.app_id

    @app_id.setter
    def app_id(self, value):
        self._rest_client.app_id = value

    @property
    def app_version(self):
        """A string containing your application's version."""
        return self._rest_client.app_version

    @app_version.setter
    def app_version(self, value):
        self._rest_client.app_version = value

    def authenticate(self, username=None, password_md5=None):
        """Authenticate with the Nirvana API.

        Attempts to authenticate with the API using the credentials stored
        in this object (self.username and self.password_md5) by default,
        or the credentials passed to this method if provided. Upon
        successful authentication, the authentication token is stored in
        self.auth_token.

        Args:
            username: A string containing the username.
            password_md5: A string containing the MD5 hash of the user's
                    password.

        Raises:
            AuthenticationError: Invalid login credentials.
            ApiCommunicationError: Error while communicating, or
                    attempting to communicate, with the API.

        """
        user = username or self.username
        passwd = password_md5 or self.password_md5
        log.info("Attempting to authenticate user %s", user)
        if not user or not passwd:
            error = "Missing username and/or password"
            log.info(error)
            raise AuthenticationError(error)

        try:
            _, results = self._rest_client.api_auth_new(user, passwd)
        except rest_client.InvalidLoginError as exc:
            log.info("Authentication failed, invalid credentials")
            raise AuthenticationError(exc), None, sys.exc_info()[2]
        except rest_client.CommunicationError as exc:
            log.info("Authentication failed, API communication error")
            raise ApiCommunicationError(exc), None, sys.exc_info()[2]

        try:
            self.auth_token = results[0]['auth']['token']
        except (IndexError, KeyError, TypeError):
            error = "Can't find auth token in results: {0}".format(results)
            log.info(error)
            raise ApiCommunicationError(error)

        log.info("Successfully authenticated, auth token %s", self.auth_token)
