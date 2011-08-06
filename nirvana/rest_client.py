#!/usr/bin/env python

"""Lower-level wrapper around Nirvana's REST API.

The rest_client module provides low-level access to the operations
supported by Nirvana's REST API.

Warning: Nirvana's public API hasn't been announced yet so this was done
by looking at how the website uses the API. Use at your own risk,
everything is subject to change, this should get better once the API is
announced, yaddy yaddy yadda.

Example:
    # Authenticate
    client = RestClient(app_id='my-app', app_version='1.0')
    raw_auth = client.api_auth_new(user, md5_password)
    auth_token = # ... TODO: get token out of raw_auth
    client.auth_token = auth_token

    # Retrieve all of the user's data
    raw_everything = client.api_everything()

"""

import json
import sys
import time
import urllib
import urllib2
import uuid

__all__ = ['Error', 'CommunicationError', 'HTTPError', 'RestClient']

DEFAULT_API_URL = 'https://api.nirvanahq.com/'
DEFAULT_APP_ID = 'nirvana-python'
DEFAULT_APP_VERSION = '0'   # TODO: Use the same version as setup.py?


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class CommunicationError(Error):
    """Exception raised for API communication errors."""
    pass


class HTTPError(CommunicationError):
    """Exception raised for HTTP error codes from the API.

    Can be used as a regular exception, or can be caught and examined to
    interpret the HTTP error. The exception can be read() like a file-like
    object to get the body of the HTTP response. This behaves the same way
    as urllib2.HTTPError.

    Attributes:
        code: HTTP error code
        (see urllib2.HTTPError for a complete list)

    """
    pass


class RestClient(object):
    """Provides lower-level access to the REST API.

    Each api_*() method is a small wrapper around an operation supported
    by the API with a similar name. Raw JSON responses are converted to
    native Python data structures (e.g., dictionaries and lists) and
    returned. Little, if any, additional processing is done.

    Attributes:
        auth_token: The user's authentication token string.
        app_id: A string containing your application's name.
        app_version: A string containing your application's version.
        api_url: A string containing the URL of the API's entry point.

    """
    def __init__(self, auth_token=None, app_id=None, app_version=None):
        """Initialize a REST client.

        Args:
            auth_token: The user's authentication token string. Can be
                    passed in if the user has already been authenticated,
                    otherwise leave it empty and use api_auth_new() to
                    authenticate.
            app_id: A string containing your application's name. Defaults
                    to DEFAULT_APP_ID but should be set to identify your
                    app to the API.
            app_version: A string containing your application's version.
                    Defaults to DEFAULT_APP_VERSION but should be set
                    along with app_id to identify your app to the API.

        """
        self.auth_token = auth_token
        self.app_id = app_id or DEFAULT_APP_ID
        self.app_version = app_version or DEFAULT_APP_VERSION
        self.api_url = DEFAULT_API_URL

    def api_auth_new(self, user, password_md5):
        """Authenticate the user with the API.

        Uses a username a password to authenticate with the API's
        "auth.new" method. See Nirvana's API documentation (once
        available) for details.

        Args:
            user: A string containing the username.
            password_md5: A string containing the MD5 hash of the user's
                    password.

        Returns:
            The raw response from the API after being converted from JSON
            to native Python data structures. A successful response
            includes an authentication token that must be provided to
            this object's auth_token property for further API access.

        Raises:
            HTTPError: HTTP error (e.g., 404 Not Found) occurred. See
                    HTTPError for details.
            CommunicationError: Failed to communicate with the server or
                    get a valid JSON response.

        """
        post_data = {
                'method': 'auth.new',
                'u': user,
                'p': password_md5}
        return self._api_post_rest(post_data)

    def api_everything(self, since=None):
        """Get "everything" from the API.

        Uses the API's "everything" method to get the user's data. See
        Nirvana's API documentation (once available) for details.

        Args:
            since: An integer containing the Unix time (seconds since the
                    Unix epoch). All data that has changed since this time
                    will be retrieved. A value of 0 will get all data.

        Returns:
            The raw response from the API after being converted from JSON
            to native Python data structures.

        Raises:
            HTTPError: HTTP error (e.g., 404 Not Found) occurred. See
                    HTTPError for details.
            CommunicationError: Failed to communicate with the server or
                    get a valid JSON response.

        """
        since = since or 0
        params = {'method': 'everything', 'since': str(since)}
        url, _, _ = self._create_request_url('rest', extra_params=params)
        return _api_request(url)

    def _api_post_rest(self, data):
        """Submit a POST (type 'rest') to the API."""
        url, _, _ = self._create_request_url('rest')
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = urllib.urlencode(data)
        return _api_request(url, extra_headers=headers, data=data)

    def _api_post_json(self, json_data):
        """Submit a POST (type 'json') to the API."""
        url, _, _ = self._create_request_url('json')
        headers = {'Content-Type': 'application/json'}
        return _api_request(url, extra_headers=headers, data=json_data)

    def _create_request_url(self, api_type, extra_params=None):
        """Assemble the URL for an API request."""
        request_id = str(uuid.uuid4())
        client_time = str(int(time.time()))
        query_params = {
                'api': api_type,
                'requestid': request_id,
                'clienttime': client_time,
                'appid': self.app_id,
                'appversion': self.app_version}
        if self.auth_token:
            query_params['authtoken'] = self.auth_token
        if extra_params:
            query_params = dict(query_params.items() + extra_params.items())
        query_string = urllib.urlencode(query_params)
        url = "{0}?{1}".format(self.api_url, query_string)
        return url, request_id, client_time


def _api_request(url, extra_headers=None, data=None):
    """Submit an API request."""
    request = urllib2.Request(url)
    if extra_headers:
        for header, value in extra_headers.items():
            request.add_header(header, value)
    if data:
        request.add_data(data)

    # TODO: The urllib2 documentation says "Warning: HTTPS requests do not
    # do any verification of the server's certificate."  What does this
    # mean and what (if anything) should be done about it?
    # TODO: Need to support proxies?
    try:
        json_data = urllib2.urlopen(request).read()
    except urllib2.HTTPError as exc:
        # Re-brand the urllib2.HTTPError as a rest_client.HTTPError
        new_exc = HTTPError()
        new_exc.__dict__ = exc.__dict__.copy()
        raise new_exc, None, sys.exc_info()[2]
    except urllib2.URLError as exc:
        raise CommunicationError(exc), None, sys.exc_info()[2]

    try:
        response = json.loads(json_data)
    except ValueError as exc:
        raise CommunicationError(exc), None, sys.exc_info()[2]

    return response
