#!/usr/bin/env python

"""Unit tests for rest_client.py."""

import StringIO
import sys
import time
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest
import urllib2
import urlparse
import uuid

from mock import patch

__pychecker__ = 'no-miximport'
import rest_client
from rest_client import *
__pychecker__ = ''

FAKE_API_URL = 'https://fake.url/api/'
FAKE_APP_ID = 'my-app'
FAKE_APP_VERSION = '1.2.3'
FAKE_AUTH_TOKEN = '35b5aafda29e7dccb8b922fde0389309'
FAKE_EVERYTHING_SINCE = 1325476980
FAKE_HTTP_ERROR_CODE = 999
FAKE_PASSWORD = '5f4dcc3b5aa765d61d8327deb882cf99'
FAKE_TIME = 1234567890
FAKE_USER = 'username'
FAKE_UUID4 = '1aae458a-efb1-4534-b7a2-31e3c77a8e31'
INVALID_JSON = '{"invalid": "json"'
NOT_JSON = 'not even close to json'
VALID_JSON = '{"valid": "json"}'
VALID_JSON_AS_NATIVE = {'valid': 'json'}

# In general, all API calls have these parameters in the request URL's
# query string.
BASE_EXPECTED_QUERY = {
        'authtoken': [FAKE_AUTH_TOKEN],
        'clienttime': [str(FAKE_TIME)],
        'appid': [rest_client.DEFAULT_APP_ID],
        'appversion': [rest_client.DEFAULT_APP_VERSION],
        'api': ['rest'],
        'requestid': [FAKE_UUID4]}


class ApiCallCommonMixin(object):
    """Common tests for API calls."""

    callable_obj = None
    callable_obj_args = ()
    callable_obj_kwargs = {}

    @patch.object(urllib2, 'urlopen')
    def test_communication_error_from_url_error(self, urlopen_mock):
        """Verifies CommunicationError from URLErrors."""
        assert callable(self.callable_obj)
        urlopen_mock.side_effect = urllib2.URLError('error')
        with self.assertRaises(CommunicationError):
            self.callable_obj(
                    *self.callable_obj_args,
                    **self.callable_obj_kwargs)

    @patch.object(urllib2, 'urlopen')
    def test_communication_error_from_bad_json(self, urlopen_mock):
        """Verifies CommunicationError from invalid JSON responses."""
        assert callable(self.callable_obj)
        urlopen_mock.return_value = StringIO.StringIO(INVALID_JSON)
        with self.assertRaises(CommunicationError):
            self.callable_obj(
                    *self.callable_obj_args,
                    **self.callable_obj_kwargs)

    @patch.object(urllib2, 'urlopen')
    def test_communication_error_from_non_json(self, urlopen_mock):
        """Verifes CommunicationError from non-JSON responses."""
        assert callable(self.callable_obj)
        urlopen_mock.return_value = StringIO.StringIO(NOT_JSON)
        with self.assertRaises(CommunicationError):
            self.callable_obj(
                    *self.callable_obj_args,
                    **self.callable_obj_kwargs)

    @patch.object(urllib2, 'urlopen')
    def test_http_error(self, urlopen_mock):
        """Verifies HTTP errors are reported as HTTPError."""
        assert callable(self.callable_obj)
        urlopen_mock.side_effect = urllib2.HTTPError(
                'http://localhost/fake', FAKE_HTTP_ERROR_CODE, 'fake', {},
                StringIO.StringIO(NOT_JSON))
        response = None
        try:
            self.callable_obj(
                    *self.callable_obj_args,
                    **self.callable_obj_kwargs)
        except HTTPError as exc:
            response = exc
        self.assertIsNotNone(response)
        self.assertEqual(response.code, FAKE_HTTP_ERROR_CODE)
        self.assertEqual(response.read(), NOT_JSON)

    @patch.object(urllib2, 'urlopen')
    def test_valid_json_response(self, urlopen_mock):
        """Verifies a valid JSON response from the API is decoded properly."""
        assert callable(self.callable_obj)
        urlopen_mock.return_value = StringIO.StringIO(VALID_JSON)
        result = self.callable_obj(
                *self.callable_obj_args,
                **self.callable_obj_kwargs)
        self.assertEqual(result, VALID_JSON_AS_NATIVE)


class ApiCallUrlMixin(object):
    """URL tests common to all API calls."""

    callable_obj = None
    callable_obj_args = ()
    callable_obj_kwargs = {}
    extra_params = None
    excluded_params = None

    def test_url(self):
        """Verifies the URL requested by an API call."""
        assert callable(self.callable_obj)
        url = outgoing_url_from_callable(
                self.callable_obj, *self.callable_obj_args,
                **self.callable_obj_kwargs)
        query = BASE_EXPECTED_QUERY.copy()
        if self.extra_params:
            query = dict(query.items() + self.extra_params.items())
        if self.excluded_params:
            for param in self.excluded_params:
                del query[param]
        assert_url(
                self, url, address=FAKE_API_URL,
                query=query)


class ApiCallGetMixin(object):
    """Tests common to API call using the HTTP GET method."""

    __pychecker__ = 'missingattrs=assertEqual'
    callable_obj = None
    callable_obj_args = ()
    callable_obj_kwargs = {}

    def test_http_method(self):
        """Verifies the HTTP GET method is used."""
        assert callable(self.callable_obj)
        method = outgoing_http_method_from_callable(
                self.callable_obj,
                *self.callable_obj_args,
                **self.callable_obj_kwargs)
        self.assertEqual(method, 'GET')

    def test_outgoing_headers(self):
        """Verifies the HTTP request headers."""
        assert callable(self.callable_obj)
        expected_headers = []
        headers = extra_outgoing_headers_from_callable(
                self.callable_obj,
                *self.callable_obj_args,
                **self.callable_obj_kwargs)
        self.assertEqual(headers, expected_headers)


class ApiCallPostMixin(object):
    """Tests for API calls using the HTTP POST method."""

    __pychecker__ = 'missingattrs=assertEqual'
    callable_obj = None
    callable_obj_args = ()
    callable_obj_kwargs = {}

    def test_http_method(self):
        """Verifies the HTTP POST method is used."""
        assert callable(self.callable_obj)
        method = outgoing_http_method_from_callable(
                self.callable_obj,
                *self.callable_obj_args,
                **self.callable_obj_kwargs)
        self.assertEqual(method, 'POST')


class ApiCallPostQueryStringMixin(object):
    """Tests for API calls POSTing URL encoded data."""

    __pychecker__ = 'missingattrs=assertEqual'
    callable_obj = None
    callable_obj_args = ()
    callable_obj_kwargs = {}
    expected_post_data = None

    def test_outgoing_post_data(self):
        """Verifies the request's POST data."""
        assert callable(self.callable_obj)
        data = outgoing_post_data_from_callable(
                self.callable_obj,
                *self.callable_obj_args,
                **self.callable_obj_kwargs)
        assert_query_string(self, data, self.expected_post_data)

    def test_outgoing_headers(self):
        """Verifies the HTTP request headers."""
        assert callable(self.callable_obj)
        expected_headers = [
                ('Content-Type', 'application/x-www-form-urlencoded')]
        headers = extra_outgoing_headers_from_callable(
                self.callable_obj,
                *self.callable_obj_args,
                **self.callable_obj_kwargs)
        self.assertEqual(headers, expected_headers)


class RestClientDefaultInit(unittest.TestCase):
    """Test RestClient constructor's default arguments."""

    def setUp(self):
        """Creates a RestClient() with default arguments."""
        self.client = RestClient()

    def test_default_auth_token(self):
        """Verifies auth_token is None."""
        self.assertIsNone(self.client.auth_token)

    def test_default_app_id(self):
        """Verifies the default application ID."""
        self.assertEqual(self.client.app_id, rest_client.DEFAULT_APP_ID)

    def test_default_app_version(self):
        """Verifies the default application version."""
        self.assertEqual(self.client.app_version,
                rest_client.DEFAULT_APP_VERSION)

    def test_default_api_url(self):
        """Verifies the default API URL."""
        self.assertEqual(self.client.api_url, rest_client.DEFAULT_API_URL)


class RestClientInitArgs(unittest.TestCase):
    """Test RestClient constructor with custom arguments."""

    def setUp(self):
        """Creates a RestClient with custom arguments."""
        self.client = RestClient(
                auth_token=FAKE_AUTH_TOKEN, app_id=FAKE_APP_ID,
                app_version=FAKE_APP_VERSION)

    def test_auth_token(self):
        """Verifies custom auth token."""
        self.assertEqual(self.client.auth_token, FAKE_AUTH_TOKEN)

    def test_app_id(self):
        """Verifies custom application ID."""
        self.assertEqual(self.client.app_id, FAKE_APP_ID)

    def test_app_version(self):
        """Verifies custom application version."""
        self.assertEqual(self.client.app_version, FAKE_APP_VERSION)


class ApiAuthNewCommon(unittest.TestCase, ApiCallCommonMixin):
    """Tests 'auth.new' functionality common to API calls."""

    def setUp(self):
        self.callable_obj = do_api_auth_new


class ApiAuthNewUrlNoAuthToken(unittest.TestCase, ApiCallUrlMixin):
    """Tests 'auth.new' request URL without an auth token."""

    def setUp(self):
        self.callable_obj = do_api_auth_new
        self.excluded_params = ['authtoken']


class ApiAuthNewUrlWithAuthToken(unittest.TestCase, ApiCallUrlMixin):
    """Tests 'auth.new' request URL with an auth token."""

    def setUp(self):
        self.callable_obj = do_api_auth_new
        self.callable_obj_kwargs = {
                'rest_client_kwargs': {'auth_token': FAKE_AUTH_TOKEN}}


class ApiAuthNewPost(unittest.TestCase, ApiCallPostMixin):
    """Tests 'auth.new' POST."""

    def setUp(self):
        self.callable_obj = do_api_auth_new


class ApiAuthNewPostQueryString(
        unittest.TestCase, ApiCallPostQueryStringMixin):
    """Tests 'auth.new' POST data."""

    def setUp(self):
        self.callable_obj = do_api_auth_new
        self.expected_post_data = {
                'method': ['auth.new'],
                'u': [FAKE_USER],
                'p': [FAKE_PASSWORD]}


class ApiAuthNew(unittest.TestCase):
    """Tests 'auth.new' functionality specific to this API call."""
    pass


class ApiEverythingCommon(unittest.TestCase, ApiCallCommonMixin):
    """Tests 'everything' functionality common API calls."""

    def setUp(self):
        self.callable_obj = do_api_everything


class ApiEverythingUrlDefaultSince(unittest.TestCase, ApiCallUrlMixin):
    """Tests 'everything' request URL with default 'since' argument."""

    def setUp(self):
        self.callable_obj = do_api_everything
        self.extra_params = {
                'method': ['everything'],
                'since': ['0']}


class ApiEverythingUrlCustomSince(unittest.TestCase, ApiCallUrlMixin):
    """Tests 'everything' request URL with custom 'since' argument."""

    def setUp(self):
        self.callable_obj = do_api_everything
        self.callable_obj_kwargs = {'since': FAKE_EVERYTHING_SINCE}
        self.extra_params = {
                'method': ['everything'],
                'since': [str(FAKE_EVERYTHING_SINCE)]}


class ApiEverythingGet(unittest.TestCase, ApiCallGetMixin):
    """Tests 'everything' GET functionality."""

    def setUp(self):
        self.callable_obj = do_api_everything


class ApiEverything(unittest.TestCase):
    """Tests 'everything' functionality specific to this API calls ."""
    pass


def do_api_auth_new(
        rest_client_kwargs=None, user=FAKE_USER, password=FAKE_PASSWORD,
        api_url=FAKE_API_URL):
    """Do an API 'auth.new' operation."""
    client = RestClient(**rest_client_kwargs or {})
    client.api_url = api_url
    result = client.api_auth_new(user, password)
    return result


def do_api_everything(
        rest_client_kwargs=None, auth_token=FAKE_AUTH_TOKEN,
        api_url=FAKE_API_URL, since=None):
    """Do an API 'everything' operation."""
    client = RestClient(**rest_client_kwargs or {})
    client.auth_token = auth_token
    client.api_url = api_url
    result = client.api_everything(since=since)
    return result


def assert_url(test_case, url, address=None, query=None, fragment=None):
    """Assert a URL's components match expected values."""
    address = address or ''
    query = query or {}
    fragment = fragment or ''
    split = urlparse.urlsplit(url)
    actual_address = urlparse.urlunsplit(
            (split.scheme, split.netloc, split.path, None, None))
    test_case.assertEqual(actual_address, address)
    assert_query_string(test_case, split.query, query)
    test_case.assertEqual(split.fragment, fragment)


def assert_query_string(test_case, query, expected_query):
    """Assert a query strig matches the expected value."""
    actual_query = urlparse.parse_qs(query)
    test_case.assertEqual(actual_query, expected_query)


def outgoing_http_method_from_callable(callable_obj, *args, **kwargs):
    """Collect a request's HTTP method.

    Call callable_obj(), which is expected to send an HTTP request, and
    collect the HTTP method (e.g., POST) from the request.

    """
    with patch.object(urllib2, 'urlopen') as urlopen_mock:
        urlopen_mock.return_value = StringIO.StringIO(VALID_JSON)
        callable_obj(*args, **kwargs)
        request = urlopen_mock.call_args[0][0]
    return request.get_method()


def extra_outgoing_headers_from_callable(callable_obj, *args, **kwargs):
    """Collect a request's outgoing headers.

    Call callable_obj(), which is expected to send an HTTP request, and
    collect any extra outgoing HTTP headers from the request.

    """
    with patch.object(urllib2, 'urlopen') as urlopen_mock:
        urlopen_mock.return_value = StringIO.StringIO(VALID_JSON)
        with patch.object(urllib2.Request, 'add_header') as add_header_mock:
            callable_obj(*args, **kwargs)
            headers = [
                    header for (header, _) in add_header_mock.call_args_list]
    return headers


def outgoing_post_data_from_callable(callable_obj, *args, **kwargs):
    """Collect a request's POST data.

    Call callable_obj(), which is expected to send an HTTP POST
    request, and collect the data from the request body.

    """
    with patch.object(urllib2, 'urlopen') as urlopen_mock:
        urlopen_mock.return_value = StringIO.StringIO(VALID_JSON)
        callable_obj(*args, **kwargs)
        request = urlopen_mock.call_args[0][0]
    return request.get_data()


def _outgoing_url_from_callable(callable_obj, *args, **kwargs):
    with patch.object(urllib2, 'urlopen') as urlopen_mock:
        urlopen_mock.return_value = StringIO.StringIO(VALID_JSON)
        callable_obj(*args, **kwargs)
        request = urlopen_mock.call_args[0][0]
    return request.get_full_url()


@patch.object(time, 'time', lambda: FAKE_TIME)
@patch.object(uuid, 'uuid4', lambda: FAKE_UUID4)
def outgoing_url_from_callable(callable_obj, *args, **kwargs):
    """Collect a request's URL.

    Call callable_obj(), which is expected to send an HTTP request, and
    collect the URL from the request. time.time() and uuid.uuid4() are
    stubbed to provide predictable values.

    """
    return _outgoing_url_from_callable(callable_obj, *args, **kwargs)


if __name__ == "__main__":
    unittest.main()
