#!/usr/bin/env python

"""Unit tests for nirvana.py."""

import sys
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from mock import patch

import rest_client
from nirvana import *

FAKE_API_URL = 'https://fake.url/api/'
FAKE_APP_ID = 'my-app'
FAKE_APP_VERSION = '1.2.3'
FAKE_AUTH_TOKEN = '35b5aafda29e7dccb8b922fde0389309'
FAKE_PASSWORD = '5f4dcc3b5aa765d61d8327deb882cf99'
FAKE_USER = 'username'

FAKE_AUTH_NEW_REQUEST = {
    'api': 'rest',
    'authtoken': False,
    'callback': False,
    'clienttime': '1312991498',
    'method': 'auth.new',
    'requestid': '8cc93a70-78c3-4f6e-9c6a-93693c446103',
    'servertime': '1312991499',
    'since': False}
FAKE_AUTH_NEW_RESULTS = [{
    'auth': {
        'expires': '1313005899',
        'token': FAKE_AUTH_TOKEN,
        'user': {
            '_emailaddress': '0',
            '_firstname': '0',
            '_gmtoffset': '0',
            '_inmailaddress': '0',
            '_lastname': '0',
            '_password': '0',
            '_pokemefri': '0',
            '_pokememon': '0',
            '_pokemesat': '0',
            '_pokemesun': '0',
            '_pokemeth': '0',
            '_pokemetue': '0',
            '_pokemewed': '0',
            '_username': '0',
            '_version': '1300482847',
            'emailaddress': 'fake@email.com',
            'firstname': 'First',
            'gmtoffset': '-7',
            'id': '99999',
            'inmailaddress': '8675309ab',
            'lastactivityip': '',
            'lastactivityon': '0',
            'lastname': 'Last',
            'lastwritebyuseron': '1312987448',
            'password': FAKE_PASSWORD,
            'pokemefri': '0',
            'pokememon': '0',
            'pokemesat': '0',
            'pokemesun': '0',
            'pokemeth': '0',
            'pokemetue': '0',
            'pokemewed': '0',
            'roles': '',
            'servicelevel': 'basic',
            'username': FAKE_USER,
            'version': '2'}}}]


class NirvanaDefaultInit(unittest.TestCase):
    """Test Nirvana constructor's default arguments."""

    def setUp(self):
        """Creates an instance of Nirvana with default arguments."""
        self.nirv = Nirvana()

    def test_default_auth_token(self):
        """Verifies auth_token is None."""
        self.assertIsNone(self.nirv.auth_token)

    def test_default_username(self):
        """Verifies username is None."""
        self.assertIsNone(self.nirv.username)

    def test_default_password(self):
        """Verifies password is None."""
        self.assertIsNone(self.nirv.password_md5)

    def test_default_app_id(self):
        """Verifies the default application ID."""
        self.assertEqual(self.nirv.app_id, rest_client.DEFAULT_APP_ID)

    def test_default_app_version(self):
        """Verifies the default application version."""
        self.assertEqual(
                self.nirv.app_version, rest_client.DEFAULT_APP_VERSION)

    def test_default_api_url(self):
        """Verifies the default API URL."""
        self.assertEqual(self.nirv.api_url, rest_client.DEFAULT_API_URL)


class NirvanaInitArgs(unittest.TestCase):
    """Test Nirvana constructor with custom arguments."""

    def setUp(self):
        """Creates an instance of Nirvana with custom arguments."""
        self.nirv = Nirvana(
                username=FAKE_USER, password_md5=FAKE_PASSWORD,
                auth_token=FAKE_AUTH_TOKEN, app_id=FAKE_APP_ID,
                app_version=FAKE_APP_VERSION, api_url=FAKE_API_URL)

    def test_username(self):
        """Verifies custom username."""
        self.assertEqual(self.nirv.username, FAKE_USER)

    def test_password(self):
        """Verifies custom password."""
        self.assertEqual(self.nirv.password_md5, FAKE_PASSWORD)

    def test_auth_token(self):
        """Verifies custom auth token."""
        self.assertEqual(self.nirv.auth_token, FAKE_AUTH_TOKEN)

    def test_app_id(self):
        """Verifies custom application ID."""
        self.assertEqual(self.nirv.app_id, FAKE_APP_ID)

    def test_app_version(self):
        """Verifies custom application version."""
        self.assertEqual(self.nirv.app_version, FAKE_APP_VERSION)

    def test_api_url(self):
        """Verifies custom API URL."""
        self.assertEqual(self.nirv.api_url, FAKE_API_URL)


class NirvanaReadWriteProperties(unittest.TestCase):
    """Test public read/write properties."""

    def setUp(self):
        self.nirv = Nirvana()
        self.str_props = ['auth_token', 'api_url', 'app_id', 'app_version']

    def test_read_write_str_props(self):
        """Verifies each read/write string property works correctly.

        Writes a value to each property and and verifies the same value is
        read back.

        """
        for num in range(0, len(self.str_props)):
            prop = self.str_props[num]
            val = str(num)
            setattr(self.nirv, prop, val)
            self.assertEqual(getattr(self.nirv, prop), val)


class NirvanaAuthenticateArguments(unittest.TestCase):
    """Test arguments to Nirvana's authenticate() method."""

    def setUp(self):
        self.nirv = Nirvana()

    def _test_no_username_or_password(self):
        with self.assertRaisesRegexp(
                AuthenticationError, 'Missing username and/or password'):
            self.nirv.authenticate()

    def test_no_username_and_password(self):
        """Verifies AuthenticationError from no username and password."""
        self._test_no_username_or_password()

    def test_no_username(self):
        """Verifies AuthenticationError from no username."""
        self.nirv.password_md5 = FAKE_PASSWORD
        self._test_no_username_or_password()

    def test_no_password(self):
        """Verifies AuthenticationError from no password."""
        self.nirv.username = FAKE_USER
        self._test_no_username_or_password()

    @patch.object(rest_client.RestClient, 'api_auth_new')
    def test_default_arguments(self, api_auth_new_mock):
        """Verifies stored credentials are used if not provided as args."""
        api_auth_new_mock.return_value = (
                FAKE_AUTH_NEW_REQUEST, FAKE_AUTH_NEW_RESULTS)
        self.nirv.username = FAKE_USER
        self.nirv.password_md5 = FAKE_PASSWORD
        self.nirv.authenticate()
        expected_args = ((FAKE_USER, FAKE_PASSWORD), {})
        self.assertEqual(api_auth_new_mock.call_args, expected_args)

    @patch.object(rest_client.RestClient, 'api_auth_new')
    def test_with_arguments(self, api_auth_new_mock):
        """Verifies credentials passed as args are used if provided."""
        api_auth_new_mock.return_value = (
                FAKE_AUTH_NEW_REQUEST, FAKE_AUTH_NEW_RESULTS)
        self.nirv.authenticate(username=FAKE_USER, password_md5=FAKE_PASSWORD)
        expected_args = ((FAKE_USER, FAKE_PASSWORD), {})
        self.assertEqual(api_auth_new_mock.call_args, expected_args)


class NirvanaAuthenticateErrors(unittest.TestCase):
    """Test errors from Nirvana's authenticate() method."""

    def setUp(self):
        self.nirv = Nirvana()
        self.nirv.username = FAKE_USER
        self.nirv.password_md5 = FAKE_PASSWORD

    @patch.object(rest_client.RestClient, 'api_auth_new')
    def test_authentication_error(self, api_auth_new_mock):
        """Verifies AuthenticationError from invalid credentials."""
        api_auth_new_mock.side_effect = rest_client.InvalidLoginError
        with self.assertRaises(AuthenticationError):
            self.nirv.authenticate()

    @patch.object(rest_client.RestClient, 'api_auth_new')
    def test_api_communication_error(self, api_auth_new_mock):
        """Verifies ApiCommunicationError from communication issues."""
        api_auth_new_mock.side_effect = rest_client.CommunicationError
        with self.assertRaises(ApiCommunicationError):
            self.nirv.authenticate()

    @patch.object(rest_client.RestClient, 'api_auth_new')
    def _test_no_auth_in_results(self, results, api_auth_new_mock):
        api_auth_new_mock.return_value = (FAKE_AUTH_NEW_REQUEST, results)
        with self.assertRaisesRegexp(
                ApiCommunicationError, "Can't find auth token"):
            self.nirv.authenticate()

    def test_no_auth_in_results(self):
        """Verifies ApiCommunicationError from invalid API results."""
        self._test_no_auth_in_results(None)
        self._test_no_auth_in_results([])
        self._test_no_auth_in_results({})
        self._test_no_auth_in_results([{}])
        self._test_no_auth_in_results([{'asdf': {}}])
        self._test_no_auth_in_results([{'auth': {'asdf': {}}}])


class NirvanaAuthenticateSuccess(unittest.TestCase):
    """Test behavior of successful Nirvana authenticate() call."""

    def setUp(self):
        with patch.object(
                rest_client.RestClient, 'api_auth_new') as api_auth_new_mock:
            api_auth_new_mock.return_value = (
                    FAKE_AUTH_NEW_REQUEST, FAKE_AUTH_NEW_RESULTS)
            self.nirv = Nirvana()
            self.nirv.username = FAKE_USER
            self.nirv.password_md5 = FAKE_PASSWORD
            self.assertEqual(self.nirv.auth_token, None)
            self.nirv.authenticate()

    def test_auth_token_stored(self):
        """Verifies auth token is stored in self.auth_token."""
        self.assertEqual(self.nirv.auth_token, FAKE_AUTH_TOKEN)


if __name__ == "__main__":
    unittest.main()
