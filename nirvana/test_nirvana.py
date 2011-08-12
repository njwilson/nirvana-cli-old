#!/usr/bin/env python

"""Unit tests for nirvana.py."""

import datetime
import sys
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from mock import patch

import rest_client
__pychecker__ = 'no-miximport'
import nirvana
from nirvana import *
__pychecker__ = ''

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

    def test_default_user(self):
        """Verifies the user is None."""
        self.assertIsNone(self.nirv.user)


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
                ApiCommunicationError, "Can't find token/user"):
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
        self.nirv = Nirvana()
        self.nirv.username = FAKE_USER
        self.nirv.password_md5 = FAKE_PASSWORD
        self.assertEqual(self.nirv.auth_token, None)
        self.assertEqual(self.nirv.user, None)

    @patch.object(rest_client.RestClient, 'api_auth_new')
    def test_auth_token_stored(self, api_auth_new_mock):
        """Verifies auth token is stored in self.auth_token."""
        api_auth_new_mock.return_value = (
                FAKE_AUTH_NEW_REQUEST, FAKE_AUTH_NEW_RESULTS)
        self.nirv.authenticate()
        self.assertEqual(self.nirv.auth_token, FAKE_AUTH_TOKEN)

    @patch.object(User, 'update')
    @patch.object(rest_client.RestClient, 'api_auth_new')
    def test_user_created_and_updated(
            self, api_auth_new_mock, user_update_mock):
        """Verify user data is created/updated after authentication."""

        # Verify nirv.user is created and update() is called on first auth
        api_auth_new_mock.return_value = (
                FAKE_AUTH_NEW_REQUEST, FAKE_AUTH_NEW_RESULTS)
        self.nirv.authenticate()
        self.assertIsNotNone(self.nirv.user)
        self.assertEqual(type(self.nirv.user), User)
        self.assertEqual(user_update_mock.call_count, 1)

        # Verify nirv.user's update() is called on second auth
        self.nirv.authenticate()
        self.assertEqual(user_update_mock.call_count, 2)

        # Verify both calls to nirv.user's update() were passed the
        # correct data
        raw_user_arg = ((FAKE_AUTH_NEW_RESULTS[0]['auth']['user'],), {})
        expected_arg_list = [raw_user_arg, raw_user_arg]
        self.assertEqual(user_update_mock.call_args_list, expected_arg_list)


class ItemAttr(unittest.TestCase):
    def setUp(self):
        self.str_field = 'asdf'
        self.int_field = '123'
        self.int_field_val = 123
        self.priv_field = 'private'
        self.item = Item()
        self.item._config = {
                'str_field': (None,),
                'int_field': (int,)}
        self.item.update({
                'str_field': self.str_field, '_str_field': '12345',
                'int_field': self.int_field, '_int_field': '23456',
                'priv_field': self.priv_field, '_priv_field': '34567'})

    def test_str_field_get(self):
        """Verifies str_field is exposed as a gettable property."""
        self.assertEqual(self.item.str_field, self.str_field)

    def test_int_field_get(self):
        """Verifies int_field is exposed as a gettable int property."""
        self.assertEqual(self.item.int_field, self.int_field_val)

    def test_priv_field_get(self):
        """Verifies priv_field is not exposed as a gettable property."""
        with self.assertRaises(AttributeError):
            print self.item.priv_field

    def test_field_set(self):
        """Verifies none of the public fields are settable.

        TODO: Update once item write support is implemented.

        """
        with self.assertRaises(AttributeError):
            self.item.str_field = 'abc'
        with self.assertRaises(AttributeError):
            self.item.int_field = 555


class ItemUpdate(unittest.TestCase):

    DATA = (
            ('a', 11), ('_a', '123'),
            ('b', 22), ('_b', '234'))

    def _assert_update(self, orig_data, update_data, expected_data):
        self.item._data = orig_data
        self.item.update(update_data)
        self.assertEqual(self.item._data, expected_data)

    def setUp(self):
        self.item = Item()

    def test_default_data_empty(self):
        """Verifies an item's data is empty by default."""
        self.assertEqual(self.item._data, {})

    def test_update_empty_from_empty(self):
        """Verifies an empty update to empty data has no effect."""
        self._assert_update({}, {}, {})

    def test_update_with_timestamp(self):
        """Verifies a field with a timestamp is added properly."""
        data = {'a': 11, '_a': '123'}
        self._assert_update({}, data, data)

    def test_update_empty(self):
        """Verifies an empty update has no effect."""
        self._assert_update(dict(self.DATA), {}, dict(self.DATA))

    def test_update_unmodified(self):
        """Verifies an update without new data has no effect."""
        self._assert_update(dict(self.DATA), dict(self.DATA), dict(self.DATA))

    def test_update_no_timestamp(self):
        """Verifies fields without timestamps are ignored."""
        self._assert_update(dict(self.DATA), {'d': 44}, dict(self.DATA))

    def test_update_newer_timestamp(self):
        """Verifies fields with newer timestamps are updated."""
        expected = dict(self.DATA)
        expected['a'] = 111
        expected['_a'] = '124'
        self._assert_update(dict(self.DATA), {'a': 111, '_a': '124'}, expected)

    def test_update_equal_timestamp(self):
        """Verifies fields with equal timestamps are updated."""
        expected = dict(self.DATA)
        expected['a'] = 111
        expected['_a'] = '123'
        self._assert_update(dict(self.DATA), {'a': 111, '_a': '123'}, expected)

    def test_update_older_timestamp(self):
        """Verifies fields with older timestamps are not updated."""
        self._assert_update(
                dict(self.DATA), {'a': 111, '_a': '122'}, dict(self.DATA))

    def test_ignore_timestamps(self):
        """Verifies timestamps without values are ignored."""
        self._assert_update(dict(self.DATA), {'_x': 99}, dict(self.DATA))

    def test_add_timestamp(self):
        """Verifies a field with a timestamp is added properly."""
        expected = dict(self.DATA)
        expected['c'] = 33
        expected['_c'] = '345'
        self._assert_update(dict(self.DATA), {'c': 33, '_c': '345'}, expected)

    def test_add_timestamp_to_field_without(self):
        """Verifies adding timestamp to a field that doesn't have one yet."""
        orig = dict(self.DATA)
        orig['d'] = 44
        expected = dict(self.DATA)
        expected['d'] = 444
        expected['_d'] = '457'
        self._assert_update(orig, {'d': 444, '_d': '457'}, expected)

    def test_update_multiple(self):
        """Verifies proper behavior when updating multiple fields."""
        update = {
                'a': 11, '_a': '123',
                'c': 33, '_c': '345',
                '_x': '999',
                'd': 44,
                'b': 222, '_b': '235',
                }
        expected = dict(self.DATA)
        expected['b'] = 222
        expected['_b'] = '235'
        expected['c'] = 33
        expected['_c'] = '345'
        self._assert_update(dict(self.DATA), update, expected)


class UserUpdate(unittest.TestCase):
    def setUp(self):
        self.user = User()

    def test_valid_update(self):
        data = FAKE_AUTH_NEW_RESULTS[0]['auth']['user']
        self.user.update(data)
        self.assertEqual(self.user._data, data)

    def test_invalid_user_version(self):
        data = FAKE_AUTH_NEW_RESULTS[0]['auth']['user'].copy()
        data['version'] = '1'
        with self.assertRaisesRegexp(Error, 'Unsupported user version'):
            self.user.update(data)


class UserProperties(unittest.TestCase):
    def setUp(self):
        self.user = User()
        self.user.update(FAKE_AUTH_NEW_RESULTS[0]['auth']['user'])

    def test_properties(self):
        fake_user = FAKE_AUTH_NEW_RESULTS[0]['auth']['user']
        expected_last_write = datetime.datetime.fromtimestamp(
                int(fake_user['lastwritebyuseron']))
        data = (
                (self.user.emailaddress, fake_user['emailaddress']),
                (self.user.firstname, fake_user['firstname']),
                (self.user.gmtoffset, int(fake_user['gmtoffset'])),
                (self.user.id, fake_user['id']),
                (self.user.inmailaddress, fake_user['inmailaddress']),
                (self.user.lastname, fake_user['lastname']),
                (self.user.lastwritebyuseron, expected_last_write),
                (self.user.password, fake_user['password']),
                (self.user.username, fake_user['username']),
                (self.user.version, fake_user['version']))
        for actual, expected in data:
            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
