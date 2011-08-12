#!/usr/bin/env python

"""High-level library for Nirvana's API.

This library only supports Nirvana version 2.

Example:
    user, password_md5 = # [user's credentials]
    nirv = Nirvana(app_id='my-app', app_version='1.0')
    nirv.username = user
    nirv.password_md5 = password_md5
    nirv.authenticate()

TODO:
    - Be more careful not to get local data into a weird state. Don't
      halfway update items and then raise exceptions. Don't authenticate a
      different user and overwrite some data from the original. Etc...

"""

import datetime
import logging
import sys

import rest_client

__all__ = [
        'Error', 'AuthenticationError', 'ApiCommunicationError', 'Nirvana',
        'Item', 'User']

# Silence invalid "Redefining attribute" from @property decorator
__pychecker__ = 'no-reuseattr'

log = logging.getLogger(__name__)


def _to_datetime(str_time):
    # TODO: Should the user's timezone be taken into account?
    return datetime.datetime.fromtimestamp(int(str_time))


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class AuthenticationError(Error):
    """Exception raised for authentication errors."""


class ApiCommunicationError(Error):
    """Exception raised for API communication errors."""


class Item(object):
    """Parent class for API items such as tasks and tags.

    Represents any of the core items from the API such as tasks and tags.
    An Item stores the raw data from the API and exposes it to the
    application in a convenient way.

    Raw item data from the API looks like this once it's converted from
    JSON:

        {'name': 'Task name', '_name': '123456789', ...}

    Each field (this example only contains one field called 'name') has an
    entry in the dictionary containing the value of the field, as well as
    an entry with the name preceded by an underscore ('_name') that
    represents the time the field was last modified. Item's update()
    method takes raw data from the API in this format and updates its
    internal representation of the item.

    By default, the raw item data from the API is not exposed by the
    Item's public interface. Subclasses should set self._config to a
    dictionary that specifies which raw fields should be exposed as public
    properties of the object.  Each key in the dictionary is the name of
    the field and its value is a tuple with the following format:

        (read_func,)

    where:
        - read_func is a callable object that accepts the raw field value
          as an argument and returns the value in the format expected by
          users of the Item. If read_func is None, the raw field value is
          returned unmodified.

    The following example shows a sample item with two fields: 'id' and
    'name'. Both fields are represented internally by a string, but the
    public 'id' property is configured to be presented to the application
    as an int.

        class SampleItem(Item):
            def __init__(self):
                super(SampleItem, self).__init__()
                self._config = {'id': (int,), 'name': (None,)}

        item = SampleItem()
        assert item.id is None
        assert item.name is None

        item.update({'id': '999', '_id': '123456789',
                     'name': 'My Item', '_name': '123456789',
                     'private': 'value', '_private': '123456789'})
        assert item.id == 999
        assert item.name == 'My Item'

        # Attempting to read item.private would raise an AttributeError
        # because 'private' is not in item._config

    """

    _CONFIG_READ_FUNC_IDX = 0

    def __init__(self):
        self._config = {}
        self._data = {}

    def update(self, data):
        """Update the Item from raw data.

        Args:
            data: A dictionary containing the raw item fields in the
                    format used by the API. A field is ignored unless its
                    timestamp is greater than or equal to the field
                    already stored.

        """
        for name, value in data.items():
            if name[0] != '_':
                ts_field = '_' + name
                if ts_field in data:
                    self._update_field(name, value, timestamp=data[ts_field])
                else:
                    log.warning(
                            "Ignoring update of field {0}={1} because "
                            "timestamp field {2} is missing", name,
                            value, ts_field)

    def __getattr__(self, name):
        """Get raw fields through public properties if present in _config."""
        if '_config' in self.__dict__:
            if name in self.__dict__['_config']:
                config = self.__dict__['_config'][name]
                value = self.__dict__['_data'].get(name, None)
                if value is not None:
                    read_convert = config[self._CONFIG_READ_FUNC_IDX]
                    if callable(read_convert):
                        value = read_convert(value)
                return value
        raise AttributeError("'{0}' object has no attribute '{1}'".format(
                self.__class__.__name__, name))

    def __setattr__(self, name, value):
        """Set raw fields through public properties if present in _config.

        Currently raises AttributeError for all properties since modifying
        Items is not supported yet.

        """
        if '_config' in self.__dict__:
            config = self.__dict__['_config'].get(name, None)
            if config:
                # TODO: implement once we support writing stuff
                raise AttributeError("can't set attribute")
        object.__setattr__(self, name, value)

    def _update_field(self, name, value, timestamp=None):
        update = True
        ts_field = '_' + name
        if timestamp:
            if ts_field in self._data:
                old_ts = int(self._data[ts_field])
                new_ts = int(timestamp)
                if int(new_ts) < int(old_ts):
                    update = False
        if update:
            self._data[name] = value
            if timestamp:
                self._data[ts_field] = timestamp


class User(Item):
    """Representation of the API's 'user' item.

    Attributes:
        emailaddress: A string containing the user's email address.
        firstname: A string containing the user's first name.
        gmtoffset: An integer containing the user's timezone offset.
        id: A string containing the user's ID.
        inmailaddress: A string containing the user's email address for
                adding tasks ([inmailaddress]@nirvanahq.com).
        lastname: A string containing the user's last name.
        lastwritebyuseron: A DateTime object representing the time of the
                last write by the user.
        password: A string containing the MD5 hash of the user's password.
        username: A string containing the user's username.
        version: A string containing the Nirvana version of the user's
                account.

    """

    CONFIG = {
            'emailaddress': (None,),
            'firstname': (None,),
            'gmtoffset': (int,),
            'id': (None,),
            'inmailaddress': (None,),
            'lastname': (None,),
            'lastwritebyuseron': (_to_datetime,),
            'password': (None,),
            'username': (None,),
            'version': (None,)}

    def __init__(self):
        """Initialize an empty User object."""
        super(User, self).__init__()
        self._config = self.CONFIG

    def update(self, data):
        """Update the User from raw data.

        This overrides Item's update method to support fields that don't
        have timestamps.

        """
        for name, value in data.items():
            if name[0] != '_':
                if name == 'version':
                    if value != '2':
                        raise Error(
                                "Unsupported user version {0}".format(value))
                ts_field = '_' + name
                timestamp = data.get(ts_field, None)
                self._update_field(name, value, timestamp=timestamp)


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
