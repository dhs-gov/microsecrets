"""
Microsecrets, a simple S3 secrets store.
"""

VERSION = '0.3.3'

import contextlib
import getpass
import hashlib
import json
import logging
import numbers
import os
import re
import socket
import stat
import sys
import time

from datetime import datetime
from operator import attrgetter

import boto3
import botocore

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

# Set this to True to enable logging of environment variable values
INSECURE_DEBUG = False

logging.basicConfig(
    format='%(asctime)s %(name)s: %(levelname)s %(message)s',
    stream=sys.stderr
)

# Mapping from hash length to hash function
HASH_LEN_FUNC_MAP = {
    40: hashlib.sha1,
    64: hashlib.sha256,
    96: hashlib.sha384,
    128: hashlib.sha512,
}

class MicrosecretsError(Exception): pass
class NotFound(MicrosecretsError): pass

def assert_string(obj):
    if not isinstance(obj, basestring):
        raise ValueError('object is not a string: {!r}'.format(obj))

def assert_scalar(obj):
    if isinstance(obj, basestring):
        return
    if isinstance(obj, numbers.Number):
        return

    raise ValueError('object is not a scalar: {!r}'.format(obj))

def assert_dict_of_strings(obj):
    for key, val in obj.iteritems():
        assert_string(key)
        assert_string(val)

def assert_dict_of_scalars(obj):
    for key, val in obj.iteritems():
        assert_scalar(key)
        assert_scalar(val)

def set_log_verbose_mode():
    log.setLevel(logging.INFO)

def set_log_debug_mode():
    logging.getLogger().setLevel(logging.INFO)
    log.setLevel(logging.DEBUG)

class Microsecrets(object):
    def __init__(self, region_name, bucket_name, service_name):
        """
        Microsecrets, a simple S3 + KMS secrets store.

        :param region_name: The AWS region to use
        :type region_name: string

        :param bucket_name: The S3 bucket to use
        :type bucket_name: string

        :param bucket_name: The S3 bucket to use
        :type bucket_name: string

        :param service_name: The name of the service (determines S3 path)
        :type service_name: string
        """

        log.info('Init Microsecrets for service %r, S3 bucket %r',
                 service_name, bucket_name)
        self.region_name = region_name
        self.bucket_name = bucket_name
        self.service_name = service_name

        self._connect_s3(bucket_name=bucket_name)


    def upload_environment_from_stream(self, stream, json_input=False,
                                       kms_key_alias=None, kms_key_id=None):
        """
        Read environment variable data from a file stream, upload it to S3
        encrypted with KMS.

        :param stream: The stream object to read environment data from

        :param json_input: Whether the input is in key=value lines or JSON
        :type json_input: boolean

        :param kms_key_alias: Optional alias to specify the KMS key to use
        :type kms_key_alias: string

        :param kms_key_id: Optional ID of KMS key to use, avoids the DescribeKey
                           call needed to look up key by alias
        :type kms_key_id: string
        """
        log.debug('Method: upload_environment_from_stream')

        # set / look up the KMS key to use
        if kms_key_id is not None:
            assert not kms_key_alias, 'kms_key_id, kms_key_alias are exclusive'
        else:
            if kms_key_alias is None:
                kms_key_alias = self._default_kms_alias()
            kms_key_id = self._get_kms_key_id(kms_key_alias)

        if json_input:
            env = self._load_env_from_json_stream(stream)
        else:
            env = self._load_env_from_pairs_stream(stream)

        if INSECURE_DEBUG:
            log.debug('Uploading environment: %r', env)
        else:
            log.debug('Uploading environment keys: %r', env.keys())

        return self._upload_environment(env=env, kms_key_id=kms_key_id)

    def _load_env_from_pairs_stream(self, stream):
        log.info('Reading KEY=value environment pairs from %r', stream.name)
        env = {}

        for line in stream:
            # ignore whitespace
            line = line.strip()

            # skip lines starting with # and blank lines
            if line.startswith('#') or not line:
                continue

            if '=' not in line:
                raise ValueError("Could not parse line (no '='): " +
                                 repr(line))

            key, val = line.split('=', 1)
            env[key] = val

        return env

    def _load_env_from_json_stream(self, stream):
        log.info('Reading JSON environment dict from %r', stream.name)
        data = json.load(stream)

        assert_dict_of_strings(data)

        return data

    def _connect_s3(self, bucket_name):
        config = botocore.client.Config(signature_version='s3v4')
        self._s3 = self.boto_session.resource('s3', config=config)
        self.bucket = self._s3.Bucket(bucket_name)

    @property
    def boto_session(self):
        if not hasattr(self, '_boto_session'):
            self._boto_session = boto3.session.Session(region_name=self.region_name)

        return self._boto_session

    def _kms(self):
        return self.boto_session.client('kms')

    def _describe_kms_key(self, alias):
        log.debug('Looking up KMS key with alias %r', alias)
        return self._kms().describe_key(KeyId='alias/'+alias)

    def _default_kms_alias(self):
        return 'microsecrets-' + self.service_name

    def _get_kms_key_id(self, alias):
        key_id = self._describe_kms_key(alias=alias)['KeyMetadata']['KeyId']
        log.debug('Loaded KMS key %r', key_id)
        return key_id

    def _service_folder(self):
        return 'services/' + self.service_name

    def _s3_path(self, suffix):
        return self._service_folder() + '/' + suffix

    def _s3_path_environment(self):
        return self._s3_path('environment')

    def _s3_path_files(self, name):
        return self._s3_path('files/' + name)

    def _upload_environment(self, env, kms_key_id):
        # validate that env is a dict of strings
        for key, val in env.iteritems():
            assert_string(key)
            assert_string(val)

        log.info('Uploading environment with %d variables', len(env))

        # prepare json for upload
        text = json.dumps({
            'environment': env,
            'metadata': {
                'timestamp': time.time(),
                'user': getpass.getuser() + '@' + socket.gethostname(),
            }
        })

        r_dict = self._s3_upload_file(folder=self._s3_path_environment(),
                                      text=text, extension='json',
                                      kms_key_id=kms_key_id,
                                      content_type='application/json')

        log.info('Uploaded environment to path %r', r_dict['key'])

        return r_dict


    def upload_file_from_stream(self, stream, label, kms_key_alias=None,
                                kms_key_id=None):
        """
        Read data from a file stream, upload it to S3 encrypted with KMS.

        :param stream: The stream object to read file data from

        :param label: The label used to determine the S3 folder
        :type label: str

        :param kms_key_alias: Optional alias to specify the KMS key to use
        :type kms_key_alias: str

        :param kms_key_id: Optional ID of KMS key to use, avoids the DescribeKey
                           call needed to look up key by alias
        :type kms_key_id: str
        """
        log.debug('Method: upload_file_to_s3')

        log.info('Uploading data to S3 from %r', stream)

        # set / look up the KMS key to use
        if kms_key_id is not None:
            assert not kms_key_alias, 'kms_key_id, kms_key_alias are exclusive'
        else:
            if kms_key_alias is None:
                kms_key_alias = self._default_kms_alias()
            kms_key_id = self._get_kms_key_id(kms_key_alias)

        text = stream.read()

        if INSECURE_DEBUG:
            log.debug('Will upload data: %r', text)
        else:
            log.debug('Will upload %d bytes', len(text))

        r_dict = self._s3_upload_file(folder=self._s3_path_files(label),
                                      text=text, kms_key_id=kms_key_id)
        # TODO: content_type?

        log.info('Uploaded file: %r', r_dict['key'])

        return r_dict


    def _s3_upload_file(self, folder, text, kms_key_id, extension=None,
                        content_type=None):
        """
        Upload text to S3 with the given prefix folder.

        File will be uploaded under folder with a name based on the current
        time and the hash of the content.
        """

        fname, digest = self._compute_s3_filename_and_digest(text, extension=extension)

        key = folder.rstrip('/') + '/' + fname

        self._s3_raw_upload(key=key, body=text, kms_key_id=kms_key_id,
                            content_type=content_type)

        return {
            'bucket': self.bucket.name,
            'key': key,
            'digest': digest,
        }

    def _s3_raw_upload(self, key, body, kms_key_id, content_type=None):
        """
        Low level method: upload text to S3 at key.

        See boto3.resources.factory.s3.Object#put()
        """

        obj = self.bucket.Object(key=key)

        kwargs = {}

        if content_type:
            kwargs['ContentType'] = content_type

        kwargs['ServerSideEncryption'] = 'aws:kms'
        kwargs['SSEKMSKeyId'] = kms_key_id

        log.debug('Putting %d bytes of content to S3: %r', len(body), obj)

        return obj.put(ACL='private', Body=body, **kwargs)

    def _s3_raw_download(self, key, bucket=None):
        """
        Download text from S3.

        :param bucket: S3 bucket object
        :type bucket: boto3.resources.factory.s3.Bucket

        :param key: S3 path to get
        :type key: string
        """
        obj = (bucket or self.bucket).Object(key)
        log.debug('Downloading %r', obj)
        resp = obj.get()
        return resp['Body'].read()

    def _s3_find_latest(self, prefix, bucket=None):
        if bucket is None:
            bucket = self.bucket

        url = 's3://{}{}'.format(bucket.name, prefix)
        log.info('_s3_find_latest: %r', url)

        try:
            results = bucket.objects.filter(Prefix=prefix)
            return max(results, key=attrgetter('key'))
        except ValueError as e:
            if 'empty sequence' in e.message:
                log.warning('No S3 objects found: %r', url)
                raise NotFound('No S3 objects under {!r}'.format(url))
            raise

    def _compute_s3_filename_and_digest(self, text, extension=None):
        digest = hashlib.sha256(text).hexdigest()
        log.debug('Computed SHA256 digest: ' + digest)

        datestamp = datetime.utcnow().strftime('%Y-%m-%d.%H-%M-%S')

        fname = datestamp + '.' + digest
        if extension:
            fname += '.' + extension

        return (fname, digest)

    def list_files_and_env(self):
        try:
            env_obj = self._s3_find_latest(prefix=self._s3_path_environment()+'/')
        except NotFound:
            objs = []
        else:
            objs = [env_obj]

        return objs + self._list_files()

    def _list_files(self):
        prefix = self._s3_path_files('')
        log.info('list files: s3://%s%s', self.bucket.name, prefix)
        results = list(self.bucket.objects.filter(Prefix=prefix))
        if not results:
            return []

        found_files = {}

        for obj in results:
            assert obj.key.startswith(prefix)
            suffix = obj.key[len(prefix):]
            parts = suffix.split('/')

            if len(parts) != 2:
                log.warning("Skipping S3 key with unexpected depth: %r",
                            obj.key)

            file_name, file_info = parts

            # keep only the latest (greatest sort order) object for each
            # file_name prefix
            if file_name in found_files:
                if obj.key > found_files[file_name].key:
                    found_files[file_name] = obj
            else:
                found_files[file_name] = obj

        return list(found_files.values())

    def download_s3_file(self, name, dest_path=None, dest_stream=None,
                         checksum=None, mode=0o600):

        if not dest_stream and not dest_path:
            raise ValueError('must pass either dest_path or dest_stream')

        if dest_stream:
            if dest_path:
                log.error('dest_stream %r, dest_path %r', dest_stream, dest_path)
                raise ValueError('dest_stream and dest_path are exclusive args')
            else:
                out_name = dest_stream.name
        else:
            out_name = dest_path

        log.info('Downloading %r from S3 to %r', name, out_name)
        log.debug('mode: %r, expected checksum: %r', mode, checksum)

        prefix = self._s3_path_files(name) + '/'
        obj = self._s3_find_latest(prefix=prefix)

        log.info('Downloading file: s3://%s/%s', obj.bucket_name, obj.key)
        resp = obj.get()

        # TODO: stream response rather than keeping it all in memory?
        data = resp['Body'].read()

        if checksum is None:
            log.info('Not verifying checksum')
        else:
            if checksum_is_valid(data=data, checksum=checksum):
                log.debug('File passes checksum %r', checksum)
            else:
                raise ValueError('File {!r} does not match checksum {!r}'
                                 .format(obj.key, checksum))

        if dest_stream:
            log.debug('Appending data to stream %r', out_name)
            dest_stream.write(data)
        else:
            log.debug('Writing out data to %r', dest_path)
            with _open_new_file_rw(path=dest_path, mode=mode) as fh:
                fh.write(data)

        log.info('Successfully downloaded file')

        return obj

    def parse_file_arg(self, string, require_path=True):
        """
        Parse the string argument to the --file NAME[:PATH[:HASH]] option.

        Return a dictionary with 'name', 'path', and 'checksum' keys.

        :param string: The argument
        :type string: str

        :param require_path: Whether to require that the PATH is present
        :type require_path: boolean
        """
        parts = string.split(':')

        if len(parts) == 1:
            if require_path:
                raise ValueError('Cannot parse as NAME:PATH[:HASH]: ' +
                                 repr(string))
            name = parts[0]
            path = None
            checksum = None
        elif len(parts) == 2:
            name, path = parts
            checksum = None
        elif len(parts) == 3:
            name, path, checksum = parts
            if not _is_hex_string(checksum):
                raise ValueError('invalid checksum: ' + repr(checksum))
        else:
            raise ValueError('Cannot parse as NAME:PATH[:HASH]: ' +
                             repr(string))

        return {
            'name': name,
            'path': path,
            'checksum': checksum,
        }

    def exec_with_s3_env(self, command, checksum=None, env_whitelist=None,
                         env_whitelist_all=None, ignore_extra=False,
                         use_path=True, env_delete=None):
        """
        Execute command with extra environment variables downloaded from S3.

        :param command: The command to execute
        :type command: list

        :param checksum: The SHA1/SHA256 hexdigest of the env file to verify
        :type checksum: string or None

        :param env_whitelist: An iterable of allowed environment variable names
        :type env_whitelist: iterable of strings

        :param env_whitelist_all: Whether to allow all environment variables
        :type env_whitelist_all: boolean

        :param ignore_extra: Whether to proceed even if there are extra
                             disallowed environment variables. (Default of
                             False will cause an exception to be raised.)
        :type ignore_extra: boolean

        :param use_path: Whether to search PATH to find the command to exec
        :type use_path: boolean

        :param env_delete: A list of environment variables to remove before
                           executing the command
        :type env_delete: iterable of strings
        """

        log.debug('Method: exec_with_s3_env')

        log.info('Downloading environment from S3')

        env = self._download_s3_environment(checksum=checksum,
                                            env_whitelist=env_whitelist,
                                            env_whitelist_all=env_whitelist_all,
                                            ignore_extra=ignore_extra)

        if INSECURE_DEBUG and log.level <= logging.DEBUG:
            log.debug('S3 environment: %r', env)
        else:
            log.info('S3 environment keys: %r', env.keys())

        log.debug('Command: %r', command)

        log.info('Executing command with environment')

        exec_with_extra_env(command=command, env=env, use_path=use_path,
                            env_delete=env_delete)

        log.error('Somehow returned from exec?')

    def _download_s3_environment(self, checksum=None, env_whitelist=None,
                                 env_whitelist_all=None, ignore_extra=False,
                                 include_metadata=True):

        result = self._download_s3_environment_raw()

        data = result['body']
        s3_key = result['key']

        if checksum is not None:
            if checksum_is_valid(data=data, checksum=checksum):
                log.debug('JSON passes checksum %r', checksum)
            else:
                raise ValueError(
                    'JSON does not match checksum {!r}'.format(checksum))

        return self._process_environment_json(
            data,
            env_whitelist=env_whitelist,
            env_whitelist_all=env_whitelist_all,
            ignore_extra=ignore_extra,
            s3_key=s3_key,
            include_metadata=include_metadata)

    def _download_s3_environment_raw(self):
        obj = self._s3_find_latest(prefix=self._s3_path_environment()+'/')

        log.debug('Downloading object from S3: %r', obj)
        log.info('Downloading environment variables from S3 at %r', obj.key)
        return {
            'body': obj.get()['Body'].read(),
            'key': obj.key,
        }

    def _process_environment_json(self, json_text, env_whitelist=None,
                                  env_whitelist_all=False, ignore_extra=False,
                                  s3_key=None, include_metadata=True):

        if env_whitelist is None:
            env_whitelist = set()

        data = json.loads(json_text)
        env = {}

        if not 'environment' in data:
            raise KeyError("No `environment' key found in JSON")
        if not 'metadata' in data:
            raise KeyError("No `metadata' key found in JSON")

        assert_dict_of_strings(data['environment'])
        assert_dict_of_scalars(data['metadata'])

        for key, val in data['environment'].iteritems():
            if not env_whitelist_all:
                if key not in env_whitelist:
                    if ignore_extra:
                        log.warning(
                            'Skipping env variable %r, not on whitelist', key)
                        continue
                    else:
                        log.debug('Offending key: %r', key)
                        log.debug('Whitelist: %r', env_whitelist)
                        msg = ('Received env variable not on whitelist: {!r}'
                               .format(key))
                        log.error(msg)
                        log.error('To allow, pass --whitelist %r', str(key))
                        log.error('To ignore extra keys, pass --ignore-extra')
                        raise ValueError(msg)

            env[key] = val

        if include_metadata:
            env['MICROSECRETS_METADATA'] = json.dumps(data['metadata'])
            env['MICROSECRETS_SOURCE'] = s3_key or ''

        return env


def exec_with_extra_env(command, env, use_path=False, env_delete=None):
    """
    Exec command, merging in environment variables from env. On success, this
    command replaces the current process and does not return.

    :param command: The command to run
    :type command: list<string>

    :param env: An environment variable dict
    :type env: dict<string:string>

    :param use_path: Whether to search PATH to find the command
    :type use_path: boolean

    :param env_delete: A list of environment variables to remove before
                       executing the command
    :type env_delete: iterable of strings
    """
    # copy a new environment for the child with merged keys
    new_env = dict(os.environ, **env)

    # delete any blacklisted environment variables
    if env_delete:
        log.debug('Removing blacklisted env variables: %r', env_delete)
        for key in env_delete:
            new_env.pop(key, None)

    if INSECURE_DEBUG:
        log.debug('Environment for command: %r', new_env)
    else:
        log.debug('Environment keys for command: %r', new_env.keys())

    if use_path:
        log.debug('Will search PATH for the command')
        exec_func = os.execvpe
    else:
        log.debug('Will not search PATH for the command')
        exec_func = os.execve

    log.debug('About to os.%s: %r', exec_func.__name__, command)

    sys.stderr.flush()
    sys.stdout.flush()

    exec_func(command[0], command, new_env)
    # does not return

def checksum_is_valid(data, checksum):
    try:
        func = HASH_LEN_FUNC_MAP[len(checksum)]
    except KeyError:
        log.error('Could not find algorithm for hash length %d', len(checksum))
        raise

    real_csum = func(data).hexdigest()

    if real_csum == checksum:
        return True
    else:
        log.error('Computed checksum %r does not match %r',
                  real_csum, checksum)
        return False

@contextlib.contextmanager
def _open_new_file_rw(path, mode):
    """
    Atomically create a new file at `path` with `mode`. Fail if the file
    already exists. Return an open handle to the file in read/write mode.

    Will run os.open(path, os.O_RDWR|os.O_CREAT|os.O_EXCL, mode)

    :param path: The path to the file
    :type path: string

    :param mode: The file system mode of the file to create. The actual file
                 will have umask bits removed from the resulting permissions.
    :type mode: int
    """

    # sanity check mode, refusing to set setuid, setgid, or sticky bits
    if mode & stat.S_ISUID: raise ValueError('Refusing to set file setuid')
    if mode & stat.S_ISGID: raise ValueError('Refusing to set file setgid')
    if mode & stat.S_ISVTX: raise ValueError('Refusing to set file sticky bit')

    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w+') as fh:
        yield fh

def _is_hex_string(text):
    hex_digits = set('0123456789abcdefABCDEF')
    return all(c in hex_digits for c in text)
