"""
Microsecrets, a simple S3 secrets store.
"""

VERSION = '0.1.1'

import getpass
import hashlib
import json
import logging
import os
import re
import socket
import sys
import time

from datetime import datetime

import boto3
import botocore

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

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

def assert_string(obj):
    if not isinstance(obj, basestring):
        raise ValueError('object is not a string: {!r}'.format(obj))

def assert_dict_of_strings(obj):
    for key, val in obj.iteritems():
        assert_string(key)
        assert_string(val)

def set_log_verbose_mode():
    logging.getLogger().setLevel(logging.INFO)
    log.setLevel(logging.DEBUG)

class Microsecrets(object):
    def __init__(self, region_name, bucket_name, service_name,
                 kms_key_alias=None, kms_key_id=None):
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

        :param kms_key_alias: Optional alias to specify the KMS key to use
        :type kms_key_alias: string

        :param kms_key_id: Optional ID of KMS key to use, avoids the DescribeKey
                           call needed to look up key by alias
        :type kms_key_id: string
        """

        log.debug('Init Microsecrets for service %r', service_name)
        self.region_name = region_name
        self.bucket_name = bucket_name
        self.service_name = service_name

        self._connect_s3(bucket_name=bucket_name)

        # set / look up the KMS key to use
        if kms_key_id is not None:
            assert not kms_key_alias
            self.kms_key_id = kms_key_id
        else:
            if kms_key_alias is not None:
                self.kms_key_alias = kms_key_alias
            else:
                self.kms_key_alias = 'microsecrets-' + self.service_name
            self.kms_key_id = self._get_kms_key_id()

    def upload_environment_from_stream(self, stream, json_input=False):
        log.debug('Method: upload_environment_from_stream')

        if json_input:
            env = self._load_env_from_json_stream(stream)
        else:
            env = self._load_env_from_pairs_stream(stream)

        log.debug('Uploading environment: %r', env)
        return self._upload_environment(env)

    def _load_env_from_pairs_stream(self, stream):
        log.debug('Reading KEY=value environment pairs from %r', stream.name)
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
        log.debug('Reading JSON environment dict from %r', stream.name)
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

    def _describe_kms_key(self, alias=None):
        if alias is None:
            alias = self.kms_key_alias

        log.debug('Looking up KMS key with alias %r', alias)
        return self._kms().describe_key(KeyId='alias/'+alias)

    def _get_kms_key_id(self, alias=None):
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

    def _upload_environment(self, env):
        # validate that env is a dict of strings
        for key, val in env.iteritems():
            assert_string(key)
            assert_string(val)

        log.debug('Uploading environment with %d variables', len(env))

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
                                      content_type='application/json')

        log.debug('Uploaded environment to path %r', r_dict['key'])

        return r_dict

    def _s3_upload_file(self, folder, text, extension=None, content_type=None):
        """
        Upload text to S3 with the given prefix folder.

        File will be uploaded under folder with a name based on the current
        time and the hash of the content.
        """

        fname, digest = self._compute_s3_filename_and_digest(text, extension=extension)

        key = folder.rstrip('/') + '/' + fname

        self._s3_raw_upload(key=key, body=text, content_type=content_type)

        return {
            'bucket': self.bucket.name,
            'key': key,
            'digest': digest,
        }

    def _s3_raw_upload(self, key, body, content_type=None):
        """
        Low level method: upload text to S3 at key.

        See boto3.resources.factory.s3.Object#put()
        """

        obj = self.bucket.Object(key=key)

        kwargs = {}

        if content_type:
            kwargs['ContentType'] = content_type

        kwargs['ServerSideEncryption'] = 'aws:kms'
        kwargs['SSEKMSKeyId'] = self.kms_key_id

        log.debug('Putting content to S3: %r', obj)

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
        try:
            return max((bucket or self.bucket).objects.filter(Prefix=prefix))
        except ValueError as e:
            if 'empty sequence' in e.message:
                log.error('No S3 objects found')
            raise

    def _compute_s3_filename_and_digest(self, text, extension=None):
        digest = hashlib.sha256(text).hexdigest()
        log.debug('Computed SHA256 digest: ' + digest)

        datestamp = datetime.utcnow().strftime('%Y-%m-%d.%H-%M-%S')

        fname = datestamp + '.' + digest
        if extension:
            fname += '.' + extension

        return (fname, digest)


    def exec_with_s3_env(self, command, checksum=None, env_whitelist=None,
                         env_whitelist_all=None, ignore_extra=False):
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
        """

        log.debug('Method: exec_with_s3_env')

        env = self._download_s3_environment(checksum=checksum,
                                            env_whitelist=env_whitelist,
                                            env_whitelist_all=env_whitelist_all,
                                            ignore_extra=ignore_extra)

        log.debug('Environment: %r', env)
        log.debug('Command: %r', command)

        exec_with_extra_env(command=command, env=env)

        log.error('Somehow returned from exec?')

    def _download_s3_environment(self, checksum=None, env_whitelist=None,
                                 env_whitelist_all=None, ignore_extra=False):
        obj = self._s3_find_latest(prefix=self._s3_path_environment()+'/')

        log.debug('Downloading object from S3: %r', obj)
        data = obj.get()['Body'].read()

        if checksum is not None:
            if checksum_is_valid(data=data, checksum=checksum):
                log.debug('JSON passes checksum %r', checksum)
            else:
                raise ValueError(
                    'JSON does not match checksum {!r}'.format(checksum))

        return self._process_environment_json(
            data, env_whitelist=env_whitelist,
            env_whitelist_all=env_whitelist_all,
            ignore_extra=ignore_extra)

    def _process_environment_json(self, json_text, env_whitelist=None,
                                  env_whitelist_all=False, ignore_extra=False):

        data = json.loads(json_text)
        env = {}

        if not 'environment' in data:
            raise KeyError("No `environment' key found in JSON")

        assert_dict_of_strings(data['environment'])

        for key, val in data['environment'].iteritems():
            assert_string(key)
            assert_string(val)

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

        return env


def exec_with_extra_env(command, env):
    """
    Exec command, merging in environment variables from env. On success, this
    command replaces the current process and does not return.
    """
    # copy a new environment for the child with merged keys
    new_env = dict(os.environ, **env)

    log.debug('about to os.execve: %r', command)

    sys.stderr.flush()
    sys.stdout.flush()

    # TODO: do we want to use execvpe to use the PATH to find the command?

    os.execve(command[0], command, new_env)
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

