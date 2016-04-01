"""
Microsecrets, a simple S3 secrets store.
"""

VERSION = '0.0.1'

import hashlib
import json
import logging
import os
import re
import sys

import boto3
import botocore

log = logging.getLogger(__name__)
log.level = logging.DEBUG

log.addHandler(logging.StreamHandler())

# Blacklist some known dangerous environment variables. It is still quite
# plausible that there exists a way to get code execution from environment
# variables, so it's recommended to either pass -w/--whitelist or to check the
# JSON file's checksum with -c/--checksum.
ENV_BLACKLIST_RE = [
    r'^LD_',
]
ENV_BLACKLIST = set([
    'PATH',
    'HTTP_PROXY',
    'http_proxy',
    'HTTPS_PROXY',
    'https_proxy',
    'NO_PROXY',
    'no_proxy',
    'USER',
    'LOGNAME',
    'HOME',
    'IFS',
])

# Mapping from hash length to hash function
HASH_LEN_FUNC_MAP = {
    40: hashlib.sha1,
    64: hashlib.sha256,
    96: hashlib.sha384,
    128: hashlib.sha512,
}

def with_s3_env(command, region_name, bucket_name, service_name, checksum=None,
               files=None):

    s3_bucket = get_s3_bucket(region_name=region_name, bucket_name=bucket_name)

    if opts.env:
        # TODO
        env = get_env_from_s3(bucket=s3_bucket, key=opts.env,
                              checksum=opts.checksum)
    else:
        env = {}
        log.warning('No environment file specified')

    log.debug('Environment: {!r}'.format(env))
    log.debug('Command: {!r}'.format(command))

    exec_with_extra_env(command=command, env=env)

    log.error('Somehow returned from exec?')

def hash_is_valid(data, checksum):
    try:
        func = HASH_LEN_FUNC_MAP[len(checksum)]
    except KeyError:
        log.error('Could not find algorithm for hash length {!r}'.format(
            len(checksum)))
        raise

    real_csum = func(data).hexdigest()

    if real_csum == checksum:
        return True
    else:
        log.error('Computed checksum {!r} does not match {!r}'.format(
            real_csum, checksum))
        return False

def get_env_from_s3(bucket, key, checksum=None):
    data = get_s3_text(bucket, key)

    if checksum:
        if hash_is_valid(data=data, checksum=checksum):
            log.debug('JSON passes checksum {!r}'.format(checksum))
        else:
            raise ValueError(
                'JSON does not match checksum {!r}'.format(checksum))

    return process_environment_json(data)

def process_environment_json(json_text):

    data = json.loads(json_text)
    env = {}

    if not 'environment' in data:
        raise KeyError("No `environment' key found in JSON")

    for key, val in data['environment'].iteritems():
        assert isinstance(key, str) or isinstance(key, unicode)
        assert isinstance(val, str) or isinstance(val, unicode)

        if env_var_on_blacklist(key):
            log.warning('Skipping {0!r} due to env var blacklist'.format(key))
            continue

        env[key] = val

    return env

def get_s3_bucket(region_name, bucket_name):
    config = botocore.client.Config(signature_version='s3v4')
    session = boto3.session.Session(region_name=region_name)
    s3 = session.resource('s3', config=config)
    return s3.Bucket(bucket_name)

def get_s3_text(bucket, key):
    """
    Download text from S3.

    :param bucket: S3 bucket object
    :type bucket: boto3.resources.factory.s3.Bucket

    :param key: S3 path to get
    :type key: string
    """
    obj = bucket.Object(key)
    resp = obj.get()
    return resp['Body'].read()

def env_var_on_blacklist(key):
    if key in ENV_BLACKLIST:
        return True
    for pattern in ENV_BLACKLIST_RE:
        if re.search(pattern, key):
            return True
    return False

def exec_with_extra_env(command, env):
    """
    Exec command, merging in environment variables from env. On success, this
    command replaces the current process and does not return.
    """
    sys.stderr.flush()
    sys.stdout.flush()

    # copy a new environment for the child with merged keys
    new_env = dict(os.environ, **env)

    log.debug('about to os.execve: {!r}'.format(command))

    # TODO: do we want to use execvpe to use the PATH to find the command?

    os.execve(command[0], command, new_env)
    # does not return

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


