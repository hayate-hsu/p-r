'''
    Utility module
'''
import hashlib
import uuid
import base64
import random

import functools

import time
import datetime

import json

import re

from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

KEY = base64.b64encode(uuid.uuid5(uuid.NAMESPACE_X500, 'bidong wifi').hex)

b64encode = base64.b64encode
b64decode = base64.b64decode

class My_JSONEncoder(json.JSONEncoder):
    '''
        serial datetime date
    '''
    def default(self, obj):
        '''
            serialize datetime & date
        '''
        if isinstance(obj, datetime.datetime):
            return obj.strftime(DATE_FORMAT)
        elif isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        else:
            return super(json.JSONEncoder, self).default(obj)

json_encoder = My_JSONEncoder(ensure_ascii=False).encode
json_decoder = json.JSONDecoder().decode

# json_encoder = json.JSONEncoder().encode
# json_decoder = json.JSONDecoder().decode

# _PASSWORD_ = '23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ~!@#$^&*<>=+-_'
_PASSWORD_ = '23456789abcdefghjkmnpqrstuvwxyz'
_VERIFY_CODE_ = '1234567890'

MAC_PATTERN = re.compile(r'[-:_]')

def check_codes(method):
    '''
        Decorator to check parameters.
        Encode unicode to utf-8 codes
    '''
    functools.wraps(method)
    def wrapper(*args, **kwargs):
        args = [arg.encode('utf-8', 'replace') if isinstance(arg, unicode) else arg for arg in args]
        for key,value in kwargs.iteritems():
            if isinstance(value, unicode):
                kwargs[key] = value.encode('utf-8', 'replace')
        return method(*args, **kwargs)
    return wrapper

def now(fmt=DATE_FORMAT, days=0, hours=0):
    _now = datetime.datetime.now()
    if days or hours:
        _now = _now + datetime.timedelta(days=days, hours=hours)
    return _now.strftime(fmt)

def cala_delta(start):
    '''
    '''
    _now = datetime.datetime.now()
    start = datetime.datetime.strptime(start, '%Y-%m-%d %H:%M:%S')
    return (_now - start).seconds

@check_codes
def md5(*args):
    '''
        join args and calculate md5
        digest() : bytes
        hexdigest() : str
    '''
    md5 = hashlib.md5()
    md5.update(''.join(args))
    return md5

@check_codes
def sha1(*args):
    sha1 = hashlib.sha1()
    sha1.update(''.join(args))
    return sha1

def generate_password(len=6):
    '''
        Generate password randomly
    '''
    return ''.join(random.sample(_PASSWORD_, len))

def generate_verify_code(_len=6):
    '''
        generate verify code
    '''
    return ''.join(random.sample(_VERIFY_CODE_, _len))

@check_codes
def token(user):
    '''
        as bidong's util module
    '''
    _now = int(time.time())
    _88hours_ago = _now - 3600*88
    _now, _88hours_ago = hex(_now)[2:], hex(_88hours_ago)[2:]
    data = ''.join([user, _88hours_ago])
    ret_data = uuid.uuid5(uuid.NAMESPACE_X500, data).hex
    return '|'.join([ret_data, _now])

@check_codes
def token2(user, _time):
    _t = int('0x'+_time, 16)
    _88hours_ago = hex(_t - 3600*88)[2:]
    data = ''.join([user, _88hours_ago])
    return uuid.uuid5(uuid.NAMESPACE_X500, data).hex

def format_mac(mac):
    '''
        output : ##:##:##:##:##:##
    '''
    mac = re.sub(r'[_.,; -]', ':', mac).upper()
    if 12 == len(mac):
        mac = ':'.join([mac[:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:]])
    elif 14 == len(mac):
        mac = ':'.join([mac[:2],mac[2:4],mac[5:7],mac[7:9],mac[10:12],mac[12:14]])
    return mac

def strip_mac(mac):
    if mac:
        return re.sub(MAC_PATTERN, '', mac.upper())
    else:
        return ''

def _fix_key(key):
    '''
        Fix key length to 32 bytes
    '''
    slist = list(key)
    fixkeys = ('*', 'z', 'a', 'M', 'h', '.', '8', '0', 'O', '.', 
               '.', 'a', '@', 'v', '5', '5', 'k', 'v', 'O', '.', 
               '*', 'z', 'a', 'r', 'h', '.', 'x', 'k', 'O', '.', 
               'q', 'g')
    if len(key) < 32:
        pos = len(key)
        while pos < 32:
            slist.append(fixkeys[pos-len(key)])
            pos += 1
    if len(key) > 32:
        slist = slist[:32]
    return ''.join(slist)

@check_codes
def aes_encrypt(data, key, mode=AES.MODE_ECB):
    '''
        Port aes encrypt from c#
    '''
    iv = '\x00'*16
    # padding input data
    encoder = PKCS7Encoder()
    padded_text = encoder.encode(data)
    key = _fix_key(key)
    cipher =  AES.new(key, mode, iv)
    cipher_text = cipher.encrypt(padded_text)
    return base64.b64encode(cipher_text)

@check_codes
def aes_decrypt(data,key, mode=AES.MODE_ECB):
    data = base64.b64decode(data)
    iv = '\x00'*16
    key = _fix_key(key)
    cipher = AES.new(key, mode, iv)
    encode_data = cipher.decrypt(data)
    encoder = PKCS7Encoder()
    chain_text = encoder.decode(encode_data)
    return chain_text

class PKCS7Encoder():
    '''
        Technique for padding a string as defined in RFC2315, section 10.3, note #2
    '''
    class InvalidBlockSizeError(Exception):
        '''
            Raise for invalid block sizes
        '''
        pass
    
    def __init__(self, block_size=16):
        if block_size < 1 or block_size > 99:
            raise InvalidBlockSizeError('The block size must be between 1 and 99')
        self.block_size = block_size

    def encode(self, text):
        text_length = len(text)
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = unhexlify('{:02x}'.format(amount_to_pad))
        return text + pad * amount_to_pad

    def decode(self, text):
        pad = int(hexlify(text[-1]))
        return text[:-pad]

def format_left_time(expired, coin):
    '''
    expired : datetime %Y-%m-%d %H:%M:%S
    '''
    days, hours = 0, 0
    # check current data
    if expired:
        delta = expired - datetime.datetime.now()
        days = delta.days
        hours = int(delta.seconds/3600) 
        if days < 0:
            days = 0
        else:
            days = days + 1

    # if coin>0:
    #     # one coin = 3 minutes
    #     times = coin*60
    #     hours = '{:02d}:{:02d}'.format(int(times/3600), int(times%3600/60))

    return days, hours

