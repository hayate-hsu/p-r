'''
'''
from __future__ import absolute_import, division, print_function, with_statement
# from __future__ import division, print_function, with_statement

from tornado.web import HTTPError

import time
import itertools

import struct
import socket

# import sys
# 
# sys.path.insert(0, '/web/radius')

import utility

# celery application
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

from task.celery import celery

BAS_PORT = 2000
_BUFSIZE=1024

PORTAL_PORT = 50100

LOGIN = 0
LOGOUT = 1

# global variable, initilize when create
_SERIAL_NO_ = itertools.cycle(xrange(2**15))
_TIMEOUT_ = 5
_SECRET_ = 'Bidong_Wifi'

@celery.task(throws=(HTTPError,))
def login(_user, ac_ip, user_ip, user_mac):
    '''
        user_ip: 32bit 
    '''
    user = _user['user']
    name = _user.get('name', u'')
    #  
    __user__ = u'{} ({})'.format(user, name) if name else user
    # __user__ = u'{} ({})'.format(user, name)
    password = _user['password']
    user_ip = socket.inet_aton(user_ip)
    # logger.info('progress %s login, ip: %s', user, self.request.remote_ip)
    _mac = user_mac.split(':')
    user_mac = ''.join([chr(int(item, base=16)) for item in _mac])
    ver,start = 0x01,16
    header = Header(ver, 0x01, 0x00, 0x00, next(_SERIAL_NO_), 
                    0, user_ip, 0 , 0x00, 0x00)
    packet = Packet(header, Attributes(mac=user_mac))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
    try:
        sock.settimeout(_TIMEOUT_)
        data, address = sock.recvfrom(_BUFSIZE)
    except socket.timeout:
        logger.warning('Challenge timeout')
        # timeout(sock, ac_ip, header, user_mac)
        sock.close()
        # raise HTTPError(400, reason='challenge timeout, retry')
        raise HTTPError(408)

    header = Header.unpack(data)
    if header.type != 0x02 or header.err:
        logger.info('0x{:x} error, errno: 0x{:x}, user: {}, ip: {}'.format(header.type, header.err, user, socket.inet_ntoa(user_ip)))
        sock.close()
        if header.err == 0x02:
            # linked has been established, has been authed 
            logger.info('user: {} has been authed, mac:{}'.format(user, ':'.join(_mac)))
            # if self.is_weixin:
            #     return
            raise HTTPError(440)
        elif header.err == 0x03:
            # user's previous link has been verifring 
            logger.info('user: {}\'s previous has been progressing, mac:{}'.format(user, ':'.join(_mac)))
            raise HTTPError(441)
        # raise HTTPError(400, reason='challenge timeout, retry')
        raise HTTPError(531)
    # parse challenge value
    attrs = Attributes.unpack(header.num, data[start:])
    if not attrs.challenge:
        logger.warning('Abnormal challenge value, 0x{:x}, 0x{:x}'.format(header.err, header.num))
        sock.close()
        raise HTTPError(400, reason='abnormal challenge value')
    if attrs.mac:
        assert user_mac == attrs.mac

    header.type = 0x03
    # header.serial = PortalHandler._SERIAL_NO_.pop()
    # chap_password = utility.md5(data[8], password, attrs.challenge).digest()
    # attrs = Attributes(user=user, chap_password=chap_password)
    logger.info('user {} challenge successfully'.format(user))
    attrs = Attributes(user=__user__, password=password, challenge=attrs.challenge, mac=user_mac, chap_id=data[8])
    packet = Packet(header, attrs)
    sock.settimeout(None)
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

    # wait auth response
    try:
        sock.settimeout(_TIMEOUT_)
        data, address = sock.recvfrom(_BUFSIZE)
    except socket.timeout:
        logger.warning('auth timeout')
        # send timeout package
        timeout(sock, ac_ip, header, user_mac)
        sock.close()
        # raise HTTPError(408, reason='auth timeout, retry')
        raise HTTPError(408)
        # return self.render_json_response(Code=408, Msg='auth timeout, retry')
    header = Header.unpack(data)
    if header.type != 0x04 or header.err:
        logger.info('0x{:x} error, errno: 0x{:x}'.format(header.type, header.err))
        sock.close()
        if header.err == 0x02:
            # linked has been established, has been authed 
            logger.info('user: {} has been authed, mac:{}'.format(user, ':'.join(_mac)))
            # if self.is_weixin:
            #     return
            raise HTTPError(440)
        elif header.err == 0x03:
            # user's previous link has been verifring 
            logger.info('user: {}\'s previous has been progressing, mac:{}'.format(user, ':'.join(_mac)))
            raise HTTPError(441)
        raise HTTPError(531)

    # send aff_ack_auth to ac 
    header.type = 0x07
    attrs = Attributes(mac=user_mac)
    packet = Packet(header, attrs)
    sock.settimeout(None)
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
    sock.close()

    # self.update_mac_record(user, _user_mac)
    # time.sleep(1)

    return _user

# @celery.task
def timeout(sock, ac_ip, header, user_mac):
    '''
    '''
    header.type = 0x05
    header.err = 0x01
    packet = Packet(header, Attributes(mac=user_mac))
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

@celery.task
def sleep(seconds):
    time.sleep(int(seconds))
    return seconds

@celery.task
def add(x,y):
    time.sleep(3)
    return x+y

@celery.task(ignore_result=True)
def log_result(result):
    logger.info('log_result got: {}'.format(result))

@celery.task(ignore_result=True)
def logout(ac_ip, user_ip, user_mac):
    '''
    '''
    ver = 0x01
    user_ip = socket.inet_aton(user_ip)
    # logger.info('progress %s login, ip: %s', user, self.request.remote_ip)
    if user_mac:
        _mac = user_mac.split(':')
        user_mac = ''.join([chr(int(item, base=16)) for item in _mac])

    header = Header(ver, 0x05, 0x00, 0x00, next(_SERIAL_NO_), 
                    0, user_ip, 0 , 0x00, 0x00)
    packet = Packet(header, Attributes(mac=user_mac))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

    # deesn't wait response, directo return
    sock.close()

@celery.task(ignore_result=True)
def ack_logout(ac_ip, user_ip, user_mac, serial):
    '''
    '''
    ver = 0x01
    user_ip = socket.inet_aton(user_ip)
    # logger.info('progress %s login, ip: %s', user, self.request.remote_ip)
    if user_mac:
        _mac = user_mac.split(':')
        user_mac = ''.join([chr(int(item, base=16)) for item in _mac])

    header = Header(ver, 0x06, 0x00, 0x00, serial, 
                    0, user_ip, 0 , 0x00, 0x00)
    packet = Packet(header)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
    # deesn't wait response, directo return
    sock.close()

@celery.task(ignore_result=True, throws=(HTTPError,))
def mac_existed(user, ac_ip, user_ip, user_mac, serial, existed):
    ver = 0x01
    errcode = 0 if existed else 1
    header = Header(ver, 0x31, 0x00, 0x00, serial, 
                    0, user_ip, 0 , errcode, 0x00)
    _mac = user_mac.split(':')
    _mac = ''.join([chr(int(item, base=16)) for item in _mac])
    packet = Packet(header, Attributes(mac=_mac))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
    sock.close()

    if existed:
        user_ip = socket.inet_ntoa(user_ip)
        login(user, ac_ip, user_ip, user_mac)


class Packet():
    '''
    '''
    _ZERO_AUTH = b'0x00'*16

    def __init__(self, header, attrs=None, auth=b''):
        self.header = header
        self.attrs = attrs
        self.auth = auth

    def pack(self):
        '''
            return binary bytes
        '''
        num, data = 0, b''
        if self.attrs:
            num, data = self.attrs.pack()
        self.header.num = num
        header = self.header.pack()
        attrs = data
        # REQ_CHALLENGE(0x01) | REQ_AUTH(0x03) | REQ_LOGOUT(0x05) | REQ_INFO(0x0a) | NTF_LOGOUT(0x08) | AFF_ACK_AUTH(0x07)
        if self.header.ver == 0x02:
            self.auth = self.md5(header, Packet._ZERO_AUTH, attrs, _SECRET_)

        return b''.join([header, self.auth, attrs])

    @classmethod
    def unpack(cls, data):
        auth = b''
        header = Header.unpack(data)
        attrs = None
        data = data[16:]
        if header.ver == 0x02:
            auth = data[16:16]
            data = data[32:]
        if header.num and data:
            attrs = Attributes.unpack(header.num, data)

        return cls(header, attrs, auth)

    def verify_packet(self, req_auth):
        num, data = 0, b''
        if self.attrs:
            num, data = self.attrs.pack()
        self.header.num = num
        header = self.header.pack()
        attrs = data
        auth = self.md5(header, req_auth, attrs, _SECRET_)

        # check calculate auth equal response auth 
        if auth != self.auth:
            return False

        return True

    def md5(self, header, attrs):
        '''
            calc md5 of (header, attrs)
        '''
        data = b''.join([header, Packet._ZERO_AUTH, attrs, _SECRET_])
        return utility.md5(data).digest()

class Attributes():
    '''
        Attr            Type    Length 
        UserName        0x01    <=253
        PassWord        0x02    <=16
        Challenge       0x03    16
        ChapPassword    0x04    16

        method
            pack    : return binary data, if set chap_id, calculate chap password(challenge & reqid must not None)
            unpack  : class method to parse attributes
    '''
    USERNAME = 0x01
    PASSWORD = 0x02
    MASK = 0x03
    CHAPPW = 0x04
    TEXTINFO = 0x05

    # H3C extend attribute
    H3C_MAC = 0x0b
    H3C_AC_IP = 0x0a
    H3C_SSID = 0x3b
    MAC = 0xff

    def __init__(self, user='', password='', challenge='', mac='', textinfo='', chap_id='', extend={}):
        self.user = user
        self.password = password
        self.challenge = challenge
        self.chap_password = '' 
        self.mac = mac
        self.textinfo = textinfo
        self.chap_id = chap_id
        self.extend = extend

    def __str__(self):
        return 'user:{}\nextend:{}'.format(self.user, self.extend)

    def pack(self):
        '''
            struct data into binary model
        '''
        num, data = 0, b''
        if self.user:
            user = self.user.encode('utf-8')
            data = b''.join([struct.pack('>BB', self.USERNAME, 2+len(user)), user])
            num = num + 1
        if self.password :
            password = self.password.encode('utf-8')
            if self.chap_id and self.challenge:
                md5 = utility.md5(self.chap_id, password, self.challenge)
                chap_pw = md5.digest()
                data += b''.join([struct.pack('>BB', self.CHAPPW, 2+len(chap_pw)), chap_pw])
            else:
                data += b''.join([struct.pack('>BB', self.PASSWORiD, 2+len('!@#$%^&*')), '!@#$%^&*'])
            num = num + 1
        if self.mac:
            data += struct.pack('>BB6s', self.MAC, 6+2, self.mac)
            num = num + 1

        return num, data

    @classmethod
    def unpack(cls, num,  data):
        '''
            parse data
        '''
        user, password, challenge, chap_password, mac, textinfo = '', '', '', '', '', ''
        kwargs = {}
        while num and data:
            # check length
            # length contain type&length bytes.
            # 0xff0x08 6bytes mac address
            type, length = struct.unpack('>BB', data[:2])
            if type == 0x01:
                # username 
                user, data = data[2:length],data[length:]
            elif type == 0x02:
                password, data = data[2:length],data[length:]
            elif type == 0x03:
                challenge, data = data[2:length],data[length:]
            elif type == 0x04:
                chap_password, data = data[2:length],data[length:]
            elif type == 0x05:
                textinfo,data = data[2:length],data[length:]
            elif type == 0x0a:
                kwargs['ac_ip'],data = data[2:length],data[length:]
            elif type == 0x0b:
                kwargs['mac'],data = data[2:length],data[length:]
            elif type == 0x3b:
                kwargs['ssid'],data = data[2:length],data[length:]
            elif type == 0xff:
                mac, data = data[2:length],data[length:]
            else:
                # unknown attributes
                data = data[length:]
            num = num - 1
        return cls(user=user, password=password, challenge=challenge, 
                   mac=mac, textinfo=textinfo, extend=kwargs)

class Header():
    '''
        ver     : portal protocol version 0x01 | 0x02
        type    : 0x01 ~ 0x0a
        auth    : Chap 0x00 | Pap 0x01
        rsv     : reserve byte always 0x00
        serial  : serial number
        req     : req id
        ip      : user ip (wlan user's ip)
        port    : haven't used, always 0
        err     : error code
        num     : attribute number
    '''
    _FMT = '>BBBBHH4sHBB'
    def __init__(self, ver, type, auth, rsv, serial, req, ip, port, err, num):
        self.ver = ver
        self.type = type
        self.auth = auth
        self.rsv = rsv
        self.serial = serial
        self.req = req
        self.ip = ip
        self.port = port
        self.err = err
        self.num = num
        # self.auth = b'0'*16

    def pack(self):
        '''
            return binary data in big-endian[>]
        '''
        return struct.pack(self._FMT, 
                           self.ver, self.type, self.auth, self.rsv, 
                           self.serial, self.req, self.ip, self.port, 
                           self.err, self.num)
    
    @classmethod
    def unpack(cls, data):
        '''
            check & parse data, return new instance
        '''
        if len(data) < 16:
            raise ValueError('Read Data length abnormal')
        return cls(*struct.unpack(cls._FMT, data[:16]))

def init(config, log, _range):
    '''
        init logger & serial range
        _range : [start, end)
    '''
    global _SERIAL_NO_, _TIMEOUT_, _SECRET_
    _SERIAL_NO_ = itertools.cycle(_range)
    _TIMEOUT_ = config['nas_timeout']
    _SECRET_ = config['secret']

if __name__ == '__main__':
    import config
    init(config['portal_config'], None, xrange(2**15))
    celery.start()
