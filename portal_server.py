'''
'''
from __future__ import absolute_import, division, print_function, with_statement

# Tornado framework
import tornado.web
HTTPError = tornado.web.HTTPError

import tornado.ioloop
import tornado.auth
import tornado.escape
import tornado.options
import tornado.locale
import tornado.httpclient
import tornado.gen
import tornado.httputil
from tornado.util import errno_from_exception
from tornado.platform.auto import set_close_exec

from tornado.options import define, options

define('port', default=8880, help='running on the given port', type=int)

import errno
import os
import sys

import datetime
import time

import struct
import socket
import collections
import functools
import copy

import re

from urlparse import parse_qs

import xml.etree.ElementTree as ET

# Mako template
import mako.lookup
import mako.template

from MySQLdb import (IntegrityError)

logger = None

import utility
# import settings
import config
import user_agents
from radiusd.store import store
from bd_err import bd_errs

portal_config = config['portal_config']

json_encoder = utility.json_encoder
json_decoder = utility.json_decoder
# b64encode = utility.b64encode
# b64decode = utility.b64decode

# from radiusd.store import store

_PORTAL_VERSION = 0x01
RUN_PATH = '/var/run'

# portal server send request
# { serialno : (Header, Attributes) }
# 
_REQUESTES_ = {}

AC_CONFIGURE = config['ac_policy']

BAS_PORT = 2000
_BUFSIZE=1024

PORTAL_PORT = 50100

LOGIN = 0
LOGOUT = 1

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))
# STATIC_PATH = os.path.join('/home/niot/wifi', 'webpro/bidong_v2')
# TEMPLATE_PATH = os.path.join('/home/niot/wifi', 'webpro/bidong_v2/portal')
STATIC_PATH = '/www/bidong'
TEMPLATE_PATH = '/www/portal'
PAGE_PATH = os.path.join(TEMPLATE_PATH, 'm')

# PN_PROFILE {pn:{ssid1:policy, ssid2:policy}, }
PN_PROFILE = collections.defaultdict(dict)
# {ap_mac:pn}  : ap_mac(11:22:33:44:55:66)
AP_MAPS = {}

# MOBILE_PATTERN = re.compile(r'^(?:13[0-9]|14[57]|15[0-35-9]|17[678]|18[0-9])\d{8}$')

class Application(tornado.web.Application):
    '''
        Web application class.
        Redefine __init__ method.
    '''
    def __init__(self):
        handlers = [
            (r'/account$', PortalHandler),
            (r'/wx_auth$', PortalHandler),
            (r'/(.*?\.html)$', PageHandler),
            # in product environment, use nginx to support static resources
            (r'/(.*\.(?:css|jpg|js|png))$', tornado.web.StaticFileHandler, 
             {'path':STATIC_PATH}),
            (r'/test1$', TestHandler),
            # (r'/weixin', WeiXinHandler),
        ]
        settings = {
            'cookie_secret':utility.sha1('portal_server').hexdigest(), 
            'static_path':TEMPLATE_PATH,
            # 'static_url_prefix':'resource/',
            'debug':False,
            'autoreload':True,
            'autoescape':'xhtml_escape',
            'i18n_path':os.path.join(CURRENT_PATH, 'resource/i18n'),
            # 'login_url':'',
            'xheaders':True,    # use headers like X-Real-IP to get the user's IP address instead of
                                # attributeing all traffic to the balancer's IP address.
        }
        super(Application, self).__init__(handlers, **settings)

class BaseHandler(tornado.web.RequestHandler):
    '''
        BaseHandler
        override class method to adapt special demands
    '''
    LOOK_UP = mako.lookup.TemplateLookup(directories=[TEMPLATE_PATH, ], 
                                         module_directory='/tmp/mako',
                                         output_encoding='utf-8',
                                         input_encoding='utf-8',
                                         encoding_errors='replace')
    LOOK_UP_MOBILE = mako.lookup.TemplateLookup(directories=[PAGE_PATH, ], 
                                                module_directory='/tmp/mako_mobile',
                                                output_encoding='utf-8',
                                                input_encoding='utf-8',
                                                encoding_errors='replace')

    RESPONSES = {}
    RESPONSES.update(tornado.httputil.responses)

    def initialize(self, lookup=LOOK_UP):
        '''
        '''
        pass

    def render_string(self, filename, **kwargs):
        '''
            Override render_string to use mako template.
            Like tornado render_string method, this method also
            pass request handler environment to template engine
        '''
        try:
            if not self.is_mobile:
                template = self.LOOK_UP.get_template(filename)
            else:
                template = self.LOOK_UP_MOBILE.get_template(filename)
            env_kwargs = dict(
                handler = self,
                request = self.request,
                # current_user = self.current_user
                locale = self.locale,
                _ = self.locale.translate,
                static_url = self.static_url,
                xsrf_form_html = self.xsrf_form_html,
                reverse_url = self.application.reverse_url,
                agent = self.agent,
            )
            env_kwargs.update(kwargs)
            return template.render(**env_kwargs)
        except:
            from mako.exceptions import RichTraceback
            tb = RichTraceback()
            for (module_name, line_no, function_name, line) in tb.traceback:
                print('File:{}, Line:{} in {}'.format(module_name, line_no, function_name))
                print(line)
            logger.error('Render {} failed, {}:{}'.format(filename, tb.error.__class__.__name__, tb.error), 
                         exc_info=True)
            raise HTTPError(500, 'Render page failed')

    def render(self, filename, **kwargs):
        '''
            Render the template with the given arguments
        '''
        directory = TEMPLATE_PATH
        if self.is_mobile:
            directory = PAGE_PATH

        if not os.path.exists(os.path.join(directory, filename)):
            raise HTTPError(404, 'File Not Found')

        self.finish(self.render_string(filename, **kwargs))

    def set_status(self, status_code, reason=None):
        '''
            Set custom error resson
        '''
        self._status_code = status_code
        self._reason = 'Unknown Error'
        if reason is not None:
            self._reason = tornado.escape.native_str(reason)
        else:
            try:
                self._reason = self.RESPONSES[status_code]
            except KeyError:
                raise ValueError('Unknown status code {}'.format(status_code))

    def write_error(self, status_code, **kwargs):
        '''
            Customer error return format
        '''
        if self.settings.get('Debug') and 'exc_info' in kwargs:
            self.set_header('Content-Type', 'text/plain')
            import traceback
            for line in traceback.format_exception(*kwargs['exc_info']):
                self.write(line)
            self.finish()
        else:
            # self.render('error.html', Code=status_code, Msg=self._reason)
            self.render_json_response(Code=status_code, Msg=self._reason)

    def render_exception(self, ex):
        self.set_status(ex.status_code)
        self.render('error.html', Code=ex.status_code, Msg=ex.reason)

    def render_json_response(self, **kwargs):
        '''
            Encode dict and return response to client
        '''
        callback = self.get_argument('callback', None)
        # check should return jsonp
        if callback:
            self.set_status(200, kwargs.get('Msg', None))
            self.finish('{}({})'.format(callback, json_encoder(kwargs)))
        else:
            self.set_status(kwargs['Code'], kwargs.get('Msg', None))
            self.set_header('Content-Type', 'application/json')
            self.finish(json_encoder(kwargs))

    def prepare(self):
        '''
            check client paltform
        '''
        self.agent_str = self.request.headers.get('User-Agent', '')
        self.agent = None
        self.is_mobile = False
        
        # check app & os info 
        self.check_app()
        
        if self.agent_str:
            self.agent = user_agents.parse(self.agent_str)
            self.is_mobile = self.agent.is_mobile

    def check_app(self):
        '''
        '''
        name = '\xe8\x87\xaa\xe8\xb4\xb8\xe9\x80\x9a'
        if name in self.agent_str:
            self.is_mobile = True
            # if self.agent_str.find('Android'):
            #     self.agent['os'] = {'family':'Android'}
            # else:
            #     self.agent['os'] = {'family':'IOS'}

    def b64encode(self, **kwargs):
        '''
            use base64 to encode kwargs
            the end of b64 : '' | '=' | '==' 
        '''
        arguments = copy.copy(kwargs)
        arguments.pop('firsturl', '')
        arguments.pop('urlparam', '')
        data = utility.b64encode(json_encoder(arguments))
        if data[-2] == '=':
            data = data[:-2] + '2'
        elif data[-1] == '=':
            data = data[:-1] + '1'
        else:
            data = data + '0'
        return data

    def b64decode(self, data):
        '''
            decode data to dict
        '''
        bdata, nums = data[:-1], data[-1]
        nums = int(nums, 10)
        if nums == 2:
            bdata = bdata + '=='
        elif nums == 1:
            bdata = bdata + '='

        return json_decoder(utility.b64decode(bdata))

def _parse_body(method):
    '''
        Framework only parse body content as arguments 
        like request POST, PUT method.
        Through this method parameters can be send in uri or
        in body not matter request methods(contain 'GET', 'DELETE')
    '''
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        content_type = self.request.headers.get('Content-Type', '')

        # parse json format arguments in request body content
        if content_type.startswith('application/json') and self.request.body:
            arguments = json_decoder(tornado.escape.native_str(self.request.body))
            for name, values in arguments.iteritems():
                if isinstance(values, basestring):
                    values = [values, ]
                else:
                    values = [v for v in values if v]
                if values:
                    self.request.arguments.setdefault(name, []).extend(values)
        
        # parse body if request's method not in (PUT, POST, PATCH)
        if self.request.method not in ('PUT', 'PATCH', 'POST'):
            if content_type.startswith('application/x-www-form-urlencode'):
                arguments = tornado.escape.parse_qs_bytes(
                    tornado.escape.native_str(self.request.body))
                for name, values in arguments.iteritems():
                    values = [v for v in values if v]
                    if values:
                        self.request.arguments.setdefault(name, []).extend(values)
            elif content_type.startswith('multipart/form-data'):
                fields = content_type.split(';')
                for field in fields:
                    k, sep, v = field.strip().partition('=')
                    if k == 'boundary' and v:
                        tornado.httputil.parse_multipart_form_data(
                            tornado.escape.utf8(v), self.request.body, 
                            self.request.arguments, self.request.files)
                        break
                    else:
                        logger.warning('Invalid multipart/form-data')
        return method(self, *args, **kwargs)
    return wrapper

def _trace_wrapper(method):
    '''
        Decorate method to trace logging and exception.
        Remarks : to make sure except catch and progress record
        _trace_wrapper should be the first decorator if a method
        is decorated by multiple decorators.
    '''
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            logger.info('<-- In %s: <%s> -->', self.__class__.__name__, self.request.method)
            return method(self, *args, **kwargs)
        except HTTPError as ex:
            logger.error('HTTPError catch', exc_info=True)
            raise
        except KeyError as ex:
            if self.application.settings.get('debug', False):
                print(self.request)
            logger.warning('Arguments error', exc_info=True)
            raise HTTPError(400)
        except ValueError as ex:
            if self.application.settings.get('debug', False):
                print(self.request)
            logger.warning('Arguments value abnormal', exc_info=True)
            raise HTTPError(400)
        except Exception:
            # Only catch normal exceptions
            # exclude SystemExit, KeyboardInterrupt, GeneratorExit
            logger.error('Unknow error', exc_info=True)
            raise HTTPError(500)
        finally:
            logger.info('<-- Out %s: <%s> -->\n\n', self.__class__.__name__, self.request.method)
    return wrapper

def _check_token(method):
    '''
        check user & token
    '''
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        user = self.get_argument('user') 
        if not user:
            raise HTTPError(400, reason='account can\'t be null')
        token = self.get_argument('token')

        token, expired = token.split('|')
        token2 = utility.token2(user, expired)
        if token != token2:
            raise HTTPError(400, reason='Abnormal token')

        return method(self, *args, **kwargs)
    return wrapper

def TestHandler(BaseHandler):
    def get(self):
        self.redirect('/nagivation.html')

class PageHandler(BaseHandler):
    '''
    '''
    _WX_IP = 'api.weixin.qq.com'
    # for family,type,proto,canonname,sockaddr in socket.getaddrinfo('api.weixin.qq.com', None, socket.AF_INET, 0, socket.SOL_TCP):
    #     _WX_IP = sockaddr[0]
    #     # print(_WX_IP)
    #     break
    # _APP_ID = 'wxa7c14e6853105a84'
    # _SHOP_ID = '4873033'
    # _SECRET_KEY = '9db64a9e2ef817abd463e06bb50ec4e2'

    def redirect_to_bidong(self):
        '''
        '''
        logger.info('redirect : {}'.format(self.request.arguments))
        self.redirect(config['bidong'])

    def prepare_wx_wifi(self, **kwargs):
        wx_wifi = {}
        wx_wifi['extend'] = self.b64encode(appid=self.profile['appid'], shopid=self.profile['shopid'], **kwargs)
        wx_wifi['timestamp'] = str(int(time.time()*1000))
        # portal_server = '{}://{}:{}/wx_auth'.format(self.request.protocol, 
        #                                             self.request.headers.get('Host'), 
        #                                             self.request.headers.get('Port'))
        portal_server = 'http://{}:9898/wx_auth'.format(self.request.headers.get('Host'))
        
        wx_wifi['auth_url'] = tornado.escape.url_escape(portal_server)
        wx_wifi['auth_url'] = portal_server
        wx_wifi['sign'] = self.calc_sign(self.profile['appid'], wx_wifi['extend'], wx_wifi['timestamp'], 
                                         self.profile['shopid'], wx_wifi['auth_url'], 
                                         kwargs['user_mac'], self.profile['ssid'], kwargs['ap_mac'], 
                                         self.profile['secret'])

        self.wx_wifi = wx_wifi


    @_trace_wrapper
    @_parse_body
    def get(self, page):
        '''
            Render html page
        '''
        # logger.info(self.request)
        page = page.lower()

        if page == 'nansha.html':
            return self.render('nansha.html')

        if page not in ('login.html'):
            return self.redirect_to_bidong()
            # return self.redirect('http://58.241.41.148/index.html')

        kwargs = {}
        accept = self.request.headers.get('Accept', 'text/html')
        if page.startswith('login'):
            kwargs['ac_ip'] = self.get_argument('wlanacip', '') or self.get_argument('nasip', '')
            if not kwargs['ac_ip']:
                logger.error('can\'t found ac parameter, please check ac url configuration')
                # doesn't contain ac_ip parameter, return redirect response
                # if user hasn't auth, ac will redirect the next request
                # with necessary parameters
                # return self.redirect('http://10.10.1.175:8080/index.html')
                return self.redirect_to_bidong()
                # return self.redirect('http://58.241.41.148/index.html')
            self.parse_ac_parameters(kwargs)

            # logger.info('Parsed arguments: {}'.format(kwargs))

            url = kwargs['firsturl']
            
            # logger.info('begin get billing policy')
            self.get_current_billing_policy(**kwargs)


            # process weixin argument
            self.prepare_wx_wifi(**kwargs)

            # logger.info('{}'.format(kwargs))

            # check mac address, login by mac address
            # if login successfully, return _user, else return None
            _user = self.login_auto_by_mac(**kwargs)
            if _user:
                # auto login successfully
                # redirect to previous url 
                if accept.startswith('application/json'):
                    # request from app (android & ios)
                    # if mask & 1<<4 ,indicate account is nansha city account
                    # app need create app account & merge account
                    token = utility.token(_user['user'])
                    self.render_json_response(User=_user['user'], Token=token, Mask=_user['mask'], 
                                              Code=200, Msg='OK')
                elif url:
                    # self.set_header('Access-Control-Allow-Origin', '*')
                    if kwargs['urlparam']:
                        url = ''.join([url, '?', kwargs['urlparam']])
                    self.redirect(url)
                # update online tables
                store.add_online2(user=_user['user'], nas_addr=kwargs['ac_ip'], 
                                  acct_start_time=utility.now(), framed_ipaddr=kwargs['user_ip'], 
                                  mac_addr=kwargs['user_mac'], ap_mac=kwargs['ap_mac'])
                return 

            # url = self.get_argument('wlanuserfirsturl', '') or self.get_argument('url', '')
            if url.find('m_web/onetonet') != -1:
                # user from weixin, parse code & and get openid
                urlparam = parse_qs('urlparam='+kwargs['urlparam'])
                params = parse_qs(urlparam['urlparam'][0])
                
                openid = self.get_openid(params['code'][0])

                # check agent
                agent_str = self.request.headers.get('User-Agent', '')
                if 'MicroMessenger' not in agent_str:
                    return self.render_exception(HTTPError(400, 'Abnormal agent'))
                try:
                    return self.wx_login(openid, **kwargs)
                except HTTPError as ex:
                    return self.render_exception(ex)
                except:
                    return self.render_exception(HTTPError(400, 'Unknown error'))

        # get policy
        kwargs['user'] = ''
        kwargs['password'] = ''

        logger.info('profile: {}'.format(self.profile))
        
        pn_ssid, pn_note, pn_logo = '', '', ''

        if accept.startswith('application/json'):
            # ssid key:value in kwargs
            if not self.profile['ispri']:
                profile = store.get_pn(self.profile['pn'])
                if profile:
                    pn_ssid = profile['ssid']
                    pn_note = profile['note']
                    pn_logo = profile['logo']
                

            return self.render_json_response(Code=200, Msg='OK', openid='', pn_ssid=pn_ssid, 
                                             pn_note=pn_note, pn_logo=pn_logo,  
                                             ispri=self.profile['ispri'], pn=self.profile['pn'], 
                                             note=self.profile['note'], image=self.profile['logo'], 
                                             **kwargs)
                    

        # now all page user login, later after update back to use self.profile['portal']  
        page = self.profile['portal'] or 'login.html'

        return self.render(page, openid='', ispri=self.profile['ispri'], 
        # return self.render('login.html', openid='', ispri=self.profile['ispri'], 
                           pn=self.profile['pn'], note=self.profile['note'], image=self.profile['logo'], 
                           appid=self.profile['appid'], shopid=self.profile['shopid'], secret=self.profile['secret'], 
                           extend=self.wx_wifi['extend'], timestamp=self.wx_wifi['timestamp'], 
                           sign=self.wx_wifi['sign'], authUrl=self.wx_wifi['auth_url'], 
                           **kwargs)


    def get_user_by_mac(self, mac, ac):
        records = store.get_user_records_by_mac(mac)
        if records:
            return records[-1]['user']
        return ''

    def get_current_billing_policy(self, **kwargs):
        '''
            user's billing policy based on the connected ap 
        '''
        profile = get_billing_policy(kwargs['ac_ip'], kwargs['ap_mac'], kwargs['ssid'])
        self.profile = profile

    def format_mac(self, mac):
        '''
            output : ##:##:##:##:##:##
        '''
        mac = re.sub(r'[_.,; -]', ':', mac).upper()
        if 12 == len(mac):
            mac = ':'.join([mac[:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:]])
        elif 14 == len(mac):
            mac = ':'.join([mac[:2],mac[2:4],mac[5:7],mac[7:9],mac[10:12],mac[12:14]])
        return mac

    def parse_ac_parameters(self, kwargs):
        '''
        '''
        if kwargs['ac_ip'] not in AC_CONFIGURE:
            raise HTTPError(400, reason='Unknown AC: {}'.format(kwargs['ac_ip']))

        kwargs['vlan'] = self.get_argument('vlan', 1)
        kwargs['ssid'] = self.get_argument('ssid', 'NS_GOV')
        kwargs['user_ip'] = self.get_argument('wlanuserip', '') or self.get_argument('userip', '')

        # user mac address 
        mac = self.get_argument('mac', '') or self.get_argument('wlanstamac', '') 
        if not mac:
            raise HTTPError(400, 'mac address can\'t be none')
        kwargs['user_mac'] = self.format_mac(mac)

        # ap mac address
        # 00:00:00:00:00:00 - can't get ap mac address
        ap_mac = self.get_argument('apmac', '') or self.get_argument('wlanapmac', '00:00:00:00:00:01')
        kwargs['ap_mac'] = self.format_mac(ap_mac)


        try:
            kwargs['firsturl'] = self.get_argument('wlanuserfirsturl', '') or self.get_argument('url', '') or self.get_argument('userurl', '')
            kwargs['urlparam'] = self.get_argument('urlparam', '')
        except:
            kwargs['firsturl'] = config['bidong']
            # kwargs['firsturl'] = 'http://wwww.bidongwifi.com/'
            kwargs['urlparam'] = ''

    
    def login_auto_by_mac(self, **kwargs):
        '''
            if found bd_account by mac, and check successfully return user account 
            otherwise return None
        '''
        if self.profile['pn'] == 10000:
            # 10000 (test) owner, skip auto login check
            return None
        user = self.get_user_by_mac(kwargs['user_mac'], kwargs['ac_ip'])
        if not user:
            return None

        _user = store.get_bd_user(user) or store.get_bd_user2(user)
        if not _user:
            return None

        # check private network
        # logger.info('>>profile : {}'.format(self.profile))
        if self.profile['ispri']:
            # current network is private, check user privilege
            # logger.info('pn:{}, user:{}'.format(self.profile['pn'], _user['user']))
            if not store.check_pn_privilege(self.profile['pn'], _user['user']):
                return None
                # raise HTTPError(427, reason='Can\'t access private network : {}'.format(self.profile['pn']))

        if not self.profile['policy']:
            if _user['mask']>>30 & 1:
                # raise HTTPError(403, reason='Account has been frozened')
                return None
                # raise HTTPError(403, reason=bd_errs[434])
            # ipolicy =0, check billing
            self.expired = utility.check_account_balance(_user)
            if self.expired:
                # raise HTTPError(403, reason='Account has no left time')
                return None
        
        onlines = store.get_onlines(_user['user'])
        if kwargs['user_mac'] not in onlines and len(onlines) >= _user['ends']:
            # allow user logout ends 
            return None
            # raise HTTPError(403, reason='Over the limit ends')
        try:
            logger.info('Progress {} (mac: {}) auto login'.format(user, kwargs['user_mac']))
            self.login(_user, kwargs['ac_ip'], socket.inet_aton(kwargs['user_ip']), kwargs['user_mac'])
        except:
            logger.warning('auto login error', exc_info=True)
            return None

        return _user

    def login(self, _user, ac_ip, user_ip, user_mac):
        '''
            user_ip: 32bit
            login, if error raise exception
        '''
        user = _user['user']
        password = _user['password']
        logger.info('progress %s login, ip: %s', user, self.request.remote_ip)
        _mac = user_mac.split(':')
        # mac_addr = user_mac.replace('.', ':').upper()
        user_mac = ''.join([chr(int(item, base=16)) for item in _mac])
        ver,start = 0x01, 16
        # if ac_ip in H3C_AC:
        #     ver = 0x02
        #     start = 16 + 16
        header = Header(ver, 0x01, 0x00, 0x00, PortalHandler._SERIAL_NO_.pop(), 
                        0, user_ip, 0 , 0x00, 0x00)
        packet = Packet(header, Attributes(mac=user_mac))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
        try:
            sock.settimeout(5)
            data, address = sock.recvfrom(_BUFSIZE)
        except socket.timeout:
            logger.warning('Challenge timeout')
            self.timeout(sock, ac_ip, header, user_mac)
            sock.close()
            raise HTTPError(400, reason='challenge timeout, retry')
            # return self.render_error(Code=400, Msg='challenge timeout, retry')

        header = Header.unpack(data)
        if header.type != 0x02 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            if header.err == 0x02:
                # linked has been established, has been authed 
                logger.info('user: {} has been authed, mac:{}'.format(user, ':'.join(_mac)))
                return
            elif header.err == 0x03:
                # user's previous link has been verifring 
                logger.info('user: {}\'s previous has been progressing, mac:{}'.format(user, ':'.join(_mac)))
                raise HTTPError(436, reason=bd_errs[436])
                # raise HTTPError(449, reason='in progressing, wait')
                return

            raise HTTPError(400, reason='challenge error')
            # return self.render_json_response(Code=400, Msg='challenge error')
        # parse challenge value
        attrs = Attributes.unpack(header.num, data[start:])
        if not attrs.challenge:
            logger.warning('Abnormal challenge value, 0x%x, 0x%x', header.err, header.num)
            sock.close()
            raise HTTPError(400, reason='abnormal challenge value')
            # return self.render_error(Code=400, Msg='abnormal challenge value')
        if attrs.mac:
            assert user_mac == attrs.mac

        header.type = 0x03
        # header.serial = PortalHandler._SERIAL_NO_.pop()
        attrs = Attributes(user=user, password=password, challenge=attrs.challenge, mac=user_mac, chap_id=data[8])
        packet = Packet(header, attrs)
        sock.settimeout(None)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

        # wait auth response
        try:
            sock.settimeout(5)
            data, address = sock.recvfrom(_BUFSIZE)
        except socket.timeout:
            logger.warning('auth timeout')
            # send timeout package
            self.timeout(sock, ac_ip, header, user_mac)
            sock.close()
            raise HTTPError(408, reason='auth timeout, retry')
            # return self.render_error(Code=408, Msg='auth timeout, retry')
        header = Header.unpack(data)
        if header.type != 0x04 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            raise HTTPError(403, reason='auth error')
            # return self.render_error(Code=403, Msg='auth error')
        # self.finish('auth successfully')

        # send aff_ack_auth to ac 
        header.type = 0x07
        attrs = Attributes(mac=user_mac)
        packet = Packet(header, attrs)
        sock.settimeout(None)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
        sock.close()
        logger.info('%s login successfully, wlan: %s', user, self.request.remote_ip)

        time.sleep(1.5)

    def get_openid(self, code):
        URL = 'https://{}/sns/oauth2/access_token?appid={}&secret={}&code={}&grant_type=authorization_code'
        url = URL.format(self._WX_IP, config['weixin']['appid'], config['weixin']['secret'], code)
        client = tornado.httpclient.HTTPClient()
        response = client.fetch(url)
        result = json_decoder(response.body)
        if 'openid' not in result:
            logger.error('Get weixin account\'s openid failed, msg: {}'.format(result))
            raise HTTPError(500)

        return result['openid']

    @_trace_wrapper
    def wx_login(self, openid, **kwargs):
        user, password = '', ''
        _user = store.get_user(openid, column='weixin', appid=self.profile['appid']) or store.get_user2(openid, column='weixin', appid=self.profile['appid'])
        if not _user:
            # create new account
            _user = store.add_user(openid, utility.generate_password(), appid=self.profile['appid'])
        if not _user:
            raise HTTPError(400, reason='Should subscribe first')
        # user unsubscribe, the account will be forbid
        # logger.info('weixin account {}'.format(_user))
        if _user['mask']>>31 & 1:
            raise HTTPError(401, reason='Account has been frozen')
            
        # check ac ip
        if kwargs['ac_ip'] not in AC_CONFIGURE:
            logger.error('not avaiable ac & ap')
            raise HTTPError(403, reason='AC ip error')

        # check account & password
        # if not _user:
        #     _user = store.get_bd_user(user)
        # if not _user:
        #     raise HTTPError(404, reason='Account not existed')
        # if password != _user['password']:
        #     raise HTTPError(401, reason='Password error')
        if self.profile['ispri']:
            # current network is private, check user privilege
            # logger.info('pn:{}, user:{}'.format(self.profile['pn'], _user['user']))
            if not store.check_pn_privilege(self.profile['pn'], _user['user']):
                raise HTTPError(427, reason='Can\'t access private network : {}'.format(self.profile['pn']))

        if not self.profile['policy']:
            # ipolicy =0, check billing
            self.expired = utility.check_account_balance(_user)
            if self.expired:
                raise HTTPError(403, reason='Account has no left time')

        # allow weixin ends uses, ingore ends limit

        # onlines = store.get_onlines(_user['user'])
        # if kwargs['user_mac'] not in onlines and len(onlines) >= _user['ends']:
        #     # allow user logout ends 
        #     return False
        # onlines = store.count_online(_user['user'])
        # if onlines >= _user['ends']:
        #     # allow user logout ends 
        #     raise HTTPError(403, reason='Over the limit ends')

        self.login(_user, kwargs['ac_ip'], socket.inet_aton(kwargs['user_ip']), kwargs['user_mac'])

        # login successfully
        # redirect to account page
        token = utility.token(_user['user'])
        self.redirect(config['bidong'] + 'account/{}?token={}'.format(_user['user'], token))
        # self.redirect('http://www.bidongwifi.com/account/{}?token={}'.format(_user['user'], token))

        self.update_mac_record(_user, kwargs['user_mac'])


    def timeout(self, sock, ac_ip, header, user_mac):
        '''
        '''
        logger.info('ip: %s timeout', self.request.remote_ip)
        header.type = 0x05
        header.err = 0x01
        packet = Packet(header, Attributes(mac=user_mac))
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

    def check_mac_online_recently(self, mac, flag):
        '''
            check ruijie client's online
            if last_start is '': use hasn't been online
            else : check last_start & now timedelta
        '''
        last_start = store.get_online_by_mac(mac, flag)
        if last_start:
            seconds = utility.cala_delta(last_start)
            if seconds < 60:
                # check user online(if user login in 1 minutes, assume use has been login)
                return True
        return False

    def update_mac_record(self, user, mac):
        # agent_str = self.request.headers.get('User-Agent', '')
        records = store.get_mac_records(user['user'])
        m_records = {record['mac']:record for record in records}
        if mac not in m_records:
            # update mac record 
            if (not records) or len(records) < user['ends']:
                store.update_mac_record(user['user'], mac, '', self.agent_str, False)
            else:
                # records = sorted(records.values(), key=lambda item: item['datetime'])
                store.update_mac_record(user['user'], mac, records[0]['mac'], self.agent_str, True)

    def calc_sign(self, *args):
        '''
            sign = md5(appid, extend,timestamp, shop_id, authUrl, 
                       mac, ssid, bssid, secretkey) 
        '''
        data = ''.join(args)
        # logger.info('calc md5: {}'.format(data))
        return utility.md5(data).hexdigest()

class SerialNo:
    def __init__(self):
        self.cur = 1
    def pop(self):
        if self.cur > 65536:
            self.cur = 1
        ret = self.cur
        self.cur = ret + 1
        return ret

class PortalHandler(BaseHandler):
    '''
        Handler portal auth request
    '''
    _SERIAL_NO_ = SerialNo()

    def prepare(self):
        super(PortalHandler, self).prepare()
        self.is_weixin = False

    @_trace_wrapper
    @_parse_body
    def get(self):
        # tid = self.get_argument('tid')
        # timestamp = self.get_argument('timestamp')
        # sign = self.get_argument('sign')
        openid = self.get_argument('openId')
        extend = self.get_argument('extend')

        kwargs = self.b64decode(extend)
        user, password = '',''
        _user = store.get_user(openid, column='weixin', appid=kwargs['appid']) or  store.get_user2(openid, column='weixin', appid=kwargs['appid'])
        if not _user:
            # create new account
            _user = store.add_user(openid, utility.generate_password(), appid=kwargs['appid'])
        if not _user:
            raise HTTPError(400, reason='Should subscribe first')
        
        self.user = _user

        # check account left, forbin un-meaning request to ac
        ac_ip = kwargs['ac_ip']
        # check ac ip
        if ac_ip not in AC_CONFIGURE:
            logger.error('not avaiable ac & ap')
            raise HTTPError(403, reason='AC ip error')

        ap_mac = kwargs['ap_mac']
        user_mac = kwargs['user_mac']
        user_ip = kwargs['user_ip']

        # vlanId = self.get_argument('vlan')
        ssid = kwargs['ssid']
        profile = get_billing_policy(ac_ip, ap_mac, ssid)

        # check private network
        if profile['ispri']:
            # current network is private, check user privilege
            if not store.check_pn_privilege(profile['pn'], self.user['user']):
                raise HTTPError(427, reason='{} Can\'t access private network : {}'.format(self.user['user'], profile['pn']))
        
        # check billing
        # nanshan account user network freedom (check by ac_ip)
        # if not profile['policy']:
        if not profile['policy']:
            self.expired = utility.check_account_balance(self.user)
            if self.expired:
                # raise HTTPError(403, reason='Account has no left time')
                raise HTTPError(403, reason=bd_errs[450])

        # user_ip = socket.inet_aton(user_ip)

        self.is_weixin = True

        self.login(ac_ip, socket.inet_aton(user_ip), user_mac)
        self.update_mac_record(self.user, user_mac)

        store.add_online2(user=self.user['user'], nas_addr=kwargs['ac_ip'], 
                          acct_start_time=utility.now(), framed_ipaddr=kwargs['user_ip'], 
                          mac_addr=kwargs['user_mac'], ap_mac=kwargs['ap_mac'])

        # self.render_json_response(Code=200, Msg='OK')

    @_trace_wrapper
    @_parse_body
    def post(self):
        # parse request data
        openid = self.get_argument('openid', None)
        user = self.get_argument('user', '')
        password = self.get_argument('password', '')
        _user = None

        ac_ip = self.get_argument('ac_ip')
        # check ac ip
        if ac_ip not in AC_CONFIGURE:
            logger.error('not avaiable ac & ap')
            raise HTTPError(403, reason='AC ip error')

        ap_mac = self.get_argument('ap_mac')
        user_mac = self.get_argument('user_mac')
        user_ip = self.get_argument('user_ip')

        # vlanId = self.get_argument('vlan')
        ssid = self.get_argument('ssid')

        profile = get_billing_policy(ac_ip, ap_mac, ssid)

        # flags = self.get_argument('flags', 0)
        _user = ''

        if openid:
            # weixin client
            appid = self.get_argument('appid')
            shopid = self.get_argument('shopid')
            _user = store.get_user(openid, column='weixin', appid=appid) or store.get_user2(openid, column='weixin', appid=appid)
            
            if not _user:
                raise HTTPError(404, reason=bd_errs[430])
                # user unsubscribe, the account will be forbid
                # if _user['mask']>>31 & 1:
                #     raise HTTPError(403, reason='No privilege')
                # _user = store.get_bd_user(_user['id'])
            user = _user['user']
            password = _user['password']
        else:
            # user is mobile number and password is verify code
            # _user = self.check_mobile_account(user, user_mac) 
            _user = store.get_bd_user(user)
            # else:
            #     # portal by mobile & code, ingore input password
            #     password = _user['password']

        # _user = store.get_bd_user(user)
        if not _user:
            raise HTTPError(401, reason=bd_errs[431])

        if password not in (_user['password'], utility.md5(_user['password']).hexdigest()):
            # password or user account error
            raise HTTPError(401, reason=bd_errs[431])

        # check account status & account ends number on networt
        if _user['mask']>>30 & 1:
            # raise HTTPError(403, reason='Account has been frozened')
            raise HTTPError(403, reason=bd_errs[434])

        self.user = _user

        # onlines = store.get_onlines(self.user['user'])
        # if user_mac not in onlines and len(onlines) >= self.user['ends']:
        #     # allow user login ends 
        #     raise HTTPError(403, reason=bd_errs[451])
        #     # return False

        # check private network
        if profile['ispri']:
            # current network is private, check user privilege
            if not store.check_pn_privilege(profile['pn'], self.user['user']):
                raise HTTPError(427, reason='{} Can\'t access private network : {}'.format(self.user['user'], profile['pn']))
        
        # check billing
        # nanshan account user network freedom (check by ac_ip)
        # if not profile['policy']:
        if not profile['policy']:
            self.expired = utility.check_account_balance(self.user)
            if self.expired:
                # raise HTTPError(403, reason='Account has no left time')
                raise HTTPError(403, reason=bd_errs[450])

        # send challenge to ac
        flags = int(self.get_argument('flags', LOGIN))
        flags = LOGIN
        if flags == LOGIN:
            # portal-radius server doesn't check password, so send a 
            # no-meaning value
            self.login(ac_ip, socket.inet_aton(user_ip), user_mac)
            # update mac address
            # if ac_ip in RJ_AC:
            #     # Record nansha city user's platform
            #     # distinguish nansha_city accoutn & bidong account
            #     user_mac = user_mac.replace(':', '-')
            self.update_mac_record(self.user, user_mac)
            store.add_online2(user=self.user['user'], nas_addr=ac_ip, 
                              acct_start_time=utility.now(), framed_ipaddr=user_ip, 
                              mac_addr=user_mac, ap_mac=ap_mac)
        else:
            self.logout(ac_ip, user_ip, user_mac)

    def login(self, ac_ip, user_ip, user_mac):
        '''
            user_ip: 32bit 
        '''
        user = self.user['user']
        password = self.user['password']
        logger.info('progress %s login, ip: %s', user, self.request.remote_ip)
        _mac = user_mac.split(':')
        # mac_addr = user_mac.replace('.', ':').upper()
        user_mac = ''.join([chr(int(item, base=16)) for item in _mac])
        ver,start = 0x01,16
        # if ac_ip in H3C_AC:
        #     # user portal v2
        #     ver = 0x02
        #     start = 16 + 16
        header = Header(ver, 0x01, 0x00, 0x00, PortalHandler._SERIAL_NO_.pop(), 
                        0, user_ip, 0 , 0x00, 0x00)
        packet = Packet(header, Attributes(mac=user_mac))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
        try:
            sock.settimeout(portal_config['nas_timeout'])
            data, address = sock.recvfrom(_BUFSIZE)
        except socket.timeout:
            logger.warning('Challenge timeout')
            self.timeout(sock, ac_ip, header, user_mac)
            sock.close()
            # raise HTTPError(400, reason='challenge timeout, retry')
            raise HTTPError(400, reason=bd_errs[530])
            # return self.render_json_response(Code=400, Msg='challenge timeout, retry')

        header = Header.unpack(data)
        if header.type != 0x02 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            if header.err == 0x02:
                # linked has been established, has been authed 
                logger.info('user: {} has been authed, mac:{}'.format(user, ':'.join(_mac)))
                if self.is_weixin:
                    return
                raise HTTPError(435, reason=bd_errs[435])
            elif header.err == 0x03:
                # user's previous link has been verifring 
                logger.info('user: {}\'s previous has been progressing, mac:{}'.format(user, ':'.join(_mac)))
                raise HTTPError(436, reason=bd_errs[436])
            # raise HTTPError(400, reason='challenge timeout, retry')
            raise HTTPError(400, reason=bd_errs[530])
            # return self.render_json_response(Code=400, Msg='challenge error')
        # parse challenge value
        attrs = Attributes.unpack(header.num, data[start:])
        if not attrs.challenge:
            logger.warning('Abnormal challenge value, 0x%x, 0x%x', header.err, header.num)
            sock.close()
            # raise HTTPError(400, reason='abnormal challenge value')
            raise HTTPError(400, reason=bd_errs[530])
            # return self.render_json_response(Code=400, Msg='abnormal challenge value')
        if attrs.mac:
            assert user_mac == attrs.mac

        header.type = 0x03
        # header.serial = PortalHandler._SERIAL_NO_.pop()
        # chap_password = utility.md5(data[8], password, attrs.challenge).digest()
        # attrs = Attributes(user=user, chap_password=chap_password)
        logger.info('user %s, password %s, challenge:%s', user, password, attrs.challenge)
        attrs = Attributes(user=user, password=password, challenge=attrs.challenge, mac=user_mac, chap_id=data[8])
        packet = Packet(header, attrs)
        sock.settimeout(None)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

        # wait auth response
        try:
            sock.settimeout(portal_config['nas_timeout'])
            data, address = sock.recvfrom(_BUFSIZE)
        except socket.timeout:
            logger.warning('auth timeout')
            # send timeout package
            self.timeout(sock, ac_ip, header, user_mac)
            sock.close()
            # raise HTTPError(408, reason='auth timeout, retry')
            raise HTTPError(408, reason=bd_errs[530])
            # return self.render_json_response(Code=408, Msg='auth timeout, retry')
        header = Header.unpack(data)
        if header.type != 0x04 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            if header.err == 0x02:
                # linked has been established, has been authed 
                logger.info('user: {} has been authed, mac:{}'.format(user, ':'.join(_mac)))
                if self.is_weixin:
                    return
                raise HTTPError(435, reason=bd_errs[435])
            elif header.err == 0x03:
                # user's previous link has been verifring 
                logger.info('user: {}\'s previous has been progressing, mac:{}'.format(user, ':'.join(_mac)))
                raise HTTPError(436, reason=bd_errs[436])
            # attrs = Attributes.unpack(header.num, data[start:])
            # raise HTTPError(403, reason='auth error')
            raise HTTPError(403, reason=bd_errs[531])

        # send aff_ack_auth to ac 
        header.type = 0x07
        attrs = Attributes(mac=user_mac)
        packet = Packet(header, attrs)
        sock.settimeout(None)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
        sock.close()

        # self.update_mac_record(user, _user_mac)
        time.sleep(1.5)

        # self.set_login_cookie(user)
        token = utility.token(user)
        if self.is_weixin:
            self.redirect(config['bidong'] + 'account/{}?token={}'.format(user, token))
            # self.redirect('http://www.bidongwifi.com/account/{}?token={}'.format(user, token))
        else:
            self.render_json_response(User=user, Token=token, Code=200, Msg='OK')
        logger.info('%s login successfully, ip: %s', user, self.request.remote_ip)

    def logout(self, ac_ip, user_ip, user_mac):
        '''
        '''
        user = self.user['user']
        logger.info('progress %s logout, ip: %s', user, self.request.remote_ip)
        ver = 0x01
        # if ac_ip in H3C_AC:
        #     ver = 0x02
        header = Header(ver, 0x05, 0x00, 0x00, PortalHandler._SERIAL_NO_.pop(), 
                        0, user_ip, 0 , 0x00, 0x00)
        packet = Packet(header, Attributes(mac=user_mac))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
        sock.close()
        self.finish('logout successfully')
        logger.info('%s logout, ip: %s', user, self.request.remote_ip)

    def timeout(self, sock, ac_ip, header, user_mac):
        '''
        '''
        logger.info('ip: %s timeout', self.request.remote_ip)
        header.type = 0x05
        header.err = 0x01
        packet = Packet(header, Attributes(mac=user_mac))
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))
        # ignore response

    def check_app_account(self, user_mac):
        '''
            mask:
                    1<<6 : android 
                    1<<7 : ios
        '''
        value,mask = '', int(self.get_argument('mask',0))
        if mask & (1<<6|1<<7):
            value = self.get_argument('uuid')
        else:
            return None 

        if mask:
            _user = store.get_user(value, column='uuid') or store.get_user2(value, column='uuid')

            if _user:
                return _user

        return None

    def get_holder(self, ap_mac):
        '''
            query holder id by ap_mac
        '''
        return store.get_holder_by_mac(ap_mac)

    def update_mac_record(self, user, mac):
        # agent_str = self.request.headers.get('User-Agent', '')
        if user['user'] == '10001':
            return
        records = store.get_mac_records(user['user'])
        m_records = {record['mac']:record for record in records}
        if mac not in m_records:
            # update mac record 
            if (not records) or len(records) < user['ends']:
                store.update_mac_record(user['user'], mac, '', self.agent_str, False)
            else:
                # records = sorted(records.values(), key=lambda item: item['datetime'])
                store.update_mac_record(user['user'], mac, records[0]['mac'], self.agent_str, True)

    def set_login_cookie(self, user, days=7):
        '''
        '''
        pass
        # self.set_secure_cookie('p_user', user, expires_days=7)
        # expire_date = utility.now('%Y-%m-%d', days=days)
        # self.set_secure_cookie('p_expire', expire_date, expires_days=7)
        
class Packet():
    '''
    '''
    def __init__(self, header, attrs=None, auth=''):
        self.header = header
        self.attrs = attrs
        self.auth = ''

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
        auths = b''
        if self.header.ver == 0x02:
            auths = self.md5(header, attrs)

        return b''.join([header, auths, data])

    @classmethod
    def unpack(cls, data):
        auth = ''
        header = Header.unpack(data)
        attrs = None
        data = data[16:]
        if header.num and data:
            if header.ver == 0x02:
                auth, data = data[:16],data[16:]
                attrs = Attributes.unpack(header.num, data)

        return cls(header, attrs, auth)

    def md5(self, header, attrs):
        '''
            calc md5 of (header, attrs)
        '''
        data = b''.join([header, b'0'*16, attrs, portal_config['secret']])
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
    MAC = 0xff

    def __init__(self, user='', password='', challenge='', mac='', textinfo='', chap_id=''):
        self.user = user
        self.password = password
        self.challenge = challenge
        self.chap_password = '' 
        self.mac = mac
        self.textinfo = textinfo
        self.chap_id = chap_id

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
                # md5 = hashlib.md5()
                # md5.update(chap_id.encode('utf-8'))
                # md5.update(password)
                # md5.update(self.challenge.encode('utf-8'))
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
            elif type == 0xff:
                mac, data = data[2:length],data[length:]
            else:
                # unknown attributes
                data = data[length:]
            num = num - 1
        return cls(user=user, password=password, challenge=challenge, 
                   mac=mac, textinfo=textinfo)

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

# ap billing profile should refress each 7200 seconds

EXPIRE = 7200

def get_billing_policy(nas_addr, ap_mac, ssid):
    '''
        1. check ap profile
        2. check ssid profile
        3. check ac profile
    '''
    configure = AC_CONFIGURE[nas_addr]
    if (configure['mask'])>>2 & 1:
        # check ap prifile in cache?
        if ap_mac in AP_MAPS:
            profile = PN_PROFILE[AP_MAPS[ap_mac]].get(ssid, None)
            if profile and int(time.time()) < profile['expired']:
                return profile

        # get policy by ap
        profile = store.query_ap_policy(ap_mac, ssid)
        logger.info('mac:{} ssid:{} ---- {}'.format(ap_mac, ssid, profile))

        if not profile:
            raise HTTPError(400, 'Abnormal, query pn failed, {} {}'.format(ap_mac, ssid))
        profile['expired'] = int(time.time()) + EXPIRE
        AP_MAPS[ap_mac] = profile['pn']
        PN_PROFILE[profile['pn']][profile['ssid']] = profile
        # else:
        #     pn = store.query_ap_holder(ap_mac)
        #     pn = pn['holder'] if pn else 10001
        #     profile = {'pn':pn, 'ssid':ssid, 'policy':1, 'note':'', 
        #                'logo':'', 'ispri':0, 'portal':'login.html', 
        #                'expired':int(time.time())+EXPIRE, 
        #                'appid':'', 'shopid':'', 'secret':''}

        #     AP_MAPS[ap_mac] = pn
        #     PN_PROFILE[profile['pn']][profile['ssid']] = profile

            
        return PN_PROFILE[AP_MAPS[ap_mac]][ssid]

    if (configure['mask'])>>1 & 1:
        return store.query_pn_policy(pn=configure['pns'][ssid], ssid=ssid)

    if (configure['mask'] & 1):
        return store.query_pn_policy(pn=configure['pn'], ssid=ssid)


_DEFAULT_BACKLOG = 128
# These errnos indicate that a non-blocking operation must be retried
# at a later time. On most paltforms they're the same value, but on 
# some they differ
_ERRNO_WOULDBLOCK = (errno.EWOULDBLOCK, errno.EAGAIN)
if hasattr(errno, 'WSAEWOULDBLOCK'):
    _ERRNO_WOULDBLOCK += (errno.WSAEWOULDBLOCK, )

def bind_udp_socket(port, address=None, family=socket.AF_UNSPEC, backlog=_DEFAULT_BACKLOG, flags=None):
    '''
    '''
    udp_sockets = []
    if address == '':
        address = None
    if not socket.has_ipv6 and family == socket.AF_UNSPEC:
        family = socket.AF_INET
    if flags is None:
        flags = socket.AI_PASSIVE
    bound_port = None
    for res in socket.getaddrinfo(address, port, family, socket.SOCK_DGRAM, 0, flags):
        af, socktype, proto, canonname, sockaddr = res
        try:
            sock = socket.socket(af, socktype, proto)
        except socket.error as e:
            if errno_from_exception(e) == errno.EAFNOSUPPORT:
                continue
            raise
        set_close_exec(sock.fileno())
        if os.name != 'nt':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            if hasattr(socket, 'IPPROTO_IPV6'):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        # automatic port allocation with port=None
        # should bind on the same port on IPv4 & IPv6 
        host, requested_port = sockaddr[:2]
        if requested_port == 0 and bound_port is not None:
            sockaddr = tuple([host, bound_port] + list(sockaddr[2:]))
        sock.setblocking(0)
        sock.bind(sockaddr)
        bound_port = sock.getsockname()[1]
        udp_sockets.append(sock)
    return udp_sockets

def add_udp_handler(sock, servers, io_loop=None):
    '''
        Read data in 4096 buffer
    '''
    if io_loop is None:
        io_loop = tornado.ioloop.IOLoop.current()
    def udp_handler(fd, events):
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                if data:
                    ac_data_handler(sock, data, addr)
                    # ac data arrived, deal with
                    pass
            except socket.error as e:
                if errno_from_exception(e) in _ERRNO_WOULDBLOCK:
                    # _ERRNO_WOULDBLOCK indicate we have accepted every
                    # connection that is avaiable
                    return
                import traceback
                traceback.print_exc(file=sys.stdout)
            except: 
                import traceback
                traceback.print_exc(file=sys.stdout)
    io_loop.add_handler(sock.fileno(), udp_handler, tornado.ioloop.IOLoop.READ)

def ac_data_handler(sock, data, addr):
    '''
        User logout
    '''
    # parse data, get ntf_logout packet
    # query online db by mac_addr

    # send 
    print('Receive data from {}: message type {:02X}'.format(addr, ord(data[2])))
    header = Header.unpack(data)
    if header.type & 0x08:
        # ac notify portal, user logout

        # return ack_logout
        # header.type = 0x07
        data = '\x01\x07' + data[2:]
        # sock.sendto(data, addr)

        if True:
            start = 32 if header.ver == 0x02 else 16
            attrs = Attributes.unpack(header.num, data[start:])
            if not attrs.mac:
                logger.info('User quit, ip: {}'.format(socket.inet_ntoa(header.ip)))
                return
            #
            mac = []
            for b in attrs.mac:
                mac.append('{:X}'.format(ord(b)))
            mac = ':'.join(mac)
            store.delete_online2(mac)
            logger.info('User quit, mac: {}'.format(mac))

def init_log(log_folder, log_config, port):
    global logger
    import logging
    import logging.config
    log_config['handlers']['file']['filename'] = os.path.join(log_folder, 
                                                              '{}_{}.log'.format(log_config['handlers']['file']['filename'], port))
    logging.config.dictConfig(log_config)
    logger = logging.getLogger()
    logger.propagate = False

def main():
    tornado.options.parse_command_line()

    init_log(config['log_folder'], config['logging_config'], options.port)

    portal_pid = os.path.join(config['RUN_PATH'], 'portal/p_{}.pid'.format(options.port))
    with open(portal_pid, 'w') as f:
        f.write('{}'.format(os.getpid()))

    # # store set
    # import config
    store.setup(config)


    app = Application()
    app.listen(options.port, xheaders=app.settings.get('xheaders', False))
    io_loop = tornado.ioloop.IOLoop.instance()

    udp_sockets = bind_udp_socket(PORTAL_PORT)
    for udp_sock in udp_sockets:
        add_udp_handler(udp_sock, '', io_loop)

    logger.info('Portal Server Listening:{} Started'.format(options.port))
    io_loop.start()

if __name__ == '__main__':
    main()
