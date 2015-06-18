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

define('port', default=9898, help='running on the given port', type=int)

import errno
import os
import sys

import datetime
import time

import struct
import socket
import collections
import functools

from urlparse import parse_qs

import xml.etree.ElementTree as ET

# Mako template
import mako.lookup
import mako.template

logger = None

import utility
# import settings
import config
import user_agents
from radiusd.store import store

portal_config = config['portal_config']

json_encoder = utility.json_encoder
json_decoder = utility.json_decoder

# from radiusd.store import store

_PORTAL_VERSION = 0x01
RUN_PATH = '/var/run'

# portal server send request
# { serialno : (Header, Attributes) }
# 
_REQUESTES_ = {}

BAS_IP = ['10.10.0.50', '10.10.0.60']

# hanming ac 
HM_AC = ['10.10.0.50',]
# Ruijie ac
RJ_AC = ['10.10.0.60',]
BAS_PORT = 2000
_BUFSIZE=1024

PORTAL_PORT = 50100

LOGIN = 0
LOGOUT = 1

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))
STATIC_PATH = os.path.join('/home/niot/wifi', 'webpro/bidong_v2')
TEMPLATE_PATH = os.path.join('/home/niot/wifi', 'webpro/bidong_v2/portal')
PAGE_PATH = os.path.join(TEMPLATE_PATH, 'm')

class Application(tornado.web.Application):
    '''
        Web application class.
        Redefine __init__ method.
    '''
    def __init__(self):
        handlers = [
            (r'/account', PortalHandler),
            (r'/(.*?\.html)$', PageHandler),
            # in product environment, use nginx to support static resources
            (r'/(.*\.(?:css|jpg|js|png))$', tornado.web.StaticFileHandler, 
             {'path':STATIC_PATH}),
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
            if not self.is_mobile():
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
        if not os.path.exists(os.path.join(TEMPLATE_PATH, filename)):
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

    def is_mobile(self):
        agent_str = self.request.headers.get('User-Agent', '')
        if not agent_str:
            return False
        self.agent_str = agent_str
        agent = user_agents.parse(agent_str)
        
        return agent.is_mobile

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

class PageHandler(BaseHandler):
    '''
    '''
    _WX_IP = 'api.weixin.qq.com'
    for family,type,proto,canonname,sockaddr in socket.getaddrinfo('api.weixin.qq.com', None, socket.AF_INET, 0, socket.SOL_TCP):
        _WX_IP = sockaddr[0]
        # print(_WX_IP)
        break

    AC = 'AC'
    AP = 'AP'

    def redirect_to_bidong(self):
        '''
        '''
        self.redirect('http://www.bidongwifi.com/')

    @_trace_wrapper
    @_parse_body
    def get(self, page):
        '''
            Render html page
        '''
        print(self.request)
        page = page.lower()

        if page not in ('login.html'):
            return self.redirect_to_bidong()
            # return self.redirect('http://58.241.41.148/index.html')

        kwargs = {}
        if page.startswith('login'):
            kwargs['ac_ip'] = self.get_argument('wlanacip', '') or self.get_argument('nasip', '')
            if not kwargs['ac_ip']:
                # doesn't contain parameter, return redirect response
                # if user hasn't auth, ac will redirect the next request
                # with necessary parameters
                # return self.redirect('http://10.10.1.175:8080/index.html')
                return self.redirect_to_bidong()
                # return self.redirect('http://58.241.41.148/index.html')
            self.parse_ac_parameters(kwargs)
            
            # check mac address
            if self.login_auto_by_mac(**kwargs):
                return

            # get cookie setting and auto login
            # p_user = self.get_secure_cookie('p_user')
            # p_expire = self.get_secure_cookie('p_expire')
            # if p_user and p_expire:
            #     if self.login_auto_by_cookie(p_user, p_expire, **kwargs):
            #         # if return True, return
            #         return
            url = self.get_argument('wlanuserfirsturl', '') or self.get_argument('url', '')
            if url.find('m_web/onetonet') != -1:
                # user from weixin, parse code & and get openid
                urlparam = self.get_argument('urlparam')
                urlparam = parse_qs('urlparam='+urlparam)
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
                    
                    
            kwargs['firsturl'] = url
            kwargs['urlparam'] = self.get_argument('urlparam', '')
            # check mac address has been login?

        # if self.is_mobile() and page == 'login.html':
        #     return self.render('login.html', openid='', **kwargs)
        # else:
        return self.render(page, openid='', **kwargs)

    def get_user_by_mac(self, mac):
        records = store.get_mac_records(mac)
        records = {record['mac']:record for record in records}
        if mac in records:
            return records['mac']['user']
        return ''

    def parse_ac_parameters(self, kwargs):
        if kwargs['ac_ip'] in HM_AC:
            kwargs['vlan'] = self.get_argument('vlan')
            kwargs['ssid'] = self.get_argument('ssid')
            # 
            kwargs['user_ip'] = self.get_argument('wlanuserip')
            kwargs['user_mac'] = self.get_argument('wlanstamac').replace('.', ':').upper()

            # kwargs['apname'] = self.get_argument('apname')
            kwargs['ap_mac'] = self.get_argument('wlanapmac').replace('.', ':').upper()
        elif kwargs['ac_ip'] in RJ_AC:
            kwargs['vlan'] = self.get_argument('vlan', '1')
            kwargs['ssid'] = self.get_argument('ssid')

            kwargs['user_ip'] = self.get_argument('wlanuserip')
            kwargs['ap_mac'] = self.get_argument('wlanapmac', '')
            mac = self.get_argument('mac').upper()
            kwargs['user_mac'] = ':'.join([mac[:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:12]])
        else:
            raise HTTPError(400, reason='Unknown AC: {}'.format(kwargs['ac_ip']))
    
    def login_auto_by_mac(self, **kwargs):
        user = self.get_user_by_mac(kwargs['user_mac'])
        if not user:
            return False

        _user = store.get_bd_user(user)
        if not _user:
            return False
        # check billing
        self.expired, self.rejected = False, False
        self._check_account(_user)
        if self.rejected:
            # raise HTTPError(403, reason='Account has no left time')
            return False
        onlines = store.count_online(_user['user'])
        if onlines >= _user['ends']:
            # allow user logout ends 
            return False
            # raise HTTPError(403, reason='Over the limit ends')
        try:
            logger.info('Progress {} (mac: {}) auto login'.format(user, kwargs['user_mac']))
            self.login(_user, kwargs['ac_ip'], socket.inet_aton(kwargs['user_ip']), kwargs['user_mac'])
        except:
            logger.warning('auto login error', exc_info=True)
            return False

        return True

    def login_auto_by_cookie(self, p_user, p_expire, **kwargs):
        now = utility.now('%Y-%m-%d')
        if now >= p_expire:
            # cookie expired
            return False
        _user = store.get_bd_user(p_user)
        if not _user:
            return False
        # check billing
        self.expired, self.rejected = False, False
        self._check_account(_user)
        if self.rejected:
            # raise HTTPError(403, reason='Account has no left time')
            return False
        onlines = store.count_online(_user['user'])
        if onlines >= _user['ends']:
            # allow user logout ends 
            return False
            # raise HTTPError(403, reason='Over the limit ends')
        try:
            logger.info('Progress {} auto login'.format(p_user))
            self.login(_user, kwargs['ac_ip'], socket.inet_aton(kwargs['user_ip']), kwargs['user_mac'])
        except:
            logger.warning('auto login error', exc_info=True)
            return False

        return True


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
        header = Header(0x01, 0x01, 0x00, 0x00, PortalHandler._SERIAL_NO_.pop(), 
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
            raise HTTPError(400, reason='challenge timeout, retry')
            # return self.render_error(Code=400, Msg='challenge timeout, retry')

        header = Header.unpack(data)
        if header.type != 0x02 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            raise HTTPError(400, reason='challenge error')
            # return self.render_json_response(Code=400, Msg='challenge error')
        # parse challenge value
        attrs = Attributes.unpack(header.num, data[16:])
        if not attrs.challenge:
            logger.warning('Abnormal challenge value, 0x%x, 0x%x', header.err, header.num)
            sock.close()
            raise HTTPError(400, reason='abnormal challenge value')
            # return self.render_error(Code=400, Msg='abnormal challenge value')
        assert user_mac == attrs.mac

        header.type = 0x03
        # header.serial = PortalHandler._SERIAL_NO_.pop()
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

        time.sleep(1.5)

        token = utility.token(user)
        # self.render_json_response(User=user, Token=token, Code=200, Msg='OK')
        self.redirect('http://www.bidongwifi.com/account/{}?token={}'.format(user, token))
        logger.info('%s login successfully, wlan: %s', user, self.request.remote_ip)


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
        _user = store.get_user(openid)
        if not _user:
            # create new account
            store.add_user(openid, utility.generate_password())
            _user = store.get_user(openid)
            if not _user:
                raise HTTPError(400, reason='Should subscribe first')
        # user unsubscribe, the account will be forbid
        if _user['mask']>>31 & 1:
            raise HTTPError(401, reason='Account has been frozen')
        _user = store.get_bd_user(_user['id'])
        user = _user['user']
        password = _user['password']
            
        # check ac ip
        if kwargs['ac_ip'] not in BAS_IP:
            logger.error('not avaiable ac & ap')
            raise HTTPError(403, reason='AC ip error')

        # check account & password
        if not _user:
            _user = store.get_bd_user(user)
        if not _user:
            raise HTTPError(404, reason='Account not existed')
        if password != _user['password']:
            raise HTTPError(401, reason='Password error')

        # check billing
        self.expired, self.rejected = False, False
        self._check_account(_user)
        if self.rejected:
            raise HTTPError(403, reason='Account has no left time')

        onlines = store.count_online(_user['user'])
        if onlines >= _user['ends']:
            # allow user logout ends 
            raise HTTPError(403, reason='Over the limit ends')

        self.login(_user, kwargs['ac_ip'], socket.inet_aton(kwargs['user_ip']), kwargs['user_mac'])

    def timeout(self, sock, ac_ip, header, user_mac):
        '''
        '''
        logger.info('ip: %s timeout', self.request.remote_ip)
        header.type = 0x05
        header.err = 0x01
        packet = Packet(header, Attributes(mac=user_mac))
        sock.sendto(packet.pack(), (ac_ip, BAS_PORT))

    def _calculate_left_time(self, _user):
        date, time = _user['expire_date'], '00:00'
        if _user['expire_date']:
            now = datetime.datetime.now()
            _expire_datetime = datetime.datetime.strptime(_user['expire_date'] + ' 23:59:59', 
                                                          '%Y-%m-%d %H:%M:%S')
            if now > _expire_datetime:
                date = ''

        if _user['coin']>0:
            times = _user['coin']*3*60
            time = '{:02d}:{:02d}'.format(int(times/3600), int(times%3600/60))

        _user['left_time'] = ' + '.join([date, time])

    def _check_expire_date(self, _user):
        '''
        '''
        if not _user['expire_date']:
            return True
        now = datetime.datetime.now()
        _expire_datetime = datetime.datetime.strptime(_user['expire_date'], '%Y-%m-%d')
        if now > _expire_datetime:
            return True
        return False

    def _check_left_time(self, _user):
        return _user['coin'] <= 0

    def _check_account(self, _user):
        '''
            bd_account
        '''
        # if (_user['mask']>>8 & 1):
        self.expired = self._check_expire_date(_user)
        if self.expired:
            self.rejected = self._check_left_time(_user)

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
    def get(self):
        '''
        '''  
        pass

    @_trace_wrapper
    @_parse_body
    def put(self):
        openid = self.get_argument('openid', None)
        user = self.get_argument('user', '')
        password = self.get_argument('password', '')
        _user = None
        pass

    @_trace_wrapper
    @_parse_body
    def post(self):
        # parse request data
        openid = self.get_argument('openid', None)
        user = self.get_argument('user', '')
        password = self.get_argument('password', '')
        _user = None
        if openid:
            # weixin client
            _user = store.get_user(openid)
            if not _user:
                # create new account
                raise HTTPError(404, reason='Can\'t found account')
            else:
                # user unsubscribe, the account will be forbid
                if _user['mask']>>31 & 1:
                    raise HTTPError(403, reason='No privilege')
                _user = store.get_bd_user(_user['id'])
                user = _user['user']
                password = _user['password']
        # check account left, forbin un-meaning request to ac
        ac_ip = self.get_argument('ac_ip')
        # check ac ip
        if ac_ip not in BAS_IP:
            logger.error('not avaiable ac & ap')
            raise HTTPError(403, reason='AC ip error')

        # ap_mac = self.get_argument('ap_mac')
        # check account & password
        if len(user) == 4:
            # room number
            holder = self.get_holder(self.get_argument('ap_mac'))
            user = str(holder) + user
        _user = store.get_bd_user(user, password)
        if not _user:
            raise HTTPError(401, reason='Please check your input account or password')
        if password != _user['password']:
            raise HTTPError(401, reason='Password error')

        # check account status & account ends number on networt
        if _user['mask']>>30 & 1:
            raise HTTPError(403, reason='Account has been frozened')
        onlines = store.count_online(_user['user'])
        if onlines >= _user['ends']:
            # allow user logout ends 
            raise HTTPError(403, reason='Over the limit ends')

        self.user = _user

        # check billing
        self.expired, self.rejected = False, False
        self._check_account(self.user)
        if self.rejected:
            raise HTTPError(403, reason='Account has no left time')

        ap_mac = self.get_argument('ap_mac')
        user_mac = self.get_argument('user_mac')
        user_ip = self.get_argument('user_ip')
        # vlanId = self.get_argument('vlan')
        # ssid = self.get_argument('ssid')

        user_ip = socket.inet_aton(user_ip)
        # send challenge to ac
        flags = int(self.get_argument('flags', LOGIN))
        flags = LOGIN
        if flags == LOGIN:
            # portal-radius server doesn't check password, so send a 
            # no-meaning value
            self.login(ac_ip, user_ip, user_mac)
            # update mac address
            self.update_mac_record(self.user, user_mac)
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
        header = Header(0x01, 0x01, 0x00, 0x00, PortalHandler._SERIAL_NO_.pop(), 
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
            raise HTTPError(400, reason='challenge timeout, retry')
            # return self.render_json_response(Code=400, Msg='challenge timeout, retry')

        header = Header.unpack(data)
        if header.type != 0x02 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            raise HTTPError(400, reason='challenge timeout, retry')
            # return self.render_json_response(Code=400, Msg='challenge error')
        # parse challenge value
        attrs = Attributes.unpack(header.num, data[16:])
        if not attrs.challenge:
            logger.warning('Abnormal challenge value, 0x%x, 0x%x', header.err, header.num)
            sock.close()
            raise HTTPError(400, reason='abnormal challenge value')
            # return self.render_json_response(Code=400, Msg='abnormal challenge value')
        if attrs.mac:
            assert user_mac == attrs.mac

        header.type = 0x03
        # header.serial = PortalHandler._SERIAL_NO_.pop()
        # chap_password = utility.md5(data[8], password, attrs.challenge).digest()
        # attrs = Attributes(user=user, chap_password=chap_password)
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
            raise HTTPError(408, reason='auth timeout, retry')
            # return self.render_json_response(Code=408, Msg='auth timeout, retry')
        header = Header.unpack(data)
        if header.type != 0x04 or header.err:
            logger.info('0x%x error, errno: 0x%x', header.type, header.err)
            sock.close()
            attrs = Attributes.unpack(header.num, data[16:])
            raise HTTPError(403, reason='auth error')
        # self.finish('auth successfully')
        # generate token

        # if self.user['mask'] | 1<<3:
        #     # self._calculate_left_time(self.user)
        #     print('http://www.bidongwifi.com/account/{}?token={}'.format(user, token))
        #     self.redirect('http://www.bidongwifi.com/account/{}?token={}'.format(user, token))
        #     # self.render('account.html', token=token, **self.user)
        # else:
        #     url = self.get_argument('firsturl', '')
        #     if url:
        #         if self.expired:
        #             # prompt account renewal
        #             pass
        #         self.set_header('Access-Control-Allow-Origin', '*')
        #         urlparam = self.get_argument('urlparam', '')
        #         if urlparam:
        #             url = url + '?' + urlparam
        #         self.redirect(url)
        #     else:
        #         token = utility.token(user)
        #         self.render_json_response(Code=200, Msg='auth successfully', 
        #                                   # ac_ip=ac_ip, user_mac=mac_addr, 
        #                               Account=self.user, Token=token, Expired=self.expired)

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
        self.render_json_response(User=user, Token=token, Code=200, Msg='OK')
        # self.redirect('http://www.bidongwifi.com/account/{}?token={}'.format(user, token))
        logger.info('%s login successfully, ip: %s', user, self.request.remote_ip)

    def logout(self, ac_ip, user_ip, user_mac):
        '''
        '''
        user = self.user['user']
        logger.info('progress %s logout, ip: %s', user, self.request.remote_ip)
        header = Header(0x01, 0x05, 0x00, 0x00, PortalHandler._SERIAL_NO_.pop(), 
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

    def get_holder(self, ap_mac):
        '''
            query holder id by ap_mac
        '''
        return store.get_holder_by_mac(ap_mac)

    def _calculate_left_time(self, _user):
        date, time = self.user['expire_date'], '00:00'
        # if (_user['mask']>>8 & 1) and date:
        #     now = datetime.datetime.now()
        #     _expire_datetime = datetime.datetime.strptime(_user['expire_date'] + ' 23:59:59', 
        #                                                   '%Y-%m-%d %H:%M:%S')
        #     if now > _expire_datetime:
        #         date = ''
        # if _user['mask']>>9 & 1:
        #     if _user['time_length']:
        #         left = int(_user['time_length'])
        #         time = '{:02d}:{:02d}:{:02d}'.format(int(left/3600),
        #                                              int(left/60),
        #                                              int(left%60))
        if _user['expire_date']:
            now = datetime.datetime.now()
            _expire_datetime = datetime.datetime.strptime(_user['expire_date'] + ' 23:59:59', 
                                                          '%Y-%m-%d %H:%M:%S')
            if now > _expire_datetime:
                date = ''

        if _user['coin']>0:
            times = _user['coin']*3*60
            time = '{:02d}:{:02d}'.format(int(times/3600), int(times%3600/60))

        _user['left_time'] = ' + '.join([date, time])

    def _check_expire_date(self, _user): 

        '''
        '''
        if not _user['expire_date']:
            return True
        now = datetime.datetime.now()
        _expire_datetime = datetime.datetime.strptime(_user['expire_date'], '%Y-%m-%d')
        if now > _expire_datetime:
            return True
        return False

    def _check_left_time(self, _user):
        return _user['coin'] <= 0

    def _check_account(self, _user):
        '''
            bd_account
        '''
        # if (_user['mask']>>8 & 1):
        self.expired = self._check_expire_date(_user)
        if self.expired:
            self.rejected = self._check_left_time(_user)

    def update_mac_record(self, user, mac):
        agent_str = self.request.headers.get('User-Agent', '')
        records = store.get_mac_records(user['user'])
        m_records = {record['mac']:record for record in records}
        logger.info(records, m_records, mac)
        if mac not in m_records:
            # update mac record 
            if (not records) or len(records) < user['ends']:
                store.update_mac_record(user['user'], mac, '', agent_str, False)
            else:
                # records = sorted(records.values(), key=lambda item: item['datetime'])
                store.update_mac_record(user['user'], mac, records[0]['mac'], agent_str, True)

    def set_login_cookie(self, user, days=7):
        '''
        '''
        self.set_secure_cookie('p_user', user, expires_days=7)
        expire_date = utility.now('%Y-%m-%d', days=days)
        self.set_secure_cookie('p_expire', expire_date, expires_days=7)
        
class Packet():
    '''
    '''
    def __init__(self, header, attrs=None):
        self.header = header
        self.attrs = attrs

    def pack(self):
        '''
            return binary bytes
        '''
        num, data = 0, b''
        if self.attrs:
            num, data = self.attrs.pack()
        self.header.num = num
        return self.header.pack() + data

    def md5(self):
        pass

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
        while num:
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

    def pack(self):
        '''
            return binary data in big-endiani[>]
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
        family = socket.AFINET
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
            attrs = Attributes.unpack(header.num, data[16:])
            if not attrs.mac:
                logger.info('Mac address abnormal from {}'.format(addr))
                return
            #
            mac = []
            for b in attrs.mac:
                mac.append('{:X}'.format(ord(b)))
            print(':'.join(mac))

def init_log(log_folder, log_config):
    global logger
    import logging
    import logging.config
    log_config['handlers']['file']['filename'] = os.path.join(log_folder, 
                                                              log_config['handlers']['file']['filename'])
    logging.config.dictConfig(log_config)
    logger = logging.getLogger()
    logger.propagate = False

def main():
    tornado.options.parse_command_line()

    init_log(config['log_folder'], config['logging_config'])

    portal_pid = portal_config['portal_pid']
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
