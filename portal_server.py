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
from tornado.log import access_log, gen_log, app_log
# from tornado.concurrent import Future

from tornado.options import define, options

define('port', default=8880, help='running on the given port', type=int)
define('index', default=0, help='portal start index, used for serial number range', type=int)
define('total', default=1, help='portal server total number , used for serial number range', type=int)

# log configuration
define('log_file_prefix', type=str, default='/var/log/radiusd/portal_8880.log')
define('log_rotate_mode', type=str, default='time', help='time or size')

import errno
import os
import sys

import time

import socket
import collections
import functools
import copy

from urlparse import parse_qs

# import xml.etree.ElementTree as ET

# Mako template
import mako.lookup
import mako.template

import utility
# import settings
import config
import user_agents

import account

from task import portal 

from bd_err import bd_errs

portal_config = config['portal_config']

json_encoder = utility.json_encoder
json_decoder = utility.json_decoder

_PORTAL_VERSION = 0x01
RUN_PATH = '/var/run'

_REQUESTES_ = {}

AC_CONFIGURE = config['ac_policy']

BAS_PORT = 2000
_BUFSIZE=1024

PORTAL_PORT = 50100

LOGIN = 0
LOGOUT = 1

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))
STATIC_PATH = '/www/bidong'
TEMPLATE_PATH = '/www/portal'
MOBILE_TEMPLATE_PATH = os.path.join(TEMPLATE_PATH, 'm')

PN_PROFILE = collections.defaultdict(dict)
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
            (r'/test$', TestHandler),
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
                                         module_directory='/tmp/mako/portal',
                                         output_encoding='utf-8',
                                         input_encoding='utf-8',
                                         encoding_errors='replace')
    LOOK_UP_MOBILE = mako.lookup.TemplateLookup(directories=[MOBILE_TEMPLATE_PATH, ], 
                                                module_directory='/tmp/mako_mobile/portal',
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
            access_log.error('Render {} failed, {}:{}'.format(filename, tb.error.__class__.__name__, tb.error), 
                         exc_info=True)
            raise HTTPError(500, 'Render page failed')

    def render(self, filename, **kwargs):
        '''
            Render the template with the given arguments
        '''
        directory = TEMPLATE_PATH
        if self.is_mobile:
            directory = MOBILE_TEMPLATE_PATH

        if not os.path.exists(os.path.join(directory, filename)):
            raise HTTPError(404, 'File Not Found')

        self.finish(self.render_string(filename, **kwargs))

    def _get_argument(self, name, default, source, strip=True):
        args = self._get_arguments(name, source, strip=strip)
        if not args:
            if default is self._ARG_DEFAULT:
                raise tornado.web.MissingArgumentError(name)
            return default
        return args[0]

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
            if status_code in (427,):
                self.render_json_response(Code=status_code, Msg=self._reason, pn=self.profile['pn'])
            else:
                self.render_json_response(Code=status_code, Msg=self._reason)

    def _handle_request_exception(self, e):
        if isinstance(e, tornado.web.Finish):
            # not an error; just finish the request without loggin.
            if not self._finished:
                self.finish(*e.args)
            return
        try:
            self.log_exception(*sys.exc_info())
        except Exception:
            access_log.error('Error in exception logger', exc_info=True)

        if self._finished:
            return 
        if isinstance(e, HTTPError):
            if e.status_code not in BaseHandler.RESPONSES and not e.reason:
                tornado.gen_log.error('Bad HTTP status code: %d', e.status_code)
                self.send_error(500, exc_info=sys.exc_info())
            else:
                self.send_error(e.status_code, exc_info=sys.exc_info())
        else:
            self.send_error(500, exc_info=sys.exc_info())

    def log_exception(self, typ, value, tb):
        if isinstance(value, HTTPError):
            if value.log_message:
                format = '%d %s: ' + value.log_message
                args = ([value.status_code, self._request_summary()] + list(value.args))
                access_log.warning(format, *args)

        access_log.error('Exception: %s\n%r', self._request_summary(), 
                     self.request, exc_info=(typ, value, tb))
    

    def render_exception(self, ex):
        self.set_status(ex.status_code)
        self.render('error.html', Code=ex.status_code, Msg=ex.reason)

    def render_json_response(self, **kwargs):
        '''
            Encode dict and return response to client
        '''
        callback = self.get_argument('callback', None)
        if callback:
            # return jsonp
            self.set_status(200, kwargs.get('Msg', None))
            self.finish('{}({})'.format(callback, json_encoder(kwargs)))
        else:
            self.set_status(kwargs['Code'], kwargs.get('Msg', None))
            self.set_header('Content-Type', 'application/json;charset=utf-8')
            self.finish(json_encoder(kwargs))

    def prepare(self):
        '''
            check client paltform
        '''
        self.agent_str = self.request.headers.get('User-Agent', '')
        self.agent = None
        self.is_mobile = False
        self.task_resp = None
        
        # check app & os info 
        self.check_app()
        
        if self.agent_str:
            try:
                self.agent = user_agents.parse(self.agent_str)
                self.is_mobile = self.agent.is_mobile
            except UnicodeDecodeError:
                access_log.warning('Unicode decode error, agent str: {}'.format(self.agent_str))
                # assume user platfrom is mobile
                self.is_mobile = True

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
            data = data[:-2] + '_2'
        elif data[-1] == '=':
            data = data[:-1] + '_1'
        else:
            data = data + '_0'
        return data

    def b64decode(self, data):
        '''
            decode data to dict
            data : bdata_number
        '''
        bdata, nums = data.split('_')
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
            # logger.info('arguments: {}'.format(arguments))
            for name, values in arguments.iteritems():
                if isinstance(values, basestring):
                    values = [values, ]
                elif isinstance(values, int):
                    values = [str(values), ]
                elif isinstance(values, float):
                    values = [str(values), ]
                elif values:
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
                        access_log.warning('Invalid multipart/form-data')
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
            access_log.info('<-- In %s: <%s> -->', self.__class__.__name__, self.request.method)
            return method(self, *args, **kwargs)
        except HTTPError as ex:
            access_log.error('HTTPError catch', exc_info=True)
            raise
        except KeyError as ex:
            if self.application.settings.get('debug', False):
                print(self.request)
            access_log.error('Arguments error', exc_info=True)
            raise HTTPError(400)
        except ValueError as ex:
            if self.application.settings.get('debug', False):
                print(self.request)
            access_log.error('Arguments value abnormal', exc_info=True)
            raise HTTPError(400)
        except Exception:
            # Only catch normal exceptions
            # exclude SystemExit, KeyboardInterrupt, GeneratorExit
            access_log.error('Unknow error', exc_info=True)
            raise HTTPError(500)
        finally:
            access_log.info('<-- Out %s: <%s> -->\n\n', self.__class__.__name__, self.request.method)
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

class TestHandler(BaseHandler):
    '''
    '''
    # def get(self):
    #     self.render_json_response(Code=200, Msg='OK')
    @tornado.gen.coroutine
    def get(self):
        response = yield tornado.gen.Task(portal.sleep.apply_async, args=[3,])
        # response = portal.sleep.apply_async(args=[3,])
        # self.response = None
        # result = self.test()
        # if result is not None:
        #     result = yield result

        # response = self.response

        self.write(str(response.result))
        self.finish()
        # print(dir(response))
        # print(response.status)
        # for item in dir(response):
        #     if item.startswith('_'):
        #         continue 
        #     if item in ('forget', 'get', 'get_leaf'):
        #         continue

        #     value = getattr(response, item)
        #     if callable(value):
        #         print('key:{}, value1:{}'.format(item, value()))
        #     else:
        #         print('key:{}, value2:{}'.format(item, value))

    # @tornado.gen.coroutine
    # def test(self):
    #     response = yield tornado.gen.Task(portal.sleep.apply_async, args=[3,])
    #     self.response =  response

class PageHandler(BaseHandler):
    '''
    '''
    _WX_IP = 'api.weixin.qq.com'

    def redirect_to_bidong(self):
        '''
        '''
        access_log.info('redirect : {}'.format(self.request.arguments))
        self.redirect(config['bidong'])
        self.finish()

    def prepare_wx_wifi(self, **kwargs):
        wx_wifi = {}
        wx_wifi['extend'] = self.b64encode(appid=self.profile['appid'], shopid=self.profile['shopid'], **kwargs)
        wx_wifi['timestamp'] = str(int(time.time()*1000))
        # portal_server = '{}://{}:{}/wx_auth'.format(self.request.protocol, 
        #                                             self.request.headers.get('Host'), 
        #                                             self.request.headers.get('Port'))
        portal_server = 'http://{}:9898/wx_auth'.format(self.request.headers.get('Host'))
        
        # wx_wifi['auth_url'] = tornado.escape.url_escape(portal_server)
        wx_wifi['auth_url'] = portal_server
        wx_wifi['sign'] = self.calc_sign(self.profile['appid'], wx_wifi['extend'], wx_wifi['timestamp'], 
                                         self.profile['shopid'], wx_wifi['auth_url'], 
                                         kwargs['user_mac'], self.profile['ssid'], kwargs['ap_mac'], 
                                         self.profile['secret'])

        self.wx_wifi = wx_wifi

    def parse_url_arguments(self, url):
        '''
        '''
        arguments = {}
        if url.find('?') != -1:
            url, params = url.split('?')
            items = params.split('&')

            for item in items:
                key, value = item.split('=')
                arguments[key] = value

        return arguments

    @_parse_body
    @tornado.gen.coroutine
    def get(self, page):
        '''
            Render html page
        '''
        # logger.info(self.request)
        page = page.lower()

        if page in ('nagivation.html', 'niot.html'):
            self.render(page)
            return

        if page not in ('login.html'):
            self.redirect_to_bidong()
            return
            # return self.redirect('http://58.241.41.148/index.html')

        kwargs = {}
        accept = self.request.headers.get('Accept', 'text/html')

        kwargs['ac_ip'] = self.get_argument('wlanacip', '') or self.get_argument('nasip', '') or self.get_argument('wip', '')
        if not kwargs['ac_ip']:
            access_log.error('can\'t found ac parameter, please check ac url configuration')
            # doesn't contain ac_ip parameter, return redirect response
            # if user hasn't auth, ac will redirect the next request
            # with necessary parameters
            # return self.redirect('http://10.10.1.175:8080/index.html')
            self.redirect_to_bidong()
            return

        self.parse_ac_parameters(kwargs)

        url = kwargs['firsturl']
        
        self.profile = account.get_billing_policy(kwargs['ac_ip'], kwargs['ap_mac'], kwargs['ssid'])

        # process weixin argument
        self.prepare_wx_wifi(**kwargs)

        result = yield self.login_auto_by_mac(**kwargs)

        if self.task_resp is None:
            pass
        else:
            _user, self.task_resp = self.task_resp.result, None
            if _user:
                if accept.startswith('application/json'):
                    token = utility.token(self.user['user'])
                    self.render_json_response(User=self.user['user'], Token=token, Mask=self.user['mask'], 
                                              Code=200, Msg='OK')
                elif url:
                    # self.set_header('Access-Control-Allow-Origin', '*')
                    if self.profile['pn'] in (55532, ):
                        self.redirect(self.profile['portal'])
                        return
                    if kwargs['urlparam']:
                        url = ''.join([url, '?', kwargs['urlparam']])
                    self.redirect(url)
                return 

        if 'wx/m_bidong/onetonet' in url:
            # user from weixin, parse code & and get openid

            # check agent
            # agent_str = self.request.headers.get('User-Agent', '')
            if 'MicroMessenger' not in self.agent_str:
                self.render_exception(HTTPError(400, 'Abnormal agent'))
                return

            try:
                response = yield self.wx_login(**kwargs)
            except:
                access_log.error('weixin login failed', exc_info=True)

            if self.task_resp:
                response, self.task_resp = self.task_resp, None
                if response.status in ('SUCCESS', ):
                    _user = response.result
                elif isinstance(response.result, HTTPError) and response.result.status_code in (435,):
                    _user = self.user
                else:
                    access_log.info('weixin auth failed, {}'.format(response.result))
                    _user = None

                if _user:
                    # login successfully
                    # redirect to account page
                    _user = response.result
                    token = utility.token(_user['user'])
                    self.redirect(config['bidong'] + 'account/{}?token={}'.format(_user['user'], token))

                    account.update_mac_record(_user, kwargs['user_mac'], self.agent_str)

        # get policy
        kwargs['user'] = ''
        kwargs['password'] = ''

        access_log.info('profile: {}'.format(self.profile))
        
        pn_ssid, pn_note, pn_logo = self.profile['ssid'], self.profile['note'], self.profile['logo']

        if accept.startswith('application/json'):
            self.render_json_response(Code=200, Msg='OK', openid='', pn_ssid=pn_ssid, 
                                      pn_note=pn_note, pn_logo=pn_logo,  
                                      ispri=self.profile['ispri'], pn=self.profile['pn'], 
                                      note=self.profile['note'], image=self.profile['logo'], 
                                      logo=self.profile['logo'],
                                      **kwargs)
            return
                    

        # now all page user login, later after update back to use self.profile['portal']  
        page = self.profile['portal'] or 'login.html'

        self.render(page, openid='', ispri=self.profile['ispri'], 
        # return self.render('login.html', openid='', ispri=self.profile['ispri'], 
                    pn=self.profile['pn'], note=self.profile['note'], image=self.profile['logo'], 
                    appid=self.profile['appid'], shopid=self.profile['shopid'], secret=self.profile['secret'], 
                    logo=self.profile['logo'],
                    extend=self.wx_wifi['extend'], timestamp=self.wx_wifi['timestamp'], 
                    sign=self.wx_wifi['sign'], authUrl=self.wx_wifi['auth_url'], 
                    **kwargs)


    def parse_ac_parameters(self, kwargs):
        '''
        '''
        if kwargs['ac_ip'] not in AC_CONFIGURE:
            raise HTTPError(400, reason='Unknown AC: {}'.format(kwargs['ac_ip']))

        if not AC_CONFIGURE[kwargs['ac_ip']]['mask']: 
            kwargs['vlan'] = self.get_argument('vlan', 1)
            kwargs['ssid'] = self.get_argument('ssid', 'NS_GOV')
            kwargs['user_ip'] = self.get_argument('wlanuserip', '') or self.get_argument('userip', '')

            # user mac address 
            mac = self.get_argument('mac', '') or self.get_argument('wlanstamac', '') 
            if not mac:
                raise HTTPError(400, 'mac address can\'t be none')
            kwargs['user_mac'] = utility.format_mac(mac)

            # ap mac address
            # 00:00:00:00:00:00 - can't get ap mac address
            ap_mac = self.get_argument('apmac', '') or self.get_argument('wlanapmac', '00:00:00:00:00:01')
            kwargs['ap_mac'] = utility.format_mac(ap_mac)

            try:
                kwargs['firsturl'] = self.get_argument('wlanuserfirsturl', '') or self.get_argument('url', '') or self.get_argument('userurl', '')
                kwargs['urlparam'] = self.get_argument('urlparam', '')
            except:
                kwargs['firsturl'] = config['bidong']
                # kwargs['firsturl'] = 'http://wwww.bidongwifi.com/'
                kwargs['urlparam'] = ''
        else:
            # bas mask == 1
            kwargs['vlan'] = ''
            kwargs['ssid'] = 'BD_TEST'
            kwargs['user_ip'] = self.get_argument('userip')
            mac = self.get_argument('MAC')
            kwargs['user_mac'] = utility.format_mac(mac)
            kwargs['ap_mac'] = ''

            kwargs['firsturl'] = config['bidong']
            kwargs['urlparam'] = ''

    @tornado.gen.coroutine
    def login_auto_by_mac(self, **kwargs):
        if self.profile['pn'] == 10000:
            # 10000 (test) owner, skip auto login check
            return

        if self.profile['pn'] in (55532, ):
            # all user use holder's account
            _user = {'user':'55532', 'password':'987012', 'mask':10, 'coin':60, 'ends':100}
            self.user = _user
        else:
            user = account.get_user_by_mac(kwargs['user_mac'], kwargs['ac_ip'])
            if not user:
                return

            _user = account.get_bd_user(user)
            if not _user:
                return

            self.user = _user

            # check private network
            if self.profile['ispri']:
                # current network is private, check user privilege
                ret, err = account.check_pn_privilege(self.profile['pn'], _user['user'])
                if not ret:
                    return

            if not self.profile['policy']:
                if _user['mask']>>30 & 1:
                    # raise HTTPError(403, reason='Account has been frozened')
                    return
                # ipolicy =0, check billing
                self.expired = account.check_account_balance(_user)
                if self.expired:
                    # raise HTTPError(403, reason='Account has no left time')
                    return
            
            onlines = account.get_onlines(_user['user'])
            if kwargs['user_mac'] not in onlines and len(onlines) >= _user['ends']:
                # allow user logout ends 
                return
                # raise HTTPError(403, reason='Over the limit ends')

        response = yield tornado.gen.Task(portal.login.apply_async, 
                                          args=[_user, kwargs['ac_ip'], 
                                          kwargs['user_ip'], kwargs['user_mac']])

        if response.status in ('SUCCESS', ):
            access_log.info('{} auto login successfully, mac:{}'.format(_user['user'], kwargs['user_mac']))
        elif isinstance(response.result, HTTPError) and response.result.status_code in (435,):
            access_log.info('{} has been authed, mac:{}'.format(_user['user'], kwargs['user_mac']))
        else:
            access_log.info('{}auto login failed, {}'.format(_user['user'], response.result))
            return

        self.task_resp = response
        
    def get_openid(self, code):
        URL = 'https://{}/sns/oauth2/access_token?appid={}&secret={}&code={}&grant_type=authorization_code'
        url = URL.format(self._WX_IP, config['weixin']['appid'], config['weixin']['secret'], code)
        client = tornado.httpclient.HTTPClient()
        response = client.fetch(url)
        result = json_decoder(response.body)
        if 'openid' not in result:
            access_log.error('Get weixin account\'s openid failed, msg: {}'.format(result))
            raise HTTPError(500)

        return result['openid']

    @tornado.gen.coroutine
    def wx_login(self, **kwargs):
        if kwargs['urlparam']:
            urlparam = parse_qs('urlparam='+kwargs['urlparam'])
            params = parse_qs(urlparam['urlparam'][0])
            code = params['code'][0]
        else:
            code = self.parse_url_arguments(kwargs['firsturl'])['code'] 

        URL = 'https://{}/sns/oauth2/access_token?appid={}&secret={}&code={}&grant_type=authorization_code'
        url = URL.format(self._WX_IP, config['weixin']['appid'], config['weixin']['secret'], code)
        client = tornado.httpclient.AsyncHTTPClient()
        response = yield client.fetch(url)

        if response.error:
            raise response

        result = json_decoder(response.body)
        if 'openid' not in result:
            access_log.error('Get weixin account\'s openid failed, msg: {}'.format(result))
            raise HTTPError(500)

        openid =  result['openid']

        access_log.info('openid: {} login by weixin'.format(openid))
        user, password = '', ''
        _user = account.get_user(openid, column='weixin', appid=self.profile['appid'])
        if not _user:
            # create new account
            _user = account.create_user(openid, appid=self.profile['appid'])
        if not _user:
            raise HTTPError(400, reason='Should subscribe first')
        # user unsubscribe, the account will be forbid
        if _user['mask']>>31 & 1:
            raise HTTPError(401, reason='Account has been frozen')
            
        # check ac ip
        if kwargs['ac_ip'] not in AC_CONFIGURE:
            access_log.error('not avaiable ac & ap')
            raise HTTPError(403, reason='Unknown AC,ip : {}'.format(kwargs['ac_ip']))

        if self.profile['ispri']:
            # current network is private, check user privilege
            ret, err = account.check_pn_privilege(self.profile['pn'], _user['user'])
            if not ret:
                raise err

        if not self.profile['policy']:
            # ipolicy =0, check billing
            self.expired = account.check_account_balance(_user)
            if self.expired:
                raise HTTPError(403, reason='Account has no left time')

        response = yield tornado.gen.Task(portal.login.apply_async, 
                                          args=[_user, kwargs['ac_ip'], 
                                                kwargs['user_ip'], kwargs['user_mac']])

        if response.status in ('SUCCESS', ):
            access_log.info('{} weixin login successfully, mac:{}'.format(_user['user'], kwargs['user_mac']))
        elif isinstance(response.result, HTTPError) and response.result.status_code in (435,):
            access_log.info('{} has been authed, mac:{}'.format(_user['user'], kwargs['user_mac']))
        else:
            access_log.info('{}auto login failed, {}'.format(_user['user'], response.result))
            return

        self.task_resp = response


    def timeout(self, sock, ac_ip, header, user_mac):
        '''
        '''
        access_log.info('ip: %s timeout', self.request.remote_ip)
        portal.timeout(sock, ac_ip, header, user_mac)

    def calc_sign(self, *args):
        '''
            sign = md5(appid, extend,timestamp, shop_id, authUrl, 
                       mac, ssid, bssid, secretkey) 
        '''
        data = ''.join(args)
        return utility.md5(data).hexdigest()

class GatewayHandler(BaseHandler):
    def get(self, path):
        kwargs = {} 
        kwargs['user_ip'] = self.get_argument('wlanuserip', '') or self.get_argument('userip', '')

        self.render(path, **kwargs)

class PortalHandler(BaseHandler):
    '''
        Handler portal auth request
    '''
    def prepare(self):
        super(PortalHandler, self).prepare()
        self.is_weixin = False

    # @_trace_wrapper
    @_parse_body
    @tornado.gen.coroutine
    def get(self):
        tid = self.get_argument('tid')
        # timestamp = self.get_argument('timestamp')
        # sign = self.get_argument('sign')
        openid = self.get_argument('openId')
        extend = self.get_argument('extend')

        access_log.info('openid:{}, tid: {}'.format(openid, tid))

        kwargs = self.b64decode(extend)
        user, password = '',''
        _user = account.get_user(openid, column='weixin', appid=kwargs['appid']) 
        if not _user:
            # create new account
            _user = account.add_user(openid, appid=kwargs['appid'], tid=tid)
        if not _user:
            raise HTTPError(400, reason='Should subscribe first')
        
        self.user = _user

        # check account left, forbin un-meaning request to ac
        ac_ip = kwargs['ac_ip']
        # check ac ip
        if ac_ip not in AC_CONFIGURE:
            access_log.error('not avaiable ac & ap')
            raise HTTPError(403, reason='AC ip error')

        ap_mac = kwargs['ap_mac']
        user_mac = kwargs['user_mac']
        user_ip = kwargs['user_ip']

        # vlanId = self.get_argument('vlan')
        ssid = kwargs['ssid']
        self.profile = account.get_billing_policy(ac_ip, ap_mac, ssid)

        # check private network
        if self.profile['ispri']:
            ret, err = account.check_pn_privilege(self.profile['pn'], _user['user'])
            if not ret:
                raise err
        
        # check billing
        if not self.profile['policy']:
            self.expired = account.check_account_balance(self.user)
            if self.expired:
                # raise HTTPError(403, reason='Account has no left time')
                access_log.info('{} has no left time'.format(self.user['user']))
                raise HTTPError(403, reason=bd_errs[450])

        response = yield tornado.gen.Task(portal.login.apply_async, args=[self.user,  ac_ip, user_ip, user_mac])

        if response.successful():
            # login successfully 
            account.update_mac_record(self.user['user'], user_mac, self.agent_str)
        else:
            if isinstance(response.result, HTTPError) and response.result.status_code in (435, ):
                # has been authed
                pass
            else:
                access_log.error('Auth failed, {}'.format(response.traceback))
                raise response.result
        
        token = utility.token(self.user['user'])
        
        if 'WeChat' not in self.agent_str:
            # auth by other pc 
            self.redirect(config['bidong'] + 'account/{}?token={}'.format(self.user['user'], token))
            # url = kwargs['firsturl']
            # if kwargs['urlparam']:
            #     url = ''.join([url, '?', kwargs['urlparam']])
            # self.redirect(url)
        else:
            self.render_json_response(Code=200, Msg='OK', user=self.user['user'], token=token)
        access_log.info('%s login successfully, ip: %s', self.user['user'], self.request.remote_ip)


    # @_trace_wrapper
    @_parse_body
    @tornado.gen.coroutine
    def post(self):
        # parse request data
        # logger.info(self.request.arguments)
        openid = self.get_argument('openid', None)
        user = self.get_argument('user', '')
        password = self.get_argument('password', '')
        _user = None

        ac_ip = self.get_argument('ac_ip')
        # check ac ip
        if ac_ip not in AC_CONFIGURE:
            access_log.error('not avaiable ac: {}'.format(ac_ip))
            raise HTTPError(403, reason='AC ip error')

        ap_mac = self.get_argument('ap_mac')
        user_mac = self.get_argument('user_mac')
        user_ip = self.get_argument('user_ip')

        # vlanId = self.get_argument('vlan')
        ssid = self.get_argument('ssid')

        self.profile = account.get_billing_policy(ac_ip, ap_mac, ssid)

        # flags = self.get_argument('flags', 0)
        _user = ''

        if openid:
            # weixin client
            appid = self.get_argument('appid')
            shopid = self.get_argument('shopid')
            _user = account.get_user(openid, column='weixin', appid=appid)
            
            if not _user:
                raise HTTPError(404, reason=bd_errs[430])
                # user unsubscribe, the account will be forbid
                # if _user['mask']>>31 & 1:
                #     raise HTTPError(403, reason='No privilege')
                # _user = store.get_bd_user(_user['id'])
            user = _user['user']
            password = _user['password']
        else:
            _user = account.get_bd_user(user)

        if not _user:
            access_log.warning('can\'t found user, user: {}, pwd_{}'.format(user, 
                                                                            ''.join([utility.generate_password(3), password])))
            raise HTTPError(401, reason=bd_errs[431])

        if password not in (_user['password'], utility.md5(_user['password']).hexdigest()):
            # password or user account error
            access_log.error('{} password error, pwd_{}'.format(_user['user'], 
                                                                ''.join([utility.generate_password(3), password])))
            raise HTTPError(401, reason=bd_errs[431])

        # check account status & account ends number on networt
        if _user['mask']>>30 & 1:
            # raise HTTPError(403, reason='Account has been frozened')
            access_log.error('{} has been frozened, mask: {}'.format(_user['user'], _user['mask']))
            raise HTTPError(403, reason=bd_errs[434])

        self.user = _user

        onlines = account.get_onlines(self.user['user'])
        if user_mac not in onlines and len(onlines) >= self.user['ends']:
            # allow user login ends 
            access_log.error('{} exceed edns: {}'.format(self.user['user'], self.user['ends']))
            raise HTTPError(403, reason=bd_errs[451])

        # check private network
        if self.profile['ispri']:
            # check mobile argument
            # mobile = self.get_argument('pmobile', '')
            # if mobile:
            #     # try to bind user's pns
            #     account.bind_avaiable_pns(self.user['user'], mobile)

            # current network is private, check user privilege
            ret, err = account.check_pn_privilege(self.profile['pn'], self.user['user'])
            if not ret:
                raise err
        
        # check billing
        # nanshan account user network freedom (check by ac_ip)
        # if not profile['policy']:
        if not self.profile['policy']:
            self.expired = account.check_account_balance(self.user)
            if self.expired:
                # raise HTTPError(403, reason='Account has no left time')
                access_log.error('{} has no time left, can\'t access {} network'.format(self.user['user'], self.profile['pn']))
                raise HTTPError(403, reason=bd_errs[450])

        # send challenge to ac
        # flags = int(self.get_argument('flags', LOGIN))
        # flags = LOGIN
        # if flags == LOGIN:
            # portal-radius server doesn't check password, so send a 
            # no-meaning value
        response = yield tornado.gen.Task(portal.login.apply_async, args=[self.user,  ac_ip, user_ip, user_mac])

        if response.status in ('SUCCESS', ):
            # login successfully 
            account.update_mac_record(self.user['user'], user_mac, self.agent_str)
        else:
            if isinstance(response.result, HTTPError) and response.result.status_code in (435, ):
                access_log.info('user:{} has been authed'.format(self.user['user']))
                # has been authed
                pass
            else:
                access_log.info('user:{}, pwd_{}'.format(self.user['user'], 
                                                      ''.join([utility.generate_password(3), self.user['password']])))
                access_log.error('Auth failed, {}'.format(response.traceback))
                
                raise response.result 


        token = utility.token(self.user['user'])
        self.render_json_response(User=self.user['user'], Token=token, Code=200, Msg='OK')
        access_log.info('%s login successfully, ip: %s', self.user['user'], self.request.remote_ip)

EXPIRE = 7200

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
    header = portal.Header.unpack(data)
    if header.type & 0x08:
        # ac notify portal, user logout

        # return ack_logout
        # header.type = 0x07
        data = '\x01\x07' + data[2:]
        # sock.sendto(data, addr)

        if True:
            start = 32 if header.ver == 0x02 else 16
            attrs = portal.Attributes.unpack(header.num, data[start:])
            if not attrs.mac:
                access_log.info('User quit, ip: {}'.format(socket.inet_ntoa(header.ip)))
                return
            #
            mac = []
            for b in attrs.mac:
                mac.append('{:2X}'.format(ord(b)))
            mac = ':'.join(mac)
            access_log.info('User quit, mac: {}'.format(mac))

# def init_log(log_folder, log_config, port):
#     global logger
#     import logging
#     import logging.config
#     log_config['handlers']['file']['filename'] = os.path.join(log_folder, 
#                                                               '{}_{}.log'.format(log_config['handlers']['file']['filename'], port))
#     logging.config.dictConfig(log_config)
#     logger = logging.getLogger()
#     logger.propagate = False

def get_bas():
    global AC_CONFIGURE
    results = account.list_bas()
    AC_CONFIGURE = {item['ip']:item for item in results}

def main():
    tornado.options.parse_command_line()

    # init_log(config['log_folder'], config['logging_config'], options.port)

    portal_pid = os.path.join(config['RUN_PATH'], 'portal/p_{}.pid'.format(options.port))
    with open(portal_pid, 'w') as f:
        f.write('{}'.format(os.getpid()))

    # initialize portal module
    index, total = options.index, options.total

    step = int(2**16/total) 
    start = index*step


    portal.init(config['portal_config'], None, xrange(start, start+step))

    account.setup(config['database'])

    import tcelery
    
    tcelery.setup_nonblocking_producer()

    # get bas lists
    get_bas()

    app = Application()
    app.listen(options.port, xheaders=app.settings.get('xheaders', False))
    io_loop = tornado.ioloop.IOLoop.instance()

    udp_sockets = bind_udp_socket(PORTAL_PORT)
    for udp_sock in udp_sockets:
        add_udp_handler(udp_sock, '', io_loop)

    app_log.info('Portal Server Listening:{} Started'.format(options.port))
    io_loop.start()

if __name__ == '__main__':
    main()
