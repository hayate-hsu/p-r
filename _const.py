#!/usr/bin/env python
#coding:utf-8
message = {
404:u'账号不存在',
453:u'非房东账号',

'account':'上网账号: {}\n账号密码： {}\n\n',
'notify':'上网账号: {}, 账号密码： {}, 请妥善保管.',

'welcome':'欢迎关注壁咚无线!\n\n上网账号:    {}\n上网密码:    {}\n\n<a href="http://wnl.bidongwifi.com:9899/help.html">上网帮助，请点这里</a>\n\n',

'msg_template':'动态验证码{}，用于身份验证或上网认证，有效期10分钟，请勿泄漏。',
'hz_msg_template':'动态验证码{}，用于机关大楼无线认证上网，有效期1分钟，请勿泄漏。',
'account_template':'账号注册成功，上网账号:{}, 上网密码:{}，以后除使用手机号登录外，也可以输入上网账号和密码登录。请妥善保管',
}



import sys
sys.modules[__name__] = message
