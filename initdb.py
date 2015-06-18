#!/usr/bin/env python
#coding:utf-8
import sys
import os
import argparse

from sqlalchemy import *
from sqlalchemy import event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relation
from sqlalchemy.orm import scoped_session, sessionmaker
from hashlib import md5

import functools

DeclarativeBase = declarative_base()

def get_db_connstr(config, tmpdb=None, mask=0):
    '''
        get db connection strings
        mask : as get_engine
    '''
    # return 'mysql://root:wifi_bd*@127.0.0.1:3306/bidong?charset=utf8';
    if mask:
        password = raw_input('Please input root\'s password: ')
        return 'mysql://root:{}@{}:{}/{}??charset={}'.format(password, config['host'], 
                                                 config['port'], 'mysql', config['charset'])
    return 'mysql://{}:{}@{}:{}/{}?charset={}'.format(config['user'], 
                    config['passwd'], config['host'], config['port'], 
                    config['db'], config['charset'])

def get_engine(dbconf=None, echo=False, tmpdb=None, mask=0):
    '''
        mask
            0 : as config['user']
            other : connect database use root
    '''
    data = get_db_connstr(dbconf, tmpdb=tmpdb, mask=mask)
    engine = create_engine(data, echo=echo)
    metadata = DeclarativeBase.metadata
    metadata.bind = engine
    return engine, metadata

class Bas(DeclarativeBase):
    '''
        Bas(ac) device table
    '''
    __tablename__ = 'bas'
    __table_args__ = {}

    #column definitions
    id = Column('id', INTEGER(), 
                Sequence('bas_id_seq', start=1001, increment=1),
                primary_key=True, nullable=False, doc='device id')
    vendor_id = Column('vendor', VARCHAR(length=32), nullable=False, doc='vendor id')
    ip_addr = Column('ip', VARCHAR(length=15), nullable=False, doc='ip address')
    bas_name = Column('name', VARCHAR(length=64), nullable=True, doc='bas name')
    bas_model = Column('model', VARCHAR(length=32), nullable=True, doc='bas model')
    bas_secret = Column('secret', VARCHAR(length=64), nullable=True, doc='shared secret key')
    coa_port = Column('coa_port', INTEGER(), nullable=False, doc='coa port')
    time_zone = Column('tz', SMALLINT(), nullable=True, doc='time zone')

class Account(DeclarativeBase):
    '''
        Base Account table
        mask :
            0     unverify
            2^0   verify
            
            2^1   group account, holder's code
            2^2   personal account
            2^3   holder account

            2^5   account from weixin
            2^6   account from app

            2^28  frozen
    '''
    __tablename__ = 'account'
    __table_args__ = {}

    id = Column('id', INTEGER(), 
                #Sequence('member id seq', start=100001, increment=1),
                primary_key=True, nullable=False, doc='increment id')
    mobile = Column('mobile', VARCHAR(length=16), nullable=True, doc='')
    weixin = Column('weixin', VARCHAR(length=32), nullable=True, doc='weixin number')
    uuid = Column('uuid', VARCHAR(length=32), nullable=True, doc='mobile\'s uuid')
    email = Column('email', VARCHAR(length=64), nullable=True, doc='email address')
    mask = Column('mask', INTEGER(), nullable=False, doc='bit mask')
    address = Column('address', VARCHAR(length=256), nullable=True, doc='home address')
    realname = Column('realname', VARCHAR(length=32), nullable=True, doc='')
    # sex = Column('sex', SMALLINT(), nullable=True, doc='MALE/FEMALE 0/1')
    # age = Column('age', INTEGER(), nullable=True, doc='user age')
    create_time = Column('create_time', VARCHAR(length=19), nullable=False, doc='create time')
    expire_date = Column('expire_date', VARCHAR(length=10), nullable=True, doc='group accout expired date')

class RenterAP(DeclarativeBase):
    '''
        hold binded aps
    '''
    __tablename__ = 'holder_ap'
    __table_args__ = {}
    
    holder = Column('holder', INTEGER(), nullable=False, doc='equal account\'s id')
    mac = Column('mac', CHAR(length=17), nullable=False, primary_key=True, doc='ap\'s mac address')

class AP(DeclarativeBase):
    '''
        ap info
        profile: 1, 6, 11
    '''
    __tablename__ = 'aps'
    __table_args__ = {}

    mac = Column('mac', CHAR(length=17), nullable=False, primary_key=True, doc='ap\'s mac address')
    vendor = Column('vendor', VARCHAR(length=32), doc='设备商')
    model = Column('model', VARCHAR(length=32), doc='设备型号')
    profile = Column('profile', INTEGER(), doc='AP配置方案')
    position = Column('position', POINT(), doc='ap 部署位置')
    fm = Column('fm', VARCHAR(length=32), doc='固件版本')

class RenterRoom(DeclarativeBase):
    '''
    '''
    __tablename__ = 'holder_room'
    __table_args__ = {}
    
    holder = Column('holder', INTEGER(), primary_key=True, nullable=False, doc='equal account\'s id')
    room = Column('room', CHAR(4), primary_key=True, nullable=False, doc='room number')

class BDAccount(DeclarativeBase):
    '''
        BD wifi account
        mask : 
            0   unverify
            2^0 verify
            2^1   group account, holder's code
            2^2   personal account
            2^3   holder account

            2^5   account from weixin
            2^6   account from app

            2^8   day 
            2^9   time

            2^29  frozen account(holder frozen renters' room) 
            2^30  frozen account(because holder has been frozen)
            2^31  forbid use

        user column as index
    '''
    __tablename__ = 'bd_account'
    __table_args__ = {}

    # user account equal account's weixin id
    user = Column('user', VARCHAR(length=32), primary_key=True, nullable=False, doc='')
    password = Column('password', VARCHAR(length=64), nullable=False, doc='')
    mask = Column('mask', INTEGER(), nullable=False, doc='bit mask')
    time_length = Column('time_length', INTEGER(), nullable=True, doc='online time length-second')
    flow_length = Column('flow_length', INTEGER(), nullable=True, doc='user flow')
    coin = Column('coin', INTEGER(), nullable=True, doc='')
    expire_date = Column('expire_date', VARCHAR(length=10), nullable=True, doc='expire date ####-##-##')
    ends = Column('ends', INTEGER(), doc='')
    mac_addr = Column('mac', VARCHAR(length=17), nullable=True, doc='mac address')
    ip = Column('ip', VARCHAR(length=15), nullable=True, doc='static ip address')
    holder = Column('holder', INTEGER(), nullable=True, doc='holder id, equal accout\'s id')

class MacHistory(DeclarativesBase):
    '''
        record mac online history
        user column as index
    '''
    __tablename__ = 'mac_history'
    __table_args__ = {}

    user = Column('user', VARCHAR(length=32), primary_key=True, nullable=False, doc='bd_account\'s user')
    mac = Column('mac', VARCHAR(length=17), primary_key=True, nullable=False, doc='mac addr')
    datetime = Column('datetime', VARCHAR(length=32), doc='the datetime client login')

class Online(DeclarativeBase):
    '''
        user online table
        user column as index
    '''
    __tablename__ = 'online'
    __table_args__ = {
        'mysql_engine':'MEMORY',
    }

    id = Column('id', INTEGER(), primary_key=True, nullable=False, doc='online id')
    user = Column('user', VARCHAR(length=32), nullable=False, doc='weixin account')
    nas_addr = Column('nas_addr', VARCHAR(length=15), nullable=False, doc='bas address')
    acct_session_id = Column('acct_session_id', VARCHAR(length=64), nullable=False, doc='session id')
    acct_start_time = Column('acct_start_time', VARCHAR(length=19), nullable=False, doc='session start time')
    framed_ipaddr = Column('framed_ipaddr', VARCHAR(length=32), nullable=False, doc='ip address')
    mac_addr = Column('mac_addr', VARCHAR(length=17), nullable=False, doc='mac address')
    billing_times = Column('billing_times', INTEGER(), nullable=False, doc='bill times')
    input_total = Column('input_total', INTEGER(), doc='input flow (kb)')
    output_total = Column('output_total', INTEGER(), doc='output flow (kb)')
    start_source = Column('start_source', SMALLINT(), nullable=False, doc='')

class Billing(DeclarativeBase):
    '''
          (0/1) (haven't pay/paid)
          bill log table
    '''
    __tablename__ = 'billing'
    __table_args__ = {}

    id = Column('id', INTEGER(), primary_key=True, nullable=False, doc='billing id')
    user = Column('user', VARCHAR(length=32), nullable=False, doc='weixin account')
    nas_addr = Column('nas_addr', VARCHAR(length=15), nullable=False, doc='bas address')
    acct_session_id = Column('acct_session_id', VARCHAR(length=64), nullable=False, doc='session id')
    acct_start_time = Column('acct_start_time', VARCHAR(length=19), nullable=False, doc='session start time')
    acct_session_time = Column('acct_session_time', INTEGER(), nullable=False, doc='session time')
    input_total = Column('input_total', INTEGER(), doc='input flow (kb)')
    output_total = Column('output_total', INTEGER(), doc='output flow (kb)')
    acct_coins = Column('acct_coins', INTEGER(), nullable=False, doc='')
    acct_flows = Column('acct_flows', INTEGER(), nullable=True, doc='')
    balance = Column('balance', INTEGER(), nullable=False, doc='')
    is_deduct = Column('is_deduct', INTEGER(), nullable=False, doc='')
    time = Column('time', VARCHAR(length=19), nullable=False, doc='')

class Ticket(DeclarativeBase):
    '''
        user internet log
    '''
    __tablename__ = 'ticket'
    __table_args__ = {}

    id = Column('id', INTEGER(), primary_key=True, nullable=False, doc='id')
    user = Column('user', VARCHAR(length=32), nullable=False, doc='weixin account')
    # acct_input_gigawords = Column('acct_input')
    acct_input_octets = Column('acct_input_octets', INTEGER(), doc='session upload flow')
    acct_output_octets = Column('acct_output_octets', INTEGER(), doc='')
    acct_input_packets = Column('acct_input_packets', INTEGER(), doc='upload packet numbers')
    acct_output_packets = Column('acct_output_packets', INTEGER(), doc='')
    acct_session_id = Column('acct_session_id', VARCHAR(length=64), nullable=False, doc='session id')
    acct_session_time = Column('acct_session_time', INTEGER(), nullable=False, doc='session timeout')
    acct_start_time = Column('acct_start_time', VARCHAR(length=19), nullable=False, doc='')
    acct_stop_time = Column('acct_stop_time', VARCHAR(length=19), nullable=False, doc='')
    acct_terminate_cause = Column('acct_terminate_cause', INTEGER(), doc='session end reason')
    mac_addr = Column('mac_addr', VARCHAR(length=17), doc='')
    framed_netmask = Column('framed_id_netmask', VARCHAR(length=15), doc='')
    framed_ipaddr = Column('framed_ipaddr', VARCHAR(length=15), doc='')
    nas_addr = Column('nas_addr', VARCHAR(length=15), nullable=False, doc='')
    
    session_timeout = Column('session_timeout', INTEGER(), doc='')
    start_source = Column('start_source', INTEGER(), nullable=False, doc='')
    stop_source = Column('stop_source', INTEGER(), nullable=False, doc='')


def build_db(config=None, password=None):
    '''
        config : database value
        password : root user's password 
    '''
    # tmpdbs = {'mysql':'mysql'}
    # dbtype = config['database']['dbtype']
    engine, _ = get_engine(config, tmpdb='mysql', mask=1)
    conn = engine.connect()
    try:
        drop_sql = 'drop database {}'.format(config['db'])
        print(drop_sql)
        conn.execute(drop_sql)

        # delete user
        # delete_user = 'drop user "{}"@"%%"'.format(config['user'])
        # print(delete_user)
        # conn.execute(delete_user)
    except:
        print('drop database error')

    create_sql = r'create database {} DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci'.format(config['db'])
    print(create_sql)
    conn.execute(create_sql)
    event.listen(Account.__table__, 'after_create', DDL('alter table %(table)s auto_increment = 10001;'))
    event.listen(BDAccount.__table__, 'after_create', DDL('alter table %(table)s add index idx_bd_account_index(user)'))
    event.listen(MacHistory.__table__, 'after_create', DDL('alter table %(table)s add index idx_mac_history_index(user)'))
    event.listen(Online.__table__, 'after_create', DDL('alter table %(table)s add index idx_online_index(user)'))

    # create user
    # create_user = r'create user "{}"@"%%" identified by "123456"'.format(config['user'])
    # print(create_user)
    # conn.execute(create_user)

    # # grant privilege  
    # grant_privileges = 'grant all privileges on {}.* to "{}"@"%%"'.format(config['db'], config['user'])
    # print(grant_privileges)
    # conn.execute(grant_privileges)

    # modify password
    # modify_password = 'set password for "{}"@"%%"=PASSWORD("{}")'.format(config['user'], config['passwd'])
    # print(modify_password)
    # conn.execute(modify_password)

    print('commit')
    conn.execute('commit')
    conn.close()

    engine,metadata = get_engine(config)
    metadata.create_all(engine, checkfirst=True)

def init_db(db):
    '''
        Initilize 
    '''
    bas = Bas()
    bas.vendor_id = 'hanming'
    bas.ip_addr = '10.10.0.50'
    bas.bas_name = 'niot ac'
    bas.bas_mode = 'howay6100'
    bas.bas_secret = 'abcdefghijk'
    bas.coa_port = 2000

    db.add(bas)

    account = Account()
    account.mobile = '13800000000'
    account.weixin = 'hayate'
    account.email = 'xujia@niot.cn'
    account.mask = 4
    account.create_time = '2015-03-15 10:45:20'

    db.add(account)

    bd_account = BDAccount()
    bd_account.user = 'test01'
    bd_account.password = '12345678'
    bd_account.mask = 2**9 + 2**5     # verified
    bd_account.time_length = 3600
    bd_account.flow_length = 0
    bd_account.coin = 0
    bd_account.ends = 2

    db.add(bd_account)

    db.commit()

def install(config=None):
    print('Starting create and init database ...')
    action = raw_input('Drop and create database? [y/n] ')
    if action in ('y', 'Y'):
        build_db(config=config)
        engine, _ = get_engine(config)
        db = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=True))()
        action = raw_input('init database? [y/n] ')
        if action in ('y', 'Y'):
            init_db(db)

def install2(config=None):
    print('Starting create and init database ...')
    build_db(config=config)
    engine, _ = get_engine(config)
    db = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=True))()
    init_db(db)

if __name__ == '__main__':
    import config
    install(config['database'])
