'''
'''
from __future__ import absolute_import, division, print_function, with_statement
# from __future__ import division, print_function, with_statement

# celery application
from celery import Celery, platforms

platforms.C_FORCE_ROOT = True

celery = Celery('task', include=['task.portal', ])

celery.conf.update(
    BROKER_URL = 'amqp://bidong:portal_bidong@localhost:5672/portal', 
    # BROKER_URL = 'amqp://guest:bidong@localhost:5672//', 
    # tornado-celery only support rabbitmq & redis currently
    CELERY_RESULT_BACKEND = 'amqp', 
#     CELERY_TASK_SERIALIZER = 'json', 
#     CELERY_RESULT_SERIALIZER = 'json', 
    CELERY_ACCEPT_CONTENT = ['pickle'], 

    # disable rate limits globally
    CELERY_DISABLE_RATE_LIMITS = True,
    TCELERY_RESULT_NOWAIT = False,
    CELERY_TIMEZONE = 'Asia/Shanghai', 
    CELERY_ENABLE_UTC = True,
#     CELERY_REDIRECT_STDOUTS = True,
)


# platforms.C_FORCE_ROOT = True

if __name__ == '__main__':
    celery.start()
