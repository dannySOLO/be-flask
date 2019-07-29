# coding=utf-8
import datetime
import logging
import random
import string
import time
import uuid

import faker.providers

from .user_provider import UserProvider

__author__ = 'Kien'
_logger = logging.getLogger(__name__)

fake = faker.Faker()


class Provider(faker.providers.BaseProvider):
    def id(self):
        return random.randrange(1, 10000000)

    def text(self, length=None):
        length = 10 if length is None else length
        return ''.join(
            random.choice(string.ascii_lowercase) for i in range(length))

    def long_text(self):
        return "Lorem Ipsum is simply dummy text of the printing and " \
               "typesetting industry. " \
               "Lorem Ipsum has been the industry's standard dummy text ever " \
               "since the 1500s, when an unknown printer took a galley of " \
               "type and scrambled it to make a type specimen book. It has " \
               "survived not only five "

    def unique_str(self, len=None):
        return uuid.uuid4().hex[:len or 12].upper()

    def unique_id(self):
        return str(uuid.uuid4())

    def email(self):
        return '%s_%s@teko.com' % (
            fake.name().replace(' ', '_'), fake.unique_str())

    def datetime(self, min_year=1970, max_year=None, is_unix=False,
                 format=None, is_string=True):
        max_year = max_year or datetime.datetime.now().year
        start = datetime.datetime(min_year, 1, 1, 00, 00, 00)
        years = max_year - min_year + 1
        end = start + datetime.timedelta(days=365 * years)
        random_datetime = start + (end - start) * random.random()

        if is_unix:
            return int(time.mktime(random_datetime.timetuple()))

        if is_string:
            return random_datetime.strftime(format or "%m/%d/%Y %H:%M:%S")
        return random_datetime


fake.add_provider(Provider)
fake.add_provider(UserProvider)
