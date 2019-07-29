# coding=utf-8
import logging
import random

import faker.providers

from boilerplate import models as m
from boilerplate.helpers.faker import fake

__author__ = 'Kien'
_logger = logging.getLogger(__name__)


class UserProvider(faker.providers.BaseProvider):
    def user_role(self):
        return random.choice([role for role in m.User.Role])

    def user(self, **kwargs):
        user = m.User(id=kwargs.get('id', fake.id()))
        user.username = kwargs.get('username', fake.name())
        user.email = kwargs.get('email', fake.email())
        user.role = kwargs.get('role', fake.user_role())
        user.password = kwargs.get('password', fake.text(10))

        m.db.session.add(user)
        m.db.session.flush()

        return user
