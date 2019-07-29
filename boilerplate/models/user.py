# coding=utf-8
import datetime
import enum
import logging

from sqlalchemy import ForeignKey
from flask_restplus import fields
from boilerplate.models import db, bcrypt, TimestampMixin
from sqlalchemy.orm import relationship


__author__ = 'ThucNC'
_logger = logging.getLogger(__name__)


class User(db.Model, TimestampMixin):
    """
    Contains information of users table
    """
    __tablename__ = 'users'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)


    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(191), nullable=False, unique=True)
    email = db.Column(db.String(191), nullable=False, unique=True)

    password_hash = db.Column(db.String(100))
    is_admin = db.Column(db.Integer, default=0)
    is_active = db.Column(db.SmallInteger, default=0)
    last_login = db.Column(db.TIMESTAMP, default=datetime.datetime.now)

    # history_pass_change = relationship("HistoryPassChange")
    # fullname = db.Column(db.String(191), nullable=False)

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(
            password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    def to_dict(self):
        """
        Transform user obj into dict
        :return:
        """
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            # 'fullname': self.fullname,
        }


class UserSchema:
    user = {
        'id': fields.Integer(required=True, description='user id'),
        'email': fields.String(required=True, description='user email address'),
        'username': fields.String(required=True, description='user username'),
        # 'fullname': fields.String(requited=True, description='user fullname')
    }

    user_create_req = user.copy()
    user_create_req.pop('id', None)
    user_create_req.update({
        'password': fields.String(required=True, description='user password'),
    })
    user_create_req.update({
        're_pass': fields.String(required=True, description='user rewrite password'),
    })

    user_login_req = user.copy()
    user_login_req.pop('id', None)
    user_login_req.pop('email', None)
    # user_login_req.pop('fullname', None)
    user_login_req.update({
        'password': fields.String(required=True, description='user password'),
    })


class SignupRequest(db.Model, TimestampMixin):

    __tablename__ = 'signup_request'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(191), nullable=False)
    email = db.Column(db.String(191), nullable=False)

    # fullname = db.Column(db.String(191), nullable=False)
    password_hash = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=0)
    expired_time = db.Column(db.TIMESTAMP)
    user_token_confirm = db.Column(db.String(512), nullable=True)

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(
            password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    def to_dict(self):
        """
        Transform user obj into dict
        :return:
        """
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            # 'fullname': self.fullname,
        }


class HistoryPassChange(db.Model, TimestampMixin):

    __tablename__ = 'history_pass_change'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    history_pass_change = db.Column(db.String(100), nullable=True)


class UserToken(db.Model, TimestampMixin):
    __tablename__ = 'user_token'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    token = db.Column(db.String(512))
    expired_time = db.Column(db.TIMESTAMP)


class HistoryWrongPass(db.Model, TimestampMixin):
    __tablename__ = 'history_wrong_pass'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), ForeignKey('users.username'))
    time = db.Column(db.TIMESTAMP)


class Logging(db.Model, TimestampMixin):
    __tablename__ = 'logging'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    action_id = db.Column(db.Integer, ForeignKey('action.id'))


class Action(db.Model, TimestampMixin):
    __tablename__ = 'action'

    def __init__(self, **kwargs):
        """
        Support direct initialization
        :param kwargs:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    detail = db.Column(db.String(500))

