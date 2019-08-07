# coding=utf-8
import logging
# import random

import datetime

from sqlalchemy import or_
from boilerplate import models as m
# from boilerplate.models import bcrypt

__author__ = 'Kien' + ''
_logger = logging.getLogger(__name__)


def save_user_to_database(**kwargs):
    """
    Create new user record in database from validated data.
    :param kwargs:
    :return:
    """
    user = m.User(**kwargs)
    m.db.session.add(user)
    m.db.session.commit()
    return user


def save_signup_request_to_database(**kwargs):
    """
    Create new user record in database from validated data.
    :param kwargs:
    :return:
    """
    signup_request = m.SignupRequest(**kwargs)
    m.db.session.add(signup_request)
    m.db.session.commit()
    return signup_request


def find_one_by_username_ignore_case(username):
    """
        Return a user instance if match, else None
        :param str username:
        :return: a user instance
        :rtype: m.User
    """
    user = m.User.query.filter(
        or_(
            m.User.username == username
        )
    ).first()  # type: m.User

    return user or None


def find_one_by_email_ignore_case(email):
    """
        Return a user instance if match, else None
        :param str email:
        :return: a user instance
        :rtype: m.User
    """
    user = m.User.query.filter(
        or_(
            m.User.email == email
        )
    ).first()  # type: m.User

    return user or None


def find_one_by_email_in_signup_request(email):
    """
    Return a user_signup_request instance if match, else None
    :return: a user instance
    :rtype: m.User
    """
    user_signup_request = m.SignupRequest.query.filter(
        or_(
            m.SignupRequest.email == email
        )
    ).first()

    return user_signup_request or None


def delete_one_by_email_in_signup_request(email):
    user_signup_request = m.SignupRequest.query.filter(
        or_(
            m.SignupRequest.email == email
        )
    ).first()

    m.db.session.delete(user_signup_request)
    m.db.session.commit()


# ====================
def save_user_token_to_database(**kwargs):
    user_token = m.UserToken(**kwargs)
    m.db.session.add(user_token)
    m.db.session.commit()
    return user_token


def update_last_login_to_database(email, **kwargs):
    user = m.User.query.filter_by(email=email).first()
    user.last_login = datetime.datetime.now()
    m.db.session.commit()
    return user


# Do 2 bullshit steps after password's changed
def save_history_password_to_database(**kwargs):
    password_rec = m.HistoryPassChange(**kwargs)
    m.db.session.add(password_rec)
    m.db.session.commit()
    return password_rec


def update_password_to_database(email, new_password, **kwargs):

    user = m.User.query.filter_by(email=email).first()
    user.password = new_password
    m.db.session.commit()
    return user


# after logging out, set expired_time to timestamp now
# def update_expired_time_of_token(user_id, token, **kwargs):
#     user_logout = m.UserToken.query.filter_by(user_id=m.User.id).first()
#     m.db.session.

