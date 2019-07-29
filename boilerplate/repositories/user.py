# coding=utf-8
import logging

from sqlalchemy import or_
from boilerplate import models as m

__author__ = 'Kien'
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
    :param str username:
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

# def save_history_pass_change_to_database(user_id, history_pass_change):


def save_user_token_to_database(**kwargs):
    user_token = m.UserToken(**kwargs)
    m.db.session.add(user_token)
    m.db.session.commit()
    return user_token


def save_history_password_to_database(**kwargs):
    password = m.HistoryPassChange(**kwargs)
    m.db.session.add(password)
    m.db.session.commit()
    return password

