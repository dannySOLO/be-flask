# coding=utf-8
import logging
import re
import datetime
import random


from boilerplate import models as m
from boilerplate import repositories, models
from flask_jwt_extended import create_access_token
from boilerplate.extensions.exceptions import BadRequestException
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
# from boilerplate import mail
# from flask import url_for

__author__ = 'Kien'
_logger = logging.getLogger(__name__)

serializer = URLSafeTimedSerializer('my_precious_secret_key')
validate_email = r"[^@]+@[^\.]+\..+"
validate_password = r"^[A-Za-z0-9]{6,}$"
# regex for advance: "r'[A-Za-z0-9@#$%^&+=]{8,}"
host_users = 'http://127.0.0.1:5000/api/users'


def create_user(email, **kwargs):
    """
    Validate post data and create a new user
    :param str username:
    :param str email:
    :param str password:
    :param kwargs:
    :return: a new user
    :rtype: m.User
    """
    user_signup_request = repositories.user.find_one_by_email_in_signup_request(email)

    user = repositories.user.save_user_to_database(
        username=user_signup_request.username,
        email=user_signup_request.email,
        password_hash=user_signup_request.password_hash,
        # fullname=user_signup_request.fullname,
        **kwargs
    )
    repositories.user.delete_one_by_email_in_signup_request(email)
    # repositories.user.save_history_password_to_database(user_id=find_user(id), )
    return user


def register(username, email, password, re_pass, **kwargs):
    """
    validate post data, save user in table signup_request and send email confirmation
    :param username:
    :param email:
    :param password:
    :param re_pass:
    :param kwargs:
    :return:
    """

    if (
        username and len(username) < 50 and
        email and re.match(validate_email, email) and
        password and re.match(validate_password, password) and
        re_pass and re.match(validate_password, re_pass) and
        password == re_pass
    ):
        existed_user = repositories.user.find_one_by_email_ignore_case(email)
        if existed_user:
            raise BadRequestException(
                "User with email {email} already existed!".format(
                    email=email
                )
            )

        email_confirm_token = serializer.dumps(email, salt='my_precious_security_password_salt')
        message = Message('Confirm email', sender='ducanh.danny@gmail.com', recipients=[email])
        link = host_users+'/confirm_email/?token={}'.format(email_confirm_token)

        message.body = 'Registration confirm link: {}'.format(link)
        # mail.send(message)

        # [WinError 10061] No connection could be made because the target machine actively refused it
        # Confirm register email manually instead

        repositories.user.save_signup_request_to_database(
            username=username,
            email=email,
            password=password,
            # fullname=fullname,
            user_token_confirm=email_confirm_token,
            **kwargs
        )
        return link
    else:
        raise BadRequestException("Invalid user data specified!")


def login(username, password):
    """
    Validate post data and return token
    :param username:
    :param password:
    :return:
    """
    if(
        username and len(username) < 50 and
        password and re.match(validate_password, password)
    ):
        find_user = repositories.user.find_one_by_username_ignore_case(username=username)
        if not find_user:
            raise BadRequestException("Username does not exist.")
        if models.User.check_password(find_user, password):
            token = create_access_token(identity={
                "id": find_user.id,
                'time': datetime.datetime.now() + datetime.timedelta(minutes=30),
            })
            repositories.user.save_user_token_to_database(
                user_id=find_user.id, token=token,
                expired_time=(datetime.datetime.now() + datetime.timedelta(minutes=30))
            )

            repositories.user.update_last_login_to_database(email=find_user.email)
            return token

        else:
            raise BadRequestException("Incorrect password")
    else:
        raise BadRequestException("Invalid username or password")

# ========================
# Not work


def change_password(email, old_password, new_password, confirm_password, **kwargs):
    user = repositories.user.find_one_by_email_ignore_case(email=email)
    if not user:
        raise BadRequestException("Account linked to this email does not exist.")

    if(     # this step should replace by switch() case to catch exceptions exactly
        # token??
        email and re.match(validate_email, email) and
        old_password and re.match(validate_password, old_password) and
        new_password and re.match(validate_password, new_password) and
        confirm_password and re.match(validate_password, confirm_password) and
        new_password == confirm_password and
        new_password != old_password and

        models.User.check_password(user, old_password)
    ):
        repositories.user.save_history_password_to_database(
            user_id=user.id,
            history_pass_change=user.get_password(),
            **kwargs
        )
        updated_user = repositories.user.update_password_to_database(email=email, new_password=new_password)
    else:
        raise BadRequestException("Invalid data specified")
    return "updated password"


def forget_password(username, email, **kwargs):
    if (
            username and len(username) < 50 and
            email and re.match(validate_email, email)
    ):
        existed_user = repositories.user.find_one_by_email_ignore_case(email)
        if not existed_user:
            raise BadRequestException(
                "User with email {email} not found!".format(
                    email=email
                )
            )

        email_confirm_token = serializer.dumps(email, salt='my_precious_security_password_salt')
        message = Message('Confirm email change password', sender='ducanh.danny@gmail.com', recipients=[email])
        link = host_users+'/confirm_email_password/?token={}'.format(email_confirm_token)

        message.body = 'Link to confirm password change: {}'.format(link)
        # mail.send(message)

        # repositories.user.update_password_to_database(
        #
        #     password=repositories.user.create_random_hash_password()
        # )


# def logout(user_id):
#     repositories.user.save_user_token_to_database(
#
#     )
