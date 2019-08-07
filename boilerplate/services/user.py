# coding=utf-8
import logging
import re
import datetime

import random
import string

from boilerplate import models as m
from boilerplate import repositories, models


from flask_jwt_extended import create_access_token
from boilerplate.extensions.exceptions import BadRequestException
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
# from flask import url_for

__author__ = 'Kien' + ''
_logger = logging.getLogger(__name__)

serializer = URLSafeTimedSerializer('my_precious_secret_key')
validate_email = r"[^@]+@[^\.]+\..+"
validate_password = r"^[A-Za-z0-9]{6,}$"
# regex for advance: "r'[A-Za-z0-9@#$%^&+=]{8,}"
host_users = 'http://127.0.0.1:5000/api/users'


def random_string(string_length=6):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(string_length))


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


def register(username, email, password, confirm_password, **kwargs):
    from boilerplate import mail
    """
    validate post data, save user in table signup_request and send email confirmation
    :param username:
    :param email:
    :param password:
    :param confirm_password:
    :param kwargs:
    :return:
    """

    if (
        username and len(username) < 50 and
        email and re.match(validate_email, email) and
        password and re.match(validate_password, password) and
        confirm_password and re.match(validate_password, confirm_password) and
        password == confirm_password
    ):
        existed_user = repositories.user.find_one_by_email_ignore_case(email)
        if existed_user:
            raise BadRequestException(
                "User with email {email} already existed!".format(
                    email=email
                )
            )

        email_confirm_token = serializer.dumps(email, salt='more_salt_please')
        message = Message('PROJECT - Confirm email for registration', sender='ducanh.danny@gmail.com', recipients=[email])
        link = host_users+'/confirm_email/?token={}'.format(email_confirm_token)

        message.body = 'Click the link below to confirm registration in PROJECT: {}'.format(link)
        mail.send(message)

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
        expired_time_min = datetime.timedelta(minutes=30)
        if not find_user:
            raise BadRequestException("Username does not exist.")
        if models.User.check_password(find_user, password):
            token = create_access_token(identity={
                "username": find_user.username,
                "email": find_user.email,
                "is_admin": find_user.is_admin
            }, expires_delta=expired_time_min)

            repositories.user.save_user_token_to_database(
                user_id=find_user.id,
                token=token,
                expired_time=datetime.datetime.now() + expired_time_min
            )

            repositories.user.update_last_login_to_database(email=find_user.email)
            return token

        else:
            raise BadRequestException("Incorrect password")
    else:
        raise BadRequestException("Invalid username or password")

# ========================


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
    return "Password is updated!"


def forget_password(username, email, **kwargs):
    from boilerplate import mail

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
        elif (
            existed_user != repositories.user.find_one_by_username_ignore_case(username)
        ):
            raise BadRequestException(
                "User with username and email not match!"
            )
        else:
            email_confirm_token = serializer.dumps(email, salt='more_salt_please')
            message = Message('PROJECT - Confirm email for changing password', sender='ducanh.danny@gmail.com', recipients=[email])
            link = host_users+'/confirm_email_forget_password/?token={}'.format(email_confirm_token)

            message.body = 'Click the link below to confirm changing password: {}'.format(link)
            mail.send(message)

        return link
    else:
        raise BadRequestException(
            "Invalid data specified!"
        )


def change_password_after_confirm_forgetting_to_database(email, **kwargs):
    random_password = random_string(6)
    repositories.user.update_password_to_database(
        email=email, new_password=random_password
    )
    return random_password

# def logout(user_id):
#     repositories.user.save_user_token_to_database(
#
#     )
