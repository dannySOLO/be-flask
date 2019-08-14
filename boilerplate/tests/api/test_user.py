# coding=utf-8
import json
import logging

from boilerplate import models as m, repositories
from boilerplate.tests.api import APITestCase

__author__ = 'Kien' + ''
_logger = logging.getLogger(__name__)

# existed_user = repositories.user.save_user_to_database(
#     email='existed@gmail.com',
#     username='existed',
#     password='existed'
# )


# 恋人心 我爱你 你好 一百万个可能 阮地英 不仅仅是喜欢 我爱你
class RegisterApiTestCase(APITestCase):
    def url(self):
        return '/api/users/register'

    def method(self):
        return 'POST'

    def test_raise_error_when_email_is_existed(self):
        email = 'existed@gmail.com'
        data = {
            'email': email,
            'username': 'username',
            'password': 'password',
            'confirm_password': 'password'
        }

        self.send_request(data=data)
        saved_user = m.SignupRequest.query.get(data['username'])   # type: m.SignupRequest
        assert saved_user, "No sign up request saved to database."

    # def test_save_to_signup_request_when_data_is_valid(self):
    #     email = 'emailx@gmail.com'
    #     valid_data = {
    #         'email': email,
    #         'username': 'usernamex',
    #         'password': 'passwordx',
    #         'confirm_password': 'passwordx'
    #     }
    #
    #     self.send_request(data=valid_data)
    #     saved_user = m.SignupRequest.query.get(email)    # type: m.SignupRequest
    #     assert saved_user, "Valid"
    #     self.assertEqual(saved_user.email, valid_data['email'])
    #     self.assertEqual(saved_user.username, valid_data['username'])


class LoginApiTestCase(APITestCase):
    def url(self):
        return '/api/users/login'

    def method(self):
        return 'POST'

    assert 1, "0"
