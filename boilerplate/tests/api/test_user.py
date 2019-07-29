# coding=utf-8
import json
import logging

from boilerplate import models as m
from boilerplate.tests.api import APITestCase

__author__ = 'Kien'
_logger = logging.getLogger(__name__)


class UserApiTestCase(APITestCase):
    def url(self):
        return '/api/users/'

    def method(self):
        return 'POST'

    def test_create_user_when_success_then_insert_user_into_db(self):
        uid = 1
        valid_data = {
            'id': uid,
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'secret',
            'role': 'admin'
        }

        self.send_request(data=valid_data)
        saved_user = m.User.query.get(uid)  # type: m.User

        assert saved_user
        self.assertEqual(saved_user.id, uid)
        self.assertEqual(saved_user.username, valid_data['username'])
        self.assertEqual(saved_user.email, valid_data['email'])
        self.assertEqual(saved_user.role, valid_data['role'])

    def test_create_user_when_success_then_return_user_response(self):
        uid = 1
        valid_data = {
            'id': uid,
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'secret',
            'role': 'admin'
        }

        rv = self.send_request(data=valid_data)

        self.assertEqual(200, rv.status_code)
        res_data = json.loads(rv.data)['data']
        self.assertEqual(res_data['id'], valid_data['id'])
        self.assertEqual(res_data['username'], valid_data['username'])
        self.assertEqual(res_data['username'], valid_data['username'])
        self.assertEqual(res_data['email'], valid_data['email'])
        self.assertEqual(res_data['role'], valid_data['role'])

    def test_create_user_when_invalid_data_then_return_400_code(self):
        invalid_data = {
            'id': 69,
            'username': 'moderator',
            'email': 'moderator',
            'password': 'terces',
            'role': 'moderator'
        }

        rv = self.send_request(data=invalid_data)
        self.assertEqual(400, rv.status_code)
