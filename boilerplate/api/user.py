# coding=utf-8
import logging

import flask_restplus as _fr
from flask import request, jsonify
from boilerplate import services, models
from boilerplate.extensions import Namespace
from itsdangerous import SignatureExpired
from boilerplate.services.user import serializer
import flask_jwt_extended as _jwt

__author__ = 'ThucNC'
_logger = logging.getLogger(__name__)

ns = Namespace('users', description='User operations')

_user_res = ns.model('user_res', models.UserSchema.user)
_user_create_req = ns.model('user_create_req',
                            models.UserSchema.user_create_req)
_user_login_req = ns.model('user_login_req', models.UserSchema.user_login_req)


@ns.route('/register', methods=['POST'])
class Register(_fr.Resource):
    @ns.expect(_user_create_req, validate=True)
    def post(self):
        data = request.json or request.args
        try:
            url = services.user.register(**data)
        except Exception as e:
            raise e
        else:
            return jsonify({"Successful": url})


@ns.route('/confirm_email/', methods=['GET'])
class ConfirmEmail(_fr.Resource):
    def get(self):
        token = request.values
        try:
            email = serializer.loads(token.get('token'),
                                     salt='my_precious_security_password_salt', max_age=300)  # 5'
        except SignatureExpired:
            return 'The link is expired!'
        else:
            services.user.create_user(email)
            return 'Successful, please login!'


@ns.route('/login', methods=['POST'])
class Login(_fr.Resource):
    @ns.expect(_user_login_req, validate=True)
    def post(self):
        data = request.json or request.args
        try:
            token_login = services.user.login(**data)
        except Exception as e:
            raise e
        else:
            return jsonify({"token": token_login})

# ==================
# Not work
@ns.route('/change_password', methods=['POST'])
class ChangePassword(_fr.Resource):
    # @ns.expect(username, old_password, new_password, confirm_password)
    @_jwt.jwt_required
    def post(self):
        data = request.json or request.args
        try:
            update = services.user.change_password(**data)
        except Exception as e:
            raise e
        else:
            return jsonify({"Password changed": update})


@ns.route('/confirm_email_password/', methods=['GET'])
class ConfirmEmailPassword(_fr.Resource):
    def get(self):
        token = request.values
        try:
            email = serializer.loads(token.get('token'),
                                     salt='my_precious_security_password_salt', max_age=300)  # 5'
        except SignatureExpired:
            return 'The link is expired!'
        else:
            # have to update code

            return 'Successful, please login!'


# @ns.route('/forget_password', method=['POST'])
# class ForgetPassword(_fr.resource):
#     def post(self):
#         data = request.json or request.args
#         try:
#
#         except Exception as e:
#             raise e
#         else
#             return jsonify({'' : })





@ns.route('/logout', methods=['GET'])
class Logout(_fr.Resource):
    def get(self):
        # code
        return jsonify({"Successful": "logout"})

