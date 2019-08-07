# coding=utf-8
import logging

import flask_restplus as _fr
from flask import request, jsonify
from boilerplate import services, models
from boilerplate.extensions import Namespace
from itsdangerous import SignatureExpired
from boilerplate.services.user import serializer
import flask_jwt_extended as _jwt

__author__ = 'ThucNC' + ''
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
            return jsonify({"successful": "Check your email for registration"})


@ns.route('/confirm_email/', methods=['GET'])
class ConfirmEmail(_fr.Resource):
    def get(self):
        token = request.values
        try:
            email = serializer.loads(token.get('token'),
                                     salt='more_salt_please', max_age=300)  # 5'
        except SignatureExpired:
            return 'The link is expired!'
        else:
            services.user.create_user(email)
            return "Register successfully!"


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
            return jsonify({'token': token_login,
                            'success': 'Login successfully!'})


# ==================
@ns.route('/change_password', methods=['POST'])
class ChangePassword(_fr.Resource):
    # @ns.expect(email, old_password, new_password, confirm_password)
    @_jwt.jwt_required
    def post(self):
        data = request.json or request.args
        email = _jwt.get_jwt_identity().get('email')
        try:
            update = services.user.change_password(email=email, **data)
        except Exception as e:
            raise e
        else:
            return jsonify({"successful": "Password changed"})


@ns.route('/confirm_email_forget_password/', methods=['GET'])
class ConfirmEmailForgetPassword(_fr.Resource):
    def get(self):
        token = request.values
        try:
            email = serializer.loads(token.get('token'),
                                     salt='more_salt_please', max_age=300)  # 5'
        except SignatureExpired:
            return 'The link is expired!'
        else:
            # have to update code
            new_random_password = services.user.change_password_after_confirm_forgetting_to_database(email)
            return 'Your new password: ' + new_random_password


@ns.route('/forget_password', methods=['POST'])
class ForgetPassword(_fr.Resource):
    @ns.expect()
    def post(self):
        data = request.json or request.args
        try:
            url = services.user.forget_password(**data)
        except Exception as e:
            raise e
        else:
            return jsonify({'successful': 'Check your email for password verification'})


@ns.route('/logout', methods=['GET'])
class Logout(_fr.Resource):
    def get(self):
        # code
        return jsonify({"status": "logout"})

