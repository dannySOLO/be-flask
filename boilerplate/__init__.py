# coding=utf-8
import logging

import flask
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from boilerplate.extensions.exceptions import NotFoundException, \
    UnAuthorizedException, BadRequestException, ForbiddenException
from boilerplate.extensions.sentry import before_send
from flask_cors import CORS

__author__ = 'ThucNC' + ''
_logger = logging.getLogger(__name__)

SENTRY_DSN = 'SENTRY_DSN'


def create_app():
    import config
    import logging.config
    import os

    from . import api, models
    from boilerplate import helpers

    def load_app_config(app):
        """
        Load app's configurations
        :param flask.Flask app:
        :return:
        """
        app.config.from_object(config)
        app.config.from_pyfile('config.py', silent=True)

    app = flask.Flask(
        __name__,
        instance_relative_config=True,
        instance_path=os.path.join(config.ROOT_DIR, 'instance')
    )
    app.json_encoder = helpers.JSONEncoder
    load_app_config(app)

    # Register new flask project here and get new dsn: https://sentry.io
    dns = SENTRY_DSN if os.environ.get(
        'SEND_REPORT') == 'true' else None

    app.config['SENTRY_CONFIG'] = {
        'ignore_exceptions': [NotFoundException, UnAuthorizedException,
                              BadRequestException, ForbiddenException],
        'level': logging.ERROR,
    }

    sentry_sdk.init(
        dsn=dns,
        integrations=[FlaskIntegration()],
        environment=app.config['ENV_MODE'],
        in_app_exclude=['app.extensions.exceptions'],
        before_send=before_send
    )

    # setup logging
    logging.config.fileConfig(app.config['LOGGING_CONFIG_FILE'],
                              disable_existing_loggers=False)

    app.secret_key = config.FLASK_APP_SECRET_KEY
    models.init_app(app)
    api.init_app(app)
    return app


app = create_app()
jwt = JWTManager(app)
cors = CORS(app)
mail = Mail(app)

