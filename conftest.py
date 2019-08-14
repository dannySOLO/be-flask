# coding=utf-8
import logging

import pytest

__author__ = 'Kien'
_logger = logging.getLogger(__name__)


@pytest.fixture(scope="class", autouse=True)
def app(request):
    from boilerplate import app
    from boilerplate.models import db

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    # test db initializations go below here
    db.create_all()

    def teardown():
        db.session.remove()
        db.drop_all()
        ctx.pop()

    request.addfinalizer(teardown)
    return app

