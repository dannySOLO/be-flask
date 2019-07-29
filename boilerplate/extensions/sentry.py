# Created by thanhpd on 3/21/2019
import logging

from boilerplate import BadRequestException, UnAuthorizedException, \
    ForbiddenException, NotFoundException

_logger = logging.getLogger(__name__)


def before_send(event, hint):
    """
    Ignore custom exception
    :param event:
    :param hint:
    :return:
    """
    if 'exc_info' in hint:
        exc_type, exc_value, tb = hint['exc_info']
        if isinstance(exc_value, (
                BadRequestException, UnAuthorizedException, ForbiddenException,
                NotFoundException)):
            return None
    return event
