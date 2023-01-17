""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json

import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('manage-engine-key-manager-plus')


class ManageEngine:
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            self.server_url = self.server_url.strip('/')
        else:
            self.server_url = 'https://{0}'.format(self.server_url)
        self.token = config.get('token')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, endpoint=None, params=None, method='POST', data=None):
        url = '{0}{1}{2}'.format(self.server_url, '/api/pki/restapi/', endpoint)
        logger.info('Request URL {}'.format(url))
        headers = {
            'AUTHTOKEN': self.token,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.request(method=method, url=url,
                                        params=params, headers=headers, data=data, verify=self.verify_ssl)
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            elif response.status_code == 404:
                return response
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def get_ssh_keys(config, params=None):
    me = ManageEngine(config)
    response = me.make_api_call('getAllSSHKeys', method='GET')
    return response


def get_ssl_certificates(config, params):
    me = ManageEngine(config)
    search_type = params.get('search_type')
    time_out = str(params.get('time_out'))
    port = str(params.get('port'))
    if search_type == 'Hostname/IP Address':
        host = params.get('host')
        input_data = str({"operation": {"Details": {"HOST": host, "TIMEOUT": time_out, "PORT": port}}}).replace(" ", "")
        payload = 'INPUT_DATA={0}'.format(input_data)
        endpoint = 'sslCertSingleDiscovery'
    else:
        start_ip = params.get('start_ip')
        end_ip = params.get('end_ip')
        input_data = str({"operation": {"Details": {"StartIpAddress": start_ip, "EndIpAddress": end_ip,
                                                    "TIMEOUT": time_out, "PORT": port}}}).replace(" ", "")
        payload = 'INPUT_DATA={0}'.format(input_data)
        endpoint = 'sslCertRangeDiscovery'
    response = me.make_api_call(endpoint, data=payload)
    return response


def update_credentials(config, params):
    me = ManageEngine(config)
    resource_name = params.get('resource_name')
    user_name = params.get('user_name')
    password = params.get('password')
    is_admin = "true" if params.get('is_admin') is True else "false"
    input_data = str({"operation": {"Details": {"userName": user_name, "password": password,
                                    "resourceName": resource_name, "isAdmin": is_admin}}}).replace(" ", "")
    payload = 'INPUT_DATA={0}'.format(input_data)
    response = me.make_api_call('applycredentials', data=payload)
    return response


def check_health(config):
    try:
        response = get_ssh_keys(config)
        if response:
            return True
    except Exception as Err:
        logger.exception('Error occurred while connecting server: {}'.format(str(Err)))
        raise ConnectorError('Error occurred while connecting server: {}'.format(Err))


operations = {
    'get_ssh_keys': get_ssh_keys,
    'get_ssl_certificates': get_ssl_certificates,
    'update_credentials': update_credentials
}
