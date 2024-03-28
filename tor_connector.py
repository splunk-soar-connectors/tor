# File: tor_connector.py
#
# Copyright (c) 2017-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import json
# Usage of the consts file is recommended
import time

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from tor_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class TordnselConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TordnselConnector, self).__init__()
        self._state = None

    def _parse_exit_list(self, action_result, exit_list):
        ip_list = []
        for line in exit_list.splitlines():
            if line.startswith('ExitAddress'):
                try:
                    ip_list.append(line.split()[1])
                except:
                    pass
        return phantom.APP_SUCCESS, ip_list

    def _parse_exit_list_past_16_hours(self, action_result, exit_list):
        ip_list = []
        for line in exit_list.splitlines():
            if not line.startswith('#'):
                try:
                    ip_list.append(line)
                except:
                    pass
        return phantom.APP_SUCCESS, ip_list

    def _download_save_list(self, action_result, cur_time, ips):
        self.save_progress("Updating exit node list")
        try:
            r = requests.get('https://check.torproject.org/exit-addresses', timeout=DEFAULT_TIMEOUT)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving exit node list", e)
        if r.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, "Error from server: {}".format(r.text))
        exit_lits = r.text
        ret_val, ip_list_exit_address = self._parse_exit_list(action_result, exit_lits)
        ip_list_past_16_hours = []
        if ips:
            multiple_ips = ips.split(',')
            for ip in multiple_ips:
                try:
                    res = requests.get(
                        'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={}'.format(ip.strip()),
                        timeout=DEFAULT_TIMEOUT)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error retrieving exit node list", e)

                if res.status_code == 200:
                    ret_val, ip_list_past_16_hour = self._parse_exit_list_past_16_hours(action_result, res.text)
                    ip_list_past_16_hours = ip_list_past_16_hours + ip_list_past_16_hour

        if phantom.is_fail(ret_val):
            return ret_val

        ip_list = list(set(ip_list_exit_address + ip_list_past_16_hours))
        self._state['ip_list'] = ip_list
        self._state['last_updated'] = cur_time
        return phantom.APP_SUCCESS

    def _init_list(self, action_result, force_update=False, ips=None):
        download_list_interval = 30
        cur_time = int(time.time())
        last_updated = self._state.get('last_updated')
        is_list = True if self._state.get('ip_list') else False
        if force_update:
            ret_val = self._download_save_list(action_result, cur_time, ips)
            if phantom.is_fail(ret_val):
                return ret_val, None
        elif not last_updated and is_list:
            # Someone has either created a new asset or touched the state dir
            self._state['last_updated'] = cur_time
        elif not last_updated and not is_list:
            # Probably first run of the app
            ret_val = self._download_save_list(action_result, cur_time, ips)
            if phantom.is_fail(ret_val):
                return ret_val, None
        elif last_updated and not is_list:
            # They have actively muddled with the app directory at this point
            ret_val = self._download_save_list(action_result, cur_time, ips)
            if phantom.is_fail(ret_val):
                return ret_val, None
        else:
            # See if we should update the list
            diff_seconds = cur_time - last_updated  # Time since last update
            diff_minutes = diff_seconds / 60
            if diff_minutes > download_list_interval:
                # Update list
                ret_val = self._download_save_list(action_result, cur_time, ips)
                if phantom.is_fail(ret_val):
                    return ret_val, None

        ip_set = set(self._state['ip_list'])
        return phantom.APP_SUCCESS, ip_set

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, ip_set = self._init_list(action_result, force_update=True)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)
        self.save_progress("Test Connectivity Passed")
        return self.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        num_exit_nodes = 0
        action_result = self.add_action_result(ActionResult(dict(param)))
        ips = param['ip']
        ret_val, ip_set = self._init_list(action_result, ips=ips)
        if phantom.is_fail(ret_val):
            return ret_val
        ips = [x.strip() for x in ips.split(',')]
        ips = list(filter(None, ips))
        self.save_progress("")
        for ip in ips:
            data = {}
            data['ip'] = ip
            if ip in ip_set:
                data['is_exit_node'] = True
                num_exit_nodes += 1
            else:
                data['is_exit_node'] = False
            action_result.add_data(data)

        action_result.update_summary({'num_exit_nodes': num_exit_nodes})
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully investigated IPs")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)
        elif action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        login_url = BaseConnector._get_phantom_base_url() + "login"

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TordnselConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
