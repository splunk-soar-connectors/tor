# --
# File: tor_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import os
import time
import json
import requests


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class TordnselConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TordnselConnector, self).__init__()
        self._state = None

    def _parse_exit_list(self, action_result, exit_list):
        ip_set = set()
        for line in exit_list.splitlines():
            if line.startswith('ExitAddress'):
                try:
                    ip_set.add(line.split()[1])
                except:
                    pass
        return phantom.APP_SUCCESS, ip_set

    def _download_save_list(self, action_result, exit_list_path):
        self.save_progress("Updating exit node list")
        r = requests.get('https://check.torproject.org/exit-addresses')
        if r.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, "Error from server: {}".format(r.text))
        try:
            fp = open(exit_list_path, 'w')
            fp.write(r.text)
            fp.close()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error writing to file", e)
        return phantom.APP_SUCCESS

    def _init_list(self, action_result):
        download_list_interval = 30
        exit_list_path = '{}/tor_exit_list.txt'.format(os.path.dirname(os.path.abspath(__file__)))
        cur_time = int(time.time())
        last_updated = self._state.get('last_updated')
        is_list = os.path.isfile(exit_list_path)
        if not last_updated and is_list:
            # Someone has either created a new asset or touched the state dir
            self._state['last_updated'] = cur_time
        elif not last_updated and not is_list:
            # Probably first run of the app
            ret_val = self._download_save_list(action_result, exit_list_path)
            if phantom.is_fail(ret_val):
                return ret_val, None
            self._state['last_updated'] = cur_time
        elif last_updated and not is_list:
            # They have actively muddled with the app directory at this point
            ret_val = self._download_save_list(action_result, exit_list_path)
            if phantom.is_fail(ret_val):
                return ret_val, None
            self._state['last_updated'] = cur_time
        else:
            # See if we should update the list
            diff_seconds = cur_time - last_updated  # Time since last update
            diff_minutes = diff_seconds / 60
            if diff_minutes > download_list_interval:
                # Update list
                ret_val = self._download_save_list(action_result, exit_list_path)
                if phantom.is_fail(ret_val):
                    return ret_val, None
                self._state['last_updated'] = cur_time

        try:
            fp = open(exit_list_path, 'r')
            exit_list = fp.read()
            fp.close()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error reading from file", e), None

        ret_val, ip_set = self._parse_exit_list(action_result, exit_list)
        if phantom.is_fail(ret_val):
            return ret_val, None
        return phantom.APP_SUCCESS, ip_set

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, ip_set = self._init_list(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)
            return ret_val
        self.save_progress("Test Connectivity Passed")
        return self.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, ip_set = self._init_list(action_result)
        if phantom.is_fail(ret_val):
            return ret_val
        ips = param['ip']
        for ip in ips.split(','):
            ip = ip.strip()
            data = {}
            data['ip'] = ip
            if ip in ip_set:
                data['is_exit_node'] = True
            else:
                data['is_exit_node'] = False
            action_result.add_data(data)

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

    import sys
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TordnselConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
