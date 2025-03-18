# Tor

Publisher: Splunk \
Connector Version: 2.0.4 \
Product Vendor: Tor \
Product Name: Tor \
Minimum Product Version: 5.1.0

This app implements investigative actions to query info about the Tor network

### Supported Actions

[test connectivity](#action-test-connectivity) - Validates the connection to the Tor Project website \
[lookup ip](#action-lookup-ip) - Check if IP is a Tor exit node

## action: 'test connectivity'

Validates the connection to the Tor Project website

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'lookup ip'

Check if IP is a Tor exit node

Type: **investigate** \
Read only: **True**

Download a list of current exit nodes to determine if an IP is an exit node. During each action run, if the current list is found to be downloaded over 30 minutes ago, it will download an updated version.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP or list of IPs | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip | string | `ip` | 195.154.251.25 |
action_result.data.\*.ip | string | `ip` | 84.105.18.164 195.154.251.25 |
action_result.data.\*.is_exit_node | boolean | | True False |
action_result.summary.num_exit_nodes | numeric | | 2 1 |
action_result.message | string | | Successfully investigated IPs |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
