[comment]: # "Auto-generated SOAR connector documentation"
# Tor

Publisher: Splunk  
Connector Version: 2\.0\.3  
Product Vendor: Tor  
Product Name: Tor  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app implements investigative actions to query info about the Tor network

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validates the connection to the Tor Project website  
[lookup ip](#action-lookup-ip) - Check if IP is a Tor exit node  

## action: 'test connectivity'
Validates the connection to the Tor Project website

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Check if IP is a Tor exit node

Type: **investigate**  
Read only: **True**

Download a list of current exit nodes to determine if an IP is an exit node\. During each action run, if the current list is found to be downloaded over 30 minutes ago, it will download an updated version\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP or list of IPs | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_exit\_node | boolean | 
action\_result\.summary\.num\_exit\_nodes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 