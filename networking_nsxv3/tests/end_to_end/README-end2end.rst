************************************************
Openstack NSXv3 driver end to end testing script
************************************************

1. Programming language
#######################
- bash

2. Script location
#####################################################################################
- networking-nsx-t/networking_nsxv3/tests/end_to_end/test_trunk.sh

3. Command line paramters
#########################
- None

4. Environment variables expected by the script
###################################################
- TEST_NSX_HOSTNAME - NSX FQDN or IP address
- TEST_NSX_USERNAME - NSX user with admin access
- TEST_NSX_PASSWORD - NSX user password
- TEST_ML2_INI_FILE - ML2 ini file. For example '/etc/neutron/plugins/ml2/ml2_conf.ini'

5. Script logic
###############

**openstack** command line tool is used to manage Openstack resources - *create, read* and *delete* operations

1. Check/Prepare environment
____________________________
2. Create openstack objects
___________________________

- network
- subnet
- network ports
- trunk with parent port and subports
- security groups
- security group rules
- virtual machine

3. Check NSX for expected configuration
_______________________________________
4. Cleanup openstack objects
____________________________
5. Cleanup NSX configuration
____________________________

- logical ports created by the script
- logical switch created by the script

6. How to add/remove security group rules
_________________________________________
TEST_OS_SG_RULES is an environment variables created/checked by the script. It contains a list of rules definitions, one per line.
You can create as many rules as you wish. They will be automatically created without changing rhe program code.

**Currently supported rules** are "**tcp**" and "**udp**" types. 

"**icmp**" rules are **not supported**.
