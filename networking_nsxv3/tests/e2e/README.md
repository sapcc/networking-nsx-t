# Prerequisites
1. vSphere vCenter 8 with at least one Cluster (Building Block)
2. NSX 4.x with configured VDS for the vCsphere Cluster from the previous req.
3. Openstack Deployment with Agent and Driver running
4. The Openstack "default" Security Group must exists and at least one realized and active port to be a member of it.
5. Pre-existing Openstack network and server are required (see the ENV vars: E2E_NETWORK_NAME and E2E_SERVER_NAME).
6. The following environment variables are needed for the E2E tests (e.g. ../developer/rc):
   ```bash
   # NSX vars
   export NSXV3_LOGIN_HOSTNAME="nsx-l-01a.corp.local" # NSX Hostname or IP address
   export NSXV3_LOGIN_PORT=443 # NSX HTTPS port
   export NSXV3_LOGIN_USER="admin" # NSX Service Account USER used by the Agent
   export NSXV3_LOGIN_PASSWORD="password" # NSX Service Account PASSWORD used by the Agent
   export NSXV3_TRANSPORT_ZONE_NAME="bb095-vlan" # The NSX Transport Zone on which the Agent will execute the tests (Building Block)
   
   # OpenStack vars
   export OS_HTTPS=0 # 0 use HTTP, 1 use HTTPS
   export OS_HOSTNAME="os-l-01.corp.local" # OpenStack Hostname or IP address
   export OS_USERNAME="admin" # Openstack Service Account USER
   export OS_PASSWORD="password" # Openstack Service Account PASSWORD
   export OS_PROJECT_NAME="admin" # Openastack Project name on which the E2E test wil run
   export OS_PROJECT_DOMAIN_ID="default" # Openastack Project Domain ID on which the E2E test wil run
   export OS_USER_DOMAIN_ID="default" # Openastack User Domain ID on which the E2E test wil run
   
   # Tox vars
   export OS_LOG_CAPTURE=0
   export OS_STDOUT_CAPTURE=0
   export OS_STDERR_CAPTURE=0

   # E2E Test specific vars
   export E2E_NETWORK_NAME="test-net-1" # Pre-existing Network used for the E2E Test Scenarios
   export E2E_SERVER_NAME="os-test-vm-1" # Pre-existing VM (server) used for the E2E Test Scenarios
   export E2E_CREATE_SERVER_NAME_PREFIX="os-e2e-test-" # Prefix for server names, UUID will be appended
   export E2E_CREATE_SERVER_IMAGE_NAME="cirros-0.3.2-i386-disk" # Image name to use for server creation
   export E2E_CREATE_SERVER_FLAVOR_NAME="m1.nano" # Flavor name to use for server creation
   ```

# Run the E2E Tests
   ```bash
   source ../developer/rc
   tox -e e2e
   ```

# End-to-End Test Scenarios

## Ports E2E Tests
   - Create/Delete a standalone port [implemented]
   - Attach/Detach port to/from VM [implemented]
   - Create server (auto-create port) [implemented]
   - Assign/Unassign IPv4/IPv6 address [implemented]
## QOS E2E Tests
   - Create/Delete QoS Policy
   - Assign/Remove QoS Policy to/from port
## Trunk E2E Tests
   - Create/Delete trunk
   - Add/Remove ports to/from trunk
   - Add/Remove trunk to/from server
   - Provision server with trunk
## Security Groups & Policies
   - Create/Delete/Update Security Groups (Remote IP)
   - Create/Delete/Update Security Groups (Remote Group)
   - Add/Remove rules to Security Groups
   - Add/Remove ports to/from Security Group
## Address Groups
   - Create/Delete/Update IPv4/IPv6 address groups [implemented]
   - Create mixed IPv4/IPv6 members [implemented]
   - Address group in multiple security groups [implemented]