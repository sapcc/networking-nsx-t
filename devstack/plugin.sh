# plugin.sh - DevStack plugin.sh dispatch script template
# Following the exampel of https://opendev.org/openstack/networking-bgpvpn/src/branch/master/devstack/plugin.sh

if [[ "$1" == "source" ]]; then
    # no-op
    :
elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    # Perform installation of service source
    echo_summary "Installing Networking-NSX-T"
    setup_develop $NETWORKING_NSX_T_DIR
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    # Configure after the other layer 1 and 2 services have been configured
    echo_summary "Configuring Networking-NSX-T"

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    # Initialize and start the NSX-T service
    echo_summary "Initializing Networking-NSX-T"
fi
