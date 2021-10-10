#!/bin/bash

# -------------------------------------------------------------- VARIABLES ---

# Hard coded
export TEST_VARS_VALUE_SUFFIX="$( date +%s )" # Getting unique value
export TEST_OS_SUBNET_RANGE='10.15.15.0/24'

# Initialized automatically
export TEST_TRANSPORT_ZONE='to be taken from ML2 config file'
export TEST_OS_VM_IMAGE_NAME='to be taken from the list of available images'

# This variable will be initialized automatically after creating the network
# TEST_OS_VLAN_ID

# "TEST_VARS_VALUE_SUFFIX" used to make unique values for these variables
export TEST_OS_NETWORK_NAME_R="t_net_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_SUBNET_NAME_R="t_subnet_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_VM_BASE_NAME_R="t_vm_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_TRUNK_PARENT_PORT_R="t_trunk_pp_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R="t_trunk_cp_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_TRUNK_NAME_R="t_trunk_${TEST_VARS_VALUE_SUFFIX}"

# The calling party is expected to initialize these variables
# TEST_NSX_HOSTNAME - NSX FQDN or IP address
# TEST_NSX_USERNAME - NSX user with admin access
# TEST_NSX_PASSWORD - NSX user password
# TEST_ML2_INI_FILE - ML2 ini file. For example '/etc/neutron/plugins/ml2/ml2_conf.ini'

# --------------------------------------------------- set_operation_status ---
set_operation_status() {

    # Local variables definition
    local i=

    # Check for error codes
    for i in "${@}"
    do

        # Check for error
        [ ${i} -eq 0 ] || return ${i}

    done

    # Success. No error code has been met.
    return 0
}

# ----------------------------------------------------------- nsx_api_call ---
nsx_api_call() {

    # Check function parameters
    if ( [ ${#} -ne 2 ] && [ ${#} -ne 3 ] ) || \
        ( [ "${1}x" != "GETx" ] && [ "${1}x" != "POSTx" ] && [ "${1}x" != "DELETEx" ] )
    then

        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <GET|POST|DELETE> <path> [<data>]"
            echo "Example: ${FUNCNAME[0]} \"GET\" \"/api/v1/logical-ports\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local method="${1}"
    local path="${2}"
    local data="${3}"

    # Make an API call
    curl \
        --header 'Content-Type: application/json' \
        --insecure \
        --silent \
        --request "${method}" \
        --user "${TEST_NSX_USERNAME}:${TEST_NSX_PASSWORD}" \
        --data "${data}" \
        "https://${TEST_NSX_HOSTNAME}${path}"

    # Return the operation status
    return ${?}
}

# ----------------------------------------------------- get_logical_switch ---
get_logical_switch() {

    # Local variables definition
    local x=
    local logical_switch_id=
    local logical_switch_name=

    # Get logical switches list
    x="$( nsx_api_call "GET" "/api/v1/logical-switches" )" || {

        # Print an error message
        echo "ERROR: Failed to get logical switches list !"

        # Error indication
        return 1
    }

    # Form our ulogical switch name
    logical_switch_name="${TEST_TRANSPORT_ZONE}-${TEST_OS_VLAN_ID}"

    # Get our logical switch id
    logical_switch_id="$(
        echo "${x}" |
        jq -r '(.results[] | "\(.display_name) \(.id)")' |
        grep '^'"${logical_switch_name}"'\s' |
        awk '{ print $2 }'

        set_operation_status ${PIPESTATUS[@]}
    )" || {

        # Print an info message
        echo "Logical switch \"${logical_switch_name}\" hasn't been found."

        # Error indication
        return 1
    }

    # Print our logical switch name and ID
    echo "${logical_switch_name}"
    echo "${logical_switch_id}"

    # Success indication
    return 0
}

# ------------------------------------------------------ get_logical_ports ---
get_logical_ports() {

    # Check function parameters
    if [ ${#} -ne 1 ]
    then
        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <logical switch id>"
            echo "Example: ${FUNCNAME[0]} \"ab984288-18e2-43c1-872b-7fd52919f28a\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local logical_switch_id="${1}"

    # Local variables definition
    local x=

    # Get logical ports list
    x="$( nsx_api_call "GET" "/api/v1/logical-ports" )" || {

        # Print an error message
        echo "ERROR: Failed to get logical ports list !"

        # Error indication
        return 1
    }

    # Get logical ports belonging to "logical_switch_id"
    echo "${x}" |
    jq -r '.results[] | ("\(.logical_switch_id)|\(.id)|\(.admin_state)|\(.display_name)")' |
    grep '^'"${logical_switch_id}"'|'

    # Set the operation exit code
    set_operation_status ${PIPESTATUS[@]}

    # Return the operation status code
    return ${?}
}

# ------------------------------------------------------ prepare_variables ---
prepare_variables() {

    # Local variables definition
    local vars_to_check=(
        'TEST_NSX_HOSTNAME'
        'TEST_NSX_USERNAME'
        'TEST_NSX_PASSWORD'
        'TEST_ML2_INI_FILE'
    )
    local var_name=
    local var_value=
    local rc=

    # Assume the variables are set
    rc=0

    # Check if the user has setup the expected variables
    for var_name in "${vars_to_check[@]}"
    do
        # Get variable value
        var_value="$( eval echo '"${'"${var_name}"'}"' )"

        # Check the variable value
        if [ "${var_value}x" == "x" ]
        then

            # Print an info message
            echo "Variable \"${var_name}\" is not set !"

            # Indicate there is unset variable
            rc=1
        fi
    done

    # Check for unset variables
    if [ ${rc} -ne 0 ]
    then

        # Error indication
        return 1
    fi

    # Print info messages
    echo "NSX host address : \"${TEST_NSX_HOSTNAME}\""
    echo "NSX username     : \"${TEST_NSX_USERNAME}\""
    echo "NSX INI file     : \"${TEST_ML2_INI_FILE}\""

    # Get the transport zone
    export TEST_TRANSPORT_ZONE="$(
        cat "${TEST_ML2_INI_FILE}" |
        grep '^\s*nsxv3_transport_zone_name\s*=' |
        sed 's/\s//g' |
        awk -F '=' '{ print $2 }'

        set_operation_status ${PIPESTATUS[@]}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get the transport zone !"

        # Error indication
        return 1
    }

    # Print an info message
    echo "Transport zone   : \"${TEST_TRANSPORT_ZONE}\""

    # Get the first image from the list of images
    export TEST_OS_VM_IMAGE_NAME="$(
        openstack image list |
        grep -i '\sactive\s' |
        awk '{ print $4 }' |
        head -n 1

        set_operation_status ${PIPESTATUS[@]}
    )" || {

        # Print an error message
        echo "ERROR: Failed to identify a virtual machine image !"

        # Error indication
        return 1
    }

    # Print an info message
    echo "VM image         : \"${TEST_OS_VM_IMAGE_NAME}\""

    # Success indication
    return 0
}

# -------------------------------------------------------------- create_vm ---
create_vm() {

    # Check function parameters
    if [ ${#} -ne 2 ]
    then

        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <vm name> <max wait seconds>"
            echo "Example: ${FUNCNAME[0]} \"myvm\" \"15\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local vm_name="${1}"
    local wait_max_seconds="${2}"
    local end_time=
    local x=
    local rc=

    # Print an info message
    echo "Trying to create VM \"${vm_name}\" ..."

    # Create the vm
    openstack server create \
        --flavor m1.nano \
        --image "${TEST_OS_VM_IMAGE_NAME}" \
        --network "${TEST_OS_NETWORK_NAME_R}" \
        --port "${TEST_OS_TRUNK_PARENT_PORT_R}" "${vm_name}" || {

        # Print an error message
        echo "ERROR: Failed to create virtual machine \"${vm_name}\""

        # Error indication
        return 1
    }

    # Form the end time to wait to
    end_time=$(( $( date +%s ) + wait_max_seconds ))

    # Waiting for the virtual machine creation
    while [ $( date +%s ) -lt ${end_time} ]
    do

        # Wait before the check.
        x=5
        while [ ${x} -ne 0 ]
        do
            # Print an info message
            printf "\rWaiting ... $( printf "%3d" "$(( end_time - $( date +%s ) ))" ) seconds left."

            # Wait 1 second
            sleep 1

            # Decrement the counter
            x=$(( x - 1 ))
        done

        # Querying VM build status
        printf "\rQuerying VM build status ... "

        # Get the VMs list
        x="$( openstack server list )"

        # Save operation status code
        rc=${?}

        # Clear the line
        printf "\r                               \r"

        # Check the operation status
        if [ ${rc} -ne 0 ]
        then

            # Print an error message
            echo ; echo "ERROR: Failed to get virtual machine \"${vm_name}\" status !"

            # Error indication
            return 1
        fi

        # Extract the virtual machine status
        x="$( echo "${x}" | grep '\s'"${vm_name}"'\s' | awk '{ print $6 }' )"

        # Check the virtual machine for status "ERROR"
        if [ "${x}x" == "ERRORx" ]
        then

            # Print an error message
            echo ; echo "ERROR: Failed to build virtual machine \"${vm_name}\" !"

            # Error indication
            return 1
        fi

        # Check the virtual machine for status "ACTIVE"
        if [ "${x}x" == "ACTIVEx" ]
        then

            # Print an info message
            echo ; echo "Virtual machine \"${vm_name}\" has been successfully built."

            # Success indication
            return 0
        fi

        # If the status is "BUILD" do nothing
    done

    # Print an error message
    echo ; echo "ERROR: Virtual machine \"${vm_name}\" creation timed out !"

    # Error indication
    return 1
}

# --------------------------------------------------------- create_objects ---
create_objects() {

    # Local variables definition
    local x=

    echo && echo "===> Creating openstack objects ..."

    echo "Creating network ..." &&
    x="$( openstack network create "${TEST_OS_NETWORK_NAME_R}" --provider-network-type vlan )" ||
    ( echo "${x}" && false ) &&
    export TEST_OS_VLAN_ID="$(
        echo "${x}" |
        grep '\sprovider:segmentation_id\s' |
        awk '{ print $4 }'
        set_operation_status
    )" &&
    echo "VLAN ID used: ${TEST_OS_VLAN_ID}" &&
    {
        # Get the logical switch
        x="$( get_logical_switch )"
        # Check the operation status
        if [ ${?} -eq 0 ]
        then
            # The logical switch is not expected to exist at that moment
            echo "ERROR: Logical switch \"$( echo "${x}" | head -n 1 )\" already exist in NSX."
            # Set error code
            set_operation_status 250
        else
            # Checking the error message
            if echo "${x}" | grep -q "\shasn't\s\s*been\s\s*found\.$"
            then
                # Print an info message
                echo "Logical switch \"$( echo "${x}" | awk -F '"' '{ print $2 }' )\" doesn't exist, as expected."
            else
                # Print the real message
                echo "${x}"
                # Error indication
                return 1
            fi
        fi
    } &&

    echo "Creating subnet ..." &&
    openstack subnet create "${TEST_OS_SUBNET_NAME_R}" --network "${TEST_OS_NETWORK_NAME_R}" \
      --subnet-range "${TEST_OS_SUBNET_RANGE}" &&

    echo "Creating trunk parent port ..." &&
    openstack port create --network "${TEST_OS_NETWORK_NAME_R}" "${TEST_OS_TRUNK_PARENT_PORT_R}" &&

    echo "Creating trunk child port 1 ..." &&
    openstack port create --network "${TEST_OS_NETWORK_NAME_R}" "${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_1" &&

    echo "Creating trunk child port 2 ..." &&
    openstack port create --network "${TEST_OS_NETWORK_NAME_R}" "${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_2" &&

    echo "Creating trunk ..." &&
    openstack network trunk create --parent-port "${TEST_OS_TRUNK_PARENT_PORT_R}" "${TEST_OS_TRUNK_NAME_R}" &&

    echo "Adding subport \"${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_1\" to the trunk ..." &&
    openstack network trunk set --subport \
        port="${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_1",segmentation-type=vlan,segmentation-id=100 \
        "${TEST_OS_TRUNK_NAME_R}" &&

    echo "Adding subport \"${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_2\" to the trunk ..." &&
    openstack network trunk set --subport \
        port="${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_2",segmentation-type=vlan,segmentation-id=101 \
        "${TEST_OS_TRUNK_NAME_R}" &&
    {
        create_vm "${TEST_OS_VM_BASE_NAME_R}_1" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_2" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_3" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_4" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_5" 180
    }

    # Return the operation status
    return ${?}
}

# -------------------------------------------------------------- check_nsx ---
check_nsx() {

    # Print an info message
    echo && echo "===> Checking for expected NSX configuration ..."

    # Local variables definition
    local x=
    local logical_switch_id=
    local logical_switch_name=
    local logical_ports=
    local my_logical_port=
    local my_logical_port_nsx_admin_state=
    local my_logical_port_nsx_id=
    local my_logical_port_nsx_bindings=
    local pp_os_id=
    local wait_till=
    local seconds_left=
    local message=''

    # ....................................... get parent port openstack ID ...

    # Get openstack ports list
    pp_os_id="$( openstack port list )" || {

        # Print an error message
        echo "ERROR: Cannot get ports list (2) !"

        # Error indication
        return 1
    }

    # Get the expected port id
    pp_os_id="$(
            echo "${pp_os_id}" |
            grep "\s${TEST_OS_TRUNK_PARENT_PORT_R}\s" |
            awk '{ print $2 }'

            set_operation_status ${PIPESTATUS[@]}
        )" || {

        # Print an error message
        echo "The parent trunk port was not found in the openstack configuration. Test failed !"

        # Error indication
        return 2
    }

    # Print an info message
    echo "Identified parent trunk port Openstack ID: \""${pp_os_id}\"

    # ............................................. get logical switch id  ...

    # Form the end time to wait till
    wait_till=$(( $( date +%s ) + 30 ))

    # Wait for logical switch to come up in the NSX configuration
    while true
    do
        # Get logical switch name and id
        x="$( get_logical_switch 2>&1 )" || {

            # Clear the previous line
            printf "\r%s\r" "$( printf "%s" "${message}" | sed 's/./ /g' )"

            # Set output message
            message=${x}" "

            # Calculate the seconds left
            seconds_left=$(( wait_till - $( date +%s ) ))

            # Check for timeout
            if [ ${seconds_left} -le 0 ]
            then

                # Print an info message
                message="${message}Time out ! Test failed !"
                printf "%s\n" "${message}"

                # Error indication
                return 3
            fi

            # Print an info message
            message="${message}Retrying ... ${seconds_left} seconds left."
            printf "%s" "${message}"

            # Sleep for a second
            sleep 1

            # Go for retry
            continue
        }

        # If got the logical switch ID

        # Clear the previous line
        printf "\r%s\r" "$( echo "${message}" | sed 's/.*/ /g' )"

        # Exit the loop
        break
    done

    # Select logical switch name
    logical_switch_name="$( echo "${x}" | head -n 1 )"

    # Select logical switch id
    logical_switch_id="$( echo "${x}" | tail -n 1 )"

    # Print an info message
    echo "Identified logical switch \"${logical_switch_name}\" with ID: \"${logical_switch_id}\""

    # ................................................. get logical ports  ...

    # Get logical ports belonging to "logical_switch_id"
    logical_ports="$( get_logical_ports "${logical_switch_id}" )" || {

        # Check for error messages
        if [ "${logical_ports}x" != "x" ]
        then

            # Print the error message
            echo "${logical_ports}"

            # Error indication
            return 4
        fi

        # Print error messages
        echo "Logical switch \"${logical_switch_name}\" has no logical ports."
        echo "Test failed !"

        # Error indication
        return 5
    }

    # .................................... check my logical port existence ...

    # Get my logical port data
    my_logical_port="$( echo "${logical_ports}" | grep '^.*|.*|.*|'"${pp_os_id}"'$' )"

    # Check if my parent trunk port has been created in the NSX
    if [ "${my_logical_port}x" == "x" ]
    then

        # Print error messages
        echo "Parent port \"${pp_os_id}\" was not found in the NSX configuration."
        echo "Test failed !"

        # Error indication
        return 6
    fi

    # Print error messages
    echo "Parent port \"${pp_os_id}\" was found in the NSX configuration."

    # .................................. check my logical port admin state ...

    # Get my logical port admin state
    my_logical_port_nsx_admin_state="$( echo "${my_logical_port}" | awk -F '|' '{ print $3 }' )"

    # Print error messages
    echo "Parent port \"${pp_os_id}\" NSX admin state is \"${my_logical_port_nsx_admin_state}\"."

    # Check if my logical port admin state is "UP"
    if [ "${my_logical_port_nsx_admin_state}x" != "UPx" ]
    then

        # Print error messages
        echo "Test failed !"

        # Error indication
        return 7
    fi

    # ...................................... check my logical port binding ...

    # Get mu logical port NSX id
    my_logical_port_nsx_id="$( echo "${my_logical_port}" | awk -F '|' '{ print $2 }' )"
    
    # Get my logical port state
    x="$( nsx_api_call "GET" "/api/v1/logical-ports/${my_logical_port_nsx_id}/state" )" || {

        # Print an error message
        echo "ERROR: Failed to get logical port \"${pp_os_id}\" state in NSX !"

        # Error indication
        return 8
    }

    # Get my logical port bindings
    my_logical_port_nsx_bindings="$( echo "${x}" | jq -r '.realized_bindings[].binding | "\(.ip_address) / \(.mac_address)"' )"

    # Check my logical port bindings
    if [ "${my_logical_port_nsx_bindings}x" == "x" ]
    then

        # Print an error message
        echo "Parent port \"${pp_os_id}\" was not bound."
        echo "Test failed !"

        # Error indication
        return 9
    fi

    echo "Parent port \"${pp_os_id}\" NSX bindings:"
    echo "${my_logical_port_nsx_bindings}" | sed 's/^/ - /'

    # ........................................................... finalize ...

    # Print an info message
    echo
    echo "====================================================================="
    echo "============================ TEST PASSED ============================"
    echo "====================================================================="

    # Success indication
    return 0
}

# ------------------------------------------------------------- cleanup_os ---
cleanup_os() {

    # Local variables definition
    local x=
    local y=
    local i=

    echo && echo "===> Cleaning up openstack objects ..."

    # ......................................................... delete VMs ...

    # Get VMs list
    x="$( openstack server list )" || {

        # Print an error message
        echo "ERROR: Cannot get VMs list !"

        # Error indication
        return 1
    }

    # Filter our ports
    x="$(
            echo "${x}" |
            egrep "\s${TEST_OS_VM_BASE_NAME_R}_[0-9]+\s" |
            awk '{ print $4 }'
        )"

    # Check for VMs available
    if [ "${x}x" != "x" ]
    then

        # Loop the ports
        for (( i = 0; i < $( echo "${x}" | wc -l ); i++ ))
        do

            # Get next port
            y="$( echo "${x}" | head -n $(( i + 1 )) | tail -n 1 )"

            # Print an info message
            echo "Deleting VM \"${y}\" ..."

            # Delete the VM
            openstack server delete "${y}" || {

                # Print an error message
                echo "ERROR: Failed to delete VM \"${y}\""

                # Error indication
                return 1
            }
        done

    else
        # Print an info message
        echo "VMs \"${TEST_OS_VM_BASE_NAME_R}_<N>\" do not exist."
    fi

    # ....................................................... delete trunk ...

    # Get trunks list
    x="$( openstack network trunk list )" || {

        # Print an error message
        echo "ERROR: Cannot get trunks list !"

        # Error indication
        return 1
    }

    # Filter our trunks
    x="$( echo "${x}" | grep "\s${TEST_OS_TRUNK_NAME_R}\s" | awk '{ print $4 }' )"

    # Check for trunks available
    if [ "${x}x" != "x" ]
    then

        # Print an info message
        echo "Deleting trunk \"${TEST_OS_TRUNK_NAME_R}\" ..."

        # Delete the trunk
        openstack network trunk delete "${TEST_OS_TRUNK_NAME_R}" || {

            # Print an error message
            echo "ERROR: Failed to delete trunk \"${TEST_OS_TRUNK_NAME_R}\""

            # Error indication
            return 1
        }
    else
        # Print an info message
        echo "Trunk \"${TEST_OS_TRUNK_NAME_R}\" does not exist."
    fi

    # ....................................................... delete ports ...

    # Get ports list
    x="$( openstack port list )" || {

        # Print an error message
        echo "ERROR: Cannot get ports list !"

        # Error indication
        return 1
    }

    # Filter our ports
    x="$(
            echo "${x}" |
            egrep "\s${TEST_OS_TRUNK_PARENT_PORT_R}|${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_[0-9]+\s" |
            awk '{ print $4 }'
        )"

    # Check for ports available
    if [ "${x}x" != "x" ]
    then

        # Loop the ports
        for (( i = 0; i < $( echo "${x}" | wc -l ); i++ ))
        do

            # Get next port
            y="$( echo "${x}" | head -n $(( i + 1 )) | tail -n 1 )"

            # Print an info message
            echo "Deleting port \"${y}\" ..."

            # Delete the port
            openstack port delete "${y}" || {

                # Print an error message
                echo "ERROR: Failed to delete port \"${y}\""

                # Error indication
                return 1
            }
        done

    else
        # Print an info message
        echo "Ports \"${TEST_OS_TRUNK_PARENT_PORT_R}\" and \"${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_<N>\" do not exist."
    fi

    # ...................................................... delete subnet ...

    # Get subnets list
    x="$( openstack subnet list )" || {

        # Print an error message
        echo "ERROR: Cannot get subnets list !"

        # Error indication
        return 1
    }

    # Filter our subnets
    x="$( echo "${x}" | grep "\s${TEST_OS_SUBNET_NAME_R}\s" | awk '{ print $4 }' )"

    # Check for subnets available
    if [ "${x}x" != "x" ]
    then

        # Print an info message
        echo "Deleting subnet \"${TEST_OS_SUBNET_NAME_R}\" ..."

        # Delete the subnet
        openstack subnet delete "${TEST_OS_SUBNET_NAME_R}" || {

            # Print an error message
            echo "ERROR: Failed to delete subnet \"${TEST_OS_SUBNET_NAME_R}\""

            # Error indication
            return 1
        }
    else
        # Print an info message
        echo "Subnet \"${TEST_OS_SUBNET_NAME_R}\" does not exist."
    fi

    # ..................................................... delete network ...

    # Get networks list
    x="$( openstack network list )" || {

        # Print an error message
        echo "ERROR: Cannot get networks list !"

        # Error indication
        return 1
    }

    # Filter our network
    x="$( echo "${x}" | grep "\s${TEST_OS_NETWORK_NAME_R}\s" | awk '{ print $4 }' )"

    # Check for subnets available
    if [ "${x}x" != "x" ]
    then

        # Print an info message
        echo "Deleting network \"${TEST_OS_NETWORK_NAME_R}\" ..."

        # Delete the network
        openstack network delete "${TEST_OS_NETWORK_NAME_R}" || {

            # Print an error message
            echo "ERROR: Failed to delete network \"${TEST_OS_NETWORK_NAME_R}\""

            # Error indication
            return 1
        }
    else

        # Print an info message
        echo "network \"${TEST_OS_NETWORK_NAME_R}\" does not exist."
    fi

    # Success indication
    return 0
}

# ------------------------------------------------------------ cleanup_nsx ---
cleanup_nsx() {

    # Print an info message
    echo && echo "===> Cleaning up NSX objects ..."

    # Local variables definition
    local x=
    local d=
    local i=
    local logical_switch_id=
    local logical_switch_name=
    local logical_ports=
    local rc=

    # ............................................. get logical switch id  ...

    # Get logical switch name and id
    x="$( get_logical_switch )" || {

        # Print the error message
        echo "${x}"

        # Error indication
        return 1
    }

    # Select logical switch name
    logical_switch_name="$( echo "${x}" | head -n 1 )"

    # Select logical switch id
    logical_switch_id="$( echo "${x}" | tail -n 1 )"

    # Print an info message
    echo "Identified logical switch \"${logical_switch_name}\" with ID: \"${logical_switch_id}\""

    # ................................................. get logical ports  ...

    # Get logical ports belonging to "logical_switch_id"
    logical_ports="$( get_logical_ports "${logical_switch_id}" )"

    # Check operation status
    if [ ${?} -ne 0 ]
    then

        # Check for ports availability
        if [ "${logical_ports}x" != "x" ]
        then

            # Print the error message
            echo "${logical_ports}"

            # Error indication
            return 1
        fi

        # Print an info message
        echo "Logical switch \"${logical_switch_name}\" has no logical ports."
    else

        # .......................................... delete logical ports  ...

        # Select only the IDs
        logical_ports="$( echo "${logical_ports}" | awk -F '|' '{ print $2 }' )"

        # No error by default
        rc=0

        # Loop the logical ports
        for (( i = 0; i < $( echo "${logical_ports}" | wc -l ) ; i++ ))
        do

            # Get next logical port
            x="$( echo "${logical_ports}" | head -n $(( i + 1 )) | tail -n 1 )"

            # Delete the logical port
            d="$( nsx_api_call "DELETE" "/api/v1/logical-ports/${x}?detach=true" )" || {

                # Print an info
                echo "ERROR: Failed to delete logical port \"${x}\" !"

                # Error indication
                return 1
            }

            # Check the HTTP error code
            if [ "${d}x" != "x" ] && [ $( echo "${d}" | jq -r '.error_code' ) -ne 0 ]
            then

                # Print an error message
                echo "(LP) HTTP Error message: \"$( echo "$d" | jq -r '.error_message' )\" !"

                # Set the operation error code
                rc=1
            else

                # Print an info message
                echo "Logical port \"${x}\" has been deleted."
            fi
        done

        # If error occurred, then exit
        if [ ${rc} -ne 0 ]
        then

            # Return the operation error code
            return ${rc}
        fi
    fi

    # ............................................. delete logical switch  ...

    # Delete logical switch
    d="$( nsx_api_call "DELETE" "/api/v1/logical-switches/${logical_switch_id}" )" || {

        # Print an info message
        echo "ERROR: Failed to delete logical switch \"${logical_switch_name}\"."

        # Error indication
        return 1
    }

    # Check for HTTP error
    if [ "${d}x" != "x" ] && [ $( echo "${d}" | jq -r '.error_code' ) -ne 0 ]
    then

        # Print an error message
        echo "(LS) HTTP Error message: \"$( echo "$d" | jq -r '.error_message' )\" !"

        # Error indication
        return 1
    fi

    # Print an info message
    echo "Logical switch \"${logical_switch_name} / ${logical_switch_id}\" has been deleted."

    # Success indication
    return 0
}

# ------------------------------------------------------------------- main ---
main() {

    # Local variables definition
    local rc=

    # Prepare variables
    prepare_variables || return 127

    # Create openstack objects
    create_objects

    # Save the operation status
    rc=${?}

    # Check the operation status code
    if [ ${rc} -ne 0 ]
    then

        # Clean up openstack objects
        cleanup_os

        # Check if the logical switch hasn't already been created in NSX
        if [ ${rc} -ne 250 ]
        then

            # Clean up openstack objects
            cleanup_nsx
        fi

        # Exit with the error code
        return ${rc}
    fi

    # Check if the expected configuration in NSX is in place
    check_nsx

    # Save the operation status code
    rc=${?}

    # Clean openstack objects and save the previous error code, if exists
    cleanup_os || rc=$( ( [ ${rc} -eq 0 ] && echo 100 ) || echo ${rc} )

    # Clean nsx configurations and save the previous error code, if exists
    cleanup_nsx || rc=$( ( [ ${rc} -eq 0 ] && echo 101 ) || echo ${rc} )

    # Return the testing operation status code
    return ${rc}
}

# ---------------------------- EXECUTE THE SCRIPT ----------------------------
main "${@}"