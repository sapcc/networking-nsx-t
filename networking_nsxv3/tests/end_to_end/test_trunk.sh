#!/bin/bash

# -------------------------------------------------------------- VARIABLES ---

# Hard coded
export TEST_VARS_VALUE_SUFFIX="$( date +%s )" # Getting unique value
export TEST_OS_SUBNET_RANGE='10.15.15.0/24'

# Initialized automatically
export TEST_TRANSPORT_ZONE='to be taken from ML2 config file'
export TEST_OS_VM_IMAGE_NAME='to be taken from the list of available images'

# Variables for internal usage
# TEST_OS_VLAN_ID           # Will be initialized automatically after creating the network

# "TEST_VARS_VALUE_SUFFIX" used to make unique values for these variables
export TEST_OS_NETWORK_NAME_R="t_net_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_SUBNET_NAME_R="t_subnet_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_VM_BASE_NAME_R="t_vm_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_TRUNK_PARENT_PORT_R="t_trunk_pp_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R="t_trunk_cp_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_TRUNK_NAME_R="t_trunk_${TEST_VARS_VALUE_SUFFIX}"
export TEST_OS_SECURITY_GROUP_NAME_R="t_sg_${TEST_VARS_VALUE_SUFFIX}"

# The calling party is expected to initialize these variables
# TEST_NSX_HOSTNAME - NSX FQDN or IP address
# TEST_NSX_USERNAME - NSX user with admin access
# TEST_NSX_PASSWORD - NSX user password
# TEST_ML2_INI_FILE - ML2 ini file. For example '/etc/neutron/plugins/ml2/ml2_conf.ini'

# Security groups rules to test
export TEST_OS_SG_RULES=(
#    0            1                    2            3                 4
# protocol |   direction |          remote ip | remote group | destination port
  'tcp'      '--ingress'       '101.0.0.0/24'         'None'             '1001'
  'tcp'      '--ingress'       '102.0.0.0/24'         'None'             '1010:2000'
  'tcp'       '--egress'       '103.0.0.0/24'         'None'             '1002'
  'tcp'       '--egress'       '104.0.0.0/24'         'None'             '1020:2000'

  'tcp'      '--ingress'               'None'         'MY_1'             '1101'
  'tcp'      '--ingress'               'None'         'MY_1'             '1110:2000'
  'tcp'       '--egress'               'None'         'MY_1'             '1102'
  'tcp'       '--egress'               'None'         'MY_1'             '1120:2000'

  'udp'      '--ingress'       '201.0.0.0/24'         'None'             '2001'
  'udp'      '--ingress'       '202.0.0.0/24'         'None'             '2010:4000'
  'udp'       '--egress'       '203.0.0.0/24'         'None'             '2002'
  'udp'       '--egress'       '204.0.0.0/24'         'None'             '2020:4000'

  'udp'      '--ingress'               'None'         'MY_1'             '2101'
  'udp'      '--ingress'               'None'         'MY_1'             '2110:4000'
  'udp'       '--egress'               'None'         'MY_1'             '2102'
  'udp'       '--egress'               'None'         'MY_1'             '2120:4000'
)

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

    # Form our logical switch name
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
    jq -r '.results[] | ("\(.logical_switch_id)|\(.id)|\(.admin_state)|\(.display_name)|\(.tags | @base64)")' |
    grep '^'"${logical_switch_id}"'|'

    # Set the operation exit code
    set_operation_status ${PIPESTATUS[@]}

    # Return the operation status code
    return ${?}
}

# -------------------------------------------------- set_security_group_id ---
set_security_group_id() {

    # Check function parameters
    if [ ${#} -ne 2 ]
    then
        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <pattern> <id>"
            echo "Example: ${FUNCNAME[0]} \"MY_1\" \"ac313c98-e771-4255-9d23-3819d9bc3a12\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local pattern="${1}"
    local id="${2}"

    # Local variables definition
    local i=

    # Loop the security group rules
    for (( i = 0; i < ${#TEST_OS_SG_RULES[@]}; i += 5 ))
    do

        # Check / set the security group id if there is a pattern match
        [ "${TEST_OS_SG_RULES[$(( i + 3 ))]}x" == "${pattern}x" ] &&
        TEST_OS_SG_RULES[$(( i + 3 ))]="${id}"
    done

    # Success indication
    return 0
}

# ---------------------------------------------- loop_security_group_rules ---
loop_security_group_rules() {

    # Check function parameters
    if [ ${#} -ne 3 ] || ( [ "${3}x" != "continuex" ] && [ "${3}x" != "stopx" ] )
    then
        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <rules variable name> <handler function> <behaviour on error>"
            echo "Example: ${FUNCNAME[0]} \"TEST_OS_SG_RULES\" \"my_function\" \"stop\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local rules_variable_name="${1}"
    local handler_function="${2}"
    local behaviour_on_error="${3}"

    # Local variables definition
    local i=
    local protocol=
    local direction=
    local remote_ip=
    local remote_group=
    local remote_type=
    local remote_value=
    local destination_port=
    local rc=
    local exit_code=0

    # Loop the security group rules
    for (( i = 0; i < $( eval echo '${#'"${rules_variable_name}"'[@]}' ); i += 5 ))
    do
        # Get next rule parameters
        protocol="$( eval echo '${'"${rules_variable_name}"'['"$(( i + 0 ))"']}' )"
        direction="$( eval echo '${'"${rules_variable_name}"'['"$(( i + 1 ))"']}' )"
        remote_ip="$( eval echo '${'"${rules_variable_name}"'['"$(( i + 2 ))"']}' )"
        remote_group="$( eval echo '${'"${rules_variable_name}"'['"$(( i + 3 ))"']}' )"
        destination_port="$( eval echo '${'"${rules_variable_name}"'['"$(( i + 4 ))"']}' )"

        # Validate the remote target
        [ "${remote_ip}x" == "Nonex" ] && [ "${remote_group}x" == "Nonex" ] && {

            # Print an error message
            echo "ERROR: Security group rules must have either remote IP or remote group !"

            # Error indication
            return 1
        }

        # Identify remote target details
        {
            [ "${remote_ip}x" != "Nonex" ] &&
            {
                remote_type='--remote-ip'
                remote_value="${remote_ip}"
            }
        } || {
            remote_type='--remote-group'
            remote_value="${remote_group}"
        }

        # Cal the handler function
        "${handler_function}" \
            "${protocol}" \
            "${direction}" \
            "${remote_type}" \
            "${remote_value}" \
            "${destination_port}" || {

            # Save the operation status code
            rc=${?}

            # Check for error
            [ ${rc} -ne 0 ] && {

                # If error behaviour is "stop" on error, then exit with the error code
                [ "${behaviour_on_error}x" == "stopx" ] && return ${rc}

                # Save the exit if the behaviour on error is "continue"
                exit_code=${rc}
            }
        }
    done

    # Return the last error code or success
    return ${exit_code}
}

# -------------------------------------------- create_security_group_rules ---
create_security_group_rules() {

    # Check function parameters
    if [ ${#} -ne 2 ]
    then
        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <security group_id> <rules variable>"
            echo "Example: ${FUNCNAME[0]} \"ac313c98-e771-4255-9d23-3819d9bc3a12\" \"TEST_OS_SG_RULES\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local sg_id="${1}"
    local rules_variable_name="${2}"

    # Create a handler for creating security group rules
    _handler_create_security_group_rule() {

        # Local variables definition
        local protocol="${1}"
        local direction="${2}"
        local remote_type="${3}"
        local remote_value="${4}"
        local destination_port="${5}"
        local rc=

        # Print an info message
        echo " > rule: \"${protocol}\" / \"${direction}\" / \"${remote_type}\" \"${remote_value}\" / \"${destination_port}\""

        # Create the security group rule
        openstack security group rule create \
            --protocol "${protocol}" \
            "${direction}" \
            "${remote_type}" "${remote_value}" \
            --dst-port "${destination_port}" \
            "${sg_id}"

        # Save the operation status code
        rc=${?}

        # Print an error message on error detected
        [ ${rc} -ne 0 ] && echo "ERROR: Failed to create security group rule !"

        # Return the operation status code
        return ${rc}
    }

    # Print an info message
    echo "Creating rules in security group: ${sg_id}"

    # Create the security group rules
    loop_security_group_rules "${rules_variable_name}" "_handler_create_security_group_rule" "stop"

    # Return the status code
    return ${?}
}

# --------------------------------------------- check_security_group_rules ---
check_security_group_rules() {

    # Check function parameters
    if [ ${#} -ne 2 ]
    then
        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <security group name> <rules variable>"
            echo "Example: ${FUNCNAME[0]} \"t_sg_1634813369_1\" \"TEST_OS_SG_RULES\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local sg_name="${1}"
    local rules_variable_name="${2}"

    # Local variables definition
    local sg_id=
    local nsx_sections=
    local nsx_sections_parsed=
    local sg_nsx_id=
    local nsx_rules=
    local nsx_rule=

    # Get security group ID
    sg_id="$(
        openstack security group list |
        grep '^|\s\s*\S\S*\s\s*|\s\s*'"${sg_name}"'\s\s*|' |
        awk -F '|' '{ print $2 }' |
        sed 's/^\s*//' |
        sed 's/\s*$//'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get security group \"${sg_name}\" ID !"

        # Error indication
        return 1
    }

    # Print an info message
    echo "Security_group \"${sg_name}\" has ID \"${sg_id}\""

    # Get NSX sections
    nsx_sections="$( nsx_api_call "GET" "/api/v1/firewall/sections" )" || {

        # Print an error message
        echo "ERROR: Failed to get NSX sections !"

        # Error indication
        return 2
    }

    # Parse NSX sections
    nsx_sections_parsed="$(
        echo "${nsx_sections}" |
        jq '.results' |
        grep -v '^null$' |
        jq -r '.[] | ("\(.applied_tos)")' |
        grep -v '^null$' |
        jq -r '.[] | ("\(.target_id)|\(.target_display_name)|\(.target_type)|\(.is_valid)")' |
        grep '|true$' |
        grep '.' # Filter non empty lines. Actually check if the entire result is non empty string.
    )" || {

        # Print an error message
        echo "ERROR: Parsed sections appear as empty list !"

        # Error indication
        return 3
    }

    # Get security group NSX ID
    sg_nsx_id="$(
        echo "${nsx_sections}" |
        jq '.results' | grep -v '^null$' | jq -r '.[] | ("\(.display_name)|\(.id)" )' |
        grep '^'"${sg_id}|" |
        awk -F '|' '{ print $2 }'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print the command output if any
        [ "${sg_nsx_id}x" != "x" ] && echo "${sg_nsx_id}"

        # Print an error message
        echo "ERROR: Failed to get security group \"${sg_name}\" NSX ID !"

        # Error indication
        return 4
    }

    # Print an info message
    echo "Security_group \"${sg_name}\" has NSX ID \"${sg_nsx_id}\""

    # Get NSX rules
    nsx_rules="$(
        nsx_api_call "GET" "/api/v1/firewall/sections/${sg_nsx_id}/rules" 2>&1
    )" || {

        # Print the command output if any
        [ "${nsx_rules}x" != "x" ] && echo "${nsx_rules}"

        # Print an error message
        echo "ERROR: Failed to get NSX rules for security group \"${sg_name}\" !"

        # Error indication
        return 5
    }

    # Checking for valid results
    [ "$( echo "${nsx_rules}" | jq '.results' | grep -v '^null$' )x" == "x" ] && {

        # Print an error message
        echo "ERROR: NSX rules list is not available !"

        # Print the output
        echo "${nsx_rules}"

        # Error indication
        return 6
    }

    # Create a handler for checking security group rules
    _handler_check_security_group_rule() {

        # Local variables definition
        local protocol=$( echo "${1}" | awk '{ print toupper($1) }' )
        local direction="$( { [ "${2}x" == "--ingressx" ] && echo "IN"; } || echo "OUT" )"
        local remote_type="${3}"
        local remote_value="${4}"
        local destination_port="$( echo "${5}" | sed 's/:/-/' )"
        local k=
        local rule=
        local match=0
        local direction_key=
        local remote_type_to_check=
        local remote_value_to_check=

        # Print an info message
        echo -n " ! rule:"
        echo -n " \"${protocol}\""
        echo -n " / \"${direction}\""
        echo -n " / \"${remote_type}\""
        echo -n " / \"${remote_type}\" \"${remote_value}\""
        echo -n " / \"${destination_port}\""
        echo -n " ... "

        # Loop the NSX rules
        for k in $( echo "${nsx_rules}" | jq '.results | keys[]' )
        do
            # Get the next rule
            nsx_rule="$( echo "${nsx_rules}" | jq '.results['"${k}"']' )"
            # echo rule "===============================>>>>>>>>>>---${nsx_rule}---"

            # Checking rule property "resource_type"
            [ "$( echo "${nsx_rule}" | jq -r '.resource_type' )x" == "FirewallRulex" ] || continue

            # Checking rule property "is_default"
            [ "$( echo "${nsx_rule}" | jq -r '.is_default' )x" == "falsex" ] || continue

            # Checking rule property "ip_protocol"
            [ "$( echo "${nsx_rule}" | jq -r '.ip_protocol' )x" == "IPV4x" ] || continue

            # Checking rule property "action"
            [ "$( echo "${nsx_rule}" | jq -r '.action' )x" == "ALLOWx" ] || continue

            # Checking rule property "disabled"
            [ "$( echo "${nsx_rule}" | jq -r '.disabled' )x" == "falsex" ] || continue

            # Checking rule property "direction"
            [ "$( echo "${nsx_rule}" | jq -r '.direction' )x" == "${direction}x" ] || continue

            # Checking source and destination ports
            echo "${nsx_rule}" |
            jq '.services' |
            grep -v '^null$' |
            jq -r '.[].service | ("\(.l4_protocol)|\(.source_ports[])|\(.destination_ports[])|\(.resource_type)")' |
            grep -q "^${protocol}|1-65535|${destination_port}|L4PortSetNSService$" ||
            continue

            # Transforming the direction term
            if [ "${direction}x" == "INx" ]
            then
                direction_key='sources'
            else
                direction_key='destinations'
            fi

            # Transforming the remote type term
            if [ "${remote_type}x" == "--remote-ipx" ]
            then
                remote_type_to_check='IPv4Address'
                remote_value_to_check="${remote_value}"
            else
                remote_type_to_check="$(
                    echo "${nsx_sections_parsed}" |
                    grep '|default.'"${remote_value}"'|' |
                    awk -F '|' '{ print $3 }'
                )"
                remote_value_to_check="$(
                    echo "${nsx_sections_parsed}" |
                    grep '|default.'"${remote_value}"'|' |
                    awk -F '|' '{ print $1 }'
                )"
            fi

            # Perform the check on source/destination target
            echo "${nsx_rule}" |
            jq '.'"${direction_key}" |
            grep -v '^null$' |
            jq -r '.[] | ("\(.is_valid)|\(.target_type)|\(.target_id)")' |
            grep -q "^true|${remote_type_to_check}|${remote_value_to_check}$" ||
            continue

            # Here we have a match
            match=1

            # Exit the loop
            break
        done

        # Check for a match
        [ ${match} -eq 0 ] && {

            # Print an info messages
            echo "failed"

            # Error indication
            return 1
        }

        # Print an info messages
        echo "pass"

        # Success indication
        return 0
    }

    # Print an info message
    echo "Checking the rules in security group: \"${sg_name}\" / \""${sg_id}\"

    # Create the security group rules
    loop_security_group_rules "${rules_variable_name}" "_handler_check_security_group_rule" "stop"

    # Return the status code
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
    if [ ${#} -ne 3 ]
    then

        {
            # Print usage information
            echo
            echo "Usage  : ${FUNCNAME[0]} <vm name> <security group name> <max wait seconds>"
            echo "Example: ${FUNCNAME[0]} \"my_vm\" \"my_sg\" \"15\""
            echo
        } 1>&2

        # Error indication
        return 127
    fi

    # Get function parameters
    local vm_name="${1}"
    local sg_name="${2}"
    local wait_max_seconds="${3}"
    local end_time=
    local x=
    local rc=
    local message=

    # Print an info message
    echo "Trying to create VM \"${vm_name}\" ..."

    # Create the vm
    openstack server create \
        --flavor m1.nano \
        --image "${TEST_OS_VM_IMAGE_NAME}" \
        --network "${TEST_OS_NETWORK_NAME_R}" \
        --security-group "${sg_name}" \
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
            message="$( printf "%d" "$(( end_time - $( date +%s ) ))" ) seconds left. Waiting ... "
            printf "%s"  "${message}"

            # Wait 1 second
            sleep 1

            # Delete the last message
            printf "\r%s\r" "$( echo "${message}" | sed 's/./ /g' )"

            # Decrement the counter
            x=$(( x - 1 ))
        done

        # Print an info message
        message="Querying VM build status ... "
        printf "%s"  "${message}"

        # Get the VMs list
        x="$( openstack server list )"

        # Save operation status code
        rc=${?}

        # Delete the last message
        printf "\r%s\r" "$( echo "${message}" | sed 's/./ /g' )"

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
    local sg_1_id=

    echo && echo "===> Creating openstack objects ... "

    echo "Creating network ..." &&
    {
        x="$( openstack network create "${TEST_OS_NETWORK_NAME_R}" --provider-network-type vlan )" || {
            # Print the command output
            echo "${x}"
            # Operation "openstack network create ..." failed
            false
        }
    }  &&
    echo "${x}" &&
    export TEST_OS_VLAN_ID="$(
        echo "${x}" |
        grep '\sprovider:segmentation_id\s' |
        awk '{ print $4 }'

        set_operation_status ${PIPESTATUS[@]}
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

    echo "Creating subnet ... " &&
    openstack subnet create "${TEST_OS_SUBNET_NAME_R}" --network "${TEST_OS_NETWORK_NAME_R}" \
      --subnet-range "${TEST_OS_SUBNET_RANGE}" &&

    echo "Creating trunk parent port ... " &&
    openstack port create --network "${TEST_OS_NETWORK_NAME_R}" "${TEST_OS_TRUNK_PARENT_PORT_R}" &&

    echo "Creating trunk child port 1 ... " &&
    openstack port create --network "${TEST_OS_NETWORK_NAME_R}" "${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_1" &&

    echo "Creating trunk child port 2 ... " &&
    openstack port create --network "${TEST_OS_NETWORK_NAME_R}" "${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_2" &&

    echo "Creating trunk ... " &&
    openstack network trunk create --parent-port "${TEST_OS_TRUNK_PARENT_PORT_R}" "${TEST_OS_TRUNK_NAME_R}" &&

    echo "Adding subport \"${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_1\" to the trunk ... " &&
    openstack network trunk set --subport \
        port="${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_1",segmentation-type=vlan,segmentation-id=100 \
        "${TEST_OS_TRUNK_NAME_R}" &&

    echo "Adding subport \"${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_2\" to the trunk ... " &&
    openstack network trunk set --subport \
        port="${TEST_OS_TRUNK_CHILD_PORT_BASE_NAME_R}_2",segmentation-type=vlan,segmentation-id=101 \
        "${TEST_OS_TRUNK_NAME_R}" &&

    echo "Creating security group \"${TEST_OS_SECURITY_GROUP_NAME_R}_1\" ... " &&
    {
        {
            x=$( openstack security group create "${TEST_OS_SECURITY_GROUP_NAME_R}_1" 2>&1 ) || {

                # Print the command output
                echo "${x}"

                # Set operation status code
                set_operation_status 1
            }
        } && {

            # Print the command output
            echo "${x}"

            # Get the security group 1 ID
            x="$( echo "${x}" | grep '^|\s\s*id\s\s*|' | awk -F '|' '{ print $3 }' | sed 's/^\s*//' | sed 's/\s*$//' )"
        }
    } &&
    set_security_group_id "MY_1" "${x}" &&
    echo "Identified security group \"${TEST_OS_SECURITY_GROUP_NAME_R}_1\" ID \"${x}\"" &&
    sg_1_id="${x}" &&
    echo "Creating security group \"${TEST_OS_SECURITY_GROUP_NAME_R}_2\" ... " &&
    {
        {
            x=$( openstack security group create "${TEST_OS_SECURITY_GROUP_NAME_R}_2" 2>&1 ) || {

                # Print the command output
                echo "${x}"

                # Set operation status code
                set_operation_status 1
            }
        } && {

            # Print the command output
            echo "${x}"

            # Get the security group 2 ID
            x="$( echo "${x}" | grep '^|\s\s*id\s\s*|' | awk -F '|' '{ print $3 }' | sed 's/^\s*//' | sed 's/\s*$//' )"
        }
    } &&
    set_security_group_id "MY_2" "${x}" &&
    echo "Identified security group \"${TEST_OS_SECURITY_GROUP_NAME_R}_2\" ID \"${x}\"" &&

    create_security_group_rules "${sg_1_id}" "TEST_OS_SG_RULES" &&

    echo "Creating a VM ... " &&
    {
        create_vm "${TEST_OS_VM_BASE_NAME_R}_1" "${TEST_OS_SECURITY_GROUP_NAME_R}_1" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_2" "${TEST_OS_SECURITY_GROUP_NAME_R}_1" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_3" "${TEST_OS_SECURITY_GROUP_NAME_R}_1" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_4" "${TEST_OS_SECURITY_GROUP_NAME_R}_1" 180 ||
        create_vm "${TEST_OS_VM_BASE_NAME_R}_5" "${TEST_OS_SECURITY_GROUP_NAME_R}_1" 180
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
    local my_logical_port_tags=
    local pp_os_id=
    local wait_till=
    local seconds_left=
    local mac_address=
    local ip_address=
    local message=''
    local tag_value=
    local my_sg_id=
    local my_sg_nsx_id=

    # ....................................... get parent port openstack ID ...

    # Get openstack ports list
    x="$( openstack port list )" || {

        # Print an error message
        echo "ERROR: Cannot get ports list (2) !"

        # Error indication
        return 1
    }

    # Get the expected port id
    pp_os_id="$(
            echo "${x}" |
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
    my_logical_port="$( echo "${logical_ports}" | grep '^.*|.*|.*|'"${pp_os_id}"'|' )"

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

    # Print NSX bindings
    echo "Parent port \"${pp_os_id}\" NSX bindings:"
    echo "${my_logical_port_nsx_bindings}" | sed 's/^/ - /'

    # Get openstack parent port IP address and MAC address
    x="$(
        openstack port list |
        grep '^|\s\s*'"${pp_os_id}"'\s\s*|'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get parent port \"${pp_os_id}\" IP and MAC address"
        echo "Test failed !"

        # Error indication
        return 10
    }

    # Extract the MAC addresses
    mac_address="$( echo "${x}" | awk -F '|' '{ print $4 }' | sed 's/\s//g' )"

    # Extract the IP addresses
    ip_address="$( echo "${x}" | awk -F '|' '{ print $5 }' | awk -F "'" '{ print $2 }' )"

    # Check for
    echo "${my_logical_port_nsx_bindings}" | grep -q "^${ip_address} / ${mac_address}$" || {

        # Print an error message
        echo "ERROR: IP/MAC address doesn't match a NSX binding !"
        echo "Test failed !"

        # Error indication
        return 11
    }

    # Print an info message
    echo "Parent port \"${pp_os_id}\" IP/MAC addresses matched a NSX binding"

    # ......................................... check my logical port tags ...

    # Get my logical port tags
    my_logical_port_tags="$(
        echo "${my_logical_port}" |
        awk -F '|' '{ print $5 }' |
        base64 --decode | jq -r '.[] | ("\(.scope)|\(.tag)")'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to parse logical port tags !"
        echo "Test failed !"

        # Error indication
        return 12
    }

    # Getting tag "agent_id"
    tag_value="$(
        echo "${my_logical_port_tags}" |
        grep '^agent_id|' |
        awk -F '|' '{ print $2 }'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get tag \"agent_id\" !"
        echo "Test failed !"

        # Error indication
        return 13
    }

    # Get the expected agent id from the ".INI" file
    x="$(
        cat "${TEST_ML2_INI_FILE}" |
        grep '^\s*agent_id\s*=\s*' |
        sed 's/\s//g' |
        awk -F '=' '{ print $2 }'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get \"agent_id\" from file \"${TEST_ML2_INI_FILE}\" !"
        echo "Test failed !"

        # Error indication
        return 14
    }

    # Compare tag "agent_id" value with the expected one
    [ "${tag_value}x" == "${x}x" ] || {

        # Print an error message
        echo "ERROR: Tag \"agent_id\" value \"${tag_value}\" doesn't match the expected value \"${x}\" !"
        echo "Test failed !"

        # Error indication
        return 15
    }

    # Print an info message
    echo "Tag \"agent_id\" matched the expected value: \"${x}\""

    # Getting tag "age"
    tag_value="$(
        echo "${my_logical_port_tags}" |
        grep '^age|' |
        awk -F '|' '{ print $2 }'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get tag \"age\" !"
        echo "Test failed !"

        # Error indication
        return 16
    }

    # Checking tag "age"
    echo "${tag_value}" | grep -q '^[0-9][0-9]*$' || {

        # Print an error message
        echo "ERROR: Tag \"age\" value \"${tag_value}\" is not zero or positive number !"
        echo "Test failed !"

        # Error indication
        return 17
    }

    # Print an info message
    echo "Tag \"age\" matched the expected value (zero or positive number): \"${tag_value}\""

    # Getting tag "revision_number"
    tag_value="$(
        echo "${my_logical_port_tags}" |
        grep '^revision_number|' |
        awk -F '|' '{ print $2 }'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get tag \"revision_number\" !"
        echo "Test failed !"

        # Error indication
        return 18
    }

    # Checking tag "revision_number"
    echo "${tag_value}" | grep -q '^[0-9][0-9]*$' || {

        # Print an error message
        echo "ERROR: Tag \"revision_number\" value \"${tag_value}\" is not zero or positive number !"
        echo "Test failed !"

        # Error indication
        return 19
    }

    # Print an info message
    echo "Tag \"revision_number\" matched the expected value (zero or positive number): \"${tag_value}\""

    # Getting tag "security_group"
    tag_value="$(
        echo "${my_logical_port_tags}" |
        grep '^security_group|' |
        awk -F '|' '{ print $2 }'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get tag \"security_group\" !"
        echo "Test failed !"

        # Error indication
        return 20
    }

    # Get security group name
    x="$(
        openstack security group list |
        grep '^|\s\s*'"${tag_value}"'\s\s*|' |
        awk -F '|' '{ print $3 }' |
        sed 's/^\s//' |
        sed 's/\s*$//'

        set_operation_status ${PIPESTATUS}
    )" || {

        # Print an error message
        echo "ERROR: Failed to get security group name with ID \"${tag_value}\" !"
        echo "Test failed !"

        # Error indication
        return 21
    }

    # Print an info message
    echo "Tag \"security_group\" matched a valid value: \"${tag_value}\" -> \"${x}\""

    # ...................................... checking security group rules ...

    check_security_group_rules "${TEST_OS_SECURITY_GROUP_NAME_R}_1" "TEST_OS_SG_RULES" || {

        # Print an error message
        echo "ERROR: Security group \"${TEST_OS_SECURITY_GROUP_NAME_R}_1\" check failed !"
        echo "Test failed !"

        # Error indication
        return 22
    }

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

    # Filter our VMs
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

            # Get next VM
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

    # ............................................. delete security groups ...

    # Get security groups list
    x="$( openstack security group list )" || {

        # Print an error message
        echo "ERROR: Cannot get security groups list !"

        # Error indication
        return 1
    }

    # Filter our security groups
    x="$(
            echo "${x}" |
            egrep "\s${TEST_OS_SECURITY_GROUP_NAME_R}_[0-9]+\s" |
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
            echo "Deleting security group \"${y}\" ..."

            # Delete the VM
            openstack security group delete "${y}" || {

                # Print an error message
                echo "ERROR: Failed to delete security group \"${y}\""

                # Error indication
                return 1
            }
        done

    else
        # Print an info message
        echo "Security groups \"${TEST_OS_SECURITY_GROUP_NAME_R}_<N>\" do not exist."
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

    # Check the operation status
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

        # Check if OS/NSX objects have been created at all
        [ "${TEST_OS_VLAN_ID}x" != "x" ] || return ${rc}

        # Clean up openstack objects
        cleanup_os

        # Check if the logical switch already exists in NSX
        if [ ${rc} -ne 250 ]
        then

            # Clean up NSX objects
            cleanup_nsx
        fi

        # Print an info message
        echo "FINISHED !"

        # Exit with the error code
        return ${rc}
    fi

    # Check if the expected configuration in NSX is in place
    check_nsx

    # Save the operation status code
    rc=${?}

#echo -n 'Sleeping ... ' && sleep 9999999129999999

    # Clean openstack objects and save the previous error code, if not zero (success)
    cleanup_os || rc=$( ( [ ${rc} -eq 0 ] && echo 100 ) || echo ${rc} )

    # Clean nsx configurations and save the previous error code, if not zero (success)
    cleanup_nsx || rc=$( ( [ ${rc} -eq 0 ] && echo 101 ) || echo ${rc} )

    # Print an info message
    echo "FINISHED."

    # Return the testing operation status code
    return ${rc}
}

# ---------------------------- EXECUTE THE SCRIPT ----------------------------
main "${@}"
