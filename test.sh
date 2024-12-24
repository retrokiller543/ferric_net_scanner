#!/bin/bash

# Read SNMP response from stdin
SNMP_RESPONSE=$(cat)

# Debugging step: Print out the response
echo "$SNMP_RESPONSE"

# Extract the indices of interfaces where ifAdminStatus is 1 (up)
ACTIVE_ADMIN_INDICES=$(echo "$SNMP_RESPONSE" | grep -E 'iso\.3\.6\.1\.2\.1\.2\.2\.1\.7\.[0-9]+ = INTEGER: 1' | awk -F '[ .]' '{print $(NF-1)}')

# Extract the indices of interfaces where ifOperStatus is 1 (up)
ACTIVE_OPER_INDICES=$(echo "$SNMP_RESPONSE" | grep -E 'iso\.3\.6\.1\.2\.1\.2\.2\.1\.8\.[0-9]+ = INTEGER: 1' | awk -F '[ .]' '{print $(NF-1)}')

# Debugging step: Print out the active admin and oper indices
echo "Active Admin Indices: $ACTIVE_ADMIN_INDICES"
echo "Active Oper Indices: $ACTIVE_OPER_INDICES"

# Find the common indices that are active in both admin and oper status
ACTIVE_INDICES=$(echo "$ACTIVE_ADMIN_INDICES" "$ACTIVE_OPER_INDICES" | tr ' ' '\n' | sort | uniq -d)

# Debugging step: Print out the active indices
echo "Active Indices: $ACTIVE_INDICES"

# Extract details of the active interfaces based on their indices
for INDEX in $ACTIVE_INDICES; do
    echo "Interface Index: $INDEX"
    echo "$SNMP_RESPONSE" | grep -E "iso\.3\.6\.1\.2\.1\.2\.2\.1\.(2|5|6|10|16)\.$INDEX = " | \
    awk -F' = ' '{print $1 ": " $2}'
    echo ""
done
