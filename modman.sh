#!/bin/bash
source ~/.bashrc
# Ask the user for abosulte path of the audit.log.xz
read -p "Input abosulte path of the audit.log.xz file: " auditfile

# Ask the user for domain name to check in modsec_audit.log.
read -p "Input domain name: " domainname

# Ask the user the URL
read -p "Input URL: " uri

# Ask the user the Client IP
read -p "Input Client IP: " Cip

# saves the value of the triggered modsec unique id in $rules.
rules=( $( xzcat $auditfile | grep $domainname | grep $uri | grep ${Cip} | grep 'Pattern match' | cut -d " " -f 2 | awk -F ',' '{print $2}' | awk -F ':' '{print $2}' | sed s/\"//g) );

#Finds the modsec rules to be whitelisted based on the unique id.
for element in "${rules[@]}"; do echo "${element}"; sup_catlogs $auditfile | grep --color=auto -F "${element}" | grep --color=auto -Po ' \[id\s+\\"\K[0-9]*' | grep -v "^981176$\|^4011015$\|^4049" | sort -u; echo " " ;done
