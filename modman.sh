#!/bin/bash
source ~/.bashrc

Tid=" "

# Ask the user for abosulte path of the audit.log.xz
dateArray=($(ls /var/log/httpd/modsec_audit*.xz))

PS3='Please pick the date from the following: '

select date in "${dateArray[@]}"
do
        case $date in
        $date)
           echo $date
                break
                ;;
        *) echo "invalid option $REPLY"
                ;;
        esac
done

# Ask the user for domain name to check in modsec_audit.log then normalize the domainname.
read -p "Input domain name: " domainname
domainname=$(sup_normalizedomain $domainname)

#echo $domainname                                       #//For Debugging


# Ask the user the URL
read -p "Input URL: " uri

# Ask the user the Client IP
iptest='([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
until [[ $Cip =~ ^$iptest\.$iptest\.$iptest\.$iptest$ ]]
do
  read -p "Input valid Client IP: " Cip
done



# Ask the user the Ticket ID
read -p "Input Ticket ID (optional): " Tid

#echo "$date $domainname $uri $Cip"                            #//For Debugging

# Stores the Modsec Unique IDs in an array 'rules'
rules=( $( xzcat $date | grep $domainname | grep $uri | grep ${Cip} | grep 'Pattern match' | cut -d " " -f 2 | awk -F ',' '{print $2}' | awk -F ':' '{print $2}' | sed s/\"//g) );

#for element in "${rules[@]}"; do echo "${element}"; done     #//For Debugging

# Basically runs sup_modsecrules on the modsec Unique IDs from the array 'rules' and filters out duplicate ones and forbidden modsec rules and prints out the final output.
echo " "
echo "<IfModule mod_security2.c>
  <LocationMatch $uri >
   #Ticket: $Tid   "
for element in "${rules[@]}"; do sup_catlogs $date | grep --color=auto -F "${element}" | grep --color=auto -Po ' \[id\s+\\"\K[0-9]*' | grep -v "^981176$\|^4011015$\|^4049" | sort -u; done |  sort -u | sed 's/^/   SecRuleRemoveById /'
echo "  </LocationMatch>
</IfModule>"
