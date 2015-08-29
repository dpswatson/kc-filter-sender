#!/bin/bash

# Path to the store directory. This much match the path specified in the Kerio Admin Console
# under Settings > Advanced Options > Store Directory
STOREDIR="/opt/kerio/mailserver/store"

# Name of the filter rule to be created and modified by this script. Once you go live, do not change this value.
RULENAME="Blocked Spam Senders"

# Path to the log file. Set to "stdout" to log messages to the screen.
LOGFILE="/opt/kerio/mailserver/store/logs/senderblock.log"


#--------------------------------------------------------------------------------------------

DEBUGFILE='/opt/ni/spamsenderblock/debug.log'

debug () {
    echo "$1=${!1}" >> "$DEBUGFILE"
}

#--------------------------------------------------------------------------------------------

# Get the line from the spam log in stdin
read LOGLINE
#debug LOGLINE

NOTSPAM="marked a message as not spam"

# Check if "marked as not spam" 
[[ $LOGLINE == *"$NOTSPAM"* ]] &&	ACTION="remove" || ACTION="add"
#debug ACTION

# Extract the Kerio mailbox the block applies to
MAILBOX=$(echo "$LOGLINE" | grep -i -o '[A-Z0-9._%+-]\+@[A-Z0-9.-]\+\.[A-Z]\{2,4\}' | head -1)
#debug MAILBOX

# Extract the address to be blocked/removed
BLOCKADDR=$(echo "$LOGLINE" | grep -i -o '<[A-Z0-9._%+-]\+@[A-Z0-9.-]\+\.[A-Z]\{2,4\}>' | sed 's/[<>]/\"/g')
#debug BLOCKADDR

# Get the path to the filter file and make a backup copy
SIVFILE="${STOREDIR}/mail/${MAILBOX##*@}/${MAILBOX%@*}/filter.siv"
cp "$SIVFILE" "${SIVFILE}.old"
#debug SIVFILE

# Extract the current block rule from the filter file (if it exists)
CURRULE=$(sed -n "/#!1 ${RULENAME}/,/}/p" "$SIVFILE")
#debug CURRULE

# Get all the other rules without the current block rule
OTHERRULES=$(sed "/#!1 ${RULENAME}/,/}/d" "$SIVFILE")
#debug OTHERRULES

# Get the line no. of the block rule in the filter file (if it exists)
RULELNNO=$(grep -F -n -m 1 "$RULENAME" "$SIVFILE" | cut -d : -f 1)
#debug RULELNNO

# Start assembling the new rule
NEWRULE="#!1 ${RULENAME}\r\n"

# Check if the rule currently exists
if [ "$RULELNNO" == "" ]; then 
#echo "rule doesn't exist" >> "$DEBUGFILE"

	# If we're removing, there's nothing more to do
	[ "$ACTION" == "remove" ] && exit 0

	# Set the line no. at the end of the first rule in the file (which should be after the standard Junk E-mail filter)
	RULELNNO=$(($(grep -n -m 1 -e '^}[[:space:]]$' "$SIVFILE" | cut -d : -f 1)+1))
	#debug RULELNNO

	# We'll need a blank line in front of the new rule
	NEWRULE="\r\n${NEWRULE}"

	# Since the rule is new, the only address to block is the one we're adding
	CURADDR="${BLOCKADDR}"

else 
#echo "rule already exists" >> "$DEBUGFILE"

	# Extract all the other addresses in the current rule
	CURADDR=$(echo "$CURRULE" | grep -i -o '\"[A-Z0-9._%+-]\+@[A-Z0-9.-]\+\.[A-Z]\{2,4\}\"')
	#debug CURADDR
	
	# Check if our block address is already on the list.
	if [[ $CURADDR == *$BLOCKADDR* ]]; then
	#echo "address is already on list" >> "$DEBUGFILE"
	
		# If we're adding, there's nothing more to do
		[ "$ACTION" == "add" ] && exit 0
		
		# Remove the address from the list
		CURADDR=$(echo -e "$CURADDR" | grep -vF "$BLOCKADDR")
		#debug CURADDR
		
	else
	#echo "address is not on list" >> "$DEBUGFILE"
	
		# If we're adding, append address to the list. If we're removing, we're done
		[[ "$ACTION" == "add" ]] && CURADDR=$(echo -e "${CURADDR}\n${BLOCKADDR}") || exit 0
		#debug CURADDR 
	fi
fi

# We now have all the addresses to block, one address per line. 
# I might do something with that at some point.

# Write out the rules in front of our block rule to a new temp file
echo -e "${OTHERRULES}" | head -n $(($RULELNNO-1)) > "${SIVFILE}.new"

#If the address list is not blank, finish generating the new rule, and write it out
if [[ $CURADDR == *@* ]]; then 

	# Convert all the addresses into a Sieve list
	CURADDR=$(echo "$CURADDR" | sed 's/$/, /g' | tr -d '\n' | sed 's/, $//')

	# Construct the rest of the block rule
	NEWRULE="${NEWRULE}if address :all :contains \"From\" [${CURADDR}] {\r\n"
	NEWRULE="${NEWRULE}  fileinto \"Junk E-mail\";\r\n"
	NEWRULE="${NEWRULE}  stop;\r\n"
	NEWRULE="${NEWRULE}}"
	#debug NEWRULE
	
	# Add our new block rule to the temp file
	echo -e "${NEWRULE}\r" >> "${SIVFILE}.new"

fi

# Write out the rest of the rules to the temp file
echo "${OTHERRULES}" | tail -n +$RULELNNO >> "${SIVFILE}.new"

# move the temp file to overwrite the live file. Remark this line to put the script in "test" mode.
mv "${SIVFILE}.new" "$SIVFILE"

# Write the action taken to the log file
echo "$(date),${MAILBOX},${ACTION},${BLOCKADDR}" >> "$LOGFILE"
