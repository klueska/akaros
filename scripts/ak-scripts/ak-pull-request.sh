#!/usr/bin/env bash
#
# Copyright (c) 2015 Google Inc.
# Kevin Klues <klueska@cs.berkeley.edu>
# See LICENSE for details.

# Some global variables
origin="akaros-klueska"
msgfile=".git/PULLREQ_EDITMSG"

function short_description() {
	echo "Prepare a message for a github pull request and send it"
}

function usage() {
	echo "Usage:"
	echo "    ${cmd} [ -h | --help ]"
	echo "    ${cmd} <remote> <base> <head>"
	echo "    ${cmd//?/ } [ --destination=<br> ]"
	echo "    ${cmd//?/ } [ --update ]"
	echo "    ${cmd} --edit"
	echo "    ${cmd} --send"
	echo "    ${cmd} --abandon"
	echo "    ${cmd} --print"
	echo ""
	echo "Options:"
	echo "    -h --help           Display this screen and exit"
	echo "    --update            Update an exisiting code review message"
	echo "                        with a new remote/base/head"
	echo "    --edit              Edit an exisiting code review message"
	echo "    --send              Send the pull-request off for review"
	echo "    --destination=<br>  Destination branch to rebase the changes onto"
	echo "                        [default: ${origin}:master]"
	echo "    --abandon           Abandon the current code review message"
	echo "    --print             Print the current message and exit"
}

function gen_separator()
{
	echo '# Insert your pull-request message above this line.'
	echo '# Do not edit these comments.'
	echo '# Do not edit anything below this line.'
}

function gen_request()
{
	# Get the text from a git request-pull
    request=$(git request-pull ${base} ${remote} ${head});
	ret=${?};
	if [ "${ret}" != "0" ]; then
		echo "${request}"
		kill -s TERM $TOP_PID
	else
		echo "${request}" | head -n 11
	fi
}

function gen_footer()
{
	local request="$(gen_request ${base} ${remote} ${head})"
	echo "$(gen_separator)"
	echo '--------------------------------------------------------------------------------'
	echo "This is a pull request to rebase ${remote}:${head} onto ${destination}"
	echo ""
	echo "${request}"
}

function gen_new_msg()
{
	local title=$(git log --oneline -1 ${head} | cut -d" " -f 2-)
	echo "${title}"
	echo ""
	gen_footer
}

function gen_update_msg()
{
	local sepline=$(echo "$(gen_separator)" | head -n 1)
	local msg="$(cat ${msgfile} | sed '/'"${sepline}"'/,$ d')"
	echo "${msg}"
	echo ""
	gen_footer
}

function gen_send_msg()
{
	local sepline=$(echo "$(gen_separator)" | head -n 1)
	local seplinelen="$(expr $(echo "$(gen_separator)" | wc -l) - 1)"
	msg="$(cat ${msgfile} | sed '/'"${sepline}"'/,+'${seplinelen}' d')"
	echo "${msg}"
}

function get_head_from_msg()
{
	local head="$(grep "git@github.com:" ${msgfile} | tail -1)"
	head="$(echo "${head}" | sed -e 's/git@github.com:.*\s\+//')"
	echo ${head}
}

function get_remote_from_msg()
{
	local remote="$(grep "git@github.com:" ${msgfile} | tail -1)"
	remote="$(echo "${remote}" | sed -e 's/git@github.com:\(.*\)\/.*/\1/')"
	echo ${remote}
}

function get_destination_from_msg()
{
	local destination="$(grep "This is a pull request" ${msgfile} | tail -1)"
	destination="$(echo "${destination}" | sed -e 's/.*\s\+//')"
	echo ${destination}
}

function open_editor()
{
	local editor=${FCEDIT:-${VISUAL:-${EDITOR:-vi}}}
	if [ "${editor}" = "vi" ] || [ "${editor}" = "vim" ]; then
		editor="${editor} -c \"set ft=gitcommit tw=0 wrap lbr\""
	fi
	eval "${editor} ${msgfile}"
}

function main() {
	# Declare some variables
	local request=""
	local title=""
	local msg=""
	local ret=""

	# Set so functions can exit from entire program if desired
	trap "exit 1" TERM
	export TOP_PID=$$

	# Make sure we are in a git repository
	request="git rev-parse --git-dir > /dev/null 2>&1"
	ret=${?};
	if [ "${ret}" != "0" ]; then
		echo "This script must be run from a valid git repository!"
	fi

	# If printing the code review message, just print it
	if [ "${print}" = "true" ]; then
		if [ -f "${msgfile}" ]; then
			cat ${msgfile}
		fi
		exit 0
	fi

	# If abandoning the code review message, just delete it
	if [ "${abandon}" = "true" ]; then
		rm -rf ${msgfile}
		exit 0
	fi

	# If sending the message, send it via 'git pull-request'
	if [ "${send}" = "true" ]; then
		if [ ! -f "${msgfile}" ]; then
			echo "Error: You must first prepare a message for code review before sending!"
			exit 1
		else
			hub pull-request -F <( echo "$(gen_send_msg)" ) \
			                 -b "$(get_destination_from_msg)" \
			                 -h "$(get_remote_from_msg):$(get_head_from_msg)"
			if [ "$?" == "0" ]; then
				rm -rf ${msgfile}
			fi
			exit 0
		fi
	fi

	# If editing, generate the message from the existing ${msgfile}.
	if [ "${edit}" = "true" ]; then
		if [ ! -f "${msgfile}" ]; then
			echo "Error: You must first prepare a message before trying to edit it!"
			exit 1
		else
			msg="$(cat ${msgfile})"
		fi
		echo "${msg}" > ${msgfile}
		open_editor
		exit 0
	fi

	# If we are updating the base/remote/head, then update the suffix of the
	# message appropriately.
	if [ "${update}" = "true" ]; then
		if [ ! -f "${msgfile}" ]; then
			msg="$(gen_new_msg)"
		else
			msg="$(gen_update_msg)"
		fi
		echo "${msg}" > ${msgfile}
		open_editor
		exit 0
	fi

	# If not editing or updating, then just generate the message anew
	echo "$(gen_new_msg)" > ${msgfile}
	open_editor
	exit 0
}

