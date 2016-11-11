#!/usr/bin/perl
#
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation, version 3. 
# 
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details. 
# 
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>. 
# 

use strict;
use warnings;
use utf8;
use feature qw(switch);
use Config::IniFiles;
use File::Basename;
use File::Compare;
use File::Copy;
use Net::LDAP;
use Sys::Syslog;

use Data::Dumper;

use constant {	
	NEWFILE => "/tmp/tacacs/tac_plus.new",
	CONFILE => "/etc/tac_plus.conf",
};

#####################################################
#
# SUB-ROUTINES
#
#####################################################
#
sub createConfigFile {
	# Create an standard config ini file
	my $configFile = shift;
	open ( my $fh , ">:encoding(UTF-8)" , $configFile );
		print $fh "; The sync_tacplus.pl script is designed to add users that are member of the FreeIPA group ";
		print $fh "\n; with the name started as the defined ldap_group parameter.";
		print $fh "\n; These groups most be located under 'cn=groups,cn=accounts,<ldap_base>' ";
		print $fh "\n; and 'cn=groups,cn=compat<ldap_base>'.";
		print $fh "\n; The memberUid value will also be used to find the displayName of that user";
		print $fh "\n; located under the LDAP tree 'cn=users,cn=accounts,<ldap_base>'. ";
		print $fh "\n;\n; ldap_user - only username and must exist as LDAP entry 'uid=<ldap_user>,cn=sysaccounts,cn=etc,<ldap_base>";
		print $fh "\n; To create a system account, make a LDIF file and copy the following lines into that file:";
		print $fh "\n; dn: uid=tacplususer,cn=sysaccounts,cn=etc,dc=example,dc=com";
		print $fh "\n; changetype: add";
		print $fh "\n; objectclass: account";
		print $fh "\n; objectclass: simplesecurityobject";
		print $fh "\n; uid: tacplususer";
		print $fh "\n; userPassword: secret123";
		print $fh "\n; passwordExpirationTime: 20380119031407Z";
		print $fh "\n; nsIdleTimeout: 0";
		print $fh "\n;\n; Add account into your FreeIPA server:";
		print $fh "\n; ldapadd -x -D cn='Directory Manager' -W -f tacuser.ldif";
		print $fh "\n;\n; Edit the /etc/crontab and add to file:";
		print $fh "\n; */5 * * * * root /opt/tac_plus/sync_tacplus.pl\n\n";
		print $fh "[general]\n";
		print $fh "logfile =  /var/log/tacacs.log\n";
		print $fh "tacacs_key = secret123\n\n";
		print $fh "[ldap]\n";
		print $fh "ldap_base = dc=example,dc=com\n";
		print $fh "ldap_server = my.example.com\n";
		print $fh "ldap_user = tacplususer\n";
		print $fh "ldap_pwd = mypass\n";
		print $fh "ldap_group = cs-tacplus-\n";
	close $fh;
} # End sub, createConfigFile

sub ldapSearch {
	# Based on the provided filter and basedn, get entries 
	my $basedn = shift;																				# LDAP basedn 
	my $filter = shift;																				# LDAP filter
	my $attrs = shift;																				# LDAP attribute
	my $ldap_base = shift;																			# base LDAP Tree
	my $ldap_server = shift;																		# LDAP Server hostname
	my $ldap_password = shift;																		# LDAP password linked to system account $ldap_user 
	my $ldap_user = shift;																			# LDAP system account

	$ldap_user = "uid=" .$ldap_user. ",cn=sysaccounts,cn=etc," .$ldap_base;							# Complete System account
	$basedn .= "," .$ldap_base;																		# Append base into basedn

	my $ldap = Net::LDAP->new( $ldap_server ) or die "$@";											# Make connection
	my $mesg = $ldap->bind( 																		# Bind to a directory with dn and password
					$ldap_user, 
					password => $ldap_password, 
					version => 3 );

	$mesg = $ldap->search ( 																		# Search ...
				base => $basedn ,
				filter => $filter ,
				attrs => $attrs );																	# collect the attribute memberUid
	$mesg->code && syslog("warning", "Unable to an LDAP search :" .$mesg->error) && exit 0;			# Error code -> sent syslog message
	return $mesg->as_struct;
} # End sub, ldapSearch

sub trim {
	# Remove leading and trailing whitespace
	my $str = shift;
	$str =~ s/^\s+|\s+$//g;
	return $str;
} # End sub, trim

#####################################################
#
# MAIN
#
#####################################################
#
# Variables
my $file = basename(__FILE__);																		# current name of file
my $dirname = dirname(__FILE__);																	# path of file
my $configFile = "tacplus.ini";																		# default config file for this script
my $ldapbase;
my $ldapgroup;
my $ldappwd;
my $ldapserver;
my $ldapuser;
my $logfile;
my $tacacs_key;
my %parent_h;																						# Empty hash to build our user base
my @reqSections = ( "general", "ldap" );															# Required sections that our configFile should have
my @reqParamGeneral = ( "logfile" , "tacacs_key" );													# Required parameters under section [general] 
my @reqParamLdap = ( "ldap_base" , "ldap_server", "ldap_user", "ldap_pwd", "ldap_group" );			# Required parameters under section [ldap] 


# Requirements
openlog($file, "ndelay", "local0");																	# Opens the syslog
syslog("warning", "The script " .$file. " wasn't run by uid 0 ("		 							# Check if this script is run by uid 0
		. getpwnam((getpwuid($<))[0]). ")" ) && exit 0 if (getpwnam((getpwuid($<))[0]) ne 0 );		# If not, exist
syslog("info" , "File '" .CONFILE. "' missing.") if ( ! -e CONFILE );								# Sent syslog message when CONFILE doesn't exist

unlink NEWFILE 																						# Remove file
	or (syslog("warning", "Unable to remove file '" .NEWFILE. "' : $!")								# or sent syslog message and exit program
			&& exit 0) if (-e NEWFILE);																# when file exist
createConfigFile( $dirname ."/". $configFile ) if (! -e $dirname ."/" .$configFile);				# Create configFile if not exist
my $cfg = Config::IniFiles->new( -file => $dirname ."/". $configFile);								# Load the parameters from file

foreach my $section(@reqSections) {
	syslog("warning" , "Missing section [" .$section. "] on file " . $configFile) 	 				# Sent syslog
				&& next if (! $cfg->SectionExists($section));										# when section [general] is missing

	given(lc($section)) {
		when ( /^general$/ ) { 
			foreach my $param(@reqParamGeneral) {
				syslog("warning", "Parameter '".$param."' missing under section [" .$section."]") 	# Sent syslog
						&& next if (! $cfg->exists($section,$param));								# when parameter is missing
				given(lc($param)) {

					when ( /^logfile$/ ) {
						$logfile = trim($cfg->val($section,$param));								# get entry behind the parameter logfile
						syslog("warning", "Folder '" .dirname($logfile). "' doesn't exist.")		# Sent syslog and reset the variable $ldapbase
							&& undef($logfile) if (! -d dirname($logfile));		 	 				# when directory of our logfile path doesn't exist, 
					} # End when, (/^logfile$/)

					when ( /^tacacs_key$/ ) {
						$tacacs_key = trim($cfg->val($section,$param));								# get entry behind the parameter tacacs_key
					} # End (/^tacacs_key$/)			

				} # End given, (lc($param))
			} # End foreach, $param(@reqParamGeneral)
		} # End when, ( /^general$/ )

		when ( /^ldap$/ ) {
			foreach my $param(@reqParamLdap) {
				syslog("warning", "Parameter '".$param."' missing under section [" .$section."]") 	# Sent syslog
						&& next if (! $cfg->exists($section,$param));								# when parameter is missing
				given(lc($param)) {

					when ( /^ldap_base$/ ) {
						$ldapbase = trim($cfg->val($section,$param));                               # get entry behind the parameter ldap_base
						my @arrayBaseComma = split( ',' , $ldapbase);								# Split string by comma
						foreach my $dcEntry(@arrayBaseComma) {										# Loop through array 
							syslog("warning", "The entry behind parameter '" .$param. "' isn't a valid ldap base entry")
								&& undef($ldapbase) if ( $dcEntry !~ m/^dc=/ );						# when dcEntry doesn't contain the string 'dc=' from the beginning, sent syslog
						} # End foreach, $dcEntry(@arrayBaseComma)
					} # End when, (/^ldap_base$/)

					when ( /^ldap_server$/ ) {
						$ldapserver = trim($cfg->val($section,$param));                             # get entry behind the parameter ldap_server
					} # End when, (/^ldap_server$/)

					when ( /^ldap_user$/ ) {
						$ldapuser = trim($cfg->val($section,$param));                             	# get entry behind the parameter ldap_user
					} # End when, (/^ldap_user$/)

					when ( /^ldap_pwd$/ ) {
						$ldappwd = trim($cfg->val($section,$param));                             	# get entry behind the parameter ldap_pwd
					} # End when, (/^ldap_pwd$/)

					when ( /^ldap_group$/ ) {
						$ldapgroup = trim($cfg->val($section,$param));                             	# get entry behind the parameter ldap_group
					} # End when, (/^ldap_pwd$/)

				} # End given; (lc($param))
			} # End foreach, $param(@reqParamLdap)
		} # End when, ( /^ldap$/ )
	} # End given, (lc($section))
} # End foreach, $section(@reqSections)

exit 0 if ( (!defined($logfile)) || (!defined($tacacs_key)) || (!defined($ldapbase)) 
				|| (!defined($ldapserver)) || (!defined($ldapuser)) 
				|| (!defined($ldappwd))	|| (!defined($ldapgroup)) );								# Exit program when one or more variable are not defined
# End requirements



my $attrs = [ 'cn' , 'description' ];																# Define the attribute that we want to have
my $groups_href = ldapSearch ( "cn=groups,cn=accounts"												# Do a ldapsearch
					, "(&(objectClass=posixgroup)(objectClass=ipausergroup)(cn=" .$ldapgroup. "*))"
					, $attrs, $ldapbase, $ldapserver, $ldappwd, $ldapuser );
my @arrayOfGroupDNs = keys %$groups_href;															# Returns a list consisting of all the keys of the hash ...

open( my $fh, '>' , NEWFILE ) or (syslog("warning", "Unable to open file '" .NEWFILE. "': $!") && exit 0);
print $fh "\n# Created by\t: " .$file;
print $fh "\n#";
print $fh "\n# Define where to log accounting data, this is the default.";
print $fh "\naccounting file = " .$logfile;
print $fh "\n";
print $fh "\n# This is the key that clients have to use to access Tacacs+";
print $fh "\nkey = " .$tacacs_key. "\n"; 

foreach(@arrayOfGroupDNs) {																			# Loop through key list 'Groups'
	my %members;																					# Empty hash to store our memberuid and their displayNames
	my $level;																						# Initiate an empty variable to store our prv-lvl value
	my $description;																				# Description of the group
	my $commands;																					# Initiate commands
	my $default_service = "deny";																	# Pre-set default service

	my $valref = $$groups_href{$_};																	
	given(lc($valref->{description}[0])) {															# Depend the substring within our description value
		when( /^level 15:/) { 
						$level = 15;
						$default_service = "permit";
						$description = "Administrator group"; }										# Substring = "level 15:"
		when( /^level 10:/) { 
						$level = 10;
						$default_service = "permit";
						$commands = "\n\tcmd=switchport trunk allowed vlan add {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=switchport trunk allowed vlan remove {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=switchport trunk allowed vlan none {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=switchport trunk allowed vlan all {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=switchport trunk allowed vlan except {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=switchport trunk allowed vlan {";
						$commands .= "\n\t\t deny .*";
						$commands .= "\n\t}";
						$description = "Technician group"; }										# Substring = "level 10"
		when( /^level 7:/) { 
						$level = 7;
						$commands = "\n\tcmd=show {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=ping {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=traceroute {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=test {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=exit {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=terminal {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=enable {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=snmp-server {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=no snmp-server {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=logging {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=no logging {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=interface {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=description {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=lldp {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=config {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$description = "Operator group"; }											# Substring = "level 7:"
		when( /^level 5:/) { 
						$level = 5;
						$commands = "\n\tcmd=show {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=ping {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=traceroute {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=test {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=exit {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$description = "Helpdesk group"; }											# Substring = "level 5:"
		when( /^level 1:/) { 
						$level = 1;
						$commands = "\n\tcmd=show {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$commands = "\n\tcmd=exit {";
						$commands .= "\n\t\t permit .*";
						$commands .= "\n\t}";
						$description = "View group"; }												# Substring = "level 1:"
	} # End given, ($valref->{description}[0])
	

	# Look for memberUid related to that group
	$attrs = [ 'memberUid' ];																		# Define the attribute that we want to have
	my $members_href = ldapSearch ( "cn=groups,cn=compat"											# Do a ldapsearch 
					, "(&(objectClass=posixGroup)(objectClass=ipaexternalgroup)(cn=" .$valref->{cn}[0]."))"
					, $attrs, $ldapbase, $ldapserver, $ldappwd, $ldapuser );
	my @arrayOfDNs = keys %$members_href;															# Returns a list consisting of all the keys of the hash ...
	foreach(@arrayOfDNs) {																			# Loop trough the key list of our group search
		my $valref2 = $$members_href{$_};															
		if ($valref2->{memberuid}) {																# Check if we have values for memberuid's
			foreach my $memberuid(@{$valref2->{memberuid}}) {										# We do, loop through the array by first dereference the array

				# Look for the displayName related to that memberUid value
				$attrs = [ 'displayName' ];															# Define the attribute that we want to have
				my $displayName_href = ldapSearch ( "cn=users,cn=accounts",							# Do a ldapsearch
										, "(&(objectClass=person)(objectClass=posixaccount)(uid=" .$memberuid."))"
										, $attrs, $ldapbase, $ldapserver, $ldappwd, $ldapuser );
				my @arrayOfDisplayNames = keys %$displayName_href;									# Returns a list consisting of all the keys of the hash ...
				foreach (@arrayOfDisplayNames) {													# Loop through key list 'displayNames'
					my $valref3 = $$displayName_href{$_};

					# We have our defined hash %members
					# Example
					#	'memberuid_value' => {
					#				'displayname => 'firstName LastName'
					#				}
					#	}
					$members{$memberuid}{displayName} = $valref3->{displayname}[0];
				} # End foreach, (@arrayOfDisplayNames)	
			} # End foreach, $memberuid(@{$valref2->{memberuid}})
		} # End if, ($valref2->{memberuid})
	} # End foreach, (@arrayOfDNs)

	# Define our groups into our NEWFILE (tac_plus.new) file
	if ( keys %members) {																			# Only when we are having entries in our memberuid attribute
		$parent_h{$valref->{cn}[0]}{memberuid} = \%members;											# Store our build up hash %members into our hash %parent_h under key memberuid
		print $fh "\n# " .$description ." (lvl" .$level. ")" ;										# Write into ...
		print $fh "\ngroup = " .$valref->{cn}[0]. " {";												# Write into ...
		print $fh "\n\tdefault service = " .$default_service;										# Write into
		print $fh "\n\tlogin = PAM";																# Write into ...
		print $fh "\n\tservice = exec {";															# Write into ...
		print $fh "\n\t\tpriv-lvl = " . $level;														# Write into ...
		print $fh "\n\t\t}";																		# Write into ...
		print $fh $commands;																		# Write into ...
		print $fh "\n\t}\n";																		# Write into ...
	} # End If, (scalar(@members) > 0)
} # End foreach, (@arrayOfGroupDNs)

# Do some clean up
undef @arrayOfGroupDNs;
undef $groups_href;
undef $attrs;


# Build our user list mapped to defined groups
foreach my $group_key(keys %parent_h) {
	print $fh "\n# Members of the group '" . $group_key. "'.";
	foreach my $attr(keys $parent_h{$group_key}) {
		foreach my $memberuid(keys $parent_h{$group_key}{$attr}) {
			print $fh "\nuser = " .$memberuid. " {";
			print $fh "\n\tmember = " .$group_key;
			print $fh "\n\tname = \"" .$parent_h{$group_key}{$attr}{$memberuid}->{displayName} ."\"";
			print $fh "\n}\n";
		} # End foreach, $memberuid(keys $parent_h{$group_key}{$attr})
	} # End foreach, $attr(keys $parent_h{$group_key})
} # End foreach, $group_key(keys %parent_h)
close $fh;


if (compare(NEWFILE, CONFILE) != 0 ) {																# If file isn't the same
	copy( NEWFILE, CONFILE) or die "Copy Failed: $!";												# Copy file
	syslog("info" , "The file " .CONFILE. " has been renewed. ");									# Sent syslog to notify
	system("systemctl restart tac_plus.service");													# Restart service
} # End If, (compare(NEWFILE, CONFILE) != 0 )
