#!/usr/local/bin/perl

use strict;
use Mail::VRFY;

my @emails = qw/postmaster@rfc-ignorant.org postmaster@iana.org postmaster@nanog.org/;

my $version = Mail::VRFY::Version();
print "testing Mail::VRFY v${version}\n";

foreach my $email (@emails){
	print "Testing ${email}...\n";
	my $result = Mail::VRFY::CheckAddress(addr => $email, method => 'extended', timeout => 12, debug => 0);
	if($result) {
		print "Invalid email address: ";
		if($result == 7){
			print "MX Server permanently refused mail\n";
		}elsif($result == 6){
			print "All SMTP servers temporarily refused mail\n";
		}elsif($result == 5){
			print "All SMTP servers are misbehaving and not accepting mail\n";
		}elsif($result == 4){
			print "no SMTP servers accepting mail\n";
		}elsif($result == 3){
			print "no MX or A DNS records for this domain\n";
		}elsif($result == 2){
			print "Syntax error in email address\n";
		}elsif($result == 1){
			print "No email address supplied\n";
		}else{
			print "$result\n";
		}
	}else{
		print "$email seems to be valid\n";
		exit;
	}
}

print "no email addresses tested were valid, something is probably wrong\n";
exit 1;
