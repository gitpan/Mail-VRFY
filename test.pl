#!/usr/local/bin/perl

use strict;
use Mail::VRFY;

my $email = shift;
unless(defined($email)){
	print "email address to be tested: ";
	chop($email=<STDIN>);
}

my $result = Mail::VRFY::CheckAddress(addr => $email, method => 'extended');
if($result) {
	print "Invalid email address: ";
	if($result == 8){
		print "MX Server permanently refused mail\n";
	}elsif($result == 7){
		print "All SMTP servers temporarily refused mail\n";
	}elsif($result == 6){
		print "All SMTP servers gave us an unknown result\n";
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
}