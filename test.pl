#!/usr/local/bin/perl

use strict;
use Mail::VRFY;

my @emails = qw/postmaster@rfc-ignorant.org postmaster@google.com postmaster@aol.com postmaster@nanog.org postmaster@nic.museum/;

my $version = Mail::VRFY::Version();
print "testing Mail::VRFY v${version}\n";

foreach my $email (@emails){
	print "Testing ${email}...\n";
	my $code = Mail::VRFY::CheckAddress(addr => $email, method => 'extended', timeout => 21, debug => 0);

	print Mail::VRFY::English($code) ."\n";
	exit unless($code);
}

print "no email addresses tested were valid, something is probably wrong\n";
exit 1;
