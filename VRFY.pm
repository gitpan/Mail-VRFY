# Mail::VRFY.pm
# $Id: VRFY.pm,v 0.51 2004/10/09 06:52:32 jkister Exp $
# Copyright (c) 2004 Jeremy Kister.
# Released under Perl's Artistic License.

$Mail::VRFY::VERSION = "0.51";

=head1 NAME

Mail::VRFY - Utility to verify an email address

=head1 SYNOPSIS

use Mail::VRFY;

my $result = Mail::VRFY::ChkAddress($emailaddress);

my $result = Mail::VRFY::ChkAddress(addr   => $emailaddress,
                                    method => 'extended',
                                    debug  => 0);
	
=head1 DESCRIPTION

C<Mail::VRFY> was derived from Pete Fritchman's L<Mail::Verify>.
Lots of code has been plucked.  This package attempts to be
completely compatibile with Mail::Verify.

C<Mail::VRFY> provides a C<CheckAddress> function for verifying email
addresses.  Lots can be checked, according to the C<method> option,
as described below.

C<Mail::VRFY> differs from L<Mail::Verify> in that:

A.  More granular control over what kind of checks to run
    (via the method option).

B.  Email address syntax checking is much more stringent.

C.  After making a socket to an authoritative SMTP server,
    we can start a SMTP converstation, to ensure the
    mailserver does not give a permanent failure on RCPT TO.

D.  More return codes.

=head1 CONSTRUCTOR

=over 4

=item CheckAddress( [ADDR] [,OPTIONS] );

If C<ADDR> is not given, then it may instead be passed as the C<addr>
option described below.

C<OPTIONS> are passed in a hash like fashion, using key and value
pairs.  Possible options are:

B<addr> - The email address to check

B<method> - Which method of checking should be used:

   syntax - check syntax of email address only (no network testing).

   compat - check syntax, DNS, and MX connectivity (i.e. Mail::Verify)

   extended - compat + talk SMTP to see if server will reject RCPT TO

B<debug> - Print debugging info to STDERR (0=Off, 1=On).

=head1 RETURN VALUE

Here are a list of return codes and what they mean:

=item 0 The email address appears to be valid.

=item 1 No email address was supplied.

=item 2 There is a syntactical error in the email address.

=item 3 There are no MX or A DNS records for the host in question.

=item 4 There are no SMTP servers accepting connections.

=item 5 All SMTP servers are misbehaving and wont accept mail.

=item 6 All the SMTP servers gave us an unknown result code.

=item 7 All the SMTP servers temporarily refused mail.

=item 8 One SMTP server permanently refused mail to this address.

=head1 EXAMPLES

  use Mail::VRFY;
  my $email = shift;
  unless(defined($email)){
    print "email address to be tested: ";
    chop($email=<STDIN>);
  }
  my $result = Mail::VRFY::CheckAddress($email);
  if($result){
    print "Invalid email address: ${result}\n";
  }else{
    print "$email seems to be valid\n";
  }

=head1 CAVEATS

An SMTP server can reject RCPT TO at SMTP time, or it can accept all
recipients, and send bounces later.  All other things being equal,
Mail::VRFY will not detect the invalid email address in the latter case.

Greylisters will cause you pain; look out for return code 7.  Some
users will want to deem email addresses returning code 7 are invalid,
others will want to assume they are valid.

=head1 RESTRICTIONS

Email address syntax checking does not conform to RFC2822, however, it
will work fine on email addresses as we usually think of them.
(do you really want:

"Foo, Bar" <test((foo) b`ar baz)@example(hi there!).com>

be be considered valid ?)

=head1 AUTHOR

Jeremy Kister - http://jeremy.kister.net/

=cut

package Mail::VRFY;

use strict;
use IO::Socket::INET;
use Net::DNS;
use Sys::Hostname;

sub Version { $Mail::VRFY::VERSION }

sub CheckAddress {
	my %arg;
	if(@_ % 2){
		my $addr = shift;
		%arg = @_;
		$arg{addr} = $addr;
	}else{
		%arg = @_;
	}
	return 1 unless $arg{addr};

	my ($user,$domain,@mxhosts);

	# First, we check the syntax of the email address.
	if(length($arg{addr}) > 256){
		 print STDERR "email address is more than 256 characters\n" if exists($arg{debug});
		 return 2;
	}
	if($arg{addr} =~ /^(([a-z0-9_\.\+\-\=\?\^\#]){1,64})\@((([a-z0-9\-]){1,251}\.){1,252}[a-z0-9]{2,4})$/i){
		$user = $1;
		$domain = $3;
		if(length($domain) > 255){
			print STDERR "domain in email address is more than 255 characters\n" if exists($arg{debug});
			return 2;
		}
	}else{
		 print STDERR "email address does not look correct\n" if exists($arg{debug});
		 return 2;
	}
	return 0 if($arg{method} eq 'syntax');

	my @mxrr = Net::DNS::mx( $domain );
	# Get the A record for each MX RR
	foreach my $rr (@mxrr) {
		push( @mxhosts, $rr->exchange );
	}
	unless(@mxhosts) { # check for an A record...
		my $resolver = new Net::DNS::Resolver;
		my $dnsquery = $resolver->search( $domain );
		return 3 unless $dnsquery;
		foreach my $rr ($dnsquery->answer) {
			next unless $rr->type eq "A";
			push( @mxhosts, $rr->address );
		}
		return 3 unless @mxhosts;
	}
	if($arg{debug}){
		foreach( @mxhosts ) {
			print STDERR "\@mxhosts -> $_\n";
		}
	}
	my $misbehave=0;
	my $tmpfail=0;
	my $unknown=0;
	my $livesmtp=0;
	foreach my $mx (@mxhosts) {
		my $sock = IO::Socket::INET->new(Proto=>'tcp',
													PeerAddr=> $mx,
													PeerPort=> 25,
													Timeout => 12
												 );
		if($sock){
			print "connected to ${mx}\n" if(exists($arg{debug}));
			$livesmtp=1;
			if($arg{method} eq 'compat'){
				close $sock;
				return 0;
			}		

			my @banner = getlines($sock);
			if(@banner){
				if(exists($arg{debug})){
					print "BANNER: ";
					for(@banner){ print " $_"; }
					print "\n";
				}
				unless($banner[-1] =~ /^220\s/){
					print $sock "QUIT\r\n"; # be nice
					close $sock;
					$misbehave=1;
					next;
				}
			}else{
				print STDERR "$mx not behaving correctly\n" if(exists($arg{debug}));
				$misbehave=1;
			}

			my $me = hostname();
			print $sock "HELO $me\r\n";
			my @helo = getlines($sock);
			if(@helo){
				if(exists($arg{debug})){
					print "HELO: ";
					print for(@helo);
					print "\n";
				}
				unless($helo[-1] =~ /^250\s/){
					print $sock "QUIT\r\n"; # be nice
					close $sock;
					$misbehave=1;
					next;
				}
			}else{
				print STDERR "$mx not behaving correctly\n" if(exists($arg{debug}));
				$misbehave=1;
			}

			print $sock "MAIL FROM:<>\r\n";
			my @mf = getlines($sock);
			if(@mf){
				if(exists($arg{debug})){
					print "MAIL FROM: ";
					print for(@mf);
					print "\n";
				}
				unless($mf[-1] =~ /^250\s/){
					print $sock "QUIT\r\n"; # be nice
					close $sock;
					$misbehave=1;
					next;
				}
			}else{
				print STDERR "$mx not behaving correctly\n" if(exists($arg{debug}));
				$misbehave=1;
			}

			print $sock "RCPT TO:<$arg{addr}>\r\n";
			my @rt = getlines($sock);
			print $sock "QUIT\r\n"; # be nice
			close $sock;
			if(@mf){
				if(exists($arg{debug})){
					print "RECIPIENT TO: ";
					print for(@rt);
					print "\n";
				}
				if($rt[-1] =~ /^250\s/){
					# host accepted
					return 0;
				}elsif($rt[-1] =~ /^4\d{2}/){
					# host temp failed, greylisters go here.
					$tmpfail=1;
				}elsif($rt[-1] =~ /^5\d{2}/){
					# host rejected
					return 8;
				}else{
					$unknown=1;
				}
			}else{
				print STDERR "$mx not behaving correctly\n" if(exists($arg{debug}));
				$misbehave=1;
			}
		}
	}
	return 4 unless($livesmtp);
	return 5 if($misbehave);
	return 6 if($unknown);
	return 7 if($tmpfail);
	return 0;
}

sub getlines {
	my $sock = shift;
	my @lines;
	while(<$sock>){
		if(/^\d+\s/){
			chomp;
			push @lines, $_;
			last;
		}else{
			push @lines, $_;
		}
	}
	return(@lines);
}

1;
