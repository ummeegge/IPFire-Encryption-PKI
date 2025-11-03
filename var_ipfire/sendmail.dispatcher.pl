#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/bin/sendmail.dispatcher.pl
# Version: 0.3 – encryption.conf support + GPG_KEY validation
#===============================================================================
use strict;
use warnings;
require '/var/ipfire/general-functions.pl';

my $MAIL_CONF       = "/var/ipfire/dma/mail.conf";
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";

my %mail = ();
my %enc  = ();

&General::readhash($MAIL_CONF, \%mail) if (-f $MAIL_CONF);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);

# Use main settings for fallback sender
my %mainsettings = ();
&General::readhash('/var/ipfire/main/settings', \%mainsettings);
my $from = $mail{'SENDER'} || "$mainsettings{'HOSTNAME'}.$mainsettings{'DOMAINNAME'}";

my $debug = ($mail{'DEBUG'} // '') eq 'on';

sub debug { print STDERR "[DISPATCHER] @_\n" if $debug; }
sub error { print STDERR "[ERROR] @_\n"; }

debug "START - SENDER=$from";

my @recips = grep { /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/i } @ARGV;
unless (@recips) {
	error "No valid recipients";
	exit 1;
}
debug "Recipients: @recips";

my $use_gpg = 0;
my $gpg_key = $enc{'GPG_KEY'} // '';

if (($mail{'ENCRYPT'} // '') eq 'on' && $gpg_key =~ /^[0-9A-F]{40}$/i) {
	$use_gpg = 1;
	debug "ENCRYPTION ENABLED → using GPG wrapper (KEY: $gpg_key)";
} else {
	$use_gpg = 0;
	if (($mail{'ENCRYPT'} // '') eq 'on') {
		debug "ENCRYPT=on but no valid GPG_KEY → falling back to plain DMA";
	} else {
		debug "ENCRYPT=off → using plain DMA";
	}
}

my $wrapper = $use_gpg ? '/var/ipfire/encryption/gpg/bin/sendmail.gpg.pl' : '/usr/sbin/sendmail.dma';

if ($use_gpg) {
	debug "EXEC → $wrapper @recips";
	exec $wrapper, @recips or do {
		error "Cannot exec $wrapper: $!";
		exit 1;
	};
} else {
	debug "EXEC → $wrapper -f $from @recips";
	exec $wrapper, '-f', $from, @recips or do {
		error "Cannot exec $wrapper: $!";
		exit 1;
	};
}
