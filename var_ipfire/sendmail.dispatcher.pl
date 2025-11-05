#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/bin/sendmail.dispatcher.pl
# Version: 0.4.0 – centralized logging via Encryption::Logging
#===============================================================================
use strict;
use warnings;

require '/var/ipfire/general-functions.pl';
use lib '/var/ipfire/encryption/logging';
require 'logging.pl';

my $MODULE = 'DISPATCHER';

# === Logging Helpers ===
sub debug { &Encryption::Logging::log_message($MODULE, 3, @_) if ($mail{'DEBUG'} // '') eq 'on'; }
sub info  { &Encryption::Logging::log_message($MODULE, 2, @_); }
sub warn  { &Encryption::Logging::log_message($MODULE, 1, @_); }
sub error { &Encryption::Logging::log_message($MODULE, 0, @_); }

# === Configs ===
my $MAIL_CONF       = "/var/ipfire/dma/mail.conf";
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my %mail = ();
my %enc  = ();

&General::readhash($MAIL_CONF, \%mail)       if (-f $MAIL_CONF);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);

# Fallback sender
my %mainsettings = ();
&General::readhash('/var/ipfire/main/settings', \%mainsettings);
my $from = $mail{'SENDER'} || "$mainsettings{'HOSTNAME'}.$mainsettings{'DOMAINNAME'}";

info "START - SENDER=$from";

# === Validate recipients ===
my @recips = grep { /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/i } @ARGV;
unless (@recips) {
	error "No valid recipients";
	exit 1;
}
info "Recipients: @recips";

# === Decide encryption ===
my $use_gpg  = 0;
my $gpg_key  = $enc{'GPG_KEY'} // '';
my $encrypt  = ($mail{'ENCRYPT'} // '') eq 'on';

if ($encrypt && $gpg_key =~ /^[0-9A-F]{40}$/i) {
	$use_gpg = 1;
	info "ENCRYPTION ENABLED → using GPG wrapper (KEY: $gpg_key)";
} else {
	if ($encrypt) {
		warn "ENCRYPT=on but no valid GPG_KEY → falling back to plain DMA";
	} else {
		info "ENCRYPT=off → using plain DMA";
	}
}

# === Execute wrapper ===
my $wrapper = $use_gpg
	? '/var/ipfire/encryption/gpg/bin/sendmail.gpg.pl'
	: '/usr/sbin/sendmail.dma';

if ($use_gpg) {
	info "EXEC → $wrapper @recips";
	exec $wrapper, @recips or do {
		error "Cannot exec $wrapper: $!";
		exit 1;
	};
} else {
	info "EXEC → $wrapper -f $from @recips";
	exec $wrapper, '-f', $from, @recips or do {
		error "Cannot exec $wrapper: $!";
		exit 1;
	};
}