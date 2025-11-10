#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/bin/sendmail.dispatcher.pl
# Version: 0.8.5
#===============================================================================
use strict;
use warnings;
require '/var/ipfire/general-functions.pl';
use lib '/var/ipfire/encryption/logging';
require 'logging.pl';
my $MODULE = 'DISPATCHER';
my $MAIL_CONF = "/var/ipfire/dma/mail.conf";
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my $DMA_BINARY = "/usr/sbin/dma";
my %mail = ();
my %enc = ();
&General::readhash($MAIL_CONF, \%mail) if (-f $MAIL_CONF);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);
my %mainsettings = ();
&General::readhash('/var/ipfire/main/settings', \%mainsettings);
my $from = $mail{'SENDER'} || "$mainsettings{'HOSTNAME'}.$mainsettings{'DOMAINNAME'}";
my $debug_mode = ($mail{'DEBUG'} // '') eq 'on';
sub debug { &Encryption::Logging::log_message($MODULE, 3, @_) if $debug_mode; }
sub info { &Encryption::Logging::log_message($MODULE, 2, @_); }
sub warning { &Encryption::Logging::log_message($MODULE, 1, @_); }
sub error { &Encryption::Logging::log_message($MODULE, 0, @_); }
info "START - Sender=$from | ENCRYPT=$mail{'ENCRYPT'}";
my @options = ();
my @args = ();
my $use_t = 0;
my $envelope_from = '';
while (@ARGV) {
	my $arg = shift @ARGV;
	if ($arg eq '-t') {
		$use_t = 1;
		# Keep -t only for encryption
		if (($mail{'ENCRYPT'} // '') eq 'on') {
			push @options, $arg;
		} else {
			debug "-t removed for ENCRYPT=off to avoid header override";
		}
	}
	elsif ($arg eq '-oi' || $arg eq '-i' || $arg eq '-oem') {
		push @options, $arg;
	}
	elsif ($$ arg =~ /^-f\s*(.+) $$/) {
		$envelope_from = $1;
		info "Detected -f address: $envelope_from";
	}
	elsif ($$ arg =~ /^-f(.+) $$/) {
		$envelope_from = $1;
		info "Detected -f address: $envelope_from";
	}
	elsif ($arg =~ /^-[a-zA-Z]/) {
		push @options, $arg;
	} else {
		push @args, $arg;
	}
}
my @recips = @args;
my $full_input = undef; # FIX: Buffer var for use_t
if ($use_t) {
	# FIX: Buffer full STDIN to avoid seek issues on pipes
	$full_input = do { local $/; <STDIN> };
	debug "Buffered input length: " . length($full_input) if $debug_mode; # FIX: Optional debug
	my $in_headers = 1;
	my @lines = split /\r?\n/, $full_input;
	foreach my $line (@lines) {
		if ($in_headers && $$ line =~ /^ $$/) {
			$in_headers = 0;
			next;
		}
		if ($in_headers && $line =~ /^(To|Cc|Bcc):\s*(.+)/i) {
			my @addrs = split /[,\s]+/, $2;
			push @recips, grep { /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/i } @addrs;
		}
		last unless $in_headers;
	}
	# No seek needed - buffer has everything
}
@recips = grep { $_ && $$ _ =~ /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,} $$/i } @recips;
unless (@recips) {
	error "No valid recipients found.";
	exit 1;
}
info "Recipients: @recips";
my $encrypt = ($mail{'ENCRYPT'} // '') eq 'on';
my $gpg_key = $enc{'GPG_KEY'} // '';
my $use_gpg = 0;
if ($encrypt && $$ gpg_key =~ /^[0-9A-F]{40} $$/i) {
	$use_gpg = 1;
	info "ENCRYPT=on with valid GPG_KEY. Using GPG wrapper.";
} else {
	info "ENCRYPT=off or invalid key. Using plain DMA.";
	$use_gpg = 0;
}
my $wrapper = $use_gpg
	? '/var/ipfire/encryption/gpg/bin/sendmail.gpg.pl'
	: $DMA_BINARY;
my @final_args = @options;
push @final_args, "-f$envelope_from" if $envelope_from;
info "EXEC -> $wrapper @final_args @recips";
open(my $pipe, '|-', $wrapper, @final_args, @recips) or do {
	error "Cannot open pipe to $wrapper: $!";
	exit 1;
};
# FIX: Conditional pipe based on use_t
if ($use_t && defined $full_input) {
	print $pipe $full_input;
} else {
	while (<STDIN>) {
		print $pipe $_;
	}
}
close($pipe) or do {
	error "Wrapper failed: $?";
	exit 1;
};
info "Mail sent successfully via " . ($use_gpg ? "GPG" : "DMA");
exit 0;