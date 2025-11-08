#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/bin/sendmail.dispatcher.pl
# Purpose: Smart sendmail wrapper with GPG encryption fallback
# Version: 0.8.0 – uses real /usr/sbin/dma, SENDER from mail.conf only
#===============================================================================

use strict;
use warnings;

# === Load IPFire functions ===
require '/var/ipfire/general-functions.pl';
use lib '/var/ipfire/encryption/logging';
require 'logging.pl';

my $MODULE = 'DISPATCHER';

# === Config paths ===
my $MAIL_CONF        = "/var/ipfire/dma/mail.conf";
my $ENCRYPTION_CONF  = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my $DMA_BINARY       = "/usr/sbin/dma";  # <-- REAL BINARY, NO SYMLINK

# === Load configs ===
my %mail = ();
my %enc  = ();
&General::readhash($MAIL_CONF, \%mail) if (-f $MAIL_CONF);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);

# === SENDER: from mail.conf → fallback to hostname.domainname ===
my %mainsettings = ();
&General::readhash('/var/ipfire/main/settings', \%mainsettings);
my $from = $mail{'SENDER'} || "$mainsettings{'HOSTNAME'}.$mainsettings{'DOMAINNAME'}";

# === Logging ===
my $debug_mode = ($mail{'DEBUG'} // '') eq 'on';
sub debug   { &Encryption::Logging::log_message($MODULE, 3, @_) if $debug_mode; }
sub info    { &Encryption::Logging::log_message($MODULE, 2, @_); }
sub warning { &Encryption::Logging::log_message($MODULE, 1, @_); }
sub error   { &Encryption::Logging::log_message($MODULE, 0, @_); }

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
        warning "ENCRYPT=on but no valid GPG_KEY → falling back to plain DMA";
    } else {
        info "ENCRYPT=off → using plain DMA";
    }
}

# === Execute ===
my $wrapper = $use_gpg
    ? '/var/ipfire/encryption/gpg/bin/sendmail.gpg.pl'
    : $DMA_BINARY;

if ($use_gpg) {
    info "EXEC → $wrapper @recips";
    exec $wrapper, @recips or do {
        error "Cannot exec $wrapper: $!";
        exit 1;
    };
} else {
    info "EXEC → $DMA_BINARY -f $from @recips";
    exec $DMA_BINARY, '-f', $from, @recips or do {
        error "Cannot exec $DMA_BINARY: $!";
        exit 1;
    };
}