#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/logging/logging.pl
# Purpose: Centralized logging for IPFire Encryption PKI
# Version: 1.1.1 – FIXED $fh scope + central log
#===============================================================================
package Encryption::Logging;
use strict;
use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(log_message get_log_level set_log_level);

use Fcntl qw(:flock);

use constant {


	LOG_ERROR => 0,
	LOG_WARN  => 1,
	LOG_INFO  => 2,
	LOG_DEBUG => 3,
};

my %LEVEL_NAMES = (
	0 => 'ERROR',
	1 => 'WARN',
	2 => 'INFO',
	3 => 'DEBUG',
);

# === Config & Log ===
my $CONFIG_FILE = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my $LOG_DIR     = "/var/log/encryption";
my $CENTRAL_LOG = "$LOG_DIR/encryption.log";

# Ensure log directory exists
unless (-d $LOG_DIR) {
	mkdir $LOG_DIR, 0755 or die "Cannot create $LOG_DIR: $!";
	chown 99, 99, $LOG_DIR;
}

# === Global cache for log levels (Perl 5.26 safe) ===
our %cache;
BEGIN {
	%cache = ();
}

# === Internal: read log level from config ===
sub _get_config_level {
	my ($module) = @_;
	$module = lc($module);
	my %conf = ();
	if (-f $CONFIG_FILE) {
		&General::readhash($CONFIG_FILE, \%conf);
	}
	my $key = "LOG_LEVEL_" . uc($module);
	return $conf{$key} // $conf{'LOG_LEVEL'} // 2;
}

# === Public: get current log level for module ===
sub get_log_level {
	my ($module) = @_;
	$module = lc($module);
	return $cache{$module} //= _get_config_level($module);
}

# === Public: set log level and persist to config ===
sub set_log_level {
	my ($module, $level) = @_;
	$module = lc($module);
	$level = 2 if $level !~ /^[0-3]$/;

	my %conf = ();
	&General::readhash($CONFIG_FILE, \%conf) if -f $CONFIG_FILE;

	my $key = "LOG_LEVEL_" . uc($module);
	$conf{$key} = $level;

	&General::writehash($CONFIG_FILE, \%conf);
	$cache{$module} = $level;

	return $level;
}

# === Public: log a message to CENTRAL LOG ===
sub log_message {
	my ($module, $level, $message) = @_;
	$module = uc($module);
	my $config_level = get_log_level($module);
	return if $level > $config_level;

	my $level_name = $LEVEL_NAMES{$level} // 'UNKNOWN';
	my $timestamp  = scalar localtime;
	my $pid        = $$;
	my $entry      = "[$timestamp] [$level_name] [$module] [PID:$pid] $message\n";

	my $fh;
	eval {
		# Try to open log file
		open $fh, '>>', $CENTRAL_LOG or do {
			# If fails → create it
			open my $fh_create, '>', $CENTRAL_LOG or die "create: $!";
			close $fh_create;
			chmod 0644, $CENTRAL_LOG;
			chown 99, 99, $CENTRAL_LOG;
			open $fh, '>>', $CENTRAL_LOG or die "open: $!";
		};
		flock($fh, LOCK_EX) or die "lock: $!";
		print $fh $entry;
		flock($fh, LOCK_UN);
		close $fh;
	};
	if ($@) {
		warn "LOG FAILED [$module]: $message | $@";
	}
}

1;