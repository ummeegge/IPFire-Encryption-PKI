#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/functions/gpg-functions.pl
# Purpose: Core GPG operations – zentralisiert über encryption.conf
# Version: 0.3 – encryption.conf support + secure defaults + centralized logging
# Updated: 2025-11-03
# Runs as 'nobody' – no root required
#===============================================================================
package Encryption::GPG;
use strict;
use warnings;
use POSIX qw(strftime);
use Time::Local qw(timelocal);
use File::Temp qw(tempfile);
use File::Path qw(make_path);

our $CONFIG_FILE = "/var/ipfire/encryption/gpg/conf/encryption.conf";
our %CONFIG = ();

#=====================================================================
# Load config from encryption.conf (fallback to defaults)
#=====================================================================
sub load_config {
    %CONFIG = (
        GPGDIR     => "/var/ipfire/encryption/gpg/keys",
        LOGFILE    => "/var/log/encryption/gpgmail.log",
        TRUSTMODEL => "always",
        DEBUG      => "off",
    );

    if (-f $CONFIG_FILE) {
        &General::readhash($CONFIG_FILE, \%CONFIG);
    }

    # Ensure GPGDIR exists
    unless (-d $CONFIG{'GPGDIR'}) {
        make_path($CONFIG{'GPGDIR'}, { mode => 0700 }) or do {
            log_error("Failed to create GPGDIR: $CONFIG{'GPGDIR'}");
            return 0;
        };
        chown 99, 99, $CONFIG{'GPGDIR'};
    }

    return 1;
}

#=====================================================================
# Centralized logging
#=====================================================================
sub log_msg {
    my ($level, $msg) = @_;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $logfile = $CONFIG{'LOGFILE'} // "/var/log/encryption/gpgmail.log";

    eval {
        open my $fh, '>>', $logfile or return;
        print $fh "[$ts] [GPG] [$level] $msg\n";
        close $fh;
    };
}

sub log_debug { log_msg("DEBUG", @_) if ($CONFIG{'DEBUG'} // '') eq 'on'; }
sub log_error { log_msg("ERROR", @_); }

#=====================================================================
# Ensure GPG infrastructure (idempotent, safe)
#=====================================================================
sub ensure_gpg_infrastructure {
    return 0 unless load_config();

    unless (-d $CONFIG{'GPGDIR'}) {
        log_error("GPGDIR missing: $CONFIG{'GPGDIR'}");
        return 0;
    }

    # Initialize keyring if empty
    unless (glob("$CONFIG{'GPGDIR'}/pubring.*") || glob("$CONFIG{'GPGDIR'}/secring.*")) {
        system("/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --list-keys >/dev/null 2>&1");
        log_debug("Initialized empty GPG keyring in $CONFIG{'GPGDIR'}");
    }

    # Fix permissions
    system("chmod 0600 '$CONFIG{'GPGDIR'}'/* 2>/dev/null || true");
    system("chown nobody:nobody '$CONFIG{'GPGDIR'}'/* 2>/dev/null || true");
    chmod 0700, $CONFIG{'GPGDIR'};
    chown 99, 99, $CONFIG{'GPGDIR'};

    return 1;
}

#=====================================================================
# List all keys – returns array of hashes
#=====================================================================
sub list_keys {
    return () unless ensure_gpg_infrastructure();

    my @keys;
    my @raw = `/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --list-keys --with-colons --with-fingerprint 2>&1`;
    my @output = grep { !/unsafe (ownership|permissions).*nobody/i } @raw;

    if (grep /unsafe (ownership|permissions)/i, @raw) {
        log_error("GPG permission error (not nobody)");
        return ();
    }

    my $current = undef;
    foreach my $line (@output) {
        chomp $line;
        my @f = split /:/, $line;
        next unless @f >= 10;

        if ($f[0] eq 'pub' || $f[0] eq 'sec') {
            if ($current && $current->{fingerprint} && $current->{uid} ne 'Unknown') {
                push @keys, { %$current };
            }
            my $is_secret = ($f[0] eq 'sec') ? 1 : 0;
            my $exp = $f[6] // '';
            my $expiry = 'Never';
            my $timestamp = 0;
            if ($exp =~ /^(\d{4})-(\d{2})-(\d{2})$/) {
                eval {
                    $timestamp = timelocal(0, 0, 0, $3, $2 - 1, $1 - 1900);
                    $expiry = strftime("%Y-%m-%d", localtime($timestamp));
                };
                $expiry = 'Invalid' if $@;
            }

            my $uid = ($f[9] && $f[9] ne '') ? $f[9] : 'Unknown';
            my $algo = $f[3] || 'Unknown';
            my $bits = $f[2] || 'Unknown';

            $current = {
                fingerprint   => '',
                uid           => $uid,
                expiry        => $expiry,
                expired       => 0,
                expires_soon  => 0,
                algo          => $algo,
                bits          => $bits,
                secret        => $is_secret,
            };

            if ($timestamp > 0) {
                my $now = time;
                $current->{expired} = ($timestamp < $now);
                $current->{expires_soon} = ($timestamp < $now + 7*86400 && $timestamp >= $now);
            }
        }
        elsif ($f[0] eq 'fpr' && $current && @f > 9 && $f[9]) {
            $current->{fingerprint} = $f[9];
            if ($current->{uid} ne 'Unknown') {
                push @keys, { %$current };
                $current = undef;
            }
        }
    }
    if ($current && $current->{fingerprint} && $current->{uid} ne 'Unknown') {
        push @keys, { %$current };
    }
    return @keys;
}

#=====================================================================
# Import key – returns fingerprint or error string
#=====================================================================
sub import_key {
    my ($file, $recipient) = @_;
    return "No file" unless $file && -f $file;
    return "No recipient" unless $recipient;
    return "Infrastructure failed" unless ensure_gpg_infrastructure();

    my $cmd = "/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --import " . quotemeta($file) . " 2>&1";
    my @import_output = `$cmd`;

    unless ($? == 0 || grep /imported:|unchanged:/i, @import_output) {
        log_error("Import failed: " . join(" ", @import_output));
        return "GPG error: " . join(" ", @import_output);
    }

    if (grep /unchanged:/i, @import_output) {
        my ($short_id) = map { /key\s+([0-9A-F]{8,16})/i ? $1 : () } @import_output;
        if ($short_id) {
            my @list = `/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --list-keys --with-colons $short_id 2>&1`;
            for (@list) {
                my @f = split /:/;
                next unless @f >= 10 && $f[0] eq 'fpr' && $f[9];
                return $f[9];
            }
        }
        return "unchanged";
    }

    my $short_keyid = '';
    for (@import_output) {
        if (/key\s+([0-9A-F]{8,16}):/) {
            $short_keyid = $1;
            last;
        }
    }
    return "No key ID" unless $short_keyid;

    my @raw = `/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --list-keys --with-colons --with-fingerprint $short_keyid 2>&1`;
    my @output = grep { !/unsafe (ownership|permissions).*nobody/i } @raw;
    if (grep /unsafe (ownership|permissions)/i, @raw) {
        log_error("GPG permission error during import");
        return "GPG permission error";
    }

    my $fingerprint = '';
    my @uids = ();
    for (@output) {
        chomp;
        my @f = split /:/, $_;
        next unless @f >= 10;
        $fingerprint = $f[9] if $f[0] eq 'fpr' && $f[9];
        push @uids, $f[9] if ($f[0] eq 'pub' || $f[0] eq 'sec') && $f[9];
    }
    return "No fingerprint" unless $fingerprint;
    return "No UIDs" unless @uids;

    my $recipient_clean = lc($recipient);
    $recipient_clean =~ s/^\s+|\s+$//g;

    my $exact_match = 0;
    for my $uid (@uids) {
        if ($uid =~ /<\s*([^>]+?)\s*>/) {
            my $email = lc($1);
            $email =~ s/^\s+|\s+$//g;
            if ($email eq $recipient_clean) {
                $exact_match = 1;
                last;
            }
        }
    }

    unless ($exact_match) {
        my $partial = grep { lc($_) =~ /\Q$recipient_clean\E/ } @uids;
        return $partial
            ? "Warning: Partial email match for '$recipient_clean'. Key imported: $fingerprint"
            : "Warning: No match for '$recipient_clean'. Key imported: $fingerprint";
    }

    # Set ultimate trust
    system(<<EOF);
/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --batch --command-fd 0 --edit-key '$fingerprint' trust <<INNER
5
y
quit
INNER
>/dev/null 2>&1
EOF

    log_debug("Imported key $fingerprint for $recipient");
    return $fingerprint;
}

#=====================================================================
# Delete key by fingerprint
#=====================================================================
sub delete_key {
    my ($fp) = @_;
    return 0 unless $fp =~ /^[0-9A-F]{40}$/i;
    return 0 unless ensure_gpg_infrastructure();

    my $cmd = "/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --batch --yes --delete-key " . quotemeta($fp);
    my $output = `$cmd 2>&1`;
    my $result = $?;

    if ($result != 0) {
        log_error("Delete failed for $fp: $output");
        return 0;
    }

    log_debug("Deleted key $fp");
    return 1;
}

#=====================================================================
# Encrypt file – returns encrypted tempfile path or undef
#=====================================================================
sub encrypt_file {
    my ($infile, $recipient) = @_;
    return undef unless $infile && -f $infile && $recipient;
    return undef unless ensure_gpg_infrastructure();

    my ($outfh, $outfile) = tempfile(DIR => '/tmp', SUFFIX => '.asc', UNLINK => 1);
    close $outfh;

    my $cmd = "/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' " .
              "--trust-model $CONFIG{'TRUSTMODEL'} --armor --batch --yes " .
              "--encrypt --recipient " . quotemeta($recipient) . " " .
              "--output " . quotemeta($outfile) . " " .
              quotemeta($infile);

    my $result = system($cmd);
    if ($result != 0) {
        log_error("Encryption failed for $recipient: $!");
        unlink $outfile if -f $outfile;
        return undef;
    }

    log_debug("Encrypted $infile → $outfile for $recipient");
    return $outfile;
}

#=====================================================================
# Get GPG version
#=====================================================================
sub get_gpg_version {
    my $out = `/usr/bin/gpg --version 2>&1`;
    if ($out =~ /gpg \(GnuPG\)\s+(\d+\.\d+)/) {
        return $1;
    }
    return "1.4";  # IPFire default
}

1;
