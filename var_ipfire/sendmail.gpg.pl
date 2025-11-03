#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/bin/sendmail.gpg.pl
# Version: 0.3 – encryption.conf support + secure GPG + dual mtime reload
#===============================================================================
use strict;
use warnings;
use MIME::Lite;
use File::Temp qw(tempfile);
use POSIX qw(strftime);
use File::stat;
require '/var/ipfire/general-functions.pl';
no warnings 'once';

# Config paths
my $MAIL_CONF       = "/var/ipfire/dma/mail.conf";
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";

# Load configs
my %mail = ();
my %enc  = ();

&General::readhash($MAIL_CONF, \%mail) if (-f $MAIL_CONF);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);

# mtime for reload
my $mail_mtime       = (-f $MAIL_CONF) ? stat($MAIL_CONF)->mtime : 0;
my $encryption_mtime = (-f $ENCRYPTION_CONF) ? stat($ENCRYPTION_CONF)->mtime : 0;

# Debug + Logfile from encryption.conf
my $debug   = ($enc{'DEBUG'} // '') eq 'on';
my $logfile = $enc{'LOGFILE'} // '/var/log/encryption/gpgmail.log';

sub log_msg {
    my $msg = shift;
    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    open my $log, '>>', $logfile or return;
    print $log "[$ts] [GPG] $msg\n";
    close $log;
}
sub debug { log_msg("DEBUG: @_") if $debug; print STDERR "[GPG] @_\n" if $debug; }
sub error { log_msg("ERROR: @_"); print STDERR "[ERROR] @_\n"; }

debug "START - Loaded configs (mail mtime: $mail_mtime, encryption mtime: $encryption_mtime)";

# Extract valid recipients from arguments
my @recipients = grep { /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ } @ARGV;
unless (@recipients) {
    error "No valid recipients";
    exit 1;
}
debug "Recipients: @recipients";

# Declare tempfile variables with global scope to be accessible during cleanup
my ($tmpfh, $tmpfile);
($tmpfh, $tmpfile) = tempfile(UNLINK => 1);

# Read entire mail input (headers + body) from STDIN
my $mail_data = do { local $/; <STDIN> };
debug "Read " . length($mail_data) . " bytes from STDIN";

# Parse headers and body from raw mail data
my %headers;
my $body = '';
my $in_headers = 1;
foreach my $line (split /\r?\n/, $mail_data) {
    if ($in_headers && $line =~ /^(\S+):\s*(.*)$/) {
        $headers{$1} = $2;
    } else {
        $in_headers = 0;
        $body .= "$line\n" unless $line =~ /^\s*$/;
    }
}
debug "Extracted headers: " . join(', ', keys %headers);
debug "Body length: " . length($body);

# Reload configs if changed
if (-f $MAIL_CONF) {
    my $cur_mtime = stat($MAIL_CONF)->mtime;
    if ($cur_mtime > $mail_mtime) {
        %mail = ();
        &General::readhash($MAIL_CONF, \%mail);
        $mail_mtime = $cur_mtime;
        debug "Reloaded mail.conf (mtime: $mail_mtime)";
    }
}
if (-f $ENCRYPTION_CONF) {
    my $cur_mtime = stat($ENCRYPTION_CONF)->mtime;
    if ($cur_mtime > $encryption_mtime) {
        %enc = ();
        &General::readhash($ENCRYPTION_CONF, \%enc);
        $encryption_mtime = $cur_mtime;
        $debug = ($enc{'DEBUG'} // '') eq 'on';  # Update debug flag
        debug "Reloaded encryption.conf (mtime: $encryption_mtime)";
    }
}

# Determine sender address
my $from = $mail{'MASQUERADE'} || $mail{'SENDER'} || 'nobody@ipfire.localdomain';

my $msg;
my $gpg_key = $enc{'GPG_KEY'} // '';
my $gpg_homedir = $enc{'GPG_HOMEDIR'} // '/var/ipfire/encryption/gpg/keys';

if (($mail{'ENCRYPT'} // '') eq 'on' && $gpg_key =~ /^[0-9A-F]{40}$/i) {
    debug "Encryption enabled, encrypting mail body with key $gpg_key";
    # Create plaintext MIME message for encryption
    my $plain_msg = MIME::Lite->new(
        Type => 'text/plain',
        Data => $body,
        Encoding => '7bit',
    );
    $plain_msg->attr('MIME-Version' => '1.0');
    $plain_msg->attr('Content-Disposition' => 'inline');
    my $plain_string = $plain_msg->as_string;
    debug "Plaintext MIME message length for encryption: " . length($plain_string);

    # Save plaintext MIME to temp file
    my ($fh, $plain_file) = tempfile(DIR => '/tmp', SUFFIX => '.txt', UNLINK => 0);
    print $fh $plain_string;
    close $fh;
    chmod 0600, $plain_file;
    my $encrypted_file = "$plain_file.asc";

    # Encrypt using GPG CLI with secure options
    my $gpg_cmd = "/usr/bin/gpg --homedir $gpg_homedir --no-default-keyring --keyring $gpg_homedir/pubring.gpg --trust-model always --armor --encrypt --quiet --recipient '$gpg_key' --output $encrypted_file $plain_file 2>/dev/null";
    system($gpg_cmd) == 0 or do {
        error "GPG encryption failed for $gpg_key";
        unlink $plain_file;
        exit 1;
    };
    debug "Encrypted file created";

    # Read encrypted data from file
    open(my $enc_fh, '<', $encrypted_file) or do {
        error "Cannot open encrypted file: $!";
        unlink $plain_file;
        unlink $encrypted_file;
        exit 1;
    };
    my $encrypted_data = do { local $/; <$enc_fh> };
    close $enc_fh;

    # Build PGP/MIME multipart encrypted message
    $msg = MIME::Lite->new(
        Type => 'multipart/encrypted; protocol="application/pgp-encrypted"',
        From => $from,
        To => join(',', @recipients),
        Subject => $headers{'Subject'} || 'IPFire Encrypted Mail',
        Date => strftime("%a, %d %b %Y %H:%M:%S %z", localtime),
    );
    $msg->attr('MIME-Version' => '1.0');
    $msg->attach(
        Type => 'application/pgp-encrypted',
        Data => "Version: 1\n",
        Encoding => '7bit',
        Disposition => 'inline',
    );
    $msg->attach(
        Type => 'application/octet-stream',
        Data => $encrypted_data,
        Encoding => '7bit',
        Disposition => 'inline',
        Filename => 'encrypted.asc',
        Description => 'OpenPGP encrypted message',
    );
    unlink $plain_file;
    unlink $encrypted_file;
    debug "Encrypted MIME message built";
} else {
    my $reason = ($mail{'ENCRYPT'} // '') eq 'on' ? "no valid GPG_KEY" : "ENCRYPT off";
    debug "Encryption disabled ($reason), sending plaintext";
    # Build plain text message
    $msg = MIME::Lite->new(
        Type => 'text/plain; charset=utf-8',
        From => $from,
        To => join(',', @recipients),
        Subject => $headers{'Subject'} || 'IPFire Mail',
        Date => strftime("%a, %d %b %Y %H:%M:%S %z", localtime),
        Data => $body,
    );
    $msg->attr('MIME-Version' => '1.0');
    debug "Plaintext mail built";
}

# Debug output of headers correctly using attr()
debug "Envelope-From (DMA -f): $from";
debug "Email Header From: " . ($msg->attr('From') // '(undef)');
debug "Email Header To: " . ($msg->attr('To') // '(undef)');
debug "Email Header Subject: " . ($msg->attr('Subject') // '(undef)');
debug "Email Content-Type: " . ($msg->attr('Content-Type') // '(undef)');

# Save the email contents to a file for debugging inspection
eval {
    open my $fh_out, '>', "/tmp/wrapper_debug_mail.eml" or die "Cannot open mail save file: $!";
    print $fh_out $msg->as_string;
    close $fh_out;
    debug "Mail saved to /tmp/wrapper_debug_mail.eml for inspection";
};
if ($@) {
    error "Failed to save mail to file: $@";
}

SEND:
debug "Sending via DMA with -f $from";
open my $dma, '|-', '/usr/sbin/sendmail.dma', '-f', $from, @recipients
    or do { error "Cannot start DMA: $!"; unlink $tmpfile; exit 1; };
print $dma $msg->as_string;
close $dma;
my $exit = $? >> 8;
if ($exit == 0) {
    debug "Mail successfully sent.";
} else {
    error "DMA failed with exit code $exit.";
}
unlink $tmpfile;
exit $exit;
