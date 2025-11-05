#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/bin/sendmail.gpg.pl
# Version: 0.4.0 – centralized logging via Encryption::Logging + WRAPPER
#===============================================================================
use strict;
use warnings;
use MIME::Lite;
use File::Temp qw(tempfile);
use POSIX qw(strftime);
use File::stat;

require '/var/ipfire/general-functions.pl';

# === LOAD CENTRAL LOGGING ===
use lib '/var/ipfire/encryption/logging';
require 'logging.pl';
my $MODULE = 'WRAPPER';

sub log_wrapper {
    my ($level, $msg) = @_;
    my %levels = (ERROR => 0, WARN => 1, INFO => 2, DEBUG => 3);
    my $num = $levels{$level} // 2;
    &Encryption::Logging::log_message($MODULE, $num, $msg);
}

# === Configs ===
my $MAIL_CONF       = "/var/ipfire/dma/mail.conf";
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my %mail = ();
my %enc  = ();

&General::readhash($MAIL_CONF, \%mail)       if (-f $MAIL_CONF);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);

my $mail_mtime       = (-f $MAIL_CONF)       ? stat($MAIL_CONF)->mtime       : 0;
my $encryption_mtime = (-f $ENCRYPTION_CONF) ? stat($ENCRYPTION_CONF)->mtime : 0;

my $debug = ($enc{'DEBUG'} // '') eq 'on';

log_wrapper('INFO', "START - Loaded configs (mail mtime: $mail_mtime, encryption mtime: $encryption_mtime)");

# === Validate recipients ===
my @recipients = grep { /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ } @ARGV;
unless (@recipients) {
    log_wrapper('ERROR', "No valid recipients");
    exit 1;
}
log_wrapper('INFO', "Recipients: @recipients");

# === Read mail from STDIN ===
my ($tmpfh, $tmpfile) = tempfile(UNLINK => 1);
my $mail_data = do { local $/; <STDIN> };
log_wrapper('DEBUG', "Read " . length($mail_data) . " bytes from STDIN") if $debug;

# === Parse headers + body ===
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
log_wrapper('DEBUG', "Extracted headers: " . join(', ', keys %headers)) if $debug;
log_wrapper('DEBUG', "Body length: " . length($body)) if $debug;

# === Reload configs if changed ===
if (-f $MAIL_CONF && stat($MAIL_CONF)->mtime > $mail_mtime) {
    %mail = ();
    &General::readhash($MAIL_CONF, \%mail);
    $mail_mtime = stat($MAIL_CONF)->mtime;
    log_wrapper('DEBUG', "Reloaded mail.conf (mtime: $mail_mtime)") if $debug;
}
if (-f $ENCRYPTION_CONF && stat($ENCRYPTION_CONF)->mtime > $encryption_mtime) {
    %enc = ();
    &General::readhash($ENCRYPTION_CONF, \%enc);
    $encryption_mtime = stat($ENCRYPTION_CONF)->mtime;
    $debug = ($enc{'DEBUG'} // '') eq 'on';
    log_wrapper('DEBUG', "Reloaded encryption.conf (mtime: $encryption_mtime)") if $debug;
}

# === Determine sender ===
my $from = $mail{'MASQUERADE'} || $mail{'SENDER'} || 'nobody@ipfire.localdomain';
my $msg;
my $gpg_key = $enc{'GPG_KEY'} // '';
my $gpg_homedir = $enc{'GPG_HOMEDIR'} // '/var/ipfire/encryption/gpg/keys';

# === ENCRYPTION ===
if (($mail{'ENCRYPT'} // '') eq 'on' && $gpg_key =~ /^[0-9A-F]{40}$/i) {
    log_wrapper('INFO', "Encryption enabled, encrypting mail body with key $gpg_key");

    my $plain_msg = MIME::Lite->new(
        Type => 'text/plain',
        Data => $body,
        Encoding => '7bit',
    );
    $plain_msg->attr('MIME-Version' => '1.0');
    $plain_msg->attr('Content-Disposition' => 'inline');
    my $plain_string = $plain_msg->as_string;
    log_wrapper('DEBUG', "Plaintext MIME message length for encryption: " . length($plain_string)) if $debug;

    my ($fh, $plain_file) = tempfile(DIR => '/tmp', SUFFIX => '.txt', UNLINK => 0);
    print $fh $plain_string;
    close $fh;
    chmod 0600, $plain_file;

    my $encrypted_file = "$plain_file.asc";
    my $gpg_cmd = "/usr/bin/gpg --homedir $gpg_homedir --no-default-keyring --keyring $gpg_homedir/pubring.gpg --trust-model always --armor --encrypt --quiet --recipient '$gpg_key' --output $encrypted_file $plain_file 2>/dev/null";

    system($gpg_cmd) == 0 or do {
        log_wrapper('ERROR', "GPG encryption failed for $gpg_key");
        unlink $plain_file;
        exit 1;
    };
    log_wrapper('DEBUG', "Encrypted file created") if $debug;

    open(my $enc_fh, '<', $encrypted_file) or do {
        log_wrapper('ERROR', "Cannot open encrypted file: $!");
        unlink $plain_file; unlink $encrypted_file;
        exit 1;
    };
    my $encrypted_data = do { local $/; <$enc_fh> };
    close $enc_fh;

    $msg = MIME::Lite->new(
        Type => 'multipart/encrypted; protocol="application/pgp-encrypted"',
        From => $from,
        To => join(',', @recipients),
        Subject => $headers{'Subject'} || 'IPFire Encrypted Mail',
        Date => strftime("%a, %d %b %Y %H:%M:%S %z", localtime),
    );
    $msg->attr('MIME-Version' => '1.0');
    $msg->attach(Type => 'application/pgp-encrypted', Data => "Version: 1\n", Encoding => '7bit', Disposition => 'inline');
    $msg->attach(Type => 'application/octet-stream', Data => $encrypted_data, Encoding => '7bit', Disposition => 'inline', Filename => 'encrypted.asc');

    unlink $plain_file; unlink $encrypted_file;
    log_wrapper('DEBUG', "Encrypted MIME message built") if $debug;
} else {
    my $reason = ($mail{'ENCRYPT'} // '') eq 'on' ? "no valid GPG_KEY" : "ENCRYPT off";
    log_wrapper('INFO', "Encryption disabled ($reason), sending plaintext");

    $msg = MIME::Lite->new(
        Type => 'text/plain; charset=utf-8',
        From => $from,
        To => join(',', @recipients),
        Subject => $headers{'Subject'} || 'IPFire Mail',
        Date => strftime("%a, %d %b %Y %H:%M:%S %z", localtime),
        Data => $body,
    );
    $msg->attr('MIME-Version' => '1.0');
    log_wrapper('DEBUG', "Plaintext mail built") if $debug;
}

# === Debug headers ===
log_wrapper('DEBUG', "Envelope-From (DMA -f): $from") if $debug;
log_wrapper('DEBUG', "Email Header From: " . ($msg->attr('From') // '(undef)')) if $debug;
log_wrapper('DEBUG', "Email Header To: " . ($msg->attr('To') // '(undef)')) if $debug;
log_wrapper('DEBUG', "Email Header Subject: " . ($msg->attr('Subject') // '(undef)')) if $debug;
log_wrapper('DEBUG', "Email Content-Type: " . ($msg->attr('Content-Type') // '(undef)')) if $debug;

# === Save debug mail ===
eval {
    open my $fh_out, '>', "/tmp/wrapper_debug_mail.eml" or die $!;
    print $fh_out $msg->as_string;
    close $fh_out;
    log_wrapper('DEBUG', "Mail saved to /tmp/wrapper_debug_mail.eml for inspection") if $debug;
};
log_wrapper('ERROR', "Failed to save mail to file: $@") if $@;

# === SEND via DMA ===
log_wrapper('INFO', "Sending via DMA with -f $from");
open my $dma, '|-', '/usr/sbin/sendmail.dma', '-f', $from, @recipients
    or do { log_wrapper('ERROR', "Cannot start DMA: $!"); unlink $tmpfile; exit 1; };
print $dma $msg->as_string;
close $dma;
my $exit = $? >> 8;

if ($exit == 0) {
    log_wrapper('INFO', "Mail successfully sent.");
} else {
    log_wrapper('ERROR', "DMA failed with exit code $exit.");
}

unlink $tmpfile;
exit $exit;
