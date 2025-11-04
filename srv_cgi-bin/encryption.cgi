#!/usr/bin/perl
#===============================================================================
# File: /srv/web/ipfire/cgi-bin/encryption.cgi
# Description: GPG Key Management – FULLY FIXED
# Version: 0.3.1
#===============================================================================
use strict;
use warnings;
use utf8;
use CGI qw(param);
use File::Temp qw(tempfile);

# === Fallback for missing translations ===
sub lang {
	my ($key, $default) = @_;
	return $Lang::tr{$key} // $default;
}

# === Path for gpg-functions.pl ===
use lib '/var/ipfire/encryption/gpg/functions';
require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require 'gpg-functions.pl';

# === IPFire Colors ===
my %color = ();
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);

# === Dummy to avoid "used only once" warnings ===
my @dummy = ( ${Header::colouryellow} );
undef (@dummy);
$Lang::tr{'dummy'} if 0;

#=====================================================================
# Configuration
#=====================================================================
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my $MAIL_CONF = "/var/ipfire/dma/mail.conf";
my $CGI_LOG = "/var/log/encryption/cgi.log";
my %cgiparams = ();
my %enc = ();
my %mail = ();
my $errormessage = '';
my $infomessage = '';

#=====================================================================
# Logging (CGI errors)
#=====================================================================
sub log_cgi {
	my ($level, $msg) = @_;
	my $ts = scalar localtime;
	eval {
		open my $fh, '>>', $CGI_LOG or return;
		print $fh "[$ts] [CGI] [$level] $msg\n";
		close $fh;
	};
}

#=====================================================================
# Read configs
#=====================================================================
&Header::getcgihash(\%cgiparams);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);
&General::readhash($MAIL_CONF, \%mail) if (-f $MAIL_CONF);

#=====================================================================
# SECURE DEFAULTS + INPUT VALIDATION
#=====================================================================
$cgiparams{'ACTION'} //= '';
$cgiparams{'DELETE_KEY'} //= [];
$cgiparams{'DEFAULT_KEY'} //= $enc{'GPG_KEY'} || '';
$cgiparams{'TARGET_FP'} //= '';

# === ROBUST ACTION VALIDATION ===
my $raw_action = $cgiparams{'ACTION'};
my $action = $raw_action;
$action =~ s/^\s+|\s+$//g;  # trim
$action =~ s/[\r\n]//g;     # remove CR/LF

my @allowed_actions = ('Upload GPG Key', 'Test Encryption');

if ($action && !grep { $_ eq $action } @allowed_actions) {
	my $debug = "Invalid action: '$action' (raw: '$raw_action')";
	$errormessage .= "$debug<br>";
	log_cgi("ERROR", $debug);
	$cgiparams{'ACTION'} = '';
} else {
	$cgiparams{'ACTION'} = $action;
	log_cgi("DEBUG", "ACTION validated: '$action'") if $action;
}

# Validate DELETE_KEY
my @valid_fps = ();
if (ref $cgiparams{'DELETE_KEY'} eq 'ARRAY') {
	@valid_fps = grep { $_ && $_ =~ /^[0-9A-F]{40}$/i } @{$cgiparams{'DELETE_KEY'}};
} elsif ($cgiparams{'DELETE_KEY'} && $cgiparams{'DELETE_KEY'} =~ /^[0-9A-F]{40}$/i) {
	push @valid_fps, $cgiparams{'DELETE_KEY'};
}
$cgiparams{'DELETE_KEY'} = \@valid_fps;

my $default_key = $cgiparams{'DEFAULT_KEY'} =~ /^[0-9A-F]{40}$/i ? $cgiparams{'DEFAULT_KEY'} : '';
my $target_fp = $cgiparams{'TARGET_FP'} =~ /^[0-9A-F]{40}$/i ? $cgiparams{'TARGET_FP'} : '';

#=====================================================================
# Ensure GPG infrastructure
#=====================================================================
eval { &Encryption::GPG::ensure_gpg_infrastructure(); };
if ($@) {
	$errormessage = "GPG setup failed: " . &Header::escape($@);
	log_cgi("ERROR", "GPG infrastructure failed: $@");
}

#=====================================================================
# Handle actions
#=====================================================================
if ($cgiparams{'ACTION'} eq 'Upload GPG Key') {
	log_cgi("INFO", "Starting key upload");
	&import_key();
}
elsif (exists $cgiparams{'SUBMIT'}) {
	log_cgi("INFO", "Saving settings");
	&save_settings();
}
elsif ($cgiparams{'ACTION'} eq 'Test Encryption') {
	log_cgi("INFO", "Running encryption test");
	&test_encryption();
}

#=====================================================================
# Show page
#=====================================================================
&show_page();
exit 0;

#=====================================================================
# Show UI
#=====================================================================
sub show_page {
	my @keys = &Encryption::GPG::list_keys();
	&Header::showhttpheaders();
	&Header::openpage(lang('gpg key management', 'GPG Key Management'), 1, '');
	&Header::openbigbox('100%', 'center');

	&show_error();
	&show_info();

	&Header::openbox('100%', 'left', lang('gpg key management', 'GPG Key Management'));

	# === Upload Form (SEPARATE + SAFE) ===
	print "<form method='post' enctype='multipart/form-data' style='display:inline;'>\n";
	print "<input type='hidden' name='ACTION' value='Upload GPG Key'>\n";
	print "<table width='100%' class='tbl'>\n";
	print "<tr>\n";
	print "<td class='base' width='70%'><label for='GPG_KEY_FILE'>" . lang('upload public key', 'Upload Public Key') . "</label></td>\n";
	print "<td width='20%'><input type='file' name='GPG_KEY_FILE' id='GPG_KEY_FILE' style='width:100%'></td>\n";
	print "<td width='10%' align='center'><input type='submit' value='Upload'></td>\n";
	print "</tr>\n";
	print "</table>\n";
	print "</form><br>\n";

	# === Main Settings Form ===
	print "<form method='post'>\n";

	# === Debug Checkbox ===
	my $debug_checked = ($enc{'DEBUG'} // '') eq 'on' ? 'checked' : '';
	print "<table width='100%' class='tbl'>\n";
	print "<tr>\n";
	print "<td class='base' width='70%'>" . lang('enable debug output', 'Enable Debug Output') . "</td>\n";
	print "<td width='30%'><input type='checkbox' name='DEBUG' value='on' $debug_checked></td>\n";
	print "</tr>\n";
	print "</table><br>\n";

	# === Key Table ===
	print "<table width='100%' class='tbl'>\n";
	print "<tr>\n";
	print "<th width='12%' align='center'>" . lang('default', 'Default') . "</th>\n";
	print "<th width='33%' align='center'>" . lang('fingerprint', 'Fingerprint') . "</th>\n";
	print "<th width='28%' align='center'>" . lang('email', 'Email') . "</th>\n";
	print "<th width='15%' align='center'>" . lang('expiry', 'Expiry') . "</th>\n";
	print "<th width='10%' align='center'>" . lang('delete', 'Delete') . "</th>\n";
	print "<th width='10%' align='center'>" . lang('test', 'Test') . "</th>\n";
	print "</tr>\n";

	my $current_default = $enc{'GPG_KEY'} || '';
	my $key_index = 0;

	if (@keys) {
		foreach my $k (@keys) {
			my $email = Encryption::GPG::extract_email($k->{uid});
			my $email_escaped = &Header::escape($email);
			my $fp_escaped = &Header::escape($k->{fingerprint});
			my $fp_full = $k->{fingerprint};
			my $style = $k->{expired} ? " style='color:red'" : ($k->{expires_soon} ? " style='color:orange'" : '');
			my $checked = ($current_default eq $k->{fingerprint}) ? 'checked' : '';

			# Zebra + Highlight
			my $row_class = '';
			my $bg_color = '';
			if ($current_default eq $k->{fingerprint}) {
				$row_class = " bgcolor='${Header::colouryellow}'";
			} elsif ($key_index % 2) {
				$bg_color = "bgcolor='$color{'color20'}'";
			} else {
				$bg_color = "bgcolor='$color{'color22'}'";
			}

			print "<tr>\n";
			print "<td align='center' $bg_color><input type='radio' name='DEFAULT_KEY' value='$fp_escaped' $checked></td>\n";
			print "<td align='center' $bg_color $row_class><code title='$fp_full'>$fp_full</code></td>\n";
			print "<td align='center' $bg_color>$email_escaped</td>\n";
			print "<td align='center' $bg_color$style>$k->{expiry}</td>\n";
			print "<td align='center' $bg_color><input type='checkbox' name='DELETE_KEY' value='$fp_escaped'></td>\n";
			print "<td align='center' $bg_color>\n";
			print " <form method='post' action='$ENV{'SCRIPT_NAME'}' id='testform$key_index' style='display:inline' target='_blank'>\n";
			print "  <input type='hidden' name='ACTION' value='Test Encryption'>\n";
			print "  <input type='hidden' name='TARGET_FP' value='$fp_escaped'>\n";
			print "  <button type='submit' style='cursor:pointer; border:none;' title='Test Encryption'>\n";
			print "    <img src='/images/view.gif' alt='Test'>\n";
			print "  </button>\n";
			print " </form>\n";
			print "</td>\n";
			print "</tr>\n";
			$key_index++;
		}
	} else {
		print "<tr><td colspan='6' class='base' align='center'>" . lang('no keys found', 'No keys found. Upload one to get started.') . "</td></tr>\n";
	}
	print "</table><br>\n";

	# === Save Button ===
	print "<input type='submit' name='SUBMIT' value='Save Settings' style='width:100%'>\n";
	print "<p><a href='/cgi-bin/mail.cgi'>" . lang('back to mail settings', 'Back to Mail Settings') . "</a></p>\n";
	print "</form>\n";

	&Header::closebox();
	&Header::closebigbox();
	&Header::closepage();
}

#=====================================================================
# Save Settings
#=====================================================================
sub save_settings {
	my $new_gpg_key = $cgiparams{'DEFAULT_KEY'} // '';
	my $new_debug = ($cgiparams{'DEBUG'} && $cgiparams{'DEBUG'} eq 'on') ? 'on' : 'off';

	# --- 1. Validate new default key ---
	if ($new_gpg_key && $new_gpg_key !~ /^[0-9A-F]{40}$/i) {
		$errormessage .= "Invalid default key fingerprint.<br>";
		$new_gpg_key = '';
	} elsif ($new_gpg_key) {
		my @keys = &Encryption::GPG::list_keys();
		unless (grep { $_->{fingerprint} eq $new_gpg_key } @keys) {
			$errormessage .= "Selected default key not found.<br>";
			$new_gpg_key = '';
		}
	}

	# --- 2. Handle deletions ---
	my $delete_changed = 0;
	my $current_default = $enc{'GPG_KEY'} // '';
	my $default_was_deleted = 0;
	foreach my $fp (@{$cgiparams{'DELETE_KEY'}}) {
		next unless $fp =~ /^[0-9A-F]{40}$/i;
		if (&Encryption::GPG::delete_key($fp)) {
			$infomessage .= "Key <strong>$fp</strong> deleted.<br>";
			$delete_changed = 1;
			if ($current_default eq $fp) {
				$default_was_deleted = 1;
			}
		}
	}

	# --- 3. Only clear default if deleted AND no new one selected ---
	if ($default_was_deleted && !$new_gpg_key) {
		$new_gpg_key = '';
	}

	# --- 4. Compare ALL values ---
	my $current_debug = $enc{'DEBUG'} // 'off';
	my $gpg_changed = ($current_default ne $new_gpg_key);
	my $debug_changed = ($current_debug ne $new_debug);

	# --- 5. Write if ANYTHING changed ---
	my $needs_write = ($gpg_changed || $debug_changed || $delete_changed || !-f $ENCRYPTION_CONF);
	if ($needs_write) {
		$enc{'GPG_KEY'} = $new_gpg_key;
		$enc{'DEBUG'} = $new_debug;
		my $dir = "/var/ipfire/encryption/gpg/conf";
		unless (-d $dir) {
			mkdir $dir, 0750 or do {
				$errormessage .= "Failed to create config directory: $!<br>";
				log_cgi("ERROR", "mkdir failed: $!");
				return;
			};
		}
		if (&General::writehash($ENCRYPTION_CONF, \%enc)) {
			$infomessage .= "Settings saved." unless $infomessage;
			log_cgi("INFO", "Settings saved");
		} else {
			$errormessage .= "Failed to write config file.<br>";
			log_cgi("ERROR", "writehash failed");
		}
	} else {
		$infomessage .= "No changes detected.";
	}
}

#=====================================================================
# Import key
#=====================================================================
sub import_key {
	my $fh = param('GPG_KEY_FILE') or do { 
		$errormessage = "No file selected"; 
		log_cgi("ERROR", "No file selected");
		return; 
	};
	my $size = 0;
	eval { $size = -s $fh; };
	if ($@ || $size > 1048576) {
		$errormessage = "File too large (max 1MB)";
		log_cgi("ERROR", "File too large: $size bytes");
		return;
	}

	my ($tmpfh, $tmpfile) = tempfile(DIR => '/tmp', SUFFIX => '.asc', UNLINK => 1);
	my $buffer;
	my $read = read($fh, $buffer, 1048576);
	unless (defined $read && $read > 0) {
		$errormessage = "Failed to read file";
		log_cgi("ERROR", "read() failed");
		unlink $tmpfile if $tmpfile;
		return;
	}
	print $tmpfh $buffer; close $tmpfh;
	chmod 0600, $tmpfile;

	my $recipient = $mail{'RECIPIENT'} || '';
	unless ($recipient) {
		$errormessage = "No recipient configured in mail settings";
		log_cgi("ERROR", "No recipient in mail.conf");
		unlink $tmpfile;
		return;
	}

	my $result = &Encryption::GPG::import_key($tmpfile, $recipient);
	if ($result && $result !~ /^(No|GPG|ECC)/) {
		if ($result eq 'unchanged') {
			$infomessage = "Key already exists (unchanged)";
		} else {
			$infomessage = "GPG key <strong>" . &Header::escape($result) . "</strong> imported successfully";
			log_cgi("INFO", "Key imported: $result");
		}
	} else {
		$errormessage = $result || "Import failed";
		log_cgi("ERROR", "Import failed: " . ($result || 'unknown'));
	}
	unlink $tmpfile;
}

#=====================================================================
# Test encryption
#=====================================================================
sub test_encryption {
	my $fp = $target_fp || $default_key || $enc{'GPG_KEY'};
	unless ($fp && $fp =~ /^[0-9A-F]{40}$/i) {
		$errormessage = "No valid key selected for test";
		log_cgi("ERROR", "No valid key for test");
		return;
	}

	my @keys = &Encryption::GPG::list_keys();
	my ($key) = grep { $_->{fingerprint} eq $fp } @keys;
	unless ($key) {
		$errormessage = "Key not found";
		log_cgi("ERROR", "Key not found: $fp");
		return;
	}

	my $test_message = "IPFire GPG Test Message\nTime: " . scalar localtime . "\nKey: $fp\n";
	my ($tmpfh, $tmpfile) = tempfile(DIR => '/tmp', SUFFIX => '.txt', UNLINK => 1);
	print $tmpfh $test_message; close $tmpfh;

	my $encfile = &Encryption::GPG::encrypt_file($tmpfile, $fp);
	unless ($encfile && -f $encfile) {
		$errormessage = "Encryption failed";
		log_cgi("ERROR", "Encryption failed for $fp");
		unlink $tmpfile;
		return;
	}

	open my $fh, '<', $encfile or do {
		$errormessage = "Read error";
		log_cgi("ERROR", "Cannot read encrypted file");
		unlink $tmpfile, $encfile;
		return;
	};
	my $encrypted = do { local $/; <$fh> }; close $fh;
	unlink $tmpfile, $encfile;

	my $enc_escaped = &Header::escape($encrypted);
	my $status = $key->{expired} ? "<span style='color:red'>Expired</span>" :
				 $key->{expires_soon} ? "<span style='color:orange'>Expires soon</span>" :
				 "<span style='color:green'>Valid</span>";
	my $default_mark = ($enc{'GPG_KEY'} && $enc{'GPG_KEY'} eq $fp) ? " <strong>(Default)</strong>" : "";
	my %algo_map = ('1'=>'RSA','17'=>'DSA','18'=>'ECC (Curve25519)','19'=>'ECC (NIST P-256)','22'=>'EdDSA');
	my $algo_name = $algo_map{$key->{algo}} || "Unknown ($key->{algo})";
	my $algo_bits = "$algo_name ($key->{bits} bits)";
	my $key_type = $key->{secret} ? "<span style='color:purple'>Private</span>" : "Public";
	my $hint = $key->{secret}
		? "Copy this into a file (e.g. <code>test.asc</code>) and <strong>decrypt</strong> with this private key."
		: "Copy this into a file (e.g. <code>test.asc</code>) and <strong>encrypt/decrypt</strong> with this key.";

	my $email = Encryption::GPG::extract_email($key->{uid});
	my $email_display = &Header::escape($email);

	&Header::showhttpheaders();
	&Header::openpage("GPG Test Encryption", 1, '');
	&Header::openbigbox('100%', 'center');
	print "<section class=\"section is-box\">\n";
	print "<h2 class=\"title\">Test Encryption Result</h2>\n";
	print "<div class=\"base\">\n";
	print "<p><strong>Key:</strong> <code>$fp</code>$default_mark</p>\n";
	print "<p><strong>Email:</strong> $email_display</p>\n";
	print "<p><strong>Type:</strong> $key_type</p>\n";
	print "<p><strong>Status:</strong> $status</p>\n";
	print "<p><strong>Algorithm:</strong> $algo_bits</p>\n";
	print "<p><strong>Expiry:</strong> $key->{expiry}</p>\n";
	print "<hr>\n";
	print "<h3>Encrypted Message:</h3>\n";
	print "<pre style=\"background:#f8f8f8; padding:15px; border:1px solid #ddd; overflow-x:auto; font-family:monospace; white-space:pre-wrap; word-wrap:break-word; font-size:0.9em;\">\n";
	print "$enc_escaped\n";
	print "</pre>\n";
	print "<p><small><i>$hint</i></small></p>\n";
	print "</div>\n";
	print "</section>\n";
	&Header::closebigbox();
	&Header::closepage();
	exit 0;
}

#=====================================================================
# Show error/info
#=====================================================================
sub show_error {
	return unless $errormessage;
	&Header::openbox('100%', 'left', lang('error messages', 'Error Messages'));
	print "<div class='base'>" . &Header::escape($errormessage) . "</div>";
	&Header::closebox();
}

sub show_info {
	return unless $infomessage;
	&Header::openbox('100%', 'left', lang('info messages', 'Info Messages'));
	print "<div class='base'>$infomessage</div>";
	&Header::closebox();
}
