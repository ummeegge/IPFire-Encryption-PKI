#!/usr/bin/perl
#===============================================================================
# File: /srv/web/ipfire/cgi-bin/encryption.cgi
# Description: GPG Key Management – MINIMAL CGI (Logic in gpg-functions.pl)
# Version: 0.4.2 – fixed log level info message + centralized logging
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

# === Load IPFire core + Logging ===
use lib '/var/ipfire/encryption/gpg/functions';
use lib '/var/ipfire/encryption/logging';
require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require 'gpg-functions.pl';
require 'logging.pl';

# === Colors ===
my %color = ();
&General::readhash("/srv/web/ipfire/html/themes/ipfire/include/colors.txt", \%color);
my @dummy = ( ${Header::colouryellow} ); undef @dummy;
$Lang::tr{'dummy'} if 0;

#=====================================================================
# Config & Logging
#=====================================================================
my $MODULE = 'CGI';
my $ENCRYPTION_CONF = "/var/ipfire/encryption/gpg/conf/encryption.conf";
my $MAIL_CONF = "/var/ipfire/dma/mail.conf";
my %cgiparams = ();
my %enc = ();
my %mail = ();
my $errormessage = '';
my $infomessage = '';

# === Logging Helper ===
sub log_cgi {
	my ($level, $msg) = @_;
	my %levels = (ERROR => 0, WARN => 1, INFO => 2, DEBUG => 3);
	my $num = $levels{uc($level)} // 2;
	&Encryption::Logging::log_message($MODULE, $num, $msg);
}

#=====================================================================
# Read configs
#=====================================================================
&Header::getcgihash(\%cgiparams);
&General::readhash($ENCRYPTION_CONF, \%enc) if (-f $ENCRYPTION_CONF);
&General::readhash($MAIL_CONF, \%mail) if (-f $MAIL_CONF);

#=====================================================================
# SECURE INPUT VALIDATION
#=====================================================================
$cgiparams{'ACTION'} //= '';
$cgiparams{'DELETE_KEY'} //= [];
$cgiparams{'DEFAULT_KEY'} //= $enc{'GPG_KEY'} || '';
$cgiparams{'TARGET_FP'} //= '';
$cgiparams{'LOG_LEVEL_CGI'} //= $enc{'LOG_LEVEL_CGI'} // 2;

# --- ACTION WHITELIST ---
my $raw_action = $cgiparams{'ACTION'};
my $action = $raw_action;
$action =~ s/^\s+|\s+$//g;
$action =~ s/[\r\n]//g;
my @allowed = ('Upload GPG Key', 'Test Encryption');
if ($action && !grep { $_ eq $action } @allowed) {
	$errormessage .= "Invalid action: '$action'<br>";
	log_cgi("ERROR", "Invalid action: '$action' (raw: '$raw_action')");
	$cgiparams{'ACTION'} = '';
} else {
	$cgiparams{'ACTION'} = $action;
	log_cgi("DEBUG", "ACTION: '$action'") if $action;
}

# --- Sanitize inputs ---
my @valid_fps = ref $cgiparams{'DELETE_KEY'} eq 'ARRAY'
	? grep { $_ && /^[0-9A-F]{40}$/i } @{$cgiparams{'DELETE_KEY'}}
	: $cgiparams{'DELETE_KEY'} && $cgiparams{'DELETE_KEY'} =~ /^[0-9A-F]{40}$/i
		? ($cgiparams{'DELETE_KEY'})
		: ();
$cgiparams{'DELETE_KEY'} = \@valid_fps;
my $default_key = $cgiparams{'DEFAULT_KEY'} =~ /^[0-9A-F]{40}$/i ? $cgiparams{'DEFAULT_KEY'} : '';
my $target_fp = $cgiparams{'TARGET_FP'} =~ /^[0-9A-F]{40}$/i ? $cgiparams{'TARGET_FP'} : '';
my $log_level_cgi = $cgiparams{'LOG_LEVEL_CGI'} =~ /^[0-3]$/ ? $cgiparams{'LOG_LEVEL_CGI'} : ($enc{'LOG_LEVEL_CGI'} // 2);

#=====================================================================
# Ensure GPG setup
#=====================================================================
eval { &Encryption::GPG::ensure_gpg_infrastructure(); };
if ($@) {
	$errormessage = "GPG setup failed: " . &Header::escape($@);
	log_cgi("ERROR", "GPG infrastructure failed: $@");
}

#=====================================================================
# ACTION DISPATCHER
#=====================================================================
if ($cgiparams{'ACTION'} eq 'Upload GPG Key') {
	log_cgi("INFO", "Upload requested");
	my ($ok, $fp, $msg) = &Encryption::GPG::handle_upload_and_import(
		param('GPG_KEY_FILE'), $mail{'RECIPIENT'}
	);
	if ($ok) {
		$infomessage .= $msg;
		$infomessage .= "<br>Key already exists (unchanged)." if $fp && $fp eq 'unchanged';
	} else {
		$errormessage .= $msg;
		log_cgi("ERROR", "Upload failed: $msg");
	}
}
elsif (exists $cgiparams{'SUBMIT'}) {
	log_cgi("INFO", "Save settings requested");

	# === Save GPG settings (without LOG_LEVEL_CGI) ===
	my ($changed, $msg) = &Encryption::GPG::save_settings(
		$default_key,
		$cgiparams{'DEBUG'},
		$cgiparams{'DELETE_KEY'},
		\%enc
	);

	# === Save LOG_LEVEL_CGI separately ===
	my $old_log_level = &Encryption::Logging::get_log_level('CGI');
	&Encryption::Logging::set_log_level('CGI', $log_level_cgi);
	my $new_log_level = &Encryption::Logging::get_log_level('CGI');

	# === Reload config (always) ===
	&General::readhash($ENCRYPTION_CONF, \%enc);

	# === Build custom info message ===
	my @info_parts;
	if ($msg && $msg ne 'No changes detected.') {
		push @info_parts, $msg;
	}
	if ($old_log_level != $new_log_level) {
		push @info_parts, "Log level for CGI changed from $old_log_level to $new_log_level.";
	}
	if (@info_parts) {
		$infomessage = join("<br>", @info_parts);
	} else {
		$infomessage = "No changes detected.";
	}

	log_cgi("INFO", "Log level for cgi set to $log_level_cgi");
}
elsif ($cgiparams{'ACTION'} eq 'Test Encryption') {
	log_cgi("INFO", "Test encryption for $target_fp");
	my $fp = $target_fp || $default_key || $enc{'GPG_KEY'};
	my $error = &Encryption::GPG::run_test_and_render($fp, $enc{'GPG_KEY'});
	if ($error) {
		$errormessage .= $error;
		log_cgi("ERROR", "Test failed: $error");
	}
}

#=====================================================================
# Show page
#=====================================================================
&show_page();
exit 0;

#=====================================================================
# UI
#=====================================================================
sub show_page {
	my @keys = &Encryption::GPG::list_keys();
	&Header::showhttpheaders();
	&Header::openpage(lang('gpg key management', 'GPG Key Management'), 1, '');
	&Header::openbigbox('100%', 'center');
	&show_error();
	&show_info();
	&Header::openbox('100%', 'left', lang('gpg key management', 'GPG Key Management'));

	# === Upload Form ===
	print "<form method='post' enctype='multipart/form-data' style='display:inline;'>\n";
	print "<input type='hidden' name='ACTION' value='Upload GPG Key'>\n";
	print "<table width='100%' class='tbl'><tr>\n";
	print "<td class='base' width='70%'><label for='GPG_KEY_FILE'>" . lang('upload public key', 'Upload Public Key') . "</label></td>\n";
	print "<td width='20%'><input type='file' name='GPG_KEY_FILE' id='GPG_KEY_FILE' style='width:100%'></td>\n";
	print "<td width='10%' align='center'><input type='submit' value='Upload'></td>\n";
	print "</tr></table></form><br>\n";

	# === Main Form ===
	print "<form method='post'>\n";
	my $debug_checked = ($enc{'DEBUG'} // '') eq 'on' ? 'checked' : '';
	my $current_log_level = &Encryption::Logging::get_log_level('CGI');

	# === Debug + Log Level ===
	print "<table width='100%' class='tbl'><tr>\n";
	print "<td class='base' width='70%'>" . lang('enable debug output', 'Enable Debug Output') . "</td>\n";
	print "<td width='30%'><input type='checkbox' name='DEBUG' value='on' $debug_checked></td>\n";
	print "</tr><tr>\n";
	print "<td class='base'>CGI Log Level (0=Error, 3=Debug)</td>\n";
	print "<td><select name='LOG_LEVEL_CGI'>\n";
	for my $l (0..3) {
		my $sel = $current_log_level == $l ? 'selected' : '';
		my $name = ('ERROR','WARN','INFO','DEBUG')[$l];
		print "<option value='$l' $sel>$l ($name)</option>\n";
	}
	print "</select></td>\n";
	print "</tr></table><br>\n";

	# === Key Table ===
	print "<table width='100%' class='tbl'>\n";
	print "<tr><th width='12%'>" . lang('default', 'Default') . "</th>\n";
	print "<th width='33%'>" . lang('fingerprint', 'Fingerprint') . "</th>\n";
	print "<th width='28%'>" . lang('email', 'Email') . "</th>\n";
	print "<th width='15%'>" . lang('expiry', 'Expiry') . "</th>\n";
	print "<th width='10%'>" . lang('delete', 'Delete') . "</th>\n";
	print "<th width='10%'>" . lang('test', 'Test') . "</th></tr>\n";
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
			my $row_class = $current_default eq $k->{fingerprint} ? " bgcolor='${Header::colouryellow}'" : '';
			my $bg_color = $key_index % 2 ? "bgcolor='$color{'color20'}'" : "bgcolor='$color{'color22'}'";
			print "<tr>\n";
			print "<td align='center' $bg_color><input type='radio' name='DEFAULT_KEY' value='$fp_escaped' $checked></td>\n";
			print "<td align='center' $bg_color $row_class><code title='$fp_full'>$fp_full</code></td>\n";
			print "<td align='center' $bg_color>$email_escaped</td>\n";
			print "<td align='center' $bg_color$style>$k->{expiry}</td>\n";
			print "<td align='center' $bg_color><input type='checkbox' name='DELETE_KEY' value='$fp_escaped'></td>\n";
			print "<td align='center' $bg_color>\n";
			print " <form method='post' action='$ENV{'SCRIPT_NAME'}' id='testform_$key_index' style='display:inline' target='_blank' rel='noopener'>\n";
			print " <input type='hidden' name='ACTION' value='Test Encryption'>\n";
			print " <input type='hidden' name='TARGET_FP' value='$fp_escaped'>\n";
			print " <button type='submit' style='cursor:pointer; border:none;' title='Test Encryption'>\n";
			print " <img src='/images/view.gif' alt='Test'>\n";
			print " </button>\n";
			print " </form>\n";
			$key_index++;
		}
	} else {
		print "<tr><td colspan='6' class='base' align='center'>" . lang('no keys found', 'No keys found. Upload one to get started.') . "</td></tr>\n";
	}
	print "</table><br>\n";
	print "<input type='submit' name='SUBMIT' value='Save Settings' style='width:100%'>\n";
	print "<p><a href='/cgi-bin/mail.cgi'>" . lang('back to mail settings', 'Back to Mail Settings') . "</a></p>\n";
	print "</form>\n";
	&Header::closebox();
	&Header::closebigbox();
	&Header::closepage();
}

sub show_error { $errormessage && do { &Header::openbox('100%', 'left', lang('error messages', 'Error Messages')); print "<div class='base'>" . &Header::escape($errormessage) . "</div>"; &Header::closebox(); }; }
sub show_info { $infomessage && do { &Header::openbox('100%', 'left', lang('info messages', 'Info Messages')); print "<div class='base'>$infomessage</div>"; &Header::closebox(); }; }