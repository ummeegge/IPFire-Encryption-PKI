#!/usr/bin/perl
#===============================================================================
# File: /var/ipfire/encryption/gpg/functions/gpg-functions.pl
# Purpose: Core GPG operations – now also CGI helper routines
# Version: 0.4 – added CGI-level helpers (import, save, test, delete)
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
# Extract email from GPG UID string (e.g. "Name <email>")
#=====================================================================
sub extract_email {
	my ($uid) = @_;
	return '' unless defined $uid;
	my ($email) = $uid =~ /<([^>]+)>/;
	return $email // $uid;
}

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

	unless (glob("$CONFIG{'GPGDIR'}/pubring.*") || glob("$CONFIG{'GPGDIR'}/secring.*")) {
		system("/usr/bin/gpg --homedir '$CONFIG{'GPGDIR'}' --list-keys >/dev/null 2>&1");
		log_debug("Initialized empty GPG keyring in $CONFIG{'GPGDIR'}");
	}

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
# Import key – returns fingerprint or status string
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

	log_debug("Encrypted $infile to $outfile for $recipient");
	return $outfile;
}

#=====================================================================
# NEW: Import key with CGI upload handling (replaces encryption.cgi::import_key)
#=====================================================================
sub import_key_with_upload {
	my ($upload_fh, $recipient, $max_size) = @_;
	$max_size //= 1048576;

	unless ($upload_fh) {
		return (0, "No file selected");
	}

	my $size = 0;
	eval { $size = -s $upload_fh; };
	if ($@ || $size > $max_size) {
		return (0, "File too large (max 1MB)");
	}

	my ($tmpfh, $tmpfile) = tempfile(DIR => '/tmp', SUFFIX => '.asc', UNLINK => 1);
	my $buffer;
	my $read = read($upload_fh, $buffer, $max_size);
	unless (defined $read && $read > 0) {
		unlink $tmpfile if $tmpfile;
		return (0, "Failed to read file");
	}
	print $tmpfh $buffer; close $tmpfh;
	chmod 0600, $tmpfile;

	unless ($recipient) {
		unlink $tmpfile;
		return (0, "No recipient configured in mail settings");
	}

	my $result = import_key($tmpfile, $recipient);
	unlink $tmpfile;

	if ($result && $result !~ /^(No|GPG|ECC)/) {
		if ($result eq 'unchanged') {
			return (1, "unchanged", "Key already exists (unchanged)");
		} else {
			return (1, $result, "GPG key <strong>" . &Header::escape($result) . "</strong> imported successfully");
		}
	} else {
		return (0, $result || "Import failed");
	}
}

#=====================================================================
# NEW: Validate default key against current key list
#=====================================================================
sub validate_default_key {
	my ($new_key, $current_keys_ref) = @_;
	return '' unless $new_key && $new_key =~ /^[0-9A-F]{40}$/i;
	my @keys = @{$current_keys_ref // [list_keys()]};
	return (grep { $_->{fingerprint} eq $new_key } @keys) ? $new_key : '';
}

#=====================================================================
# NEW: Delete selected keys and return change flags
#=====================================================================
sub delete_selected_keys {
	my ($delete_fps_ref, $current_default) = @_;
	my $changed = 0;
	my $default_deleted = 0;

	foreach my $fp (@{$delete_fps_ref}) {
		next unless $fp =~ /^[0-9A-F]{40}$/i;
		if (delete_key($fp)) {
			log_debug("Deleted key $fp via CGI");
			$changed = 1;
			$default_deleted = 1 if $current_default eq $fp;
		}
	}
	return ($changed, $default_deleted);
}

#=====================================================================
# NEW: Save encryption settings (GPG_KEY + DEBUG)
#=====================================================================
sub save_encryption_settings {
	my ($new_gpg_key, $new_debug, $old_config_ref) = @_;
	my $current_default = $old_config_ref->{'GPG_KEY'} // '';
	my $current_debug = $old_config_ref->{'DEBUG'} // 'off';

	my $gpg_changed = ($current_default ne $new_gpg_key);
	my $debug_changed = ($current_debug ne $new_debug);

	return (0, "No changes detected.") unless ($gpg_changed || $debug_changed || !-f $CONFIG_FILE);

	my %new_config = (
		GPG_KEY => $new_gpg_key,
		DEBUG   => $new_debug,
	);

	my $dir = "/var/ipfire/encryption/gpg/conf";
	make_path($dir, { mode => 0750 }) unless -d $dir;

	if (&General::writehash($CONFIG_FILE, \%new_config)) {
		log_debug("Encryption settings saved: GPG_KEY=$new_gpg_key, DEBUG=$new_debug");
		return (1, "Settings saved.");
	} else {
		log_error("Failed to write encryption.conf");
		return (0, "Failed to write config file.");
	}
}

#=====================================================================
# NEW: Run encryption test – returns (encrypted_text, key_hash, error)
#=====================================================================
sub run_encryption_test {
	my ($fp) = @_;
	return (undef, undef, "No valid key") unless $fp && $fp =~ /^[0-9A-F]{40}$/i;

	my @keys = list_keys();
	my ($key) = grep { $_->{fingerprint} eq $fp } @keys;
	return (undef, undef, "Key not found") unless $key;

	my $test_message = "IPFire GPG Test Message\nTime: " . scalar localtime . "\nKey: $fp\n";
	my ($tmpfh, $tmpfile) = tempfile(DIR => '/tmp', SUFFIX => '.txt', UNLINK => 1);
	print $tmpfh $test_message; close $tmpfh;

	my $encfile = encrypt_file($tmpfile, $fp);
	unless ($encfile && -f $encfile) {
		unlink $tmpfile;
		return (undef, undef, "Encryption failed");
	}

	open my $fh, '<', $encfile or do {
		unlink $tmpfile, $encfile;
		return (undef, undef, "Read error");
	};
	my $encrypted = do { local $/; <$fh> }; close $fh;
	unlink $tmpfile, $encfile;

	return ($encrypted, $key, "");
}

#=====================================================================
# Get GPG version
#=====================================================================
sub get_gpg_version {
	my $out = `/usr/bin/gpg --version 2>&1`;
	if ($out =~ /gpg \(GnuPG\)\s+(\d+\.\d+)/) {
		return $1;
	}
	return "1.4";
}

#=====================================================================
# CGI: Handle key upload
#=====================================================================
sub handle_upload_and_import {
	my ($upload_fh, $recipient) = @_;
	return (0, undef, "No file selected") unless $upload_fh;

	my $size = eval { -s $upload_fh } || 0;
	return (0, undef, "File too large (max 1MB)") if $size > 1048576;

	my ($tmpfh, $tmpfile) = tempfile(DIR => '/tmp', SUFFIX => '.asc', UNLINK => 1);
	my $buffer;
	my $read = read($upload_fh, $buffer, 1048576);
	unless (defined $read && $read > 0) {
		unlink $tmpfile if $tmpfile;
		return (0, undef, "Failed to read file");
	}
	print $tmpfh $buffer; close $tmpfh;
	chmod 0600, $tmpfile;

	unless ($recipient) {
		unlink $tmpfile;
		return (0, undef, "No recipient configured in mail settings");
	}

	my $result = import_key($tmpfile, $recipient);
	unlink $tmpfile;

	if ($result && $result !~ /^(No|GPG|ECC)/) {
		if ($result eq 'unchanged') {
			return (1, 'unchanged', "Key already exists (unchanged)");
		} else {
			return (1, $result, "GPG key <strong>" . &Header::escape($result) . "</strong> imported successfully");
		}
	} else {
		my $err = $result || "Import failed";
		return (0, undef, $err);
	}
}

#=====================================================================
# CGI: Save settings
#=====================================================================
sub save_settings {
	my ($new_gpg_key, $new_debug, $delete_fps_ref, $current_config_ref) = @_;
	my @messages = ();
	my $changed = 0;

	# Validate default key
	if ($new_gpg_key && $new_gpg_key !~ /^[0-9A-F]{40}$/i) {
		push @messages, "Invalid default key fingerprint.";
		$new_gpg_key = '';
	} elsif ($new_gpg_key) {
		my @keys = list_keys();
		unless (grep { $_->{fingerprint} eq $new_gpg_key } @keys) {
			push @messages, "Selected default key not found.";
			$new_gpg_key = '';
		}
	}

	# Handle deletions
	my $current_default = $current_config_ref->{GPG_KEY} // '';
	my $default_deleted = 0;
	foreach my $fp (@$delete_fps_ref) {
		next unless $fp =~ /^[0-9A-F]{40}$/i;
		if (delete_key($fp)) {
			push @messages, "Key <strong>$fp</strong> deleted.";
			$changed = 1;
			$default_deleted = 1 if $current_default eq $fp;
		}
	}
	$new_gpg_key = '' if $default_deleted && !$new_gpg_key;

	# Debug
	my $current_debug = $current_config_ref->{DEBUG} // 'off';
	$new_debug = ($new_debug eq 'on') ? 'on' : 'off';
	my $debug_changed = ($current_debug ne $new_debug);

	my $gpg_changed = ($current_default ne $new_gpg_key);
	my $needs_write = ($gpg_changed || $debug_changed || $changed || !-f $CONFIG_FILE);

	if ($needs_write) {
		my %new_config = (GPG_KEY => $new_gpg_key, DEBUG => $new_debug);
		my $dir = "/var/ipfire/encryption/gpg/conf";
		make_path($dir, { mode => 0750 }) unless -d $dir;
		if (&General::writehash($CONFIG_FILE, \%new_config)) {
			push @messages, "Settings saved." unless @messages;
			$changed = 1;
		} else {
			push @messages, "Failed to write config file.";
		}
	} else {
		push @messages, "No changes detected." unless @messages;
	}

	return ($changed, join("<br>", @messages));
}

#=====================================================================
# CGI: Run test and render
#=====================================================================
sub run_test_and_render {
	my ($fp, $default_key) = @_;
	return "No valid key selected for test" unless $fp && $fp =~ /^[0-9A-F]{40}$/i;

	my @keys = list_keys();
	my ($key) = grep { $_->{fingerprint} eq $fp } @keys;
	return "Key not found" unless $key;

	my ($encrypted, $key_info, $error) = run_encryption_test($fp);
	return $error if $error;

	my $status = $key_info->{expired} ? "<span style='color:red'>Expired</span>" :
				 $key_info->{expires_soon} ? "<span style='color:orange'>Expires soon</span>" :
				 "<span style='color:green'>Valid</span>";
	my $default_mark = ($default_key && $default_key eq $fp) ? " <strong>(Default)</strong>" : "";
	my %algo_map = ('1'=>'RSA','17'=>'DSA','18'=>'ECC (Curve25519)','19'=>'ECC (NIST P-256)','22'=>'EdDSA');
	my $algo_name = $algo_map{$key_info->{algo}} || "Unknown ($key_info->{algo})";
	my $algo_bits = "$algo_name ($key_info->{bits} bits)";
	my $key_type = $key_info->{secret} ? "<span style='color:purple'>Private</span>" : "Public";
	my $email = extract_email($key_info->{uid});
	my $email_display = &Header::escape($email);
	my $enc_escaped = &Header::escape($encrypted);
	my $hint = $key_info->{secret}
		? "Copy this into a file (e.g. <code>test.asc</code>) and <strong>decrypt</strong> with this private key."
		: "Copy this into a file (e.g. <code>test.asc</code>) and <strong>encrypt/decrypt</strong> with this key.";

	&Header::showhttpheaders();
	&Header::openpage("GPG Test Encryption", 1, '');
	&Header::openbigbox('100%', 'center');
	print "<section class=\"section is-box\"><h2 class=\"title\">Test Encryption Result</h2><div class=\"base\">";
	print "<p><strong>Key:</strong> <code>$fp</code>$default_mark</p>";
	print "<p><strong>Email:</strong> $email_display</p>";
	print "<p><strong>Type:</strong> $key_type</p>";
	print "<p><strong>Status:</strong> $status</p>";
	print "<p><strong>Algorithm:</strong> $algo_bits</p>";
	print "<p><strong>Expiry:</strong> $key_info->{expiry}</p><hr>";
	print "<h3>Encrypted Message:</h3>";
	print "<pre style=\"background:#f8f8f8; padding:15px; border:1px solid #ddd; overflow-x:auto; font-family:monospace; white-space:pre-wrap; word-wrap:break-word; font-size:0.9em;\">$enc_escaped</pre>";
	print "<p><small><i>$hint</i></small></p></div></section>";
	&Header::closebigbox();
	&Header::closepage();
	exit 0;
}

1;