#!/usr/bin/perl -Tw

use strict;
use Test::More tests => 6;

BEGIN {
    use_ok( 'Control::CLI' ) || print "Bail out!";
}

# If this test script fails to detect an available Serial port to test; one can be manually specified here
#	my $serial_port = 'COM1';
#	my $serial_port = '/dev/ttyS0';
	my $serial_port = '';


my ($cli, $testcli, $serialPortUndetected);

diag( "Testing Control::CLI $Control::CLI::VERSION" );

SKIP: {
	skip "Net::Telnet not installed, skipping Telnet constructor test", 1 unless eval {require Net::Telnet};
	# Create the object instance for Telnet
	$testcli = new Control::CLI(Use => 'TELNET', Errmode => 'return');
	ok( defined $testcli, "Testing constructor for Telnet" );
	$cli = $testcli if defined $testcli;
}

SKIP: {
	skip "Net::SSH not installed, skipping SSH constructor test", 1 unless eval {require Net::SSH2};
	# Create the object instance for SSH
	$testcli = new Control::CLI(Use => 'SSH', Errmode => 'return');
	ok( defined $testcli, "Testing constructor for SSH" );
	$cli = $testcli if defined $testcli;
}

if ($^O eq 'MSWin32') {
	SKIP: {
		skip "Win32::SerialPort not installed, skipping Serial constructor test", 1 unless eval {require Win32::SerialPort};
		unless ($serial_port) {	# Try and detect COM port to use
			unless (eval {require Win32::TieRegistry}) {
				$serialPortUndetected = 1;
				skip "Cannot make out available serial ports for Serial constructor test", 1;
			}
			import Win32::TieRegistry;
			$Win32::TieRegistry::Registry->Delimiter("/");
			my $comports = $Win32::TieRegistry::Registry->{"HKEY_LOCAL_MACHINE/HARDWARE/DEVICEMAP/SERIALCOMM"};
			unless (defined $comports) {
				$serialPortUndetected = 1;
				skip "Cannot make out available serial ports for Serial constructor test", 1;
			}
			foreach( keys %$comports ) {
				$serial_port = $comports->{$_} if $comports->{$_} =~ /^COM\d$/;
				last;
			}
		}
		# Create the object instance for Serial
		$testcli = new Control::CLI(Use => $serial_port, Errmode => 'return');
		ok( defined $testcli, "Testing constructor for Serial Port (using $serial_port)" );
		$cli = $testcli if defined $testcli;
	}
}
else {
	SKIP: {
		skip "Device::SerialPort not installed, skipping Serial constructor test", 1 unless eval {require Device::SerialPort};
		unless ($serial_port) {	# Try and detect /dev/ttyS* port to use
			my @devttys = glob '/dev/ttyS?';
			unless (@devttys) {
				$serialPortUndetected = 1;
				skip "Cannot make out available serial ports for Serial constructor test", 1;
			}
			if ($devttys[0] =~ /^(\/dev\/ttyS\d)$/) { # Untaint what we have detected
				$serial_port = $1;
			}
			else {
				$serialPortUndetected = 1;
				skip "Cannot make out available serial ports for Serial constructor test", 1;
			}
		}
		# Create the object instance for Serial
		$testcli = new Control::CLI(Use => $serial_port, Errmode => 'return');
		ok( defined $testcli, "Testing constructor for Serial Port (using $serial_port)" );
		$cli = $testcli if defined $testcli;
	}
}
diag "NOTE: Could not detect a serial port for serial port constructor test, so this was skipped; to manually specify a serial port to use, edit control-cli.t" if $serialPortUndetected;


ok( defined $cli, "Testing constructor for either Telnet/SSH/Serial" );
isa_ok($cli, 'Control::CLI');
