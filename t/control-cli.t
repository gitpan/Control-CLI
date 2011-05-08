#!/usr/bin/perl -Tw

use lib '.', './t';
use strict;
use Test::More tests => 6;

BEGIN {
	use_ok( 'Control::CLI' ) || print "Bail out!";
}

# To manually set the a Serial port to test with, can edit these lines
#	my $serial_port = 'COM1';
#	my $serial_port = '/dev/ttyS0';
	my $serial_port = '';

# ..or else, one was manually specified when running Build.pl or Makefile.pl
if ( !$serial_port && eval { require DefaultPort } && $DefaultPort::Serial_Test_Port) {
	$serial_port = $DefaultPort::Serial_Test_Port;
}

my ($modules, $cli, $testcli, $serialPortUndetected);

$modules =	((Control::CLI::useTelnet) ? 'Net::Telnet, ':'').
		((Control::CLI::useSsh)    ? 'Net::SSH2, ':'').
		((Control::CLI::useSerial) ? ($^O eq 'MSWin32' ? 'Win32::SerialPort, ':'Win32::SerialPort, '):'');
chop $modules; # trailing space
chop $modules; # trailing comma

diag "Testing Control::CLI $Control::CLI::VERSION";
diag "Available modules to test with: $modules";

SKIP: {
	skip "Net::Telnet not installed, skipping Telnet constructor test", 1 unless Control::CLI::useTelnet;
	# Create the object instance for Telnet
	$testcli = new Control::CLI(Use => 'TELNET', Errmode => 'return');
	ok( defined $testcli, "Testing constructor for Telnet" );
	$cli = $testcli if defined $testcli;
}

SKIP: {
	skip "Net::SSH not installed, skipping SSH constructor test", 1 unless Control::CLI::useSsh;
	# Create the object instance for SSH
	$testcli = new Control::CLI(Use => 'SSH', Errmode => 'return');
	ok( defined $testcli, "Testing constructor for SSH" );
	$cli = $testcli if defined $testcli;
}

SKIP: {
	skip "Win32::SerialPort not installed, skipping Serial constructor test", 1 unless Control::CLI::useSerial;
	unless ($serial_port) {	# Try and detect serial port to use
		if ($^O eq 'MSWin32') { # On Windows easy, use the registry
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
		else { # On Unix, just try the usual /dev/ttyS? ones...
			my @devttys = glob '/dev/ttyS?';
			if (@devttys && eval {require POSIX}) {
				foreach my $port (@devttys) {
					if ($port =~ /^(\/dev\/ttyS\d)$/) { # Untaint what we have detected
						my $tryport = $1;
						my $fd = POSIX::open($tryport, &POSIX::O_RDWR | &POSIX::O_NOCTTY | &POSIX::O_NONBLOCK);
						my $to = POSIX::Termios->new();
						if ( $to && $fd && $to->getattr($fd) ) {
							$serial_port = $tryport;
							last;
						}
					}
				}
			}
			unless ($serial_port) {
				$serialPortUndetected = 1;
				skip "Cannot make out available serial ports for Serial constructor test", 1;
			}
		}
		diag "Serial Port detected for testing Serial constructor with: $serial_port";
	}
	# Create the object instance for Serial
	$testcli = new Control::CLI(Use => $serial_port, Errmode => 'return');
	ok( defined $testcli, "Testing constructor for Serial Port (using $serial_port)" );
	$cli = $testcli if defined $testcli;
}
if ($serialPortUndetected) {
	diag "Skipped serial port constructor test as no serial port detected";
	diag "- can manually set one with 'perl <Build.PL|Makefile.PL> TESTPORT=<DEVICE>'";
}

ok( defined $cli, "Testing constructor for either Telnet/SSH/Serial" );
isa_ok($cli, 'Control::CLI');
