#!/usr/bin/perl

use lib '.', './t';
use strict;
use warnings;
use Test::More;
use IO::Interactive qw(is_interactive);

############################################################
# Overrides can be specified for variables in this section #
############################################################
my $serial_port		= '';		# To manually set the a Serial port to test with; e.g 'COM1', '/dev/ttyS0'
my $testMultiple	= 1;		# Set to 0 if you only want to test against one device
my $connectionType	;
my $timeout		= 10;		# seconds
my $errmode		= 'return';	# always return, so we check outcome in this test script
my $inputLog		;# = 'control-cli.t.in';
my $outputLog		;# = 'control-cli.t.out';
my $dumpLog		;# = 'control-cli.t.dump';
my $host		;
my $tcpPort		;
my $username		;
my $password		;
my $publicKeyPath	;# = 'C:\Documents and Settings\<user>\.ssh\id_dsa.pub';	# '/export/home/<user>/.ssh/id_dsa.pub'
my $privateKeyPath	;# = 'C:\Documents and Settings\<user>\.ssh\id_dsa';		# '/export/home/<user>/.ssh/id_dsa'
my $passphrase		;
my $baudrate		;# = 9600;
my $databits		= 8;	
my $parity		= 'none';	
my $stopbits		= 1;
my $handshake		= 'none';
my $promptCredentials	= 1;		# Test the module prompting for username/password 
my $debug		= 0;
############################################################

# If no $serial_port set above, see if one manually specified when running Build.pl or Makefile.pl
if ( !$serial_port && eval { require DefaultPort } && $DefaultPort::Serial_Test_Port) {
	$serial_port = $DefaultPort::Serial_Test_Port;
}

sub prompt { # For interactive testing to prompt user
	my $varRef = shift;
	my $message = shift;
	my $default = shift;
	my $userInput;
	return if $$varRef;
	print "\n", $message;
	chomp($$varRef = <STDIN>);
	print "\n";
	unless ($$varRef) {
		if (defined $default) {
			$$varRef = $default;
			return;
		}
		done_testing();
		exit;
	}
}

BEGIN {
	use_ok( 'Control::CLI' ) || print "Bail out!";
}

my $modules =	((Control::CLI::useTelnet) ? 'Net::Telnet, ':'').
		((Control::CLI::useSsh)    ? 'Net::SSH2, ':'').
		((Control::CLI::useSerial) ? ($^O eq 'MSWin32' ? 'Win32::SerialPort, ':'Device::SerialPort, '):'');
chop $modules; # trailing space
chop $modules; # trailing comma


diag "Testing Control::CLI $Control::CLI::VERSION";
diag "Available modules to test with: $modules";

						##############################
unless (IO::Interactive::is_interactive) {	# Not an interactive session #
						##############################
	my ($cli, $testcli, $serialPortUndetected);

	# Test only the constructors
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

	diag "Once installed, to test connection to a device, please run test script control-cli.t manually and follow interactive prompts";
	done_testing();
	exit;
}

############################################################
# For an interactive session we can test a real connection #
############################################################

do {{ # Test loop, we keep testing until user satisfied

	my ($cli, $eof, $returnValue, $cmd);

	# Test constructor
	prompt(\$connectionType, "Select connection type to test\n [enter string: telnet|ssh|<COM-port-name>; or just ENTER to end test]\n : ");
	$cli = new Control::CLI(
			Use		=> $connectionType,
		  	Timeout 	=> $timeout,	# optional; default timeout = 10 secs
			Errmode 	=> $errmode,	# optional; default = 'croak'
			Input_log	=> $inputLog,
			Output_log	=> $outputLog,
			Dump_log	=> $dumpLog,
			Debug		=> $debug,
		);
	ok( defined $cli, "Testing constructor for '$connectionType'" );
	unless (defined $cli) {
		diag "Probably cannot open serial port provided";
		$connectionType = undef;
		redo;
	}

	# Test isa
	isa_ok($cli, 'Control::CLI');

	# Test/Display connection type
	$connectionType = $cli->connection_type;
	ok( $connectionType, "Testing connection type = $connectionType" );

	# Test eof is reported as true prior to connection
	$eof = $cli->eof;
	ok( $eof, "Testing eof is true before connecting" );

	# Test connection
	if ($connectionType =~ /^(?i:TELNET|SSH)$/) {
		if (!defined $host) {
			prompt(\$host, "Provide an IP|hostname to test with (you will be prompted for commands to execute);\n [[username[:password@]]<host|IP>[:port]; ENTER to end test]\n : ");
			if ($host =~ /^([^:].*?)?(:(.+?))?@(.+)$/) {
				($username, $password, $host) = ($1, $3, $4);
			}
			if ($host =~ /^(.+?):(\d+)$/) {
				($host, $tcpPort) = ($1, $2);
			}
		}
	}
	else {
		prompt(\$baudrate, "Specify baudrate to use [just ENTER for 9600 baud]: ", 9600);
	}
	$returnValue = $cli->connect(
			Host			=>	$host,			# mandatory, telnet & ssh
			Port			=>	$tcpPort,		# optional, only telnet & ssh
			Username		=>	$username,		# optional (with PromptCredentials=1 will be prompted for, if required)
			Password		=>	$password,		# optional (with PromptCredentials=1 will be prompted for, if required)
			PublicKey		=>	$publicKeyPath,		# optional, only ssh
			PrivateKey		=>	$privateKeyPath,	# optional, only ssh
			Passphrase		=>	$passphrase,		# optional, only ssh  (with PromptCredentials=1 will be prompted for, if required)
			BaudRate		=>	$baudrate,		# optional, only serial
			DataBits		=>	$databits,		# optional, only serial
			Parity			=>	$parity,		# optional, only serial
			StopBits		=>	$stopbits,		# optional, only serial
			Handshake		=>	$handshake,		# optional, only serial
			Prompt_Credentials	=>	$promptCredentials,	# optional, default = 0 (no)
		);
	ok( $returnValue, "Testing connection" );
	unless ($returnValue) {
		diag $cli->errmsg;
		($connectionType, $host, $baudrate) = ();
		redo;
	}

	# Test eof is reported as false after connection
	$eof = $cli->eof;
	ok( !$eof, "Testing eof is false after connecting" );

	# Test login
	if ($connectionType =~ /^(?i:TELNET|SERIAL)$/) {
		$cli->print if $connectionType eq 'SERIAL';
		$returnValue = $cli->login(
				Username		=>	$username,		# optional (with PromptCredentials=1 will be prompted for, if required)
				Password		=>	$password,		# optional (with PromptCredentials=1 will be prompted for, if required)
				Prompt_Credentials	=>	$promptCredentials,	# optional, default = 0 (no)
			);
		ok( $returnValue, "Testing login" );
		unless ($returnValue) {
			diag $cli->errmsg;
			$cli->disconnect;
			($connectionType, $host, $baudrate) = ();
			redo;
		}
	}

	# Test sending a command
	prompt(\$cmd, "Specify a command to send, which generates some output: ");
	$returnValue = $cli->cmd(
			Command			=>	$cmd,
			Return_reference	=>	0,
		);
	ok( $returnValue, "Testing cmd() method" );
	if ($returnValue) { diag "Obtained output of command '$cmd':\n$returnValue" }
	else { diag $cli->errmsg }

	# Disconnect from host, and resume loop for further tests
	$cli->disconnect;

	# Test eof is reported as true after disconnection
	$eof = $cli->eof;
	ok( $eof, "Testing eof is true after disconnecting" );

	($connectionType, $host, $baudrate) = ();

}} while ($testMultiple);

done_testing();
