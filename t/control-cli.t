#!/usr/bin/perl

use lib '.', './t';
use strict;
use warnings;
use Test::More;
use IO::Interactive qw(is_interactive);

############################################################
# Overrides can be specified for variables in this section #
############################################################
my $SeriaPort		= '';		# To manually set the a Serial port to test with; e.g 'COM1', '/dev/ttyS0'
my $TestMultiple	= 1;		# Set to 0 if you only want to test against one device
my $ConnectionType	;
my $Timeout		= 10;		# seconds
my $ConnectionTimeout	= 15;		# seconds
my $ErrorMode		= 'return';	# always return, so we check outcome in this test script
my $InputLog		;# = 'control-cli.t.in';
my $OutputLog		;# = 'control-cli.t.out';
my $DumpLog		;# = 'control-cli.t.dump';
my $Host		;
my $TcpPort		;
my $Username		;
my $Password		;
my $PublicKeyPath	;# = 'C:\Users\<user>\.ssh\id_dsa.pub';	# '/export/home/<user>/.ssh/id_dsa.pub'
my $PrivateKeyPath	;# = 'C:\Users\<user>\.ssh\id_dsa';		# '/export/home/<user>/.ssh/id_dsa'
my $Passphrase		;
my $Baudrate		;# = 9600;
my $Databits		= 8;	
my $Parity		= 'none';	
my $Stopbits		= 1;
my $Handshake		= 'none';
my $PromptCredentials	= 1;		# Test the module prompting for username/password 
my $Debug		= 0;
############################################################

# If no $SeriaPort set above, see if one manually specified when running Build.pl or Makefile.pl
if ( !$SeriaPort && eval { require DefaultPort } && $DefaultPort::Serial_Test_Port) {
	$SeriaPort = $DefaultPort::Serial_Test_Port;
}

sub prompt { # For interactive testing to prompt user
	my $varRef = shift;
	my $message = shift;
	my $default = shift;
	my $userInput;
	return if defined $$varRef; # Come out if variable already set
	print "\n", $message;
	chomp($$varRef = <STDIN>);
	print "\n";
	unless (length $$varRef) {
		if (defined $default) {
			$$varRef = $default;
			return;
		}
		done_testing();
		exit;
	}
}

BEGIN {
	use_ok( 'Control::CLI' ) || die "Bail out!";
}

my $modules =	((Control::CLI::useTelnet) ? "Net::Telnet $Net::Telnet::VERSION, ":'').
		((Control::CLI::useSsh)    ? "Net::SSH2 $Net::SSH2::VERSION, ":'').
		((Control::CLI::useSerial) ? ($^O eq 'MSWin32' ?
						"Win32::SerialPort $Win32::SerialPort::VERSION, ":
						"Device::SerialPort $Device::SerialPort::VERSION, "):
					      '');
chop $modules; # trailing space
chop $modules; # trailing comma

diag "Testing Control::CLI $Control::CLI::VERSION";
diag "Available modules to test with: $modules";

if (Control::CLI::useTelnet || Control::CLI::useSsh) {
	if (Control::CLI::useIPv6) {
		diag "Using IO::Socket::IP ==> IPv4 and IPv6 support";
	}
	else {
		diag "Using IO::Socket::INET ==> IPv4 only (install IO::Socket::IP for IPv6 support)";
	}
}

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
		unless ($SeriaPort) {	# Try and detect serial port to use
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
					$SeriaPort = $comports->{$_} if $comports->{$_} =~ /^COM\d$/;
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
								$SeriaPort = $tryport;
								last;
							}
						}
					}
				}
				unless ($SeriaPort) {
					$serialPortUndetected = 1;
					skip "Cannot make out available serial ports for Serial constructor test", 1;
				}
			}
			diag "Serial Port detected for testing Serial constructor with: $SeriaPort";
		}
		# Create the object instance for Serial
		$testcli = new Control::CLI(Use => $SeriaPort, Errmode => 'return');
		ok( defined $testcli, "Testing constructor for Serial Port (using $SeriaPort)" );
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
	my ($connectionType, $username, $password, $host, $tcpPort, $baudrate)
	 = ($ConnectionType, $Username, $Password, $Host, $TcpPort, $Baudrate);

	# Test constructor
	prompt(\$connectionType, "Select connection type to test\n [enter string: telnet|ssh|<COM-port-name>; or just ENTER to end test]\n : ");
	$cli = new Control::CLI(
			Use			=> $connectionType,
		  	Timeout 		=> $Timeout,	# optional; default timeout = 10 secs
		  	Connection_timeout	=> $ConnectionTimeout,
			Errmode 		=> $ErrorMode,	# optional; default = 'croak'
			Input_log		=> $InputLog,
			Output_log		=> $OutputLog,
			Dump_log		=> $DumpLog,
			Debug			=> $Debug,
		);
	ok( defined $cli, "Testing constructor for '$connectionType'" );
	if (!defined $cli && $connectionType !~ /^(?i:TELNET|SSH)$/) {
		diag "Cannot open serial port provided";
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
			my $complexInput;
			prompt(\$host, "Provide an IP|hostname to test with (you will be prompted for commands to execute);\n [[username][:password]@]<host|IP> [port]; ENTER to end test]\n : ");
			if ($host =~ s/^(.+)@//) {
				($username, $password) = split(':', $1);
				undef $username unless length $username;
				undef $password unless length $password;
				print "Username = ", $username, "\n" if defined $username;
				print "Password = ", $password, "\n" if defined $password;
				$complexInput = 1;
			}
			if ($host =~ /^(\S+)\s+(\d+)$/) {
				($host, $tcpPort) = ($1, $2);
				$complexInput = 1;
			}
			if ($complexInput) {
				print "Host = ", $host, "\n" if defined $host;
				print "Port = ", $tcpPort, "\n" if defined $tcpPort;
				print "\n";
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
			PublicKey		=>	$PublicKeyPath,		# optional, only ssh
			PrivateKey		=>	$PrivateKeyPath,	# optional, only ssh
			Passphrase		=>	$Passphrase,		# optional, only ssh  (with PromptCredentials=1 will be prompted for, if required)
			BaudRate		=>	$baudrate,		# optional, only serial
			DataBits		=>	$Databits,		# optional, only serial
			Parity			=>	$Parity,		# optional, only serial
			StopBits		=>	$Stopbits,		# optional, only serial
			Handshake		=>	$Handshake,		# optional, only serial
			Prompt_Credentials	=>	$PromptCredentials,	# optional, default = 0 (no)
		);
	ok( $returnValue, "Testing connection" );
	unless ($returnValue) {
		diag $cli->errmsg;
		redo;
	}

	# Test eof is reported as false after connection
	$eof = $cli->eof;
	ok( !$eof, "Testing eof is false after connecting" );

	# Test login (we do this also for SSH, needed if device accepts SSH connection without authentication; no harm otherwise)
	$cli->print if $connectionType eq 'SERIAL';
	$returnValue = $cli->login(
			Username		=>	$username,		# optional (with PromptCredentials=1 will be prompted for, if required)
			Password		=>	$password,		# optional (with PromptCredentials=1 will be prompted for, if required)
			Prompt_Credentials	=>	$PromptCredentials,	# optional, default = 0 (no)
		);
	ok( $returnValue, "Testing login" );
	unless ($returnValue) {
		diag $cli->errmsg;
		$cli->disconnect;
		redo;
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

}} while ($TestMultiple);

done_testing();
