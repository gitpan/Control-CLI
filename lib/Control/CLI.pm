package Control::CLI;

use strict;
use warnings;
use Exporter qw( import );
use Carp;
use Term::ReadKey;
use Time::HiRes qw( time sleep );
use IO::Handle;
use IO::Socket::INET;
use Errno qw( EINPROGRESS EWOULDBLOCK );

my $Package = __PACKAGE__;
our $VERSION = '2.00';
our %EXPORT_TAGS = (
		use	=> [qw(useTelnet useSsh useSerial useIPv6)],
		prompt	=> [qw(promptClear promptHide)],
		args	=> [qw(parseMethodArgs suppressMethodArgs)],
		_rest	=> [qw(passphraseRequired parse_errmode stripLastLine poll)],
	);
push @{$EXPORT_TAGS{all}}, @{$EXPORT_TAGS{$_}} foreach keys %EXPORT_TAGS;
Exporter::export_ok_tags('all');

########################################### Global Class Variables ###########################################

my $PollTimer = 100;		# Some connection types require a polling loop; this is the loop sleep timer in ms
my $ComPortReadBuffer = 4096;	# Size of serial port read buffers
my $ComReadInterval = 100;	# Timeout between single character reads
my $ComBreakDuration = 300;	# Number of milliseconds the break signal is held for

my %Default = ( # Hash of default object settings which can be modified on a per object basis
	timeout			=> 10,			# Default Timeout value in secs
	connection_timeout	=> undef,		# Default Connection Timeout value in secs
	connection_timeout_nb	=> 20,			# If above is undefined, still need to set a value for connections in non-blocking mode
	blocking		=> 1,			# Default blocking mode
	return_reference	=> 0,			# Whether methods return data (0) or hard referece to it (1)
	read_attempts		=> 5,			# Empty reads to wait in readwait() before returning
	readwait_timer		=> 100,			# Polling loop timer for readwait() in millisecs, for further input
	prompt_credentials	=> 0,			# Interactively prompt for credentials (1) or not (0)
	tcp_port	=> {
			SSH	=>	22,		# Default TCP port number for SSH
			TELNET	=>	23,		# Default TCP port number for TELNET
	},
	read_block_size	=> {
			SSH		=> 4096,	# Default Read Block Size for SSH
			SERIAL_WIN32	=> 1024,	# Default Read Block Size for Win32::SerialPort
			SERIAL_DEVICE	=> 255,		# Default Read Block Size for Device::SerialPort
	},
	baudrate		=> 9600,		# Default baud rate used when connecting via Serial port
	handshake		=> 'none',		# Default handshake used when connecting via Serial port
	parity			=> 'none',		# Default parity used when connecting via Serial port
	databits		=> 8,			# Default data bits used when connecting via Serial port
	stopbits		=> 1,			# Default stop bits used when connecting via Serial port
	ors			=> "\n",		# Default Output Record Separator used by print() & cmd()
	errmode			=> 'croak',		# Default error mode; can be: die/croak/return/coderef/arrayref
	poll_obj_complete	=> 'all',		# Default mode for poll() method
	poll_obj_error		=> 'ignore',		# Default error mode for poll() method
	prompt		=> '.*[\?\$%#>]\s?$',		# Default prompt used in login() and cmd() methods
	username_prompt	=> '(?i:username|login)[: ]+$',	# Default username prompt used in login() method
	password_prompt	=> '(?i)password[: ]+$',	# Default password prompt used in login() method
	debug		=> 0,				# Default debug level; 0 = disabled
);

# Debug levels can be set using the debug() method or via debug argument to new() constructor
# Debug levels defined:
#	0	: No debugging
#	bit 1	: Debugging activated for for polling methods + readwait() and enables carping on Win32/Device::SerialPort
#		  This level also resets Win32/Device::SerialPort constructor $quiet flag only when supplied in Control::CLI::new()
# 	bit 2	: Debugging is activated on underlying Net::SSH2 and Win32::SerialPort / Device::SerialPort
#		  There is no actual debugging for Net::Telnet


my ($UseTelnet, $UseSSH, $UseSerial, $UseSocketIP);


############################################## Required modules ##############################################

$UseTelnet = 1 if eval {require Net::Telnet};	# Make Net::Telnet optional
$UseSSH    = 1 if eval {require Net::SSH2};	# Make Net::SSH2 optional
if ($^O eq 'MSWin32') {
	$UseSerial = 1 if eval {require Win32::SerialPort};	# Win32::SerialPort optional on Windows
}
else {
	$UseSerial = 1 if eval {require Device::SerialPort};	# Device::SerialPort optional on Unix
}
croak "$Package: no available module installed to operate on" unless $UseTelnet || $UseSSH || $UseSerial;

$UseSocketIP = 1 if eval { require IO::Socket::IP };		# Provides IPv4 and IPv6 support


################################################ Class Methods ###############################################

sub useTelnet {
	return $UseTelnet;
}

sub useSsh {
	return $UseSSH;
}

sub useSerial {
	return $UseSerial;
}

sub useIPv6 {
	return $UseSocketIP;
}

sub promptClear { # Interactively prompt for a username, in clear text
	my $username = shift;
	my $input;
	print "Enter $username: ";
	ReadMode('normal');
	chomp($input = ReadLine(0));
	ReadMode('restore');
	return $input;
}

sub promptHide { # Interactively prompt for a password, input is hidden
	my $password = shift;
	my $input;
	print "Enter $password: ";
	ReadMode('noecho');
	chomp($input = ReadLine(0));
	ReadMode('restore');
	print "\n";
	return $input;
}

sub passphraseRequired { # Inspects a private key to see if it requires a passphrase to be used
	my $privateKey = shift;
	my $passphraseRequired = 0;

	# Open the private key to see if passphrase required.. Net::SSH2 does not do this for us..
	open(my $key, '<', $privateKey) or return;
	while (<$key>) {
		/ENCRYPTED/ && do { # Certificates in OpenSSH format and passphrase encrypted
			$passphraseRequired = 1;
			last;
		};
	}
	close $key;
	return $passphraseRequired;
}


sub parseMethodArgs { # Parse arguments fed into a method against accepted arguments; also set them to lower case
	my ($pkgsub, $argsRef, $validArgsRef) = @_;
	my ($even_lc, @argsIn, @argsOut, %validArgs);
	@argsIn = map {++$even_lc%2 ? lc : $_} @$argsRef; # Sets to lowercase the hash keys only
	foreach my $key (@$validArgsRef) { $validArgs{lc $key} = 1 }
	for (my $i = 0; $i < $#argsIn; $i += 2) {
		if ($validArgs{$argsIn[$i]}) {
			push @argsOut, $argsIn[$i], $argsIn[$i + 1];
			next;
		}
		carp "$pkgsub: Invalid argument \"$argsIn[$i]\"";
	}
	return @argsOut;
}


sub suppressMethodArgs { # Parse arguments and remove the ones listed
	my ($argsRef, $suppressArgsRef) = @_;
	my ($even_lc, @argsIn, @argsOut, %suppressArgs);
	@argsIn = map {++$even_lc%2 ? lc : $_} @$argsRef; # Sets to lowercase the hash keys only
	foreach my $key (@$suppressArgsRef) { $suppressArgs{lc $key} = 1 }
	for (my $i = 0; $i < $#argsIn; $i += 2) {
		next if $suppressArgs{$argsIn[$i]};
		push @argsOut, $argsIn[$i], $argsIn[$i + 1];
	}
	return @argsOut;
}


sub parse_errmode { # Parse a new value for the error mode and return it if valid or undef otherwise
	my ($pkgsub, $mode) = @_;

	if (!defined $mode) {
		carp "$pkgsub: Errmode undefined argument; ignoring";
		$mode  = undef;
	}
	elsif ($mode =~ /^\s*die\s*$/i) { $mode = 'die' }
	elsif ($mode =~ /^\s*croak\s*$/i) { $mode = 'croak' }
	elsif ($mode =~ /^\s*return\s*$/i) { $mode = 'return' }
	elsif (ref($mode) eq "CODE") {}
	elsif (ref($mode) eq "ARRAY") {
		unless (ref($mode->[0]) eq "CODE") {
			carp "$pkgsub: Errmode first item of array ref must be a code ref; ignoring";
			$mode  = undef;
		}
	}
	else {
		carp "$pkgsub: Errmode invalid argument '$mode'; ignoring";
		$mode  = undef;
	}
	return $mode;
}


sub stripLastLine { # Remove incomplete (not ending with \n) last line, if any from the string ref provided
	my $dataRef = shift;

	# This function is needed because with Perl ...
	# 	$$dataRef =~ /(.+)$/
	# ... will unexpectedly match strings ending with single \n

	if (chomp $$dataRef) { # Yes, string ended with \n
		$$dataRef .= "\n"; # Re-add it
		return '';
	}
	else { # No, string does not end with \n
		$$dataRef =~ s/(.*)$//;
		return $1;
	}
}


############################################# Constructors/Destructors #######################################

sub new {
	my $pkgsub = "${Package}::new";
	my $invocant = shift;
	my $class = ref($invocant) || $invocant;
	my (%args, $errmode, $connectionType, $parent, $comPort, $debug);
	if (@_ == 1) { # Method invoked with just the connection type argument
		$connectionType = shift;
	}
	else {
		my @validArgs = ('use', 'timeout', 'errmode', 'return_reference', 'prompt', 'username_prompt', 'password_prompt',
				 'input_log', 'output_log', 'dump_log', 'blocking', 'debug', 'prompt_credentials', 'read_attempts',
				 'readwait_timer', 'read_block_size', 'output_record_separator', 'connection_timeout');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		$connectionType = $args{use};
	}
	$debug = defined $args{debug} ? $args{debug} : $Default{debug};
	$errmode = defined $args{errmode} ? $args{errmode} : $Default{errmode};
	return _error(__FILE__, __LINE__, $errmode, "$pkgsub: Connection type must be specified in constructor") unless defined $connectionType;

	if    ($connectionType =~ /^TELNET$/i) {
		croak "$pkgsub: Module 'Net::Telnet' required for telnet access" unless $UseTelnet;
		@CLI::ISA = qw(Net::Telnet);
		$parent = Net::Telnet->new();
		$connectionType = 'TELNET';
	}
	elsif ($connectionType =~ /^SSH$/i) {
		croak "$pkgsub: Module 'Net::SSH2' required for ssh access" unless $UseSSH;
		@CLI::ISA = qw(Net::SSH2);
		$parent = Net::SSH2->new();
		$connectionType = 'SSH';
	}
	else {
		if ($^O eq 'MSWin32') {
			croak "$pkgsub: Module 'Win32::SerialPort' required for serial access" unless $UseSerial;
			@CLI::ISA = qw(Win32::SerialPort);
			Win32::SerialPort->set_test_mode_active(!($debug & 1));	 # Suppress carping except if debug bit1 set
			$parent = Win32::SerialPort->new($connectionType, !($debug & 1))
				or return _error(__FILE__, __LINE__, $errmode, "$pkgsub: Cannot open serial port '$connectionType'");
		}
		else {
			croak "$pkgsub: Module 'Device::SerialPort' required for serial access" unless $UseSerial;
			@CLI::ISA = qw(Device::SerialPort);
			Device::SerialPort->set_test_mode_active(!($debug & 1)); # Suppress carping except if debug bit1 set
			$parent = Device::SerialPort->new($connectionType, !($debug & 1))
				or return _error(__FILE__, __LINE__, $errmode, "$pkgsub: Cannot open serial port '$connectionType'");
		}
		$comPort = $connectionType;
		$connectionType = 'SERIAL';
	}
	my $self = {
		# Lower Case ones can be set by user; Upper case ones are set internaly in the class
		TYPE			=>	$connectionType,
		PARENT			=>	$parent,
		SOCKET			=>	undef,
		SSHCHANNEL		=>	undef,
		BUFFER			=>	'', # Always defined; greater than 0 length if in use
		COMPORT			=>	$comPort,
		TCPPORT			=>	undef,
		HANDSHAKE		=>	undef,
		BAUDRATE		=>	undef,
		PARITY			=>	undef,
		DATABITS		=>	undef,
		STOPBITS		=>	undef,
		INPUTLOGFH		=>	undef,
		OUTPUTLOGFH		=>	undef,
		DUMPLOGFH		=>	undef,
		USERNAME		=>	undef,
		PASSWORD		=>	undef,
		PASSPHRASE		=>	undef,
		LOGINSTAGE		=>	'',
		LASTPROMPT		=>	undef,
		SERIALEOF		=>	1,
		POLL			=>	undef,	# Storage hash for poll-capable methods
		POLLING			=>	0,	# Flag to track if in polling-capable method or not
		POLLREPORTED		=>	0,	# Flag used by poll() to track already reported objects
		timeout			=>	$Default{timeout},
		connection_timeout	=>	$Default{connection_timeout},
		blocking		=>	$Default{blocking},
		return_reference	=>	$Default{return_reference},
		prompt_credentials	=>	$Default{prompt_credentials},
		read_attempts		=>	$Default{read_attempts},
		readwait_timer		=>	$Default{readwait_timer},
		read_block_size		=>	$Default{read_block_size}{$connectionType},
		ors			=>	$Default{ors},
		errmode			=>	$Default{errmode},
		errmsg			=>	'',
		prompt			=>	$Default{prompt},
		prompt_qr		=>	qr/$Default{prompt}/,
		username_prompt		=>	$Default{username_prompt},
		username_prompt_qr	=>	qr/$Default{username_prompt}/,
		password_prompt		=>	$Default{password_prompt},
		password_prompt_qr	=>	qr/$Default{password_prompt}/,
		debug			=>	$Default{debug},
	};
	if ($connectionType eq 'SERIAL') { # Adjust read_block_size defaults for Win32::SerialPort & Device::SerialPort
		$self->{read_block_size} = ($^O eq 'MSWin32') ? $Default{read_block_size}{SERIAL_WIN32}
							      : $Default{read_block_size}{SERIAL_DEVICE};
	}
	bless $self, $class;
	foreach my $arg (keys %args) { # Accepted arguments on constructor
		if    ($arg eq 'errmode')			{ $self->errmode($args{$arg}) }
		elsif ($arg eq 'timeout')			{ $self->timeout($args{$arg}) }
		elsif ($arg eq 'connection_timeout')		{ $self->connection_timeout($args{$arg}) }
		elsif ($arg eq 'read_block_size')		{ $self->read_block_size($args{$arg}) }
		elsif ($arg eq 'blocking')			{ $self->blocking($args{$arg}) }
		elsif ($arg eq 'read_attempts')			{ $self->read_attempts($args{$arg}) }
		elsif ($arg eq 'readwait_timer')		{ $self->readwait_timer($args{$arg}) }
		elsif ($arg eq 'return_reference')		{ $self->return_reference($args{$arg}) }
		elsif ($arg eq 'output_record_separator')	{ $self->output_record_separator($args{$arg}) }
		elsif ($arg eq 'prompt_credentials')		{ $self->prompt_credentials($args{$arg}) }
		elsif ($arg eq 'prompt')			{ $self->prompt($args{$arg}) }
		elsif ($arg eq 'username_prompt')		{ $self->username_prompt($args{$arg}) }
		elsif ($arg eq 'password_prompt')		{ $self->password_prompt($args{$arg}) }
		elsif ($arg eq 'input_log')			{ $self->input_log($args{$arg}) }
		elsif ($arg eq 'output_log')			{ $self->output_log($args{$arg}) }
		elsif ($arg eq 'dump_log')			{ $self->dump_log($args{$arg}) }
		elsif ($arg eq 'debug')				{ $self->debug($args{$arg}) }
	}
	return $self;
}

sub DESTROY { # Run disconnect
	my $self = shift;
	return $self->disconnect;
}


############################################### Object methods ###############################################

sub connect { # Connect to host
	my $pkgsub = "${Package}::connect";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked in the shorthand form
		$args{host} = shift;
		if ($args{host} =~ /^(.+?)\s+(\d+)$/ || $args{host} =~ /^([^:\s]+?):(\d+)$/) {
			($args{host}, $args{port}) = ($1, $2);
		}
	}
	else {
		my @validArgs = ('host', 'port', 'username', 'password', 'publickey', 'privatekey', 'passphrase',
				 'prompt_credentials', 'baudrate', 'parity', 'databits', 'stopbits', 'handshake',
				 'errmode', 'connection_timeout', 'blocking');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}

	# Initialize the base POLL structure
	$self->poll_struct( # $methodName, $codeRef, $blocking, $timeout, $errmode, $outputType, $outputRequested, $returnReference, $returnList
				$pkgsub,
				__PACKAGE__->can('connect_poll'),
				defined $args{blocking} ? $args{blocking} : $self->{blocking},
				defined $args{connection_timeout} ? $args{connection_timeout} : $self->{connection_timeout},
				defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef,
				0,	# no output
				0,	# no output
				undef,	# n/a
				undef,	# n/a
			);
	$self->{POLL}{$pkgsub} = { # Populate structure with method arguments/storage
		# Set method argument keys
		host			=>	$args{host},
		port			=>	$args{port},
		username		=>	$args{username},
		password		=>	$args{password},
		publickey		=>	$args{publickey},
		privatekey		=>	$args{privatekey},
		passphrase		=>	$args{passphrase},
		baudrate		=>	$args{baudrate},
		parity			=>	$args{parity},
		databits		=>	$args{databits},
		stopbits		=>	$args{stopbits},
		handshake		=>	$args{handshake},
		prompt_credentials	=>	defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials},
		# Declare method storage keys which will be used
		stage			=>	0,
		authPublicKey		=>	0,
		authPassword		=>	0,
	};
	if ($self->{TYPE} ne 'SERIAL' && !$UseSocketIP && defined $args{blocking} && !$args{blocking}) {
		carp "$pkgsub: IO::Socket::IP is required for non-blocking connect";
	}
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};
	return __PACKAGE__->can('poll_connect')->($self, $pkgsub); # Do not call a sub-classed version
}


sub connect_poll { # Poll status of connection (non-blocking mode)
	my $pkgsub = "${Package}::connect_poll";
	my $self = shift;
	carp "$pkgsub: No arguments expected" if @_; # No arguments expected

	unless (defined $self->{POLL} && $self->{POLL}{coderef} == __PACKAGE__->can('connect_poll')) {
		return $self->error("$pkgsub: Method connect() needs to be called first with blocking false");
	}
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};

	# If already completed (1) or we got an error (undef) from previous call (errmsg is already set) then we go no further
	return $self->poll_return($self->{POLL}{complete}) unless defined $self->{POLL}{complete} && $self->{POLL}{complete} == 0;

	# We get here only if we are not complete: $self->{POLL}{complete} == 0
	return __PACKAGE__->can('poll_connect')->($self, $pkgsub); # Do not call a sub-classed version
}


sub read { # Read in data from connection
	my $pkgsub = "${Package}::read";
	my $self = shift;
	my @validArgs = ('blocking', 'timeout', 'errmode', 'return_reference');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $blocking = defined $args{blocking} ? $args{blocking} : $self->{blocking};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->_read_buffer($returnRef) if length $self->{BUFFER};
	return $self->_read_blocking($pkgsub, $timeout, $returnRef) if $blocking;
	return $self->_read_nonblocking($pkgsub, $returnRef);
}


sub readwait { # Read in data initially in blocking mode, then perform subsequent non-blocking reads for more
	my $pkgsub = "${Package}::readwait";
	my $self = shift;
	my ($outref, $bufref);
	my $ticks = 0;
	my @validArgs = ('read_attempts', 'readwait_timer', 'blocking', 'timeout', 'errmode', 'return_reference');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $readAttempts = defined $args{read_attempts} ? $args{read_attempts} : $self->{read_attempts};
	my $readwaitTimer = defined $args{readwait_timer} ? $args{readwait_timer} : $self->{readwait_timer};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $blocking = defined $args{blocking} ? $args{blocking} : $self->{blocking};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	# Wait until some data is read in
	$bufref = $self->_read_buffer(1);
	if (!length $$bufref && $blocking) {
		$bufref = $self->_read_blocking($pkgsub, $timeout, 1);
		return unless defined $bufref;	# Catch errors in 'return' errmode
	}
	# Then keep reading until there is nothing more to read..
	while ($ticks++ < $readAttempts) {
		sleep($readwaitTimer/1000); # Fraction of a sec sleep using Time::HiRes::sleep
		$outref = $self->_read_nonblocking($pkgsub, 1);
		return unless defined $outref;	# Catch errors in 'return' errmode
		if (length $$outref) {
			$$bufref .= $$outref;
			$ticks = 0; # Reset ticks to zero upon successful read
		}
		$self->debugMsg(1,"ticks = $ticks\n");
	}
	return $returnRef ? $bufref : $$bufref;
}


sub waitfor { # Wait to find pattern in the device output stream
	my $pkgsub = "${Package}::waitfor";
	my $self = shift;
	my ($pollSyntax, $errmode, @matchpat);
	my $timeout = $self->{timeout};
	my $blocking = $self->{blocking};
	my $returnRef = $self->{return_reference};

	if (@_ == 1) { # Method invoked with single argument form
		$matchpat[0] = shift;
	}
	else { # Method invoked with multiple arguments form
		my @validArgs = ('match', 'timeout', 'errmode', 'return_reference', 'blocking', 'poll_syntax');
		my @args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		for (my $i = 0; $i < $#args; $i += 2) {
			push @matchpat, $args[$i + 1] if $args[$i] eq 'match';
			$timeout = $args[$i + 1] if $args[$i] eq 'timeout';
			$blocking = $args[$i + 1] if $args[$i] eq 'blocking';
			$returnRef = $args[$i + 1] if $args[$i] eq 'return_reference';
			$errmode = parse_errmode($pkgsub, $args[$i + 1]) if $args[$i] eq 'errmode';
			$pollSyntax = $args[$i + 1] if $args[$i] eq 'poll_syntax';
		}
	}
	my @matchArray = grep {defined} @matchpat;	# Weed out undefined values, if any

	# Initialize the base POLL structure
	$self->poll_struct( # $methodName, $codeRef, $blocking, $timeout, $errmode, $outputType, $outputRequested, $returnReference, $returnList
				$pkgsub,
				__PACKAGE__->can('waitfor_poll'),
				$blocking,
				$timeout,
				$errmode,
				3,
				undef,	# This is set below
				$returnRef,
				undef,	# n/a
			);
	my $waitfor = $self->{POLL}{$pkgsub} = { # Populate structure with method arguments/storage
		# Set method argument keys
		matchpat		=>	\@matchArray,
		# Declare method storage keys which will be used
		stage			=>	0,
		matchpat_qr		=>	undef,
	};
	$self->{POLL}{output_requested} = !$pollSyntax || wantarray; # Always true in legacy syntax and in poll_syntax if wantarray
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};

	my ($ok, $prematch, $match) = __PACKAGE__->can('poll_waitfor')->($self, $pkgsub); # Do not call a sub-classed version
	# We have an old and new syntax
	if ($pollSyntax) { # New syntax
		return wantarray ? ($ok, $prematch, $match) : $ok;
	}
	else { # Old syntax
		return wantarray ? ($prematch, $match) : $prematch;
	}
}


sub waitfor_poll { # Poll status of waitfor (non-blocking mode)
	my $pkgsub = "${Package}::waitfor_poll";
	my $self = shift;
	carp "$pkgsub: No arguments expected" if @_; # No arguments expected

	unless (defined $self->{POLL} && $self->{POLL}{coderef} == __PACKAGE__->can('waitfor_poll')) {
		return $self->error("$pkgsub: Method waitfor() needs to be called first with blocking false");
	}
	$self->{POLL}{output_requested} = wantarray; # This might change at every call
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};

	# If already completed (1) or we got an error (undef) from previous call (errmsg is already set) then we go no further
	return $self->poll_return($self->{POLL}{complete}) unless defined $self->{POLL}{complete} && $self->{POLL}{complete} == 0;

	# We get here only if we are not complete: $self->{POLL}{complete} == 0
	return __PACKAGE__->can('poll_waitfor')->($self, $pkgsub); # Do not call a sub-classed version
}


sub put { # Send character strings to host (no \n appended)
	my $pkgsub = "${Package}::put";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the command argument
		$args{string} = shift;
	}
	else {
		my @validArgs = ('string', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	return 1 unless defined $args{string};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->_put($pkgsub, \$args{string});
}


sub print { # Send CLI commands to host (\n appended)
	my $pkgsub = "${Package}::print";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the command argument
		$args{line} = shift;
	}
	else {
		my @validArgs = ('line', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;
	$args{line} .= $self->{ors};

	return $self->_put($pkgsub, \$args{line});
}


sub printlist { # Send multiple lines to host switch (\n appended)
	my $pkgsub = "${Package}::printlist";
	my $self = shift;
	my $output = join($self->{ors}, @_) . $self->{ors};

	return $self->_put($pkgsub, \$output);
}


sub login { # Handles basic username/password login for Telnet/Serial login and locks onto 1st prompt
	my $pkgsub = "${Package}::login";
	my $self =shift;
	my @validArgs = ('username', 'password', 'prompt_credentials', 'prompt', 'username_prompt', 'password_prompt',
		    'timeout', 'errmode', 'return_reference', 'blocking');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);

	# Initialize the base POLL structure
	$self->poll_struct( # $methodName, $codeRef, $blocking, $timeout, $errmode, $outputType, $outputRequested, $returnReference, $returnList
				$pkgsub,
				__PACKAGE__->can('login_poll'),
				defined $args{blocking} ? $args{blocking} : $self->{blocking},
				defined $args{timeout} ? $args{timeout} : $self->{timeout},
				defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef,
				1,
				wantarray,
				defined $args{return_reference} ? $args{return_reference} : $self->{return_reference},
				undef,	# n/a
			);
	$self->{POLL}{$pkgsub} = { # Populate structure with method arguments/storage
		# Set method argument keys
		username		=>	$args{username},
		password		=>	$args{password},
		prompt_credentials	=>	defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials},
		prompt			=>	defined $args{prompt} ? $args{prompt} : $self->{prompt_qr},
		username_prompt		=>	defined $args{username_prompt} ? $args{username_prompt} : $self->{username_prompt_qr},
		password_prompt		=>	defined $args{password_prompt} ? $args{password_prompt} : $self->{password_prompt_qr},
		# Declare method storage keys which will be used
		stage			=>	0,
		login_attempted		=>	undef,
	};
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};
	return __PACKAGE__->can('poll_login')->($self, $pkgsub); # Do not call a sub-classed version
}


sub login_poll { # Poll status of login (non-blocking mode)
	my $pkgsub = "${Package}::login_poll";
	my $self = shift;
	carp "$pkgsub: No arguments expected" if @_; # No arguments expected

	unless (defined $self->{POLL} && $self->{POLL}{coderef} == __PACKAGE__->can('login_poll')) {
		return $self->error("$pkgsub: Method login() needs to be called first with blocking false");
	}
	$self->{POLL}{output_requested} = wantarray; # This might change at every call
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};

	# If already completed (1) or we got an error (undef) from previous call (errmsg is already set) then we go no further
	return $self->poll_return($self->{POLL}{complete}) unless defined $self->{POLL}{complete} && $self->{POLL}{complete} == 0;

	# We get here only if we are not complete: $self->{POLL}{complete} == 0
	return __PACKAGE__->can('poll_login')->($self, $pkgsub); # Do not call a sub-classed version
}


sub cmd { # Sends a CLI command to host and returns output
	my $pkgsub = "${Package}::cmd";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the command argument
		$args{command} = shift;
	}
	else {
		my @validArgs = ('command', 'prompt', 'timeout', 'errmode', 'return_reference', 'blocking', 'poll_syntax');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	$args{command} = '' unless defined $args{command};

	# Initialize the base POLL structure
	$self->poll_struct( # $methodName, $codeRef, $blocking, $timeout, $errmode, $outputType, $outputRequested, $returnReference, $returnList
				$pkgsub,
				__PACKAGE__->can('cmd_poll'),
				defined $args{blocking} ? $args{blocking} : $self->{blocking},
				defined $args{timeout} ? $args{timeout} : $self->{timeout},
				defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef,
				1,
				undef,	# This is set below
				defined $args{return_reference} ? $args{return_reference} : $self->{return_reference},
				undef,	# n/a
			);
	my $cmd = $self->{POLL}{$pkgsub} = { # Populate structure with method arguments/storage
		# Set method argument keys
		command			=>	$args{command},
		prompt			=>	defined $args{prompt} ? $args{prompt} : $self->{prompt_qr},
		# Declare method storage keys which will be used
		stage			=>	0,
		cmdEchoRemoved		=>	0,
	};
	$self->{POLL}{output_requested} = !$args{poll_syntax} || wantarray; # Always true in legacy syntax and in poll_syntax if wantarray
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};

	my ($ok, $output) = __PACKAGE__->can('poll_cmd')->($self, $pkgsub); # Do not call a sub-classed version
	# We have a different syntax for scalar output in blocking and non-blocking modes
	if ($args{poll_syntax}) { # New syntax
		return wantarray ? ($ok, $output) : $ok;
	}
	else { # Old syntax
		return wantarray ? ($ok, $output) : $output;
	}
}


sub cmd_poll { # Poll status of cmd (non-blocking mode)
	my $pkgsub = "${Package}::cmd_poll";
	my $self = shift;
	carp "$pkgsub: No arguments expected" if @_; # No arguments expected

	unless (defined $self->{POLL} && $self->{POLL}{coderef} == __PACKAGE__->can('cmd_poll')) {
		return $self->error("$pkgsub: Method cmd() needs to be called first with blocking false");
	}
	$self->{POLL}{output_requested} = wantarray; # This might change at every call
	local $self->{POLLING} = 1; # True until we come out of this polling-capable method
	local $self->{errmode} = $self->{POLL}{errmode} if defined $self->{POLL}{errmode};

	# If already completed (1) or we got an error (undef) from previous call (errmsg is already set) then we go no further
	return $self->poll_return($self->{POLL}{complete}) unless defined $self->{POLL}{complete} && $self->{POLL}{complete} == 0;

	# We get here only if we are not complete: $self->{POLL}{complete} == 0
	return __PACKAGE__->can('poll_cmd')->($self, $pkgsub); # Do not call a sub-classed version
}


sub change_baudrate { # Change baud rate of active SERIAL connection
	my $pkgsub = "${Package}::change_baudrate";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the command argument
		$args{baudrate} = shift;
	}
	else {
		my @validArgs = ('baudrate', 'parity', 'databits', 'stopbits', 'handshake', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $baudrate = defined $args{baudrate} ? $args{baudrate} : $self->{BAUDRATE};
	my $parity = defined $args{parity} ? $args{parity} : $self->{PARITY};
	my $databits = defined $args{databits} ? $args{databits} : $self->{DATABITS};
	my $stopbits = defined $args{stopbits} ? $args{stopbits} : $self->{STOPBITS};
	my $handshake = defined $args{handshake} ? $args{handshake} : $self->{HANDSHAKE};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->error("$pkgsub: Cannot change baudrate on Telnet/SSH") unless $self->{TYPE} eq 'SERIAL';
	return $self->error("$pkgsub: No serial connection established yet") if $self->{SERIALEOF};

	$self->{PARENT}->write_done(1); # Needed to flush writes before closing with Device::SerialPort
	$self->{PARENT}->close;
	$self->{SERIALEOF} = 1;	# If all goes well we'll set this back to 0 on exit
	if ($^O eq 'MSWin32') {
		$self->{PARENT} = Win32::SerialPort->new($self->{COMPORT}, !($self->{debug} & 1))
			or return $self->error("$pkgsub: Cannot re-open serial port '$self->{COMPORT}'");
	}
	else {
		$self->{PARENT} = Device::SerialPort->new($self->{COMPORT}, !($self->{debug} & 1))
			or return $self->error("$pkgsub: Cannot re-open serial port '$self->{COMPORT}'");
	}
	$self->{PARENT}->handshake($handshake);
	$self->{PARENT}->baudrate($baudrate);
	$self->{PARENT}->parity($parity);
	# According to Win32::SerialPort, parity_enable needs to be set when parity is not 'none'...
	$self->{PARENT}->parity_enable(1) unless $parity eq 'none';
	$self->{PARENT}->databits($databits);
	$self->{PARENT}->stopbits($stopbits);
	$self->{PARENT}->write_settings or return $self->error("$pkgsub: Can't change Device_Control_Block: $^E");
	$self->{PARENT}->buffers($ComPortReadBuffer, 0);		#Set Read & Write buffers
	$self->{PARENT}->read_interval($ComReadInterval) if $^O eq 'MSWin32';
	$self->{PARENT}->read_char_time(0);     # don't wait for each character
	$self->{BAUDRATE} = $baudrate;
	$self->{PARITY}	= $parity;
	$self->{DATABITS} = $databits;
	$self->{STOPBITS} = $stopbits;
	$self->{HANDSHAKE} = $handshake;
	$self->{SERIALEOF} = 0;
	return 1;
}


sub input_log { # Log to file all input sent to host
	my ($self, $fh) = @_;
	my $pkgsub = "${Package}::input_log";

	if ($self->{TYPE} eq 'TELNET') { # For Telnet use methods provided by Net::Telnet
		$fh = $self->{PARENT}->input_log($fh);
		if (defined $fh && $self->{PARENT}->errmsg =~ /problem creating $fh: (.*)/) {
			return $self->error("$pkgsub: Unable to open input log file: $1");
		}
		return $fh;
	}
	else { # SSH & SERIAL We implement logging ourselves
		unless (defined $fh) { # No input = return current filehandle
			return $self->{INPUTLOGFH};
		}
		unless (ref $fh or length $fh) { # Empty input = stop logging
			$self->{INPUTLOGFH} = undef;
			return;
		}
		if (!ref($fh) && !defined(fileno $fh)) { # Open a new filehandle if input is a filename
			my $logfile = $fh;
			$fh = IO::Handle->new;
			open($fh, '>', "$logfile") or return $self->error("$pkgsub: Unable to open input log file: $!");
		}
		$fh->autoflush();
		$self->{INPUTLOGFH} = $fh;
		return $fh;
	}
}


sub output_log { # Log to file all output received from host
	my ($self, $fh) = @_;
	my $pkgsub = "${Package}::output_log";

	if ($self->{TYPE} eq 'TELNET') { # For Telnet use methods provided by Net::Telnet
		$fh = $self->{PARENT}->output_log($fh);
		if (defined $fh && $self->{PARENT}->errmsg =~ /problem creating $fh: (.*)/) {
			return $self->error("$pkgsub: Unable to open output log file: $1");
		}
		return $fh;
	}
	else { # SSH & SERIAL We implement logging ourselves
		unless (defined $fh) { # No input = return current filehandle
			return $self->{OUTPUTLOGFH};
		}
		unless (ref $fh or length $fh) { # Empty input = stop logging
			$self->{OUTPUTLOGFH} = undef;
			return;
		}
		if (!ref($fh) && !defined(fileno $fh)) { # Open a new filehandle if input is a filename
			my $logfile = $fh;
			$fh = IO::Handle->new;
			open($fh, '>', "$logfile") or return $self->error("$pkgsub: Unable to open output log file: $!");
		}
		$fh->autoflush();
		$self->{OUTPUTLOGFH} = $fh;
		return $fh;
	}
}


sub dump_log { # Log hex and ascii for both input & output
	my ($self, $fh) = @_;
	my $pkgsub = "${Package}::dump_log";

	if ($self->{TYPE} eq 'TELNET') { # For Telnet use methods provided by Net::Telnet
		$fh = $self->{PARENT}->dump_log($fh);
		if (defined $fh && $self->{PARENT}->errmsg =~ /problem creating $fh: (.*)/) {
			return $self->error("$pkgsub: Unable to open dump log file: $1");
		}
		return $fh;
	}
	else { # SSH & SERIAL We implement logging ourselves
		unless (defined $fh) { # No input = return current filehandle
			return $self->{DUMPLOGFH};
		}
		unless (ref $fh or length $fh) { # Empty input = stop logging
			$self->{DUMPLOGFH} = undef;
			return;
		}
		if (!ref($fh) && !defined(fileno $fh)) { # Open a new filehandle if input is a filename
			my $logfile = $fh;
			$fh = IO::Handle->new;
			open($fh, '>', "$logfile") or return $self->error("$pkgsub: Unable to open dump log file: $!");
		}
		$fh->autoflush();
		$self->{DUMPLOGFH} = $fh;
		return $fh;
	}
}


sub eof { # End-Of-File indicator
	my $pkgsub = "${Package}::eof";
	my $self = shift;

	if ($self->{TYPE} eq 'TELNET') {
		# Re-format Net::Telnet's own method to return 0 or 1
		return $self->{PARENT}->eof ? 1 : 0;
	}
	elsif ($self->{TYPE} eq 'SSH') {
		# Make SSH behave as Net::Telnet; return 1 if object created but not yet connected
		return 1 if defined $self->{PARENT} && !defined $self->{SSHCHANNEL};
		# Return Net::SSH2's own method if it is true (but it never is & seems not to work...)
		return 1 if $self->{SSHCHANNEL}->eof;
		# So we fudge it by checking Net::SSH2's last error code.. 
		return 1 if $self->{PARENT}->error == -1;  # LIBSSH2_ERROR_SOCKET_NONE
		return 1 if $self->{PARENT}->error == -43; # LIBSSH2_ERROR_SOCKET_RECV
		return 0; # If we get here, return 0
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		return $self->{SERIALEOF};
	}
	else {
		return $self->error("$pkgsub: Invalid connection mode");
	}
	return 1;
}


sub break { # Send the break signal
	my $pkgsub = "${Package}::break";
	my $self = shift;
	my $comBreakDuration = shift || $ComBreakDuration;

	return $self->error("$pkgsub: No connection to write to") if $self->eof;

	if ($self->{TYPE} eq 'TELNET') {
		# Simply use Net::Telnet's implementation
		$self->{PARENT}->break
			or return $self->error("$pkgsub: Unable to send telnet break signal\n".$self->errmsg);
	}
	elsif ($self->{TYPE} eq 'SSH') {
		# For SSH we just send '~B' and hope that the other end will interpret it as a break
		$self->put(string => '~B', errmode => 'return')
			or return $self->error("$pkgsub: Unable to send SSH break signal\n".$self->errmsg);
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		$self->{PARENT}->pulse_break_on($comBreakDuration);
	}
	else {
		return $self->error("$pkgsub: Invalid connection mode");
	}
	return 1;
}


sub disconnect { # Disconnect from host
	my $pkgsub = "${Package}::disconnect";
	my $self = shift;

	if ($self->{TYPE} eq 'TELNET') {
		$self->{PARENT}->close;
		$self->{TCPPORT} = undef;
		close $self->{SOCKET} if defined $self->{SOCKET};
		$self->{SOCKET} = undef;
	}
	elsif ($self->{TYPE} eq 'SSH') {
		$self->{SSHCHANNEL}->close if defined $self->{SSHCHANNEL};
		$self->{SSHCHANNEL} = undef;
		$self->{PARENT}->disconnect();
		$self->{TCPPORT} = undef;
		close $self->{SOCKET} if defined $self->{SOCKET};
		$self->{SOCKET} = undef;
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		$self->{PARENT}->write_done(1) if defined $self->{BAUDRATE}; # Needed to flush writes before closing with Device::SerialPort (do once only)
		$self->{PARENT}->close;
		$self->{HANDSHAKE} = undef;
		$self->{BAUDRATE} = undef;
		$self->{PARITY} = undef;
		$self->{DATABITS} = undef;
		$self->{STOPBITS} = undef;
		$self->{SERIALEOF} = 1;
	}
	else {
		return $self->error("$pkgsub: Invalid connection mode");
	}
	return 1;
}


sub close { # Same as disconnect
	my $self = shift;
	return $self->disconnect;
}


sub error { # Handle errors according to the object's error mode
	my $self = shift;
	my $errmsg = shift || '';
	my (undef, $fileName, $lineNumber) = caller; # Needed in case of die

	$self->errmsg($errmsg);
	return _error($fileName, $lineNumber, $self->{errmode}, $errmsg);
}


sub poll { # Poll objects for completion
	my ($self, %args);
	my $pkgsub = "${Package}::poll";
	my ($running, $completed, $failed);
	my (@lastCompleted, @lastFailed);
	my $objComplete = $Default{poll_obj_complete};
	my $objError = $Default{poll_obj_error};
	my $pollTimer = $PollTimer/1000; # Convert to secs
	my ($mainLoopSleep, $mainLoopTime);

	if ($_[0]->isa($Package)) { # Method invoked as object method
		$self = shift;
		my @validArgs = ('poll_code', 'poll_timer', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	elsif (ref $_[0]) { # Method invoked with single argument array or hash ref
		$args{object_list} = shift;
	}
	else {
		my @validArgs = ('object_list', 'poll_code', 'object_complete', 'object_error', 'poll_timer', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	if (defined $args{object_complete}) {
		if ($args{object_complete} =~ /^all|next$/i) {
			$objComplete = lc $args{object_complete};
		}
		else {
			carp "$pkgsub: Invalid value for 'object_complete' argument; ignoring";
		}
	}
	if (defined $args{object_error}) {
		if ($args{object_error} =~ /^return|ignore$/i) {
			$objError = lc $args{object_error};
		}
		else {
			carp "$pkgsub: Invalid value for 'object_error' argument; ignoring";
		}
	}
	if (defined $args{poll_timer}) {
		if ($args{poll_timer} =~ /\d+/) {
			$pollTimer = $args{poll_timer}/1000; # Convert to secs
		}
		else {
			carp "$pkgsub: Invalid value for 'poll_timer' argument; ignoring";
		}
	}
	if (defined $args{poll_code}) {
		unless (ref($args{poll_code}) eq 'CODE') { # Will apply also if $args{poll_code} undef
			carp "$pkgsub: Argument 'poll_code' is not a code ref; ignoring";
		}
	}
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : ( defined $self ? $self->{errmode} : $Default{errmode} );
	return _error(__FILE__, __LINE__, $errmode, "$pkgsub: No 'object_list' provided") unless defined $self || defined $args{object_list};

	while (1) {
		$mainLoopTime = time;	# Record time before going over loop below
		($running, $completed, $failed) = (0,0,0);
	
		if ( defined $self ) { # Called in object oriented form; single object
			unless (defined $self->{POLL}) { # No poll structure exists, throw an error
				return _error(__FILE__, __LINE__, $errmode, "$pkgsub: No polling method was ever called for object") if defined $args{errmode};
				return $self->error("$pkgsub: No polling method was ever called for object");
			}
			my $ok = _call_poll_method($self, defined $args{errmode} ? $errmode : undef);
			# Return if completed or failed
			return $ok if $ok || !defined $ok;
			$running = 1;	# Ensures we always loop below
		}
		elsif ( ref $args{object_list} eq 'ARRAY' ) { # Called in non-objectoriented form; list as arg
			for my $i ( 0 .. $#{$args{object_list}} ) {
				my $obj = ${$args{object_list}}[$i];
				return _error(__FILE__, __LINE__, $errmode, "$pkgsub: Array element $i is not a valid object") unless $obj->isa($Package);
				unless (defined $obj->{POLL}) { # No poll structure exists, throw an error
					return _error(__FILE__, __LINE__, $errmode, "$pkgsub: No polling method was ever called for object array element $i") if defined $args{errmode};
					return $obj->error("$pkgsub: No polling method was ever called for object array element $i");
				}
				my $ok = _call_poll_method($obj, defined $args{errmode} ? $errmode : undef);
				if ($ok) {
					$completed++;
					unless ($obj->{POLLREPORTED}) {
						push (@lastCompleted, $i);
						$obj->{POLLREPORTED} = 1;
					}
				}
				elsif (!defined $ok) {
					$failed++;
					unless ($obj->{POLLREPORTED}) {
						push (@lastFailed, $i);
						$obj->{POLLREPORTED} = 1;
					}
				}
				else { $running++ }
			}
		}
		elsif ( ref $args{object_list} eq 'HASH' ) { # Called in in non-objectoriented form; hash as arg
			foreach my $key ( keys %{$args{object_list}} ) {
				my $obj = ${$args{object_list}}{$key};
				return _error(__FILE__, __LINE__, $errmode, "$pkgsub: Hash key $key is not a valid object") unless $obj->isa($Package);
				unless (defined $obj->{POLL}) { # No poll structure exists, throw an error
					return _error(__FILE__, __LINE__, $errmode, "$pkgsub: No polling method was ever called for object hash key $key") if defined $args{errmode};
					return $obj->error("$pkgsub: No polling method was ever called for object hash key $key");
				}
				my $ok = _call_poll_method($obj, defined $args{errmode} ? $errmode : undef);
				if ($ok) {
					$completed++;
					unless ($obj->{POLLREPORTED}) {
						push (@lastCompleted, $key);
						$obj->{POLLREPORTED} = 1;
					}
				}
				elsif (!defined $ok) {
					$failed++;
					unless ($obj->{POLLREPORTED}) {
						push (@lastFailed, $key);
						$obj->{POLLREPORTED} = 1;
					}
				}
				else { $running++ }
			}
		}
		else {
			return _error(__FILE__, __LINE__, $errmode, "$pkgsub: 'object_list' is not a hash or array reference");
		}

		# Check if we are done, before calling pollcode or doing cycle wait
		last if ($running == 0) || ($objComplete eq 'next' && @lastCompleted) || ($objError eq 'return' && @lastFailed);

		if (ref($args{poll_code}) eq 'CODE' ) { # If an activity coderef was supplied..
			&{$args{poll_code}}($running, $completed, $failed, \@lastCompleted, \@lastFailed);
		}
		$mainLoopSleep = $pollTimer - (time - $mainLoopTime);	# Timer less time it took to run through loop
		sleep($mainLoopSleep) if $mainLoopSleep > 0;		# Only if positive
	}

	return $running unless wantarray;
	return ($running, $completed, $failed, \@lastCompleted, \@lastFailed);
}


#################################### Methods to set/read Object variables ####################################

sub timeout { # Set/read timeout
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{timeout};
	if (defined $newSetting) {
		$self->{timeout} = $newSetting;
		if ($self->{TYPE} eq 'TELNET') {
			$self->{PARENT}->timeout($newSetting);
		}
	}
	return $currentSetting;
}


sub connection_timeout { # Set/read connection timeout
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{connection_timeout};
	$self->{connection_timeout} = $newSetting;
	return $currentSetting;
}


sub read_block_size { # Set/read read_block_size for either SSH or SERIAL (not applicable to TELNET)
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{read_block_size};
	$self->{read_block_size} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub blocking { # Set/read blocking/unblocking mode for reading connection and polling methods
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{blocking};
	$self->{blocking} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub read_attempts { # Set/read number of read attempts in readwait()
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{read_attempts};
	$self->{read_attempts} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub readwait_timer { # Set/read poll timer in readwait()
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{readwait_timer};
	$self->{readwait_timer} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub return_reference { # Set/read return_reference mode
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{return_reference};
	$self->{return_reference} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub output_record_separator { # Set/read the Output Record Separator automaticaly appended by print() and cmd()
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{ors};
	$self->{ors} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub prompt_credentials { # Set/read prompt_credentials mode
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{prompt_credentials};
	$self->{prompt_credentials} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub flush_credentials { # Clear the stored username, password, passphrases, if any
	my $self = shift;
	$self->{USERNAME} = $self->{PASSWORD} = $self->{PASSPHRASE} = undef;
	return 1;
}


sub prompt { # Read/Set object prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{prompt};
	if (defined $newSetting) {
		$self->{prompt} = $newSetting;
		$self->{prompt_qr} = qr/$newSetting/;
	}
	return $currentSetting;
}


sub username_prompt { # Read/Set object username prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{username_prompt};
	if (defined $newSetting) {
		$self->{username_prompt} = $newSetting;
		$self->{username_prompt_qr} = qr/$newSetting/;
	}
	return $currentSetting;
}


sub password_prompt { # Read/Set object password prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{password_prompt};
	if (defined $newSetting) {
		$self->{password_prompt} = $newSetting;
		$self->{password_prompt_qr} = qr/$newSetting/;
	}
	return $currentSetting;
}


sub errmode { # Set/read error mode
	my ($self, $newSetting) = @_;
	my $pkgsub = "${Package}::errmode";
	my $currentSetting = $self->{errmode};
	if ((defined $newSetting) && (my $newMode = parse_errmode($pkgsub, $newSetting))) {
		$self->{errmode} = $newMode;
	}
	return $currentSetting;
}


sub errmsg { # Set/read the last generated error message for the object
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{errmsg};
	$self->{errmsg} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub debug { # Set/read debug level
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{debug};
	if (defined $newSetting && $newSetting != $currentSetting) {
		$self->{debug} = $newSetting;
		if ($self->{TYPE} eq 'SSH') {
			$self->{PARENT}->debug($newSetting & 2 ? 1 : 0);
		}
		elsif ($self->{TYPE} eq 'SERIAL') {
			$self->{PARENT}->debug($newSetting & 2 ? 1 : 0);
			if ($^O eq 'MSWin32') {
				Win32::SerialPort->set_test_mode_active(!($newSetting & 1));
			}
			else {
				Device::SerialPort->set_test_mode_active(!($newSetting & 1));
			}
		}
	}
	return $currentSetting;
}


################################# Methods to read read-only Object variables #################################

sub parent { # Return the parent object
	my $self = shift;
	return $self->{PARENT};
}


sub socket { # Return the socket object
	my $self = shift;
	return $self->{SOCKET};
}


sub ssh_channel { # Return the SSH channel object
	my $self = shift;
	return $self->{SSHCHANNEL};
}


sub connection_type { # Return the connection type of this object
	my $self = shift;
	return $self->{TYPE};
}


sub port { # Return the TCP port / COM port for the connection
	my $self = shift;
	if ($self->{TYPE} eq 'SERIAL') {
		return $self->{COMPORT};
	}
	else {
		return $self->{TCPPORT};
	}
}


sub connected { # Returns true if a connection is in place
	my $self = shift;
	return !$self->eof;
}


sub last_prompt { # Return the last prompt obtained
	my $self = shift;
	return $self->{LASTPROMPT};
}


sub username { # Read the username; this might have been provided or prompted for by a method in this class
	my $self = shift;
	return $self->{USERNAME};
}


sub password { # Read the password; this might have been provided or prompted for by a method in this class
	my $self = shift;
	return $self->{PASSWORD};
}


sub passphrase { # Read the passphrase; this might have been provided or prompted for by a method in this class
	my $self = shift;
	return $self->{PASSPHRASE};
}


sub handshake { # Read the serial handshake used
	my $self = shift;
	return $self->{HANDSHAKE};
}


sub baudrate { # Read the serial baudrate used
	my $self = shift;
	return $self->{BAUDRATE};
}


sub parity { # Read the serial parity used
	my $self = shift;
	return $self->{PARITY};
}


sub databits { # Read the serial databits used
	my $self = shift;
	return $self->{DATABITS};
}


sub stopbits { # Read the serial stopbits used
	my $self = shift;
	return $self->{STOPBITS};
}


#################################### Methods for modules sub-classing Control::CLI ####################################

sub poll_struct { # Initialize the poll hash structure for a new method using it
	my ($self, $methodName, $codeRef, $blocking, $timeout, $errmode, $outputType, $outputRequested, $returnReference, $returnList) = @_;
	my $pollsub = "${Package}::poll_struct";

	if (defined $self->{POLL} && defined $self->{POLL}{complete} && $self->{POLL}{complete} == 0 ) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		my $pollOwner = $self->{POLL}{method};
		carp "$pollsub (called from $fileName line $lineNumber) $methodName is trampling over existing poll structure of $pollOwner";
	}

	$self->{POLL} = { # Initialize the base POLL structure
		method			=>	$methodName,
		coderef			=>	$codeRef,
		cache			=>	[],
		blocking		=>	$blocking,
		timeout			=>	$timeout,
		endtime			=>	undef,
		waittime		=>	undef,
		errmode			=>	$errmode,
		complete		=>	0,
		return_reference	=>	$returnReference,
		return_list		=>	$returnList,
		output_requested	=>	$outputRequested,
		output_type		=>	$outputType,
		output_result		=>	undef,
		output_buffer		=>	'',
		local_buffer		=>	'',
		read_buffer		=>	undef,
		already_polled		=>	undef,
		socket			=>	undef,
	};
	$self->{POLLREPORTED} = 0;
	$self->debugMsg(1,"	--> POLL : $methodName\n");
	return;
}


sub poll_reset { # Clears the existing poll structure, if any
	my $self = shift;
	my $methodName;

	return unless defined $self->{POLL};
	$methodName = $self->{POLL}{method};
	$methodName .= '-> ' . join('-> ', @{$self->{POLL}{cache}}) if @{$self->{POLL}{cache}};
	$self->{POLL} = undef;
	$self->debugMsg(1,"	--> POLL : undef (was $methodName)\n");
	return 1;
}


sub poll_struct_cache { # Cache selected poll structure keys into a sub polling structure
	my ($self, $cacheMethod, $timeout) = @_;
	my $pollsub = "${Package}::poll_struct_cache";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	$self->{POLL}{$cacheMethod}{cache}{output_buffer} = $self->{POLL}{output_buffer};
	$self->{POLL}{output_buffer} = '';

	$self->{POLL}{$cacheMethod}{cache}{output_result} = $self->{POLL}{output_result};
	$self->{POLL}{output_result} = '';

	$self->{POLL}{$cacheMethod}{cache}{local_buffer} = $self->{POLL}{local_buffer};
	$self->{POLL}{local_buffer} = '';

	if (defined $timeout) {
		$self->{POLL}{$cacheMethod}{cache}{timeout} = $self->{POLL}{timeout};
		$self->{POLL}{timeout} = $timeout;
	}

	my $cacheChain = @{$self->{POLL}{cache}} ? '--> ' . join(' --> ', @{$self->{POLL}{cache}}) : '';
	push( @{$self->{POLL}{cache}}, $cacheMethod); # Point cache location
	$self->debugMsg(1,"	--> POLL : $self->{POLL}{method} $cacheChain --> $cacheMethod\n");
	return;
}


sub poll_struct_restore { # Restore original poll structure from cached values and return cache method output
	my $self = shift;
	my $pollsub = "${Package}::poll_struct_restore";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	my $cacheMethod = pop( @{$self->{POLL}{cache}} );
	# Save the output buffer & result
	my $output_buffer = $self->{POLL}{output_buffer};
	my $output_result = $self->{POLL}{output_result};
	# Restore the cached keys
	foreach my $key (keys %{$self->{POLL}{$cacheMethod}{cache}}) {
		$self->{POLL}{$key} = $self->{POLL}{$cacheMethod}{cache}{$key};
	}
	# Undefine the method poll structure
	$self->{POLL}{$cacheMethod} = undef;
	my $cacheChain = @{$self->{POLL}{cache}} ? '--> ' . join(' --> ', @{$self->{POLL}{cache}}) : '';
	$self->debugMsg(1,"	--> POLL : $self->{POLL}{method} $cacheChain <-- $cacheMethod\n");
	# Return the output as reference
	return (\$output_buffer, \$output_result);
}


sub poll_return { # Method to return from poll methods
	my ($self, $ok) = @_;
	my $pollsub = "${Package}::poll_return";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}
	$self->{POLL}{already_polled} = undef; # Always reset this flag on exit

	if (@{$self->{POLL}{cache}}) { # Current polled method was called by another polled method
		return 0 if defined $ok && $ok == 0;		 # Never return any output on non-blocking not ready
		# If error or poll complete then restore cached output to poll structure and recover output, if any
		my ($output_bufRef, $output_resRef) = $self->poll_struct_restore;
		return unless defined $ok;			# Never return any output on error
		return 1 unless wantarray;			# No output requested
		return (1, $output_bufRef, $output_resRef); 	# Only return output, as reference, on success & wantarray
	}

	$self->{POLL}{complete} = $ok;	# Store status for next poll
	return $ok unless $self->{POLL}{output_requested} && $self->{POLL}{output_type};
	# If we did not return above, only in this case do we have to provide output
	my @output_list;
	if ($self->{POLL}{output_type} & 1) { # Provide Output_buffer
		my $output = $self->{POLL}{output_buffer}; # 1st store the output buffer
		$self->{POLL}{output_buffer} = ''; # Then clear it in the storage structure
		if ($self->{POLL}{return_reference}) {
			push(@output_list, \$output);
		}
		else {
			push(@output_list, $output);
		}
	}
	if ($self->{POLL}{output_type} & 2) { # Provide Output_result
		if (!ref $self->{POLL}{output_result}) { # If a scalar
			push(@output_list, $self->{POLL}{output_result});
		}
		elsif (ref $self->{POLL}{output_result} eq 'ARRAY') { # If an array
			if ($self->{POLL}{return_list}) {
				push(@output_list, @{$self->{POLL}{output_result}});
			}
			else {
				push(@output_list, $self->{POLL}{output_result});
			}
		}
	}
	return ($ok, @output_list);
}


sub poll_open_socket { # Internal method to open TCP socket for either Telnet or SSH
	my ($self, $pkgsub, $host, $port) = @_;
	my $pollsub = "${Package}::poll_open_socket";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	if ($UseSocketIP) { # Use IO::Socket::IP if we can (works for both IPv4 & IPv6)

		# In non-blocking mode we will come back here, so open socket only 1st time
		unless (defined $self->{POLL}{socket}) {

			# In non-blocking mode need to set the connection endtime for timeouts
			unless ($self->{POLL}{blocking}) {
				if (defined $self->{POLL}{timeout}) { # If a connection_timeout is defined, use it
					$self->{POLL}{endtime} = time + $self->{POLL}{timeout};
				}
				else { # If no connection_timeout is defined, fall back onto module's own default value for non-blocking connections
					$self->{POLL}{endtime} = time + $Default{connection_timeout_nb};
				}
			}

			$self->{POLL}{socket} = IO::Socket::IP->new(
				PeerHost => $host,
				PeerPort => $port,
				Blocking     => 0,	# Use non-blocking mode to enforce connection timeout
							# even if blocking connect()
			) or return $self->error("$pkgsub: cannot construct socket - $@");
		}

		while ( !$self->{POLL}{socket}->connect && ( $! == EINPROGRESS || $! == EWOULDBLOCK ) ) {
			my $wvec = '';
			vec( $wvec, fileno $self->{POLL}{socket}, 1 ) = 1;
			my $evec = '';
			vec( $evec, fileno $self->{POLL}{socket}, 1 ) = 1;

			if ($self->{POLL}{blocking}) { # In blocking mode perform connection timeout
				select( undef, $wvec, $evec, $self->{POLL}{timeout} )
					or return $self->error("$pkgsub: connection timeout expired");
			}
			else { # In non-blocking mode don't wait; just come out if not ready and timeout not expired
				select( undef, $wvec, $evec, 0 ) or do {
					return (0, undef) unless time > $self->{POLL}{endtime}; # Timeout not expired
					return $self->error("$pkgsub: connection timeout expired");  # Timeout expired
				};
			}
		}
		return $self->error("$pkgsub: unable to connect - $!") if $!;
	}
	else { # Use IO::Socket::INET (only IPv4 support)
		$self->{POLL}{socket} = IO::Socket::INET->new(
			PeerHost => $host,
			PeerPort => $port,
			Timeout => $self->{POLL}{timeout},
		) or return $self->error("$pkgsub: unable to establish socket - $@");
	}
	return (1, $self->{POLL}{socket});
}


sub poll_read { # Method to handle reads for poll methods (handles both blocking and non-blocking modes)
	my ($self, $pkgsub, $errmsg) = @_;
	my $pollsub = "${Package}::poll_read";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	if ($self->{POLL}{blocking}) { # In blocking mode
		$self->{POLL}{read_buffer} = $self->read(
					blocking => 1,
					timeout => $self->{POLL}{timeout},
					return_reference => 0,
					errmode => 'return',
					);
		unless (defined $self->{POLL}{read_buffer}) { # Here we catch errors since errmode = 'return'
			return $self->error("$pkgsub: $errmsg\n".$self->errmsg) if defined $errmsg;
			return; # Otherwise
		}
		return 1; # In blocking mode we come out here indicating we have read data
	}
	else { # In non-blocking mode
		if ($self->{POLL}{already_polled}) { # In non-blocking mode and if we already went round the calling loop once
			$self->{POLL}{already_polled} = undef; # Undefine it for next time
			$self->{POLL}{read_buffer} = undef; # Undefine it for next time
			return 0;
		}

		unless(defined $self->{POLL}{endtime}) { # Set endtime for timeout
			$self->{POLL}{endtime} = time + $self->{POLL}{timeout};
		}

		$self->{POLL}{read_buffer} = $self->read( blocking => 0, return_reference => 0 );
		if (length $self->{POLL}{read_buffer}) { # We read something
			$self->{POLL}{already_polled} = 1; # Set it for next cycle
			$self->{POLL}{endtime} = undef; # Clear timeout endtime
			return 1; # This is effectively when we are done and $self->{POLL}{read_buffer} can be read by calling loop
		}

		# We read nothing from device
		if (time > $self->{POLL}{endtime}) { # Timeout has expired
			$self->{POLL}{endtime} = undef; # Clear timeout endtime
			return $self->error("$pkgsub: $errmsg") if defined $errmsg;
			return; # Otherwise
		}
		else { # Still within timeout
			return 0;
		}
	}
}


sub poll_readwait { # Method to handle readwait for poll methods (handles both blocking and non-blocking modes)
	my ($self, $pkgsub, $firstReadRequired, $readAttempts, $readwaitTimer, $errmsg) = @_;
	$readAttempts = $self->{read_attempts} unless defined $readAttempts;
	$readwaitTimer = $self->{readwait_timer} unless defined $readwaitTimer;
	my $pollsub = "${Package}::poll_readwait";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	# Different read section for blocking and non-blocking modes
	if ($self->{POLL}{blocking}) { # In blocking mode use regular readwait() method
		$self->{POLL}{read_buffer} = $self->readwait(
				read_attempts => $readAttempts,
				readwait_timer => $readwaitTimer,
				blocking => $firstReadRequired,
				timeout => $self->{POLL}{timeout},
				return_reference => 0,
				errmode => 'return',
				);
		unless (defined $self->{POLL}{read_buffer}) { # Here we catch errors since errmode = 'return'
			return $self->error("$pkgsub: $errmsg\n".$self->errmsg) if defined $errmsg;
			return; # Otherwise
		}
		return 1; # In non-blocking mode we come out here
	}
	else { # In non-blocking mode
		if ($self->{POLL}{already_polled}) { # In non-blocking mode and if we already went round the calling loop once
			$self->{POLL}{already_polled} = undef; # Undefine it for next time
			$self->{POLL}{read_buffer} = undef; # Undefine it for next time
			return 0;
		}

		if ($firstReadRequired && !defined $self->{POLL}{endtime}) { # First time we need to setup endtime timer
			$self->{POLL}{endtime} = time + $self->{POLL}{timeout};
		}
		elsif (!$firstReadRequired && !defined $self->{POLL}{waittime}) { # First time, no timeout, but we need to setup wait timer directly
			$self->{POLL}{waittime} = time + $readwaitTimer/1000 * $readAttempts;
			$self->{POLL}{read_buffer} = ''; # Make sure read buffer is defined and empty
		}

		my $outref = $self->read( blocking => 0, return_reference => 1 );
		if (length $$outref) { # We read something, reset wait timer
			$self->{POLL}{read_buffer} .= $$outref;
			$self->{POLL}{waittime} = time + $readwaitTimer/1000 * $readAttempts;
			return 0;
		}

		# We read nothing from device
		if (defined $self->{POLL}{waittime}) { # Some data already read; now just doing waittimer for more
			if (time > $self->{POLL}{waittime}) { # Wait timer has expired
				$self->{POLL}{already_polled} = 1; # Set it for next cycle
				$self->{POLL}{endtime} = undef;  # Clear timeout endtime
				$self->{POLL}{waittime} = undef; # Clear waittime
				return 1; # This is effectively when we are done and $self->{POLL}{read_buffer} can be read by calling loop
			}
			else { # Wait timer has not expired yet
				return 0;
			}
		}
		else { # No data read yet, regular timeout checking
			if (time > $self->{POLL}{endtime}) { # Timeout has expired
				$self->{POLL}{endtime} = undef; # Clear timeout endtime
				return $self->error("$pkgsub: $errmsg") if defined $errmsg;
				return; # Otherwise
			}
			else { # Still within timeout
				return 0;
			}
		}
	}
}


sub poll_connect { # Internal method to connect to host (used for both blocking & non-blocking modes)
	my $self = shift;
	my $pkgsub = shift;
	my $pollsub = "${Package}::connect";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	unless (defined $self->{POLL}{$pollsub}) { # Only applicable if called from another method already in polling mode
		my ($host, $port, $username, $password, $publickey, $privatekey, $passphrase, $baudrate,
		    $parity, $databits, $stopbits, $handshake, $promptCredentials, $timeout, $errmode) = @_;
		# In which case we need to setup the poll structure here (the main poll structure remains unchanged)
		$self->{POLL}{$pollsub} = { # Populate structure with method arguments/storage
			# Set method argument keys
			host			=>	$host,
			port			=>	$port,
			username		=>	defined $username ? $username : $self->{USERNAME},
			password		=>	defined $password ? $password : $self->{PASSWORD},
			publickey		=>	$publickey,
			privatekey		=>	$privatekey,
			passphrase		=>	defined $passphrase ? $passphrase : $self->{PASSPHRASE},
			baudrate		=>	$baudrate,
			parity			=>	$parity,
			databits		=>	$databits,
			stopbits		=>	$stopbits,
			handshake		=>	$handshake,
			prompt_credentials	=>	defined $promptCredentials ? $promptCredentials : $self->{prompt_credentials},
			# Declare method storage keys which will be used
			stage			=>	0,
			authPublicKey		=>	0,
			authPassword		=>	0,
			# Declare keys to be set if method called from another polled method
			errmode			=>	$errmode,
		};
		# Cache poll structure keys which this method will use
		$self->poll_struct_cache($pollsub, $timeout);
	}
	my $connect = $self->{POLL}{$pollsub};
	local $self->{errmode} = $connect->{errmode} if defined $connect->{errmode};

	my $ok;

	if ($connect->{stage} < 1) { # Initial setup - do only once
		$self->{BUFFER} = '';
		$self->{LOGINSTAGE} = '';
	}

	if ($self->{TYPE} eq 'TELNET') {
		if ($connect->{stage} < 1) { # Initial setup - do only once
			$connect->{stage}++; # Ensure we don't come back here in non-blocking mode
			return $self->poll_return($self->error("$pkgsub: No Telnet host provided")) unless defined $connect->{host};
			$self->{PARENT}->errmode('return');
			$self->{PARENT}->timeout($self->{timeout});
			$connect->{port} = $Default{tcp_port}{TELNET} unless defined $connect->{port};
			$self->{TCPPORT} = $connect->{port};
		}
		# TCP Socket setup and handoff to Net::Telnet object
		# Open Socket ourselves
		($ok, $self->{SOCKET}) = $self->poll_open_socket($pkgsub, $connect->{host}, $connect->{port});
		return $self->poll_return($ok) unless $ok;	# Covers 2 cases:
					# - errmode is 'return' and $ok = undef ; so we come out due to error
					# - $ok = 0 ; non-blocking mode; connection not ready yet

		# Give Socket to Net::Telnet
		$self->{PARENT}->fhopen($self->{SOCKET}) or return $self->poll_return($self->error("$pkgsub: unable to open Telnet over socket"));
		if ($^O eq 'MSWin32' && $Net::Telnet::VERSION eq '3.04') {
			# We need this hack to workaround a bug in newest Net::Telnet 3.04
			# see Net::Telnet bug report 94913: https://rt.cpan.org/Ticket/Display.html?id=94913 
			*{$self->{PARENT}}->{net_telnet}->{select_supported} = 1;
		}
	}
	elsif ($self->{TYPE} eq 'SSH') {
		if ($connect->{stage} < 1) { # Initial setup - do only once
			$connect->{stage}++; # Ensure we don't come back here in non-blocking mode
			return $self->poll_return($self->error("$pkgsub: No SSH host provided")) unless defined $connect->{host};
			$connect->{port} = $Default{tcp_port}{SSH} unless defined $connect->{port};
			$self->{TCPPORT} = $connect->{port};
		}
		if ($connect->{stage} < 2) { # TCP Socket setup and handoff to Net::SSH2 object
			# Open Socket ourselves
			($ok, $self->{SOCKET}) = $self->poll_open_socket($pkgsub, $connect->{host}, $connect->{port});
			return $self->poll_return($ok) unless $ok;	# Covers 2 cases:
						# - errmode is 'return' and $ok = undef ; so we come out due to error
						# - $ok = 0 ; non-blocking mode; connection not ready yet
			$connect->{stage}++; # Ensure we don't come back here in non-blocking mode

			# Set the SO_LINGER option as Net::SSH2 would do
			$self->{SOCKET}->sockopt(&Socket::SO_LINGER, pack('SS', 0, 0));
	
			# Give Socket to Net::SSH2
			eval { # Older versions of Net::SSH2 need to be trapped so that we get desired error mode
				$ok = $self->{PARENT}->connect($self->{SOCKET});
			};
			return $self->poll_return($self->error($@)) if $@;
			return $self->poll_return($self->error("$pkgsub: SSH unable to connect")) unless $ok;
			return $self->poll_return(0) unless $self->{POLL}{blocking};
		}
		if ($connect->{stage} < 3) { # Find out available SSH authentication options
			$connect->{stage}++; # Ensure we don't come back here in non-blocking mode
			unless ( defined $connect->{username} ) {
				if ($connect->{prompt_credentials}) {
					$connect->{username} = promptClear('Username');
					# Reset timeout endtime
					$self->{POLL}{endtime} = time + $self->{POLL}{timeout};
				}
				else {
					return $self->poll_return($self->error("$pkgsub: Username required for SSH authentication"));
				}
			}
			if ( !$self->{POLL}{blocking} && time > $self->{POLL}{endtime} ) { # Check if over time in non-blocking mode
				return $self->poll_return($self->error("$pkgsub: connection timeout expired (before auth_list)"));
			}
			my @authList = $self->{PARENT}->auth_list($connect->{username});
			foreach my $auth (@authList) {
				$connect->{authPublicKey} = 1 if $auth eq 'publickey';
				$connect->{authPassword} |= 1 if $auth eq 'password';			# bit1 = password
				$connect->{authPassword} |= 2 if $auth eq 'keyboard-interactive';	# bit2 = KI
			}
			$self->debugMsg(1,"SSH authentications accepted: ", \join(', ', @authList), "\n");
			$self->debugMsg(1,"authPublicKey flag = $connect->{authPublicKey} ; authPassword flag = $connect->{authPassword}\n");
			$self->{USERNAME} = $connect->{username};	# If we got here, we have a connection so store the username used
			return $self->poll_return(0) unless $self->{POLL}{blocking};
		}
		if ($connect->{stage} < 4) { # Try publickey authentication
			$connect->{stage}++; # Ensure we don't come back here in non-blocking mode
			if ($connect->{authPublicKey}) { # Try Public Key authentication...
				if (defined $connect->{publickey} && defined $connect->{privatekey}) { # ... if we have keys
					return $self->poll_return($self->error("$pkgsub: Public Key '$connect->{publickey}' not found"))
						unless -e $connect->{publickey};
					return $self->poll_return($self->error("$pkgsub: Private Key '$connect->{privatekey}' not found"))
						unless -e $connect->{privatekey};
					unless ($connect->{passphrase}) { # Passphrase not provided
						my $passphReq = passphraseRequired($connect->{privatekey});
						return $self->poll_return($self->error("$pkgsub: Unable to read Private key")) unless defined $passphReq;
						if ($passphReq) { # Passphrase is required
							if ($connect->{prompt_credentials}) { # We are allowed to prompt for it
								$connect->{passphrase} = promptHide('Passphrase for Private Key');
								# Reset timeout endtime
								$self->{POLL}{endtime} = time + $self->{POLL}{timeout};
							}
							else {
								return $self->poll_return($self->error("$pkgsub: Passphrase required for Private Key"));
							}
						}
					}
					if ( !$self->{POLL}{blocking} && time > $self->{POLL}{endtime} ) { # Check if over time in non-blocking mode
						return $self->poll_return($self->error("$pkgsub: connection timeout expired (before auth_publickey"));
					}
					$ok = $self->{PARENT}->auth_publickey(
										$connect->{username},
										$connect->{publickey},
										$connect->{privatekey},
										$connect->{passphrase},
										);
					if ($ok) { # Store the passphrase used if publickey authentication succeded
						$self->{PASSPHRASE} = $connect->{passphrase} if $connect->{passphrase};
					}
					elsif ( !($connect->{authPassword} && (defined $connect->{password} || $connect->{prompt_credentials})) ) {
						# Unless we can try password authentication next, throw an error now
						return $self->poll_return($self->error("$pkgsub: SSH unable to publickey authenticate"));
					}
					return $self->poll_return(0) unless $self->{POLL}{blocking};
				}
				elsif (!$connect->{authPassword}) { # If we don't have the keys and publickey authentication was the only one possible
					return $self->poll_return($self->error("$pkgsub: Only publickey SSH authenticatication possible and no keys provided"));
				}
			}
		}
		if ($connect->{stage} < 5) { # Try password authentication
			$connect->{stage}++; # Ensure we don't come back here in non-blocking mode
			if ($connect->{authPassword} && !$self->{PARENT}->auth_ok) { # Try password authentication if not already publickey authenticated
				unless ( defined $connect->{password} ) {
					if ($connect->{prompt_credentials}) {
						$connect->{password} = promptHide('Password');
						# Reset timeout endtime
						$self->{POLL}{endtime} = time + $self->{POLL}{timeout};
					}
					else {
						return $self->poll_return($self->error("$pkgsub: Password required for password authentication"));
					}
				}
				if ( !$self->{POLL}{blocking} && time > $self->{POLL}{endtime} ) { # Check if over time in non-blocking mode
					return $self->poll_return($self->error("$pkgsub: connection timeout expired (before auth_password)"));
				}
				if ($connect->{authPassword} & 1) { # Use password authentication
					$self->{PARENT}->auth_password($connect->{username}, $connect->{password})
						or return $self->poll_return($self->error("$pkgsub: SSH unable to password authenticate"));
				}
				elsif ($connect->{authPassword} & 2) { # Use keyboard-interactive authentication
					$self->{PARENT}->auth_keyboard($connect->{username}, $connect->{password})
						or return $self->poll_return($self->error("$pkgsub: SSH unable to password authenticate (using keyboard-interactive)"));
				}
				else {
					return $self->poll_return($self->error("$pkgsub: Error in processing password authentication options"));
				}
				# Store password used
				$self->{PASSWORD} = $connect->{password};
				return $self->poll_return(0) unless $self->{POLL}{blocking};
			}
		}
		# Make sure we are authenticated, in case neither publicKey nor password auth was accepted
		return $self->poll_return($self->error("$pkgsub: SSH unable to authenticate")) unless $self->{PARENT}->auth_ok;

		# Setup SSH channel
		if ( !$self->{POLL}{blocking} && time > $self->{POLL}{endtime} ) { # Check if over time in non-blocking mode
			return $self->poll_return($self->error("$pkgsub: connection timeout expired (before SSH channel setup)"));
		}
		$self->{SSHCHANNEL} = $self->{PARENT}->channel();	# Open an SSH channel
		$self->{PARENT}->blocking(0);				# Make the session non blocking for reads
		$self->{SSHCHANNEL}->ext_data('merge');			# Merge stderr onto regular channel
		$self->{SSHCHANNEL}->pty('vt100');			# Start an interactive terminal on remote host
		$self->{SSHCHANNEL}->shell();				# Start shell on channel
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		$connect->{handshake} = $Default{handshake} unless defined $connect->{handshake};
		$connect->{baudrate} = $Default{baudrate} unless defined $connect->{baudrate};
		$connect->{parity} = $Default{parity} unless defined $connect->{parity};
		$connect->{databits} = $Default{databits} unless defined $connect->{databits};
		$connect->{stopbits} = $Default{stopbits} unless defined $connect->{stopbits};
		$self->{PARENT}->handshake($connect->{handshake});
		$self->{PARENT}->baudrate($connect->{baudrate});
		$self->{PARENT}->parity($connect->{parity});
		# According to Win32::SerialPort, parity_enable needs to be set when parity is not 'none'...
		$self->{PARENT}->parity_enable(1) unless $connect->{parity} eq 'none';
		$self->{PARENT}->databits($connect->{databits});
		$self->{PARENT}->stopbits($connect->{stopbits});
		$self->{PARENT}->write_settings or return $self->poll_return($self->error("$pkgsub: Can't change Device_Control_Block: $^E"));
		$self->{PARENT}->buffers($ComPortReadBuffer, 0); #Set Read & Write buffers
		$self->{PARENT}->read_interval($ComReadInterval) if $^O eq 'MSWin32';
		$self->{PARENT}->read_char_time(0);     # don't wait for each character
		$self->{HANDSHAKE} = $connect->{handshake};
		$self->{BAUDRATE} = $connect->{baudrate};
		$self->{PARITY}	= $connect->{parity};
		$self->{DATABITS} = $connect->{databits};
		$self->{STOPBITS} = $connect->{stopbits};
		$self->{SERIALEOF} = 0;
	}
	else {
		return $self->poll_return($self->error("$pkgsub: Invalid connection mode"));
	}
	return $self->poll_return(1);
}


sub poll_login { # Method to handle login for poll methods (used for both blocking & non-blocking modes)
	my $self = shift;
	my $pkgsub = shift;
	my $pollsub = "${Package}::login";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	unless (defined $self->{POLL}{$pollsub}) { # Only applicable if called from another method already in polling mode
		my ($username, $password, $prompt, $userPrompt, $pwdPrompt, $promptCredentials, $timeout, $errmode) = @_;
		# In which case we need to setup the poll structure here (the main poll structure remains unchanged)
		$self->{POLL}{$pollsub} = { # Populate structure with method arguments/storage
			# Set method argument keys
			username		=>	defined $username ? $username : $self->{USERNAME},
			password		=>	defined $password ? $password : $self->{PASSWORD},
			prompt			=>	defined $prompt ? $prompt : $self->{prompt_qr},
			username_prompt		=>	defined $userPrompt ? $userPrompt : $self->{username_prompt_qr},
			password_prompt		=>	defined $pwdPrompt ? $pwdPrompt : $self->{password_prompt_qr},
			prompt_credentials	=>	defined $promptCredentials ? $promptCredentials : $self->{prompt_credentials},
			# Declare method storage keys which will be used
			stage			=>	0,
			login_attempted		=>	undef,
			# Declare keys to be set if method called from another polled method
			errmode			=>	$errmode,
		};
		# Cache poll structure keys which this method will use
		$self->poll_struct_cache($pollsub, $timeout);
	}
	my $login = $self->{POLL}{$pollsub};
	local $self->{errmode} = $login->{errmode} if defined $login->{errmode};
	return $self->poll_return($self->error("$pkgsub: No connection to login to")) if $self->eof;

	if ($login->{stage} < 1) { # Initial loginstage checking - do only once
		$login->{stage}++; # Ensure we don't come back here in non-blocking mode
		if ($self->{LOGINSTAGE} eq 'username') { # Resume login from where it was left
			return $self->error("$pkgsub: Username required") unless $login->{username};
			$self->print(line => $login->{username}, errmode => 'return')
				or return $self->poll_return($self->error("$pkgsub: Unable to send username\n".$self->errmsg));
			$self->{LOGINSTAGE} = '';
			$login->{login_attempted} =1;
		}
		elsif ($self->{LOGINSTAGE} eq 'password') { # Resume login from where it was left
			return $self->error("$pkgsub: Password required") unless $login->{password};
			$self->print(line => $login->{password}, errmode => 'return')
				or return $self->poll_return($self->error("$pkgsub: Unable to send password\n".$self->errmsg));
			$self->{LOGINSTAGE} = '';
		}
	}
	# Enter login loop..
	do {{
		my $ok = $self->poll_read($pkgsub, 'Timeout reading login prompt');
		return $self->poll_return($ok) unless $ok;

		$self->{POLL}{local_buffer} .= $self->{POLL}{read_buffer};  # Login buffer can get flushed along the way
		$self->{POLL}{output_buffer} .= $self->{POLL}{read_buffer}; # This buffer preserves all the output, in case it is requested

		if ($self->{POLL}{local_buffer} =~ /$login->{username_prompt}/) { # Handle username prompt
			if ($login->{login_attempted}) {
				return $self->poll_return($self->error("$pkgsub: Incorrect Username or Password"));
			}
			unless ($login->{username}) {
				if ($self->{TYPE} eq 'SSH') { # If an SSH connection, we already have the username
					$login->{username} = $self->{USERNAME};
				}
				else {
					unless ($login->{prompt_credentials}) {
						$self->{LOGINSTAGE} = 'username';
						return $self->poll_return($self->error("$pkgsub: Username required"));
					}
					$login->{username} = promptClear('Username');
				}
			}
			$self->print(line => $login->{username}, errmode => 'return')
				or return $self->poll_return($self->error("$pkgsub: Unable to send username\n".$self->errmsg));
			$self->{LOGINSTAGE} = '';
			$login->{login_attempted} =1;
			$self->{POLL}{local_buffer} = '';
			next;
		}
		if ($self->{POLL}{local_buffer} =~ /$login->{password_prompt}/) { # Handle password prompt
			unless ($login->{password}) {
				unless ($login->{prompt_credentials}) {
					$self->{LOGINSTAGE} = 'password';
					return $self->poll_return($self->error("$pkgsub: Password required"));
				}
				$login->{password} = promptHide('Password');
			}
			$self->print(line => $login->{password}, errmode => 'return')
				or return $self->poll_return($self->error("$pkgsub: Unable to send password\n".$self->errmsg));
			$self->{LOGINSTAGE} = '';
			$self->{POLL}{local_buffer} = '';
			next;
		}
	}} until ($self->{POLL}{local_buffer} =~ /($login->{prompt})/);
	$self->{LASTPROMPT} = $1;
	($self->{USERNAME}, $self->{PASSWORD}) = ($login->{username}, $login->{password}) if $login->{login_attempted};
	return $self->poll_return(1);
}


sub poll_waitfor { # Method to handle waitfor for poll methods (used for both blocking & non-blocking modes)
	my $self = shift;
	my $pkgsub = shift;
	my $pollsub = "${Package}::waitfor";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	unless (defined $self->{POLL}{$pollsub}) { # Only applicable if called from another method already in polling mode
		my ($matchpat, $timeout, $errmode) = @_;
		$matchpat = [$matchpat] unless ref($matchpat) eq "ARRAY";	# We want it as an array reference
		my @matchArray = grep {defined} @{$matchpat};			# Weed out undefined values, if any
		# In which case we need to setup the poll structure here (the main poll structure remains unchanged)
		$self->{POLL}{$pollsub} = { # Populate structure with method arguments/storage
			# Set method argument keys
			matchpat		=>	\@matchArray,
			# Declare method storage keys which will be used
			stage			=>	0,
			matchpat_qr		=>	undef,
			# Declare keys to be set if method called from another polled method
			errmode			=>	$errmode,
		};
		# Cache poll structure keys which this method will use
		$self->poll_struct_cache($pollsub, $timeout);
	}
	my $waitfor = $self->{POLL}{$pollsub};
	local $self->{errmode} = $waitfor->{errmode} if defined $waitfor->{errmode};
	return $self->poll_return($self->error("$pkgsub: Received eof from connection")) if $self->eof;

	if ($waitfor->{stage} < 1) { # 1st stage
		$waitfor->{stage}++; # Ensure we don't come back here in non-blocking mode
		return $self->poll_return($self->error("$pkgsub: Match pattern provided is undefined")) unless @{$waitfor->{matchpat}};
		eval { # Eval the patterns as they may be invalid
			@{$waitfor->{matchpat_qr}} = map {qr/^((?:.*\n?)*?)($_)/} @{$waitfor->{matchpat}}; # Convert match patterns into regex
			# This syntax did not work:          qr/^([\n.]*?)($_)/
		};
		if ($@) { # If we trap an error..
			$@ =~ s/ at \S+ line .+$//s;	# ..remove this module's line number
			return $self->poll_return($self->error("$pkgsub: $@"));
		}
	}

	READ: while (1) {
		my $ok = $self->poll_read($pkgsub, 'Timeout waiting for output');
		return $self->poll_return($ok) unless $ok;
		$self->{POLL}{local_buffer} .= $self->{POLL}{read_buffer};

		foreach my $pattern (@{$waitfor->{matchpat_qr}}) {
			if ($self->{POLL}{local_buffer} =~ s/$pattern//) {
				($self->{POLL}{output_buffer}, $self->{POLL}{output_result}) = ($1, $2);
				last READ;
			}
		}
	}
	$self->{BUFFER} = $self->{POLL}{local_buffer} if length $self->{POLL}{local_buffer};
	return $self->poll_return(1);
}


sub poll_cmd { # Method to handle cmd for poll methods (used for both blocking & non-blocking modes)
	my $self = shift;
	my $pkgsub = shift;
	my $pollsub = "${Package}::cmd";

	unless ($self->{POLLING}) { # Sanity check
		my (undef, $fileName, $lineNumber) = caller;
		croak "$pollsub (called from $fileName line $lineNumber) can only be used within polled methods";
	}

	unless (defined $self->{POLL}{$pollsub}) { # Only applicable if called from another method already in polling mode
		my ($cmd, $prompt, $timeout, $errmode) = @_;
		# In which case we need to setup the poll structure here (the main poll structure remains unchanged)
		$self->{POLL}{$pollsub} = { # Populate structure with method arguments/storage
			# Set method argument keys
			command			=>	$cmd,
			prompt			=>	defined $prompt ? $prompt : $self->{prompt_qr},
			# Declare method storage keys which will be used
			stage			=>	0,
			cmdEchoRemoved		=>	0,
			# Declare keys to be set if method called from another polled method
			errmode			=>	$errmode,
		};
		# Cache poll structure keys which this method will use
		$self->poll_struct_cache($pollsub, $timeout);
	}
	my $cmd = $self->{POLL}{$pollsub};
	local $self->{errmode} = $cmd->{errmode} if defined $cmd->{errmode};
	return $self->poll_return($self->error("$pkgsub: No connection to send cmd to")) if $self->eof;

	if ($cmd->{stage} < 1) { # Send command - do only once
		$cmd->{stage}++; # Ensure we don't come back here in non-blocking mode

		# Flush any unread data which might be pending
		$self->read(blocking => 0);

		# Send the command
		$self->print(line => $cmd->{command}, errmode => 'return')
			or return $self->poll_return($self->error("$pkgsub: Unable to send CLI command: $cmd->{command}\n".$self->errmsg));
	}

	# Wait for next prompt
	do {
		my $ok = $self->poll_read($pkgsub, 'Timeout after sending command');
		return $self->poll_return($ok) unless $ok;

		if ($cmd->{cmdEchoRemoved}) { # Initial echoed command was already removed from output
			$self->{POLL}{local_buffer} .= $self->{POLL}{read_buffer};	# Add new output
			my $lastLine = stripLastLine(\$self->{POLL}{local_buffer});	# Remove incomplete last line if any
			$self->{POLL}{output_buffer} .= $self->{POLL}{local_buffer};	# This buffer preserves all the output
			$self->{POLL}{local_buffer} = $lastLine;			# Keep incomplete lines in this buffer
		}
		else { # We have not yet received a complete line
			$self->{POLL}{local_buffer} .= $self->{POLL}{read_buffer};  # Use this buffer until we can strip the echoed command
			if ($self->{POLL}{local_buffer} =~ s/^.*\n//) { # We can remove initial echoed command from output
				my $lastLine = stripLastLine(\$self->{POLL}{local_buffer});	# Remove incomplete last line if any
				$self->{POLL}{output_buffer} = $self->{POLL}{local_buffer};	# Copy it across; it can now be retrieved
				$self->{POLL}{local_buffer} = $lastLine;			# Keep incomplete lines in this buffer
				$cmd->{cmdEchoRemoved} = 1;
			}
		}
	} until $self->{POLL}{local_buffer} =~ s/($cmd->{prompt})//;
	$self->{LASTPROMPT} = $1;
	return $self->poll_return(1);
}


sub debugMsg { # Print a debug message
	my $self = shift;
	if (shift() & $self->{debug}) {
		my $string1 = shift();
		my $stringRef = shift() || \"";#" Ultraedit hack!
		my $string2 = shift() || "";
		print $string1, $$stringRef, $string2;
	}
	return;
}


########################################## Internal Private Methods ##########################################

sub _read_buffer { # Internal method to read (and clear) any data cached in object buffer
	my ($self, $returnRef) = @_;
	my $buffer = $self->{BUFFER};
	$self->{BUFFER} = '';
	# $buffer will always be defined; worst case an empty string
	return $returnRef ? \$buffer : $buffer;
}


sub _read_blocking { # Internal read method; data must be read or we timeout
	my ($self, $pkgsub, $timeout, $returnRef) = @_;
	my $buffer;

	if ($self->{TYPE} eq 'TELNET') {
		$buffer = $self->{PARENT}->get(Timeout => $timeout);
		return $self->error("$pkgsub: Received eof from connection") if $self->eof;
		return $self->error("$pkgsub: Telnet ".$self->{PARENT}->errmsg) unless defined $buffer;
	}
	elsif ($self->{TYPE} eq 'SSH') {
		return $self->error("$pkgsub: No SSH channel to read from") unless defined $self->{SSHCHANNEL};
		$self->{SSHCHANNEL}->read($buffer, $self->{read_block_size});
		unless (defined $buffer && length $buffer) {
			return $self->error("$pkgsub: Received eof from connection") if $self->eof;
			my @poll = { handle => $self->{SSHCHANNEL}, events => ['in'] };
			unless ($self->{PARENT}->poll($timeout*1000, \@poll) && $poll[0]->{revents}->{in}) {
				return $self->error("$pkgsub: SSH read timeout");
			}
			my $inBytes = $self->{SSHCHANNEL}->read($buffer, $self->{read_block_size});
			return $self->error("$pkgsub: SSH channel read error") unless defined $inBytes;
		}
		_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
		_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		return $self->error("$pkgsub: Received eof from connection") if $self->{SERIALEOF};
		if ($^O eq 'MSWin32') { # Win32::SerialPort
			my $inBytes;
			# Set timeout in millisecs
			local $SIG{__WARN__} = sub {}; # Disable carp from Win32::SerialPort
			$self->{PARENT}->read_const_time($timeout == 0 ? 1 : $timeout * 1000) or do {
				$self->{PARENT}->close;
				$self->{SERIALEOF} = 1;
				return $self->error("$pkgsub: Unable to read serial port");
			};
			($inBytes, $buffer) = $self->{PARENT}->read($self->{read_block_size});
			return $self->error("$pkgsub: Serial Port read timeout") unless $inBytes;
		}
		else { # Device::SerialPort; we handle polling ourselves
			# Wait defined millisecs during every read
			$self->{PARENT}->read_const_time($PollTimer) or do {
				$self->{PARENT}->close;
				$self->{SERIALEOF} = 1;
				return $self->error("$pkgsub: Unable to read serial port");
			};
			my $inBytes;
			my $ticks = 0;
			my $ticksTimeout = $timeout*$PollTimer/10;
			do {
				if ($ticks++ > $ticksTimeout) {
					return $self->error("$pkgsub: Serial port read timeout");
				}
				($inBytes, $buffer) = $self->{PARENT}->read($self->{read_block_size});
			} until $inBytes > 0;
		}
		_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
		_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
	}
	else {
		return $self->error("$pkgsub: Invalid connection mode");
	}
	# $buffer should always be a defined, non-empty string
	return $returnRef ? \$buffer : $buffer;
}


sub _read_nonblocking { # Internal read method; if no data available return immediately
	my ($self, $pkgsub, $returnRef) = @_;
	my $buffer;

	if ($self->{TYPE} eq 'TELNET') {
		$buffer = $self->{PARENT}->get(Timeout => 0);
		return $self->error("$pkgsub: Received eof from connection") if $self->eof;
		$buffer = '' unless defined $buffer;
	}
	elsif ($self->{TYPE} eq 'SSH') {
		return $self->error("$pkgsub: No SSH channel to read from") unless defined $self->{SSHCHANNEL};
		$self->{SSHCHANNEL}->read($buffer, $self->{read_block_size});
		if (length $buffer) {
			_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
			_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
		}
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		return $self->error("$pkgsub: Received eof from connection") if $self->{SERIALEOF};
		my $inBytes;
		local $SIG{__WARN__} = sub {}; # Disable carp from Win32::SerialPort
		# Set timeout to nothing (1ms; Win32::SerialPort does not like 0)
		$self->{PARENT}->read_const_time(1) or do {
			$self->{PARENT}->close;
			$self->{SERIALEOF} = 1;
			return $self->error("$pkgsub: Unable to read serial port");
		};
		($inBytes, $buffer) = $self->{PARENT}->read($self->{read_block_size});
		return $self->error("$pkgsub: Serial port read error") unless defined $buffer;
		if (length $buffer) {
			_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
			_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
		}
	}
	else {
		return $self->error("$pkgsub: Invalid connection mode");
	}
	# If nothing was read, $buffer should be a defined, empty string
	return $returnRef ? \$buffer : $buffer;
}


sub _put { # Internal write method
	my ($self, $pkgsub, $outref) = @_;

	return $self->error("$pkgsub: No connection to write to") if $self->eof;

	if ($self->{TYPE} eq 'TELNET') {
		$self->{PARENT}->put($$outref) or return $self->error("$pkgsub: Telnet ".$self->{PARENT}->errmsg);
	}
	elsif ($self->{TYPE} eq 'SSH') {
		return $self->error("$pkgsub: No SSH channel to write to") unless defined $self->{SSHCHANNEL};
		print {$self->{SSHCHANNEL}} $$outref;
		_log_print($self->{OUTPUTLOGFH}, $outref) if defined $self->{OUTPUTLOGFH};
		_log_dump('>', $self->{DUMPLOGFH}, $outref) if defined $self->{DUMPLOGFH};
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		my $countOut = $self->{PARENT}->write($$outref);
		return $self->error("$pkgsub: Serial port write failed") unless $countOut;
		return $self->error("$pkgsub: Serial port write incomplete") if $countOut != length($$outref);
		_log_print($self->{OUTPUTLOGFH}, $outref) if defined $self->{OUTPUTLOGFH};
		_log_dump('>', $self->{DUMPLOGFH}, $outref) if defined $self->{DUMPLOGFH};
	}
	else {
		return $self->error("$pkgsub: Invalid connection mode");
	}
	return 1;
}


sub _log_print { # Print output to log file (input, output or dump); taken from Net::Telnet
	my ($fh, $dataRef) = @_;

	local $\ = '';
	if (ref($fh) and ref($fh) ne "GLOB") {  # fh is blessed ref
		$fh->print($$dataRef);
	}
	else {  # fh isn't blessed ref
		print $fh $$dataRef;
	}
	return 1;
}


sub _log_dump { # Dump log procedure; copied and modified directly from Net::Telnet for use with SSH/Serial access
	my ($direction, $fh, $dataRef) = @_;
	my ($hexvals, $line);
	my ($addr, $offset) = (0, 0);
	my $len = length($$dataRef);

	# Print data in dump format.
	while ($len > 0) { # Convert up to the next 16 chars to hex, padding w/ spaces.
		if ($len >= 16) {
			$line = substr($$dataRef, $offset, 16);
		}
		else {
			$line = substr($$dataRef, $offset, $len);
		}
		$hexvals = unpack("H*", $line);
		$hexvals .= ' ' x (32 - length $hexvals);

		# Place in 16 columns, each containing two hex digits.
		$hexvals = sprintf("%s %s %s %s  " x 4, unpack("a2" x 16, $hexvals));

		# For the ASCII column, change unprintable chars to a period.
		$line =~ s/[\000-\037,\177-\237]/./g;

		# Print the line in dump format.
		_log_print($fh, \sprintf("%s 0x%5.5lx: %s%s\n", $direction, $addr, $hexvals, $line));

		$addr += 16;
		$offset += 16;
		$len -= 16;
	}
	_log_print($fh, \"\n") if $$dataRef;#" Ultraedit hack!
	return 1;
}


sub _error { # Internal method to perfom error mode action
	my ($fileName, $lineNumber, $mode, $errmsg) = @_;

	if (ref($mode) eq "CODE") {
		&$mode($errmsg);
		return;
	}
	elsif (ref($mode) eq "ARRAY") {
		my ($func, @args) = @$mode;
		&$func(@args, $errmsg);
		return;
	}
	elsif ($mode eq 'return') { return }
	elsif ($mode eq 'croak') { croak "\n$errmsg" }
	elsif ($mode eq 'die') { die "\n$errmsg at $fileName line $lineNumber\n" }
	else { # should never happen..
		croak "\nInvalid errmode! Defaulting to croak\n$errmsg";
	}
}


sub _call_poll_method { # Call object's poll method and optionally alter and then restore its error mode in doing so
	my ($self, $errmode) = @_;
	my $errmodecache;

	if (defined $errmode) { # Store object's poll errormode and replace it with new error mode
		$errmodecache = $self->{POLL}{errmode};
		$self->{POLL}{errmode} = $errmode;
	}

	# Call object's poll method
	my $ok = $self->{POLL}{coderef}->($self);

	# Restore original object poll error mode if necessary
	$self->{POLL}{errmode} = $errmodecache if defined $errmode;
	return $ok;
}


1;
__END__;


######################## User Documentation ##########################
## To format the following documentation into a more readable format,
## use one of these programs: perldoc; pod2man; pod2html; pod2text.

=head1 NAME

Control::CLI - Command Line Interface I/O over either Telnet or SSH (IPv4 & IPv6) or Serial port

=head1 SYNOPSIS

=head2 Telnet access

	use Control::CLI;
	# Create the object instance for Telnet
	$cli = new Control::CLI('TELNET');
	# Connect to host
	$cli->connect('hostname');
	# Perform login
	$cli->login(	Username	=> $username,
			Password	=> $password,
		   );
	# Send a command and read the resulting output
	$output = $cli->cmd("command");
	print $output;
	$cli->disconnect;

=head2 SSH access

	use Control::CLI;
	# Create the object instance for SSH
	$cli = new Control::CLI('SSH');
	# Connect to host - Note that with SSH,
	#  authentication is normally part of the connection process
	$cli->connect(	Host		=> 'hostname',
			Username	=> $username,
			Password	=> $password,
			PublicKey	=> '.ssh/id_dsa.pub',
			PrivateKey	=> '.ssh/id_dsa',
			Passphrase	=> $passphrase,
		     );
	# In some rare cases, may need to use login
	#  if remote device accepted an SSH connection without any authentication
	#  and expects an interactive login/password authentication
	$cli->login(Password => $password);
	# Send a command and read the resulting output
	$output = $cli->cmd("command");
	print $output;
	$cli->disconnect;

=head2 Serial port access

	use Control::CLI;
	# Create the object instance for Serial port e.g. /dev/ttyS0 or COM1
	$cli = new Control::CLI('/dev/ttyS0');
	# Connect to host
	$cli->connect(	BaudRate	=> 9600,
			Parity		=> 'none',
			DataBits	=> 8,
			StopBits	=> 1,
			Handshake	=> 'none',
		     );
	# Send some character sequence to wake up the other end, e.g. a carriage return
	$cli->print;
	# Perform login
	$cli->login(	Username	=> $username,
			Password	=> $password,
		   );
	# Send a command and read the resulting output
	$output = $cli->cmd("command");
	print $output;
	$cli->disconnect;

=head2 Driving multiple Telnet/SSH connections simultaneously in non-blocking mode

	use Control::CLI qw(poll);			# Export class poll method
	# Create all the object instances
	foreach my $host (@DeviceIPs) {
		$cli{$host} = new Control::CLI(
			Use		=> 'SSH',	# or TELNET (or lots of serial ports!)
			Blocking	=> 0,		# Use non-blocking mode
	}

	print "Connecting to multiple hosts ";
	foreach my $host (@DeviceIPs) {
		$cli{$host}->connect(
			Host		=>	$host,
			Username	=>	$username,
			Password	=>	$password,
		);
	}
	poll(	# Poll all objects for completion of connect
		Object_list	=>	\%cli,
		Poll_code	=>	sub { local $| = 1; print '.' },
	);
	print " done!\n";

	print "Logging in to multiple hosts ";
	foreach my $host (@DeviceIPs) {
		$cli{$host}->login(
			Username	=>	$username,
			Password	=>	$password,
		);
	}
	poll(	# Poll all objects for completion of login
		Object_list	=>	\%cli,
		Poll_code	=>	sub { local $| = 1; print '.' },
	);
	print " done!\n";

	print "Sending same command to multiple hosts ";
	foreach my $host (@DeviceIPs) {
		$cli{$host}->cmd($cmd);
	}
	poll(	# Poll all objects for completion of cmd
		Object_list	=>	\%cli,
		Poll_code	=>	sub { local $| = 1; print '.' },
	);
	print " done!\n";

	# Disconnect from all hosts
	foreach my $host (@DeviceIPs) {
		$cli{$host}->disconnect;
	}


=head1 DESCRIPTION

A Command Line Interface (CLI) is an interface where the user is presented with a command prompt and has to enter ASCII commands to drive or control or configure that device.
That interface could be the shell on a unix system or some other command interpreter on a device such as an ethernet switch or an IP router or some kind of security appliance.

Control::CLI allows CLI connections to be made over any of Telnet, SSH or Serial port.
Connection and basic I/O can be performed in a consistent manner regardless of the underlying connection type thus allowing CLI based scripts to be easily converted between or operate over any of Telnet, SSH or Serial port connection.
Control::CLI relies on these underlying modules:

=over 2

=item *

Net::Telnet for Telnet access

=item *

Net::SSH2 for SSH access

=item *

IO::Socket::IP for IPv6 support

=item *

Win32::SerialPort or Device::SerialPort for Serial port access respectively on Windows and Unix systems

=back

Since all of the above are Perl standalone modules (which do not rely on external binaries) scripts using Control::CLI can easily be ported to any OS platform (where either Perl is installed or by simply packaging the Perl script into an executable with PAR::Packer's pp). In particular this is a big advantage for portability to Windows platforms where using Expect scripts is usually not possible.

All the above modules are optional, however if one of the modules is missing then no access of that type will be available.
For instance if Win32::SerialPort is not installed (on a Windows system) but both Net::Telnet and Net::SSH2 are, then Control::CLI will be able to operate over both Telnet and SSH, but not Serial port. There has to be, however, at least one of the Telnet/SSH/SerialPort modules installed, otherwise Control::CLI's constructor will throw an error.

Net::Telnet and Net::SSH2 both natively use IO::Socket::INET which only provides IPv4 support; if however IO::Socket::IP is installed, this class will use it as a drop in replacement to IO::Socket::INET and allow both Telnet and SSH connections to operate over IPv6 as well as IPv4.

Net::SSH2 only supports SSHv2 and this class will always and only use Net::SSH2 to establish a channel over which an interactive shell is established with the remote host. Authentication methods supported are 'publickey', 'password' and 'keyboard-interactive'.

As of version 2.00, this module offers non-blocking capability on all of its methods (in the case of connect method, IO::Socket::IP is required). Scripts using this class can now drive multiple hosts simultaneusly without resorting to Perl threads. See the non-blocking example section at the end.

In the syntax layout below, square brackets B<[]> represent optional parameters.
All Control::CLI method arguments are case insensitive.




=head1 OBJECT CONSTRUCTOR

Used to create an object instance of Control::CLI

=over 4

=item B<new()> - create a new Control::CLI object

  $obj = new Control::CLI ('TELNET'|'SSH'|'<COM_port_name>');

  $obj = new Control::CLI (
  	Use			 => 'TELNET'|'SSH'|'<COM_port_name>',
  	[Timeout		 => $secs,]
  	[Connection_timeout	 => $secs,]
  	[Errmode		 => $errmode,]
  	[Return_reference	 => $flag,]
  	[Prompt			 => $prompt,]
  	[Username_prompt	 => $usernamePrompt,]
  	[Password_prompt	 => $passwordPrompt,]
  	[Input_log		 => $fhOrFilename,]
  	[Output_log		 => $fhOrFilename,]
  	[Dump_log		 => $fhOrFilename,]
  	[Blocking		 => $flag,]
  	[Prompt_credentials	 => $flag,]
  	[Read_attempts		 => $numberOfReadAttemps,]
  	[Readwait_timer		 => $millisecs,]
  	[Read_block_size	 => $bytes,]
  	[Output_record_separator => $ors,]
  	[Debug			 => $debugFlag,]
  );

This is the constructor for Control::CLI objects. A new object is returned on success. On failure the error mode action defined by "errmode" argument is performed. If the "errmode" argument is not specified the default is to croak. See errmode() for a description of valid settings.
The first parameter, or "use" argument, is required and should take value either "TELNET" or "SSH" (case insensitive) or the name of the Serial port such as "COM1" or "/dev/ttyS0". In the second form, the other arguments are optional and are just shortcuts to methods of the same name.

=back




=head1 OBJECT METHODS

Methods which can be run on a previously created Control::CLI object instance



=head2 Main I/O Object Methods

=over 4

=item B<connect() & connect_poll()> - connect to host

  $ok = $obj->connect($host [$port]);

  $ok = $obj->connect($host[:$port]); # Deprecated

  $ok = $obj->connect(
  	[Host			=> $host,]
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[PublicKey		=> $publicKey,]
  	[PrivateKey		=> $privateKey,]
  	[Passphrase		=> $passphrase,]
  	[Prompt_credentials	=> $flag,]
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Connection_timeout	=> $secs,]
  	[Blocking		=> $flag,]
  	[Errmode		=> $errmode,]
  );

  $ok = $obj->connect_poll();	# Only applicable in non-blocking mode

This method connects to the host device. The connection will use either Telnet, SSH or Serial port, depending on how the object was created with the new() constructor.
On success a true (1) value is returned.
In non-blocking mode (blocking disabled) the connect() method will immediately return with a false, but defined, value of 0. You will then need to call the connect_poll() method at regular intervals until it returns a true (1) value indicating that the connection is complete. Note that for this method to work in non-blocking mode IO::Socket::IP needs to be installed (IO::Socket:INET will always produce a blocking connection call).
On connection timeout or other connection failures the error mode action is performed. See errmode().
The deprecated shorthand syntax is still accepted but it will not work if $host is an IPv6 address.
The optional "errmode", "connection_timeout" and "blocking" arguments are provided to override the global setting of the corresponding object parameter.
When a "connection_timeout" is defined, this will be used to enforce a connection timeout for Telnet and SSH TCP socket connections.
Which arguments are used depends on the whether the object was created for Telnet, SSH or Serial port. The "host" argument is required by both Telnet and SSH. The other arguments are optional.

=over 4

=item *

For Telnet, these forms are allowed with the following arguments:

  $ok = $obj->connect($host [$port]);

  $ok = $obj->connect($host[:$port]); # Deprecated

  $ok = $obj->connect(
  	Host			=> $host,
  	[Port			=> $port,]
  	[Connection_timeout	=> $secs,]
  	[Blocking		=> $flag,]
  	[Errmode		=> $errmode,]
  );

If not specified, the default port number for Telnet is 23

=item *

For SSH, these forms are allowed with the following arguments:

  $ok = $obj->connect($host [$port]);

  $ok = $obj->connect($host[:$port]); # Deprecated

  $ok = $obj->connect(
  	Host			=> $host,
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[PublicKey		=> $publicKey,]
  	[PrivateKey		=> $privateKey,]
  	[Passphrase		=> $passphrase,]
  	[Prompt_credentials	=> $flag,]
  	[Connection_timeout	=> $secs,]
  	[Blocking		=> $flag,]
  	[Errmode		=> $errmode,]
  );

If not specified, the default port number for SSH is 22.
A username must always be provided for all SSH connections. If not provided and prompt_credentials is true then this method will prompt for it.
Once the SSH connection is established, this method will attempt one of two possible authentication types, based on the accepted authentications of the remote host:

=over 4

=item *

B<Publickey authentication> : If the remote host accepts it and the method was supplied with public/private keys. The public/private keys need to be in OpenSSH format. If the private key is protected by a passphrase then this must also be provided or, if prompt_credentials is true, this method will prompt for the passphrase. If publickey authentication fails for any reason and password authentication is possible, then password authentication is attempted next; otherwise the error mode action is performed. See errmode().

=item *

B<Password authentication> : If the remote host accepts either 'password' or 'keyboard-interactive' authentication methods. A password must be provided or, if prompt_credentials is true, this method will prompt for the password. If password authentication fails for any reason the error mode action is performed. See errmode(). The SSH 'keyboard-interactive' authentication method is supported to match the functionality of 'password' authentication on hosts where the latter is not accepted. Use of either of these SSH authentication methods (which both ultimately provide username & password credentials to the SSH server) remains completely transparent to the code using this class.

=back

There are some devices, with a crude SSH implementation, which will accept an SSH connection without any SSH authentication, and then perform an interactive login, like Telnet does. In this case, the connect() method, will not perform any SSH authentication and will return success after simply bringing up the SSH connection; but in this case you will most likely have to complete the login authentication by calling the login() method as you would do with Telnet and Serial port connections.

The optional "prompt_credentials" argument is provided to override the global setting of the parameter by the same name which is by default false. See prompt_credentials().

=item *

For Serial port, these arguments are used:

  $ok = $obj->connect(
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Blocking		=> $flag,]	# Ignored
  	[Errmode		=> $errmode,]
  );

If arguments are not specified, the defaults are: Baud Rate = 9600, Data Bits = 8, Parity = none, Stop Bits = 1, Handshake = none.
Allowed values for these arguments are the same allowed by underlying Win32::SerialPort / Device::SerialPort:

=over 4

=item *

B<Baud Rate> : Any legal value

=item *

B<Parity> : One of the following: "none", "odd", "even", "mark", "space"

=item *

B<Data Bits> : An integer from 5 to 8

=item *

B<Stop Bits> : Legal values are 1, 1.5, and 2. But 1.5 only works with 5 databits, 2 does not work with 5 databits, and other combinations may not work on all hardware if parity is also used

=item *

B<Handshake> : One of the following: "none", "rts", "xoff", "dtr"

=back

Remember that when connecting over the serial port, the device at the far end is not necessarily alerted that the connection is established. So it might be necessary to send some character sequence (usually a carriage return) over the serial connection to wake up the far end. This can be achieved with a simple print() immediately after connect().

=back


If using the connect() method in non-blocking mode, the following example illustrates how this works:

	$ok = $obj->connect(Host => $ip-address, Blocking => 0);
	until ($ok) { # This loop will be executed while $ok = 0
		
		<do other stuff here..>
	
		$ok = $obj->connect_poll;
	}

Or, if you have set an error mode action of 'return':

	$ok = $obj->connect(Host => $ip-address, Blocking => 0, Errmode => 'return');
	die $obj->errmsg unless defined $ok;	# Error connecting
	until ($ok) { # This loop will be executed while $ok = 0
		
		<do other stuff here..>
	
		$ok = $obj->connect_poll;
		die $obj->errmsg unless defined $ok;	# Error or timeout connecting
	}

Some considerations on using connect() in non-blocking mode:

=over 4

=item *

There is no delay in establishing a serial port connection, so setting non-blocking mode has no effect on serial port connections and the connection will be established after the first call to connect()

=item *

For Telnet and SSH connections, if you provided $host as a hostname which needs to resolve via DNS, the DNS lookup will still be blocking. You will either need to supply $host as a direct IP addresses or else write your own non-blocking DNS lookup code (an example is offered in the IO::Socket::IP documentation & examples)

=item *

For SSH connections, only the TCP socket connection is treated in a true non-blocking fashion. SSH authentication will call Net::SSH2's auth_list(), auth_publickey() and/or auth_password() or auth_keyboard() which all behave in a blocking fashion; to alleviate this the connect() method will return between each of those SSH authentication steps

=back


=item B<read()> - read block of data from object

  $data || $dataref = $obj->read(
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

This method reads a block of data from the object. If blocking is enabled - see blocking() - and no data is available, then the read method will wait for data until expiry of timeout - see timeout() -, then will perform the error mode action. See errmode(). If blocking is disabled and no data is available then the read method will return immediately (in this case the timeout and errmode arguments are not applicable).

In blocking mode, if no error or timeout, this method will always return a defined non-empty string.

In non-blocking mode, if no error and nothing was read, this method will always return a defined empty string.

In case of an error, and the error mode is 'return', this method will always return an undefined value.

The optional arguments are provided to override the global setting of the parameters by the same name for the duration of this method. Note that setting these arguments does not alter the global setting for the object. See also timeout(), blocking(), errmode(), return_reference().
Returns either a hard reference to any data read or the data itself, depending on the applicable setting of "return_reference". See return_reference().


=item B<readwait()> - read in data initially in blocking mode, then perform subsequent non-blocking reads for more

  $data || $dataref = $obj->readwait(
  	[Read_attempts		=> $numberOfReadAttemps,]
  	[Readwait_timer		=> $millisecs,]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

If blocking is enabled - see blocking() - this method implements an initial blocking read followed by a number of non-blocking reads. The intention is that we expect to receive at least some data and then we wait a little longer to make sure we have all the data. This is useful when the input data stream has been fragmented into multiple packets; in this case the normal read() method (in blocking mode) will immediately return once the data from the first packet is received, while the readwait() method will return once all packets have been received. 
For the initial blocking read, if no data is available, the method will wait until expiry of timeout. If a timeout occurs, then the error mode action is performed as with the regular read() method in blocking mode. See errmode().
If blocking is disabled then no initial blocking read is performed, instead the method will move directly to the non-blocking reads (in this case the "timeout" and "errmode" arguments are not applicable).
Once some data has been read or blocking is disabled, then the method will perform a number of non-blocking reads at certain time intervals to ensure that any subsequent data is also read before returning.
The time interval is by default 100 milliseconds and can be either set via the readwait_timer() method or by specifying the optional "readwait_timer" argument which will override whatever value is globally set for the object. See readwait_timer().
The number of non-blocking reads is dependent on whether more data is received or not but a certain number of consecutive reads with no more data received will make the method return. By default that number is 5 and can be either set via the read_attempts() method or by specifying the optional "read_attempts" argument which will override whatever value is globally set for the object. See read_attempts().
Therefore note that this method will always introduce a delay of "readwait_timer" milliseconds times the value of "read_attempts" and faster response times can be obtained using the regular read() method.
Returns either a hard reference to data read or the data itself, depending on the applicable setting of return_reference. See return_reference().

In blocking mode, if no error or timeout, this method will always return a defined non-empty string.

In non-blocking mode, if no error and nothing was read, this method will always return a defined empty string.

In case of an error, and the error mode is 'return', this method will always return an undefined value.

The optional arguments are provided to override the global setting of the parameters by the same name for the duration of this method. Note that setting these arguments does not alter the global setting for the object. See also read_attempts(), timeout(), errmode(), return_reference().


=item B<waitfor() & waitfor_poll()> - wait for pattern in the input stream

Backward compatble syntax:

  $data || $dataref = $obj->waitfor($matchpat);

  ($data || $dataref, $match || $matchref) = $obj->waitfor($matchpat);

  $data || $dataref = $obj->waitfor(
  	[Match			=> $matchpattern1,
  	 [Match			=> $matchpattern2,
  	  [Match		=> $matchpattern3,
  	    ... ]]]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

  ($data || $dataref, $match || $matchref) = $obj->waitfor(
  	[Match			=> $matchpattern1,
  	 [Match			=> $matchpattern2,
  	  [Match		=> $matchpattern3,
  	    ... ]]]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

New syntax (for non-blocking use):

  $ok = $obj->waitfor(
	Poll_syntax		=> 1,
  	[Match			=> $matchpattern1,
  	 [Match			=> $matchpattern2,
  	  [Match		=> $matchpattern3,
  	    ... ]]]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

  ($ok, $data || $dataref, $match) = $obj->waitfor(
	Poll_syntax		=> 1,
  	[Match			=> $matchpattern1,
  	 [Match			=> $matchpattern2,
  	  [Match		=> $matchpattern3,
  	    ... ]]]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

Polling method (only applicable in non-blocking mode):

  $ok = $obj->waitfor_poll();

  ($ok, $data || $dataref, $match) = $obj->waitfor_poll();

This method reads until a pattern match or string is found in the input stream, or will timeout if no further data can be read.
For backwards compatibility this method preserves the original syntax from Net::Telnet (as well as in versions prior to 2.00 of this class) where in scalar context returns any data read up to but excluding the matched string, while list context returns the same data read as well as the actual string which was matched.
With the new syntax, in scalar context returns the poll status while in list context the poll status is returned together with the data read up to but excluding the matched string and actual string which was matched; in non-blocking mode the latter 2 will most likely be undefined and will need to be recovered by subsequent calling of waitfor_poll() method. To use the new syntax on the waitfor() method, the 'poll_syntax' argument needs to be set to 1; the waitfor_poll() method only uses the new syntax.
On timeout or other failure the error mode action is performed. See errmode().
In the first two forms a single pattern match string can be provided; in the other forms any number of pattern match strings can be provided and the method will wait until a match is found against any of those patterns. In both cases the pattern match can be a simple string or any valid perl regular expression match string (in the latter case use single quotes when building the string).
The optional arguments are provided to override the global setting of the parameters by the same name for the duration of this method. Note that setting these arguments does not alter the global setting for the object. See also timeout(), errmode(), return_reference().
Returns either hard reference or the data itself, depending on the applicable setting of return_reference. See return_reference(). In the legacy syntax this applied to both $data and $match strings. In the new poll sysntax this now only applies to the $data output while the $match string is always returned as a scalar.
This method is similar (but not identical) to the method of the same name provided in Net::Telnet.

In non-blocking mode (blocking disabled) the waitfor() method will most likely immediately return with a false, but defined, value of 0. You will then need to call the waitfor_poll() method at regular intervals until it returns a true (1) value indicating that the match pattern has been hit. The following example illustrates:

	$ok = $obj->waitfor(Poll_syntax => 1, Match => "seeked regex patterns", Blocking => 0);
	until ($ok) { # This loop will be executed while $ok = 0
		
		<do other stuff here..>
	
		$ok = $obj->waitfor_poll;
	}
	print "Output data up to but excluding match string:", ($obj->waitfor_poll)[1];
	print "Matched string:", ($obj->waitfor_poll)[2];
	# In this order, otherwise output [1] would get flushed while reading just [2]


=item B<put()> - write data to object

  $ok = $obj->put($string);

  $ok = $obj->put(
  	String			=> $string,
  	[Errmode		=> $errmode,]
  );

This method writes $string to the object and returns a true (1) value if all data was successfully written.
On failure the error mode action is performed. See errmode().
This method is like print($string) except that no trailing character (usually a newline "\n") is appended.


=item B<print()> - write data to object with trailing output_record_separator

  $ok = $obj->print($line);

  $ok = $obj->print(
  	[Line			=> $line,]
  	[Errmode		=> $errmode,]
  );

This method writes $line to the object followed by the output record separator which is usually a newline "\n" - see output_record_separator() -  and returns a true (1) value if all data was successfully written. If the method is called with no $line string then only the output record separator is sent.
On failure the error mode action is performed. See errmode().
To avoid printing a trailing "\n" use put() instead.


=item B<printlist()> - write multiple lines to object each with trailing output_record_separator

  $ok = $obj->printlist(@list);

This method writes every element of @list to the object followed by the output record separator which is usually a newline "\n" - see output_record_separator() -  and returns a true (1) value if all data was successfully written.
On failure the error mode action is performed. See errmode().

Note that most devices have a limited input buffer and if you try and send too many commands in this manner you risk losing some of them at the far end. It is safer to send commands one at a time using the cmd() method which will acknowledge each command as cmd() waits for a prompt after each command.


=item B<login() & login_poll()> - handle login for Telnet / Serial port 

  $ok = $obj->login(
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Prompt			=> $prompt,]
  	[Username_prompt	=> $usernamePrompt,]
  	[Password_prompt	=> $passwordPrompt,]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Errmode		=> $errmode,]
  );

  ($ok, $output || $outputRef) = $obj->login(
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Prompt			=> $prompt,]
  	[Username_prompt	=> $usernamePrompt,]
  	[Password_prompt	=> $passwordPrompt,]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

Polling method (only applicable in non-blocking mode):

  $ok = $obj->login_poll();

  ($ok, $output || $outputRef) = $obj->login_poll();


This method handles login authentication for Telnet and Serial port access on a generic host.
If a login/username prompt is seen, the supplied username is sent; if a password prompt is seen, the supplied password is sent; and once a valid CLI prompt is seen this method completes and returns a true (1) value.
This method is usually not required for SSH, where authentication is part of the connection process, however there are some devices where the SSH connection is allowed without any SSH authentication and you might then need to handle an interactive authentication in the SSH channel data stream, in which case you would use login() also for SSH and only the password needs to be supplied as the username will have already have been supplied, and cached, in connect(). In any case calling login() on an SSH connection will allow the script to lock onto the very first CLI prompt received from the host.
In the first form only a success/failure value is returned in scalar context, while in the second form, in list context, both the success/failure value is returned as well as any output received from the host device during the login sequence; the latter is either the output itself or a reference to that output, depending on the object setting of return_reference or the argument override provided in this method.
For this method to succeed the username & password prompts from the remote host must match the default prompts defined for the object or the overrides specified via the optional "username_prompt" & "password_prompt" arguments. By default these regular expressions are set to:

	'(?i:username|login)[: ]+$'
	'(?i)password[: ]+$'

Following a successful authentication, if a valid CLI prompt is received, the method will return a true (1) value. The expected CLI prompt is either the globally set prompt - see prompt() - or the local override specified with the optional "prompt" argument. By default, the following prompt is expected:

	'.*[\?\$%#>]\s?$'

In non-blocking mode (blocking disabled) the login() method will most likely immediately return with a false, but defined, value of 0. You will then need to call the login_poll() method at regular intervals until it returns a true (1) value indicating that the login is complete.
On timeout or failure or if the remote host prompts for the username a second time (the method assumes that the credentials provided were invalid) then the error mode action is performed. See errmode().
If username/password are not provided but are required and prompt_credentials is true, the method will automatically prompt the user for them interactively; otherwise the error mode action is performed.
The optional "prompt_credentials" argument is provided to override the global setting of the parameter by the same name which is by default false. See prompt_credentials().

If using the login() method in non-blocking mode, the following examples illustrate how this works:

=over 4

=item *

If you do not care to retrieve the login sequence output:

	$ok = $obj->login(Username => "admin", Password => "pwd", Blocking => 0);
	until ($ok) { # This loop will be executed while $ok = 0
		
		<do other stuff here..>
	
		$ok = $obj->login_poll;
	}

=item *

If you want to retrieve the login output sequence along the way (even in case of error/timeout):

	($ok, $output) = $obj->login(Username => "admin", Password => "pwd", Blocking => 0, Errmode => 'return');
	die $obj->errmsg unless defined $ok;	# Login failed
	until ($ok) {
		
		<do other stuff here..>
	
		($ok, $partialOutput) = $obj->login_poll;
		die $obj->errmsg unless defined $ok;	# Login failed or timeout
		$output .= $partialOutput;
	}
	print "Complete login sequence output:\n", $output;

=item *

If you only want to retrieve the full login sequence output at the end:
	
	$ok = $obj->login(Username => "admin", Password => "pwd", Blocking => 0);
	until ($ok) {
		
		<do other stuff here..>
	
		$ok = $obj->login_poll;
	}
	print "Complete login sequence output:\n", ($obj->login_poll)[1];

=back


=item B<cmd() & cmd_poll()> - Sends a CLI command to host and returns output data

Backward compatible syntax:

  $output || $outputRef = $obj->cmd($cliCommand);

  $output || $outputRef = $obj->cmd(
  	[Command		=> $cliCommand,]
  	[Prompt			=> $prompt,]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

New syntax (for non-blocking use):

  $ok = $obj->cmd(
	Poll_syntax		=> 1,
  	[Command		=> $cliCommand,]
  	[Prompt			=> $prompt,]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Errmode		=> $errmode,]
  );

  ($ok, $output || $outputRef) = $obj->cmd($cliCommand);

  ($ok, $output || $outputRef) = $obj->cmd(
	[Poll_syntax		=> 1,]
  	[Command		=> $cliCommand,]
  	[Prompt			=> $prompt,]
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

Polling method (only applicable in non-blocking mode):

  $ok = $obj->cmd_poll();

  ($ok, $output || $outputRef) = $obj->cmd_poll();

This method sends a CLI command to the host and returns once a new CLI prompt is received from the host. The output record separator - which is usually a newline "\n"; see output_record_separator() - is automatically appended to the command string. If no command string is provided then this method will simply send the output record separator and expect a new prompt back.
Before sending the command to the host, any pending input data from host is read and flushed.
The CLI prompt expected by the cmd() method is either the prompt defined for the object - see prompt() - or the override defined using the optional "prompt" argument.
For backwards compatibility, in scalar context the output data from the command is returned.
The new syntax, in scalar context returns the poll status, while in list context, both the poll status together with the output data are returned. Note that to disambiguate the new scalar context syntax the 'poll_syntax' argument needs to be set (while this is not strictly necessary in list context).
In non-blocking mode, the poll status will most likely immediately return with a false, but defined, value of 0. You will then need to call the cmd_poll() method at regular intervals until it returns a true (1) value indicating that the command has completed.

The output data returned is either a hard reference to the output or the output itself, depending on the setting of return_reference; see return_reference().
The echoed command is automatically stripped from the output as well as the terminating CLI prompt (the last prompt received from the host device can be obtained with the last_prompt() method).
This means that when sending a command which generates no output, either a null string or a reference pointing to a null string will be returned.
On I/O failure to the host device, the error mode action is performed. See errmode().
If output is no longer received from the host and no valid CLI prompt has been seen, the method will timeout - see timeout() - and will then perform the error mode action.
The cmd() method is equivalent to the following combined methods:

	$obj->read(Blocking => 0);
	$obj->print($cliCommand);
	$output = $obj->waitfor($obj->prompt);

In non-blocking mode (blocking disabled) the cmd() method will most likely immediately return with a false, but defined, value of 0. You will then need to call the cmd_poll() method at regular intervals until it returns a true (1) value indicating that the command is complete. The following example illustrates:

=over 4

=item *

If you do not care to retrieve any output from the command:

	$ok = $obj->cmd(Command => "set command", Blocking => 0);
	until ($ok) { # This loop will be executed while $ok = 0
		
		<do other stuff here..>
	
		$ok = $obj->cmd_poll;
	}

=item *

If you want to retrieve the command output sequence along the way:

	($ok, $output) = $obj->cmd(Command => "show command", Blocking => 0, Errmode => 'return');
	die $obj->errmsg unless defined $ok;	# Login failed
	until ($ok) {
		
		<do other stuff here..>
	
		($ok, $partialOutput) = $obj->cmd_poll;
		die $obj->errmsg unless defined $ok;	# Login failed or timeout
		$output .= $partialOutput;
	}
	print "Complete command output:\n", $output;

Note that $partialOutput returned will always terminate at output line boundaries (i.e. you can be sure that the last line is complete and not a fragment waiting for more output from device) so the output can be safely parsed for any seeked informaton.

=item *

If you only want to retrieve the command output at the end:
	
	$ok = $obj->cmd(Command => "show command", Blocking => 0);
	until ($ok) {
		
		<do other stuff here..>
	
		$ok = $obj->cmd_poll;
	}
	print "Complete command output:\n", ($obj->cmd_poll)[1];

=back


=item B<change_baudrate()> - Change baud rate or other serial port parameter on current serial connection

  $ok = $obj->change_baudrate($baudRate);

  $ok = $obj->change_baudrate(
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Errmode		=> $errmode,]
  );

This method is only applicable to an already established Serial port connection and will return an error if the connection type is Telnet or SSH or if the object type is for Serial but no connection is yet established.
The serial connection is restarted with the new baudrate (in the background, the serial connection is actually disconnected and then re-connected) without losing the current CLI session. As well as (or instead of) the baudrate, any of Parity, Databits, Stopbits or Handshake can also be changed for the active connection at the same time.
If there is a problem restarting the serial port connection with the new settings then the error mode action is performed - see errmode().
If the baudrate (or other parameter) was successfully changed a true (1) value is returned.
Note that you have to change the baudrate on the far end device before calling this method to change the connection's baudrate. Follows an example:

	use Control::CLI;
	# Create the object instance for Serial port
	$cli = new Control::CLI('COM1');
	# Connect to host at default baudrate
	$cli->connect( BaudRate => 9600 );
	# Send some character sequence to wake up the other end, e.g. a carriage return
	$cli->print;
	# Set the new baudrate on the far end device
	# NOTE use print as you won't be able to read the prompt at the new baudrate right now
	$cli->print("term speed 38400");
	# Now change baudrate for the connection
	$cli->change_baudrate(38400);
	# Send a carriage return and expect to get a new prompt back
	$cli->cmd; #If no prompt is seen at the new baudrate, we will timeout here
	# Send a command and read the resulting output
	$outref = $cli->cmd("command which generates lots of output...");
	print $$outerf;
	# Restore baudrate before disconnecting
	$cli->print("term speed 9600");
	# Safe to wait a little, to give time to host to process command before disconnecting
	sleep 1;

	$cli->disconnect;


=item B<input_log()> - log all input sent to host

  $fh = $obj->input_log;

  $fh = $obj->input_log($fh);

  $fh = $obj->input_log($filename);

This method starts or stops logging of all input received from host (e.g. via any of read(), readwait(), waitfor(), cmd(), login() methods).
This is useful when debugging. Because most command interpreters echo back commands received, it's likely all output sent to the host will also appear in the input log. See also output_log().
If no argument is given, the log filehandle is returned. An empty string indicates logging is off. If an open filehandle is given, it is used for logging and returned. Otherwise, the argument is assumed to be the name of a file, the file is opened for logging and a filehandle to it is returned. If the file can't be opened for writing, the error mode action is performed.
To stop logging, use an empty string as the argument.


=item B<output_log()> - log all output received from host

  $fh = $obj->output_log;

  $fh = $obj->output_log($fh);

  $fh = $obj->output_log($filename);

This method starts or stops logging of output sent to host (e.g. via any of put(), print(), printlist(), cmd(), login() methods).
This is useful when debugging.
If no argument is given, the log filehandle is returned. An empty string indicates logging is off. If an open filehandle is given, it is used for logging and returned. Otherwise, the argument is assumed to be the name of a file, the file is opened for logging and a filehandle to it is returned. If the file can't be opened for writing, the error mode action is performed.
To stop logging, use an empty string as the argument.


=item B<dump_log()> - log hex and ascii for both input and output stream

  $fh = $obj->dump_log;

  $fh = $obj->dump_log($fh);

  $fh = $obj->dump_log($filename);

This method starts or stops logging of both input and output. The information is displayed both as a hex dump as well as in printable ascii. This is useful when debugging.
If no argument is given, the log filehandle is returned. An empty string indicates logging is off. If an open filehandle is given, it is used for logging and returned. Otherwise, the argument is assumed to be the name of a file, the file is opened for logging and a filehandle to it is returned. If the file can't be opened for writing, the error mode action is performed.
To stop logging, use an empty string as the argument.


=item B<eof> - end-of-file indicator

  $eof = $obj->eof;

This method returns a true (1) value if the end of file has been read. When this is true, the general idea is that you can still read but you won't be able to write.
This method simply exposes the method by the same name provided by Net::Telnet.
Net::SSH2::Channel also has an eof method but this was not working properly (always returns 0) at the time of implementing the Control::CLI::eof method; so this method adds some logic to eof for SSH connections: if the SSH eof method returns 1, then that value is returned, otherwise a check is performed on Net::SSH::error and if this returns either LIBSSH2_ERROR_SOCKET_NONE or LIBSSH2_ERROR_SOCKET_RECV then we return an eof of 1; otherwise we return an eof of 0.
In the case of a serial connection this module simply returns eof true before a connection is established and after the connection is closed or breaks.


=item B<break()> - send the break signal

  $ok = $obj->break([$millisecs]);

This method generates the break signal on the underlying connection. The break signal is outside the ASCII character set but has local meaning on some end systems.
The $millisecs argument, if provided, is only used over Serial connections and is ignored for Telnet and SSH.
Over a Serial connection this method calls the underlying pulse_break_on($millisecs) method and if $millisecs argument is not specified the duration timer is set to 300ms which is the most commonly used duration for signalling a break signal. Over a Telnet connection this method simply uses the method by the same name provided by Net::Telnet. Over an SSH connection this method sends '~B' over the open channel though it is not clear whether Net::SSH2 or the libssh2 libraries actually support this; it is hoped that the receiving end accepts this as a break signal.  


=item B<disconnect> - disconnect from host

  $ok = $obj->disconnect;

This method closes the connection. Always returns true.


=item B<close> - disconnect from host

  $ok = $obj->close;

This method closes the connection. It is an alias to disconnect() method. Always returns true.


=item B<poll> - poll object(s) for completion

  $ok = $obj->poll(
  	[Poll_code		=> $codeRef,]
  	[Poll_timer		=> $millisecs,]
  	[Errmode		=> $errmode,]
  );

  $running = Control::CLI::poll(\%hash_of_objects | \%array_of_objects);

  ($running, $completed, $failed, \@lastCompleted, \@lastFailed) = Control::CLI::poll(\%hash_of_objects | \%array_of_objects);

  $running = Control::CLI::poll(
  	Object_list		=> \%hash_of_objects | \%array_of_objects,
  	[Poll_code		=> $codeRef,]
  	[Object_complete	=> 'all' | 'next',]
  	[Object_error		=> 'return' | 'ignore',]
  	[Poll_timer		=> $millisecs,]
  	[Errmode		=> $errmode,]
  );

  ($running, $completed, $failed, \@lastCompleted, \@lastFailed) = Control::CLI::poll(
  	Object_list		=> \%hash_of_objects | \%array_of_objects,
  	[Poll_code		=> $codeRef,]
  	[Object_complete	=> 'all' | 'next',]
  	[Object_error		=> 'return' | 'ignore',]
  	[Poll_timer		=> $millisecs,]
  	[Errmode		=> $errmode,]
  );


This is a convenience method to help polling one or more Control::CLI (or inherited) objects for completion.
In the first form this method can be called as an object method, alas it will report back the poll status of that single object. The $ok status reported will be either true (1) if the current polled method for the object has comleted, or undef if it failed with an error (and the errmode was set to 'return'). The advantage of this form is that the same poll() method can be used instead of the corresponding <methodName>_poll() method for which you would have to build your own polling loop.

In the second form, this method is called as a class method (not an object method) and the 1st argument is either a hash or an array structure holding multiple Control::CLI (or inherited) objects. Now the poll() method will cycle through all the objects and verify their corresponding status. There are multiple ways in which this method can be configured to return:

=over 4

=item *

object_complete = 'all' AND object_error = 'ignore' : Method will only return once all objects have completed whether they completed successfully or failed with an error (and the errmode was set to 'return'); this is the default mode if arguments 'object_complete' and 'object_error' are not specified

=item *

object_complete = 'all' AND object_error = 'return' : Method will only return once all objects have completed successfully or as soon as one of the objects fails with an error (and the errmode was set to 'return')

=item *

object_complete = 'next' AND object_error = 'ignore' : Method will return as soon as one (or some) of the objects has/have completed successfully; the method will not return if an object fails with an error (and the errmode was set to 'return')

=item *

object_complete = 'next' AND object_error = 'return' : Method will return as soon as one (or some) of the objects has/have completed successfully or failed with an error (and the errmode was set to 'return')

=back

When the method returns it will provide the number of objects still running ($running), those that have completed successfully ($completed) and those that have failed with an error ($failed) as well as an array reference of last objects that completed (\@lastCompleted) and one of last objects that failed (\@lastFailed). If the poll method was called with a hash structure, these arrays will hold the keys which completed/failed; if instead a list of objects was supplied then these arrays will hold the indexes which completed/failed.

By default the polling is done every 100 millisecs against all objects. A different timer can be used by specifying the poll_timer argument.
If a code reference is provided via the 'poll_code' argument, that code will be called at every polling cycle with arguments ($running, $completed, $failed, \@lastCompleted, \@lastFailed); you may use this to print out some form of activity indication (e.g. print dots). Examples on how to use this method can be found in the examples directory.

If an error mode is set using the 'errmode' argument, this will be used for errors in the class method (which is not tied to a specific object) but will also be used to override whatever the relevant object error method was, for the duration of the poll() method. If instead no error mode argument is specified then the object(s) will use whatever error mode was set for them (or set when the initial poll capable method was called) while errors in the class method (which is not tied to a specific object) will use the class default error mode of 'croak'.

Note that to call poll, as a class method, without specifying the fully qualified package name, it will need to be expressly imported when loading this module:

	use Control::CLI qw(poll);

=back



=head2 Error Handling Methods

=over 4

=item B<errmode()> - define action to be performed on error/timeout 

  $mode = $obj->errmode;

  $prev = $obj->errmode($mode);

This method gets or sets the action used when errors are encountered using the object. The first calling sequence returns the current error mode. The second calling sequence sets it to $mode and returns the previous mode. Valid values for $mode are 'die', 'croak' (the default), 'return', a $coderef, or an $arrayref.
When mode is 'die' or 'croak' and an error is encountered using the object, then an error message is printed to standard error and the program dies. The difference between 'die' and 'croak' is that 'die' will report the line number in this class while 'croak' will report the line in the calling program using this class.
When mode is 'return' then the method generating the error places an error message in the object and returns an undefined value in a scalar context and an empty list in list context. The error message may be obtained using errmsg(). 
When mode is a $coderef, then when an error is encountered &$coderef is called with the error message as its first argument. Using this mode you may have your own subroutine handle errors. If &$coderef itself returns then the method generating the error returns undefined or an empty list depending on context.
When mode is an $arrayref, the first element of the array must be a &$coderef. Any elements that follow are the arguments to &$coderef. When an error is encountered, the &$coderef is called with its arguments and the error message appended as the last argument. Using this mode you may have your own subroutine handle errors. If the &$coderef itself returns then the method generating the error returns undefined or an empty list depending on context.
A warning is printed to STDERR when attempting to set this attribute to something that's not 'die', 'croak', 'return', a $coderef, or an $arrayref whose first element isn't a $coderef.


=item B<errmsg()> - last generated error message for the object 

  $msg = $obj->errmsg;

  $prev = $obj->errmsg($msg);

The first calling sequence returns the error message associated with the object. If no error has been encountered yet an undefined value is returned. The second calling sequence sets the error message for the object.
Normally, error messages are set internally by a method when an error is encountered.


=item B<error()> - perform the error mode action

  $obj->error($msg);

This method sets the error message via errmsg().
It then performs the error mode action.  See errmode().
If the error mode doesn't cause the program to die/croak, then an undefined value or an empty list is returned depending on the context.

This method is primarily used by this class or a sub-class to perform the user requested action when an error is encountered.


=back



=head2 Methods to set/read Object variables

=over 4

=item B<timeout()> - set I/O time-out interval 

  $secs = $obj->timeout;

  $prev = $obj->timeout($secs);

This method gets or sets the timeout value that's used when reading input from the connected host. This applies to the read() method in blocking mode as well as the readwait(), waitfor(), login() and cmd() methods. When a method doesn't complete within the timeout interval then the error mode action is performed. See errmode().
The default timeout value is 10 secs.


=item B<connection_timeout()> - set Telnet and SSH connection time-out interval 

  $secs = $obj->connection_timeout;

  $prev = $obj->connection_timeout($secs);

This method gets or sets the Telnet and SSH TCP connection timeout value used when the connection is made in connect().
For backwards compatibility with earlier versions of this module, by default no connection timeout is set which results in the following behaviour:

=over 4

=item *

In blocking mode, the underlying OS's TCP connection timeout is used, and this can vary.

=item *

In non-blocking mode, this module enforces the timeout and if no connection-timeout has been defined then a hard coded value of 20 seconds will be used.

=back

To have a consistent behaviour in blocking and non-blocking modes as well as across different underlying OSes, simply set your own connection timeout value, either via this method or from the object constructor.


=item B<read_block_size()> - set read_block_size for either SSH or Serial port 

  $bytes = $obj->read_block_size;

  $prev = $obj->read_block_size($bytes);

This method gets or sets the read_block_size for either SSH or Serial port access (not applicable to Telnet).
This is the read buffer size used on the underlying Net::SSH2 and Win32::SerialPort / Device::SerialPort read() methods.
The default read_block_size is 4096 for SSH, 1024 for Win32::SerialPort and 255 for Device::SerialPort.


=item B<blocking()> - set blocking mode for read methods and polling capable methods

  $flag = $obj->blocking;

  $prev = $obj->blocking($flag);

On the one hand, determines whether the read(), readwait() or waitfor() methods will wait for data to be received (until expiry of timeout) or return immediately if no data is available.
On the other hand determines whether polling capable methods connect(), waitfor(), login() and cmd() operate in non-blocking polling mode or not.
By default blocking is enabled (1). This method also returns the current or previous setting of the blocking mode.
Note that to enable non-blocking mode this method needs to be called with a defined false value (i.e. 0); if called with an undefined value this method will only return the current blocking mode which is by default enabled.


=item B<read_attempts()> - set number of read attempts used in readwait() method

  $numberOfReadAttemps = $obj->read_attempts;

  $prev = $obj->read_attempts($numberOfReadAttemps);

In the readwait() method, determines how many non-blocking read attempts are made to see if there is any further input data coming in after the initial blocking read. By default 5 read attempts are performed, each at readwait_timer() seconds apart.
This method also returns the current or previous value of the setting.


=item B<readwait_timer()> - set the polling timer used in readwait() method

  $millisecs = $obj->readwait_timer;

  $prev = $obj->readwait_timer($millisecs);

In the readwait() method, determines how long to wait between consecutive reads for more data. By default this is set to 100 milliseconds.
This method also returns the current or previous value of the setting.


=item B<return_reference()> - set whether read methods should return a hard reference or not 

  $flag = $obj->return_reference;

  $prev = $obj->return_reference($flag);

This method gets or sets the setting for return_reference for the object.
This applies to the read(), readwait(), waitfor(), cmd() and login() methods and determines whether these methods should return a hard reference to any output data or the data itself. By default return_reference is false (0) and the data itself is returned by the read methods, which is a more intuitive behaviour.
However, if reading large amounts of data via the above mentioned read methods, using references will result in faster and more efficient code.


=item B<output_record_separator()> - set the Output Record Separator automatically appended by print & cmd methods

  $ors = $obj->output_record_separator;

  $prev = $obj->output_record_separator($ors);

This method gets or sets the Output Record Separator character (or string) automatically appended by print(), printlist() and cmd() methods when sending a command string to the host.
By default the Output Record Separator is a new line character "\n".
If you do not want a new line character automatically appended consider using put() instead of print().
Alternatively (or if a different character than newline is required) modify the Output Record Separator for the object via this method.


=item B<prompt_credentials()> - set whether connect() and login() methods should be able to prompt for credentials 

  $flag = $obj->prompt_credentials;

  $prev = $obj->prompt_credentials($flag);

This method gets or sets the setting for prompt_credentials for the object.
This applies to the connect() and login() methods and determines whether these methods can interactively prompt for username/password/passphrase information if these are required but not already provided.
By default prompt_credentials is false (0).


=item B<flush_credentials> - flush the stored username, password and passphrase credentials

  $obj->flush_credentials;

The connect() and login() methods, if successful in authenticating, will automatically store the username/password or SSH passphrase supplied to them.
These can be retrieved via the username, password and passphrase methods. If you do not want these to persist in memory once the authentication has completed, use this method to flush them. This method always returns 1.


=item B<prompt()> - set the CLI prompt match pattern for this object

  $string = $obj->prompt;

  $prev = $obj->prompt($string);

This method sets the CLI prompt match pattern for this object. In the first form the current pattern match string is returned. In the second form a new pattern match string is set and the previous setting returned.
The default prompt match pattern used is:

	'.*[\?\$%#>]\s?$'

The object CLI prompt match pattern is only used by the login() and cmd() methods.


=item B<username_prompt()> - set the login() username prompt match pattern for this object

  $string = $obj->username_prompt;

  $prev = $obj->username_prompt($string);

This method sets the login() username prompt match pattern for this object. In the first form the current pattern match string is returned. In the second form a new pattern match string is set and the previous setting returned.
The default prompt match pattern used is:

	'(?i:username|login)[: ]*$'


=item B<password_prompt()> - set the login() password prompt match pattern for this object

  $string = $obj->password_prompt;

  $prev = $obj->password_prompt($string);

This method sets the login() password prompt match pattern for this object. In the first form the current pattern match string is returned. In the second form a new pattern match string is set and the previous setting returned.
The default prompt match pattern used is:

	'(?i)password[: ]*$'


=item B<debug()> - set debugging

  $debugLevel = $obj->debug;

  $prev = $obj->debug($debugLevel);

Enables debugging for the object methods and on underlying modules.
In the first form the current debug level is returned; in the second form a debug level is configured and the previous setting returned.
By default debugging is disabled. To disable debugging set the debug level to 0.
The debug levels defined in this class are tied to bits 1 & 2 only. Higher bit orders are available for sub-classing modules.
The following debug levels are defined:

=over 4

=item *

0 : No debugging

=item *

bit 1 : Debugging activated for for polling methods + readwait() and enables carping on Win32/Device::SerialPort. This level also resets Win32/Device::SerialPort constructor $quiet flag only when supplied in Control::CLI::new()

=item *

bit 2 : Debugging is activated on underlying Net::SSH2 and Win32::SerialPort / Device::SerialPort; there is no actual debugging for Net::Telnet

=back

To enable both debug flags set a debug level of 3.

=back



=head2 Methods to access Object read-only variables

=over 4

=item B<parent> - return parent object

  $parent_obj = $obj->parent;

Since there are discrepancies in the way that parent Net::Telnet, Net::SSH2 and Win32/Device::SerialPort bless their object in their respective constructors, the Control::CLI class blesses its own object. The actual parent object is thus stored internally in the Control::CLI class. Normally this should not be a problem since the Control::CLI class is supposed to provide a common layer regardless of whether the underlying class is either Net::Telnet, Net::SSH2 and Win32/Device::SerialPort and there should be no need to access any of the parent class methods directly.
However, exceptions exist. If there is a need to access a parent method directly then the parent object is required. This method returns the parent object.
So, for instance, if you wanted to change the Win32::SerialPort read_interval (by default set to 100 in Control::CLI) and which is not implemented in Device::SerialPort:

	use Control::CLI;
	# Create the object instance for Serial
	$cli = new Control::CLI('COM1');
	# Connect to host
	$cli->connect( BaudRate => 9600 );

	# Set Win32::SerialPort's own read_interval method
	$cli->parent->read_interval(300);

	# Send a command and read the resulting output
	$outref = $cli->cmd("command");
	print $$outerf;

	[...]

	$cli->disconnect;


=item B<socket> - return socket object

  $parent_obj = $obj->socket;

Returns the socket object created either with IO::Socket::INET or IO::Socket::IP. Returns undef if the socket has not yet been setup or if the connection is over Serial port.
Use this to access any of the socket methods. For example to obtain the local IP address and peer host IP address (in case you provided a DNS hostname to the connect() method) for the Telnet or SSH connection:

	$localIP = $cli->socket->sockhost;

	$peerhostIP = $cli->socket->peerhost;


=item B<ssh_channel> - return ssh channel object

  $channel_obj = $obj->ssh_channel;

When running an SSH connection a Net::SSH2 object is created as well as a channel object. Both are stored internally in the Control::CLI class. The SSH2 object can be obtained using the above parent method. This method returns the SSH channel object.


=item B<connection_type> - return connection type for object

  $type = $obj->connection_type;

Returns the connection type of the method: either 'TELNET', 'SSH' or 'SERIAL'


=item B<port> - return the TCP port / COM port for the connection

  $port = $obj->port;

Returns the TCP port in use for Telnet and SSH modes and undef if no connection exists.
Returns the COM port for Serial port mode.
Note that the port returned might still be defined if the connection failed to establish.
To test that a connection is active, use the connected method instead.


=item B<connected> - returns status of connection

  $port = $obj->connected;

Returns a true (1) value if a connection is established and a false (0) value if not.
Note that this method is simply implemented by negating the status of eof method.


=item B<last_prompt> - returns the last CLI prompt received from host

  $string = $obj->last_prompt;

This method returns the last CLI prompt received from the host device or an undefined value if no prompt has yet been seen. The last CLI prompt received is updated in both login() and cmd() methods.


=item B<username> - read username provided

  $username = $obj->username;

Returns the last username which was successfully used in either connect() or login(), or undef otherwise.


=item B<password> - read password provided

  $password = $obj->password;

Returns the last password which was successfully used in either connect() or login(), or undef otherwise.


=item B<passphrase> - read passphrase provided

  $passphrase = $obj->passphrase;

Returns the last passphrase which was successfully used in connect(), or undef otherwise.


=item B<handshake> - read handshake used by current serial connection

  $handshake = $obj->handshake;

Returns the handshake setting used for the current serial connection; undef otherwise.


=item B<baudrate> - read baudrate used by current serial connection

  $baudrate = $obj->baudrate;

Returns the baudrate setting used for the current serial connection; undef otherwise.


=item B<parity> - read parity used by current serial connection

  $parity = $obj->parity;

Returns the parity setting used for the current serial connection; undef otherwise.


=item B<databits> - read databits used by current serial connection

  $databits = $obj->databits;

Returns the databits setting used for the current serial connection; undef otherwise.


=item B<stopbits> - read stopbits used by current serial connection

  $stopbits = $obj->stopbits;

Returns the stopbits setting used for the current serial connection; undef otherwise.


=back



=head2 Methods for modules sub-classing Control::CLI

=over 4

=item B<poll_struct()> - sets up the polling data structure for non-blocking polling capable methods

  $obj->poll_struct($methodName, $codeRef, $blocking, $timeout, $errmode, $outputType, $outputRequested, $returnReference, $returnList);

Sets up the $self->{POLL} structure with the following key values:

	method			=>	$methodName,
	coderef			=>	$codeRef,
	cache			=>	[],
	blocking		=>	$blocking,
	timeout			=>	$timeout,
	endtime			=>	undef,
	waittime		=>	undef,
	errmode			=>	$errmode,
	complete		=>	0,
	return_reference	=>	$returnReference,
	return_list		=>	$returnList,
	output_requested	=>	$outputRequested,
	output_type		=>	$outputType,
	output_result		=>	undef,
	output_buffer		=>	'',
	local_buffer		=>	'',
	read_buffer		=>	undef,
	already_polled		=>	undef,
	socket			=>	undef,

These keys represent common method storage values when a method is being called again and again using its poll method.
Method specific storage values should be stored under nested hash $self->{POLL}{$class::$methodName}.
This data structure must be setup before a polling method can make use of any of the poll_<name>() methods below.

$outputType should be set to 0 if no output, 1 if output will be stored in key output_buffer, 2 if result will be stored in key output_result and 3 if both an output and a result are to be returned respectively in keys output_buffer & output_result.

$returnReference only applies to output stored in output_buffer key. $returnList only applies to data in output_result key, if it is an ARRAY reference.
If key output_result will be used to store an array reference, $returnList will determine how that array will be returned: (1) as a list of values; (0/undef) as a single array reference.


=item B<poll_struct_cache()> - caches selected poll structure keys, if a nested polled method is called

  $obj->poll_struct_cache($methodName, $timeout);

This method is used within the internal polled method, if called directly, from within an externally called polled method.
For example a more complex login() method is written in a sub class, which is also written to support polling (non-blocking mode), and withing this new login() method we want to call poll_waitfor() directly from this class (without having to use the waitfor() and waitfor_poll() methods which would otherwise trample on the poll structure setup by the new login() method).
The poll_waitfor() method can tell if it was called directly (without a polling structure for waitfor already in place) and in this case will use this method to cache the poll structure keys that it has to use, so that their values can be restored by poll_struct_restore once the poll_waitfor() method has completed.


=item B<poll_struct_restore> - restores previously cached poll structure keys, if a nested polled method was called

  $obj->poll_struct_restore;

If an internally polled method was called, and at that time poll_struct_cache() was called, whenever that method has completed this method is automatically triggered inside poll_return() to automatically restore the polling keys used by the externally polled method.


=item B<poll_reset> - resets poll structure

  $ok = $obj->poll_reset;

Once a polling capable method is called, in non-blocking mode, a polling structure is put in place. The expectation is that the method is polled to completion (or until an error is encountered) before a new polling capable method is called. If a new method is called before the previous has completed, the new method will carp warning messages about the existing polling structure being trampled on before having completed. To avoid that, the poll_reset method can be called once to reset and clear the polling structure before calling the new method. Here is an example:

	$ok = $obj->cmd(Command => "show command", Blocking => 0, Poll_syntax => 1);
	until ($ok) {
		($ok, $partialOutput) = $obj->cmd_poll;
		if ($partialOutput =~ /<seeked information>/) {

			< do whatever with information... >

			$obj->poll_reset; # Reset structure as we are going to quit the loop
			last;
		}
	}
	# Make sure we have prompt in stream
	$obj->waitfor($obj->prompt); # Now we don't get any carps here


=item B<poll_return()> - return status and optional output while updating poll structure

  $ok = $obj->poll_return($ok);

  ($ok, $output1 [, $output2]) = $obj->poll_return($ok);

Takes the desired exit status, $ok (which could be set to 1, 0 or undef), updates the poll structure "complete" key with it and returns the same value. If the poll structure "output_requested" key is true then the exit status is returned in list context together with any available output. The poll structure "output_type" key bits 0 and 1 determine what type of output is returned in the list; if bit 0 is set, the contents of poll structure "output_buffer" key are returned (either as direct output or as a reference, depending on whether key "return_reference" is set or not) and at the same time the contents of the "output_buffer" key are deleted to ensure that the same output is not returned again at the next non-blocking call; if bit 1 is set, the contents of poll structure "output_result" key is returned added to the list (the "output_result" key can hold either a scalar value or an array; both cases are handled); if both bit 0 and bit 1 are set then both output types are added to the returned list.
Note, a polled method should ALWAYS use this poll_return method to come out; whether it has completed successfully, non-blocking not ready, or encountered an error. Otherwise the calling method's <method>_poll() will not be able to behave correctly.

In the case of an internally called poll method, poll_struct_restore() is automatically invoked and output1 & $output2 are only returned on success ($ok true), as references respectively to output_buffer and output_result poll structure keys; on failure ($ok undef) or not ready ($ok == 0) then output1 & $output2 remain undefined.


=item B<poll_open_socket()> - opens TCP socket in blocking or non-blocking mode

  ($ok, $socket) = $obj->poll_open_socket($pkgsub, $host, $port);

Uses IO::Socket::IP, if installed, to open a TCP socket in non-blocking or blocking mode while enforcing the connection timeout defined under poll structure key 'timeout'. If no connection timeout is defined then, in blocking mode the system's own TCP timeouts will apply while in non-blocking mode a default 20 sec timeout is used.
If IO::Socket::IP is not installed will use IO::Socket::INET instead but this will only work in blocking mode.
The $socket is defined and returned only on success ($ok true).


=item B<poll_read()> - performs a non-blocking poll read and handles timeout in non-blocking polling mode

  $ok = $obj->poll_read($pkgsub [, 'Timeout error string']);

In blocking mode this method is no different from a regular blocking read().
In non-blocking mode this method will allow the calling loop to either quit immediately (if nothing can be read) or to cycle once only (in case something was read) and come out immediately at the next iteration.

If nothing was read then a check is made to see if we have passed the timeout or not; the method will return 0 if the timeout has not expired or $obj->error($pkgsub.'Timeout error string') in case of timeout which, depending on the error mode action may or may not return. If you want the method to always return regardless of the error mode action (because you want the calling loop to handle this) then simply do not provide any timeout string to this method, then in case of timeout this method will always return with an undefined value. In all these above cases the return value from this method is not true and the calling loop should pass this return value (0 or undef) to poll_return() method to come out.

In the case that some output was read, this method will return a true (1) value indicating that the calling loop can process the available output stored in the poll structure "read_buffer" key. When the calling loop comes round to calling this method again, this method will simply immediately return 0, thus forcing the calling loop to come out via poll_return(). The poll structure "already_polled" key is used to keep track of this behaviour and is always reset by poll_return().

Follows an example on how to use this method:

	do {
		my $ok = $self->poll_read($pkgsub, 'Timeout <custom message>');
		return $self->poll_return($ok) unless $ok; # Come out if error (if errmode='return'), or if nothing to read in non-blocking mode

		< process data in $self->{POLL}{read_buffer}>

	} until <loop stisfied condition>;


=item B<poll_readwait()> - performs a non-blocking poll readwait and handles timeout in non-blocking polling mode

  $ok = $obj->poll_readwait($pkgsub, $firstReadRequired [, $readAttempts [, $readwaitTimer [, 'Timeout error string']]]);

In blocking mode this method is no different from a regular blocking readwait(Read_attempts => $readAttempts, Blocking => $firstReadRequired).
In non-blocking mode the same behaviuor is emulated by allowing the calling loop to either quit immediately (if nothing can be read, or if the readwait timer has not yet expired) or to cycle once only (in case something was read and the readwait timer has expired) and come out immediately at the next iteration.

The $firstReadRequired argument determines whether an initial read of data is required (and if we don't get any, then we timeout; just like the readwait() method in blocking mode) or whether we just wait the wait timer and return any data received during this time (without any timeout associated; just like the readwait() method in non-blocking mode).

If some output was read during the 1st call, the poll structure "waittime" is set to the waitread behaviuor where we wait a certain amount of time before making the output available. Subsequent poll calls to this function will only make the output available for processing once the waittime has expired. Before that happens this method will continue returning a 0 value. Once that happens this method will return a true (1) value and the calling loop can then process the output in in the poll structure "read_buffer".

If instead no data has yet been read (and $firstReadRequired was true) then a check is made to see if we have passed the timeout or not; the method will return 0 if the timeout has not expired yet, or $obj->error($pkgsub.'Timeout error string') in case of timeout which, depending on the error mode action may or may not return. If you want the method to always return regardless of the error mode action (because you want the calling loop to handle this) then simply do not provide any timeout string to this method, then in case of timeout this method will always return with an undefined value. For any of the above cases where the return value from this method is not true, the calling loop should pass this return value (0 or undef) to poll_return() method to come out.

Follows an example on how to use this method:

	do {
		my $ok = $self->poll_readwait($pkgsub, 1, $readAttempts, $readwaitTimer, 'Timeout <custom message>');
		return $self->poll_return($ok) unless $ok; # Come out if error (if errmode='return'), or if nothing to read in non-blocking mode

		< process data in $self->{POLL}{read_buffer}>

	} until <loop stisfied condition>;


=item B<poll_waitfor()> - performs a non-blocking poll for waitfor()

  ($ok, $dataref, $matchref) = $obj->poll_waitfor($pkgsub, $matchpat, [$timeout], [$errmode]);

  ($ok, $dataref, $matchref) = $obj->poll_waitfor($pkgsub, \@matchpats, [$timeout], [$errmode]);

Normally this is the internal method used by waitfor() and waitfor_poll() methods.
It is exposed so that sub classing modules can leverage the functionality within new methods themselves implementing polling.
These newer methods would have already set up a polling structure of their own.
When calling poll_waitfor() directly for the 1st time, it will detect an already existing poll structure and add itself to it (as well as caching some of it's keys; see poll_struct_cache). It will also read in the arguments provided at this point.
On subsequent calls, the arguments provided are ignored and the method simply polls the progress of the current task.

Follows an example on how to use this method:

	< processing previous stages >

	if ($newMethod->{stage} < X) { # stage X
		my ($ok, $dataref, $matchref) = $self->poll_waitfor('Login: $', [$timeout], [$errmode]);
		return $self->poll_return($ok) unless $ok;
		$newMethod->{stage}++; # Move to next stage X+1
	}

	< processing of next stages here >


=item B<poll_connect()> - performs a non-blocking poll for connect()

  $ok = $obj->poll_connect($pkgsub, $host, $port, $username, $password, $publickey, $privatekey, $passphrase,
                             $baudrate, $parity, $databits, $stopbits, $handshake, $promptCredentials, [$timeout], [$errmode]);

Normally this is the internal method used by connect() and connect_poll() methods.
It is exposed so that sub classing modules can leverage the functionality within new methods themselves implementing polling.
These newer methods would have already set up a polling structure of their own.
When calling poll_connect() directly for the 1st time, it will detect an already existing poll structure and add itself to it (as well as caching some of it's keys; see poll_struct_cache). It will also read in the arguments provided at this point.
On subsequent calls, the arguments provided are ignored and the method simply polls the progress of the current task.


=item B<poll_login()> - performs a non-blocking poll for login()

  ($ok, $outputref) = $obj->poll_login($pkgsub, $username, $password, $prompt, $userPrompt, $pwdPrompt, $promptCredentials, [$timeout], [$errmode]);

Normally this is the internal method used by login() and login_poll() methods.
It is exposed so that sub classing modules can leverage the functionality within new methods themselves implementing polling.
These newer methods would have already set up a polling structure of their own.
When calling poll_login() directly for the 1st time, it will detect an already existing poll structure and add itself to it (as well as caching some of it's keys; see poll_struct_cache). It will also read in the arguments provided at this point.
On subsequent calls, the arguments provided are ignored and the method simply polls the progress of the current task.
Arguments after $ok will only be defined if $ok is true(1).


=item B<poll_cmd()> - performs a non-blocking poll for cmd()

  ($ok, $outputref) = $obj->poll_cmd($pkgsub, $cmd, $prompt, [$timeout], [$errmode]);

Normally this is the internal method used by cmd() and cmd_poll() methods.
It is exposed so that sub classing modules can leverage the functionality within new methods themselves implementing polling.
These newer methods would have already set up a polling structure of their own.
When calling poll_cmd() directly for the 1st time, it will detect an already existing poll structure and add itself to it (as well as caching some of it's keys; see poll_struct_cache). It will also read in the arguments provided at this point.
On subsequent calls, the arguments provided are ignored and the method simply polls the progress of the current task.
Arguments after $ok will only be defined if $ok is true(1).


=item B<debugMsg()> - prints out a debug message

  $obj->debugMsg($msgLevel, $string1 [, $stringRef [,$string2]]);

A logical AND is performed between $msgLevel and the object debug level - see debug(); if the result is true, then the message is printed.
The message can be provided in 3 chunks: $string1 is always present, followed by an optional string reference (to dump large amout of data) and $string2.


=back


=head1 CLASS METHODS

Class Methods which are not tied to an object instance.
By default the Control::CLI class does not import anything since it is object oriented.
The following class methods should therefore be called using their fully qualified package name or else they can be expressly imported when loading this module:

	# Import all class methods listed in this section
	use Control::CLI qw(:all);

	# Import useTelnet, useSsh, useSerial & useIPv6
	use Control::CLI qw(:use);

	# Import promptClear & promptHide
	use Control::CLI qw(:prompt);

	# Import parseMethodArgs suppressMethodArgs
	use Control::CLI qw(:args);

	# Import just passphraseRequired
	use Control::CLI qw(passphraseRequired);

	# Import just parse_errmode
	use Control::CLI qw(parse_errmode);

	# Import just stripLastLine
	use Control::CLI qw(stripLastLine);

	# Import just poll()
	use Control::CLI qw(poll);

=over 4

=item B<useTelnet> - can Telnet be used ?

  $yes = Control::CLI::useTelnet;

Returns a true (1) value if Net::Telnet is installed and hence Telnet access can be used with this class.


=item B<useSsh> - can SSH be used ?

  $yes = Control::CLI::useSsh;

Returns a true (1) value if Net::SSH2 is installed and hence SSH access can be used with this class.


=item B<useSerial> - can Serial port be used ?

  $yes = Control::CLI::useSerial;

Returns a true (1) value if Win32::SerialPort (on Windows) or Device::SerialPort (on non-Windows) is installed and hence Serial port access can be used with this class.


=item B<useIPv6> - can IPv6 be used with Telnet or SSH ?

  $yes = Control::CLI::useIPv6;

Returns a true (1) value if IO::Socket::IP is installed and hence both Telnet and SSH can operate on IPv6 as well as IPv4.


=item B<poll()> - poll objects for completion

This method has a double identity, as object method or class method. It was already covered under the Object Methods section.


=back

The remainder of these class methods is exposed with the intention to make these available to modules sub-classing Control::CLI.

=over 4

=item B<promptClear()> - prompt for username in clear text

  $username = Control::CLI::promptClear($prompt);

This method prompts (using $prompt) user to enter a value/string, typically a username.
User input is visible while typed in.


=item B<promptHide()> - prompt for password in hidden text

  $password = Control::CLI::promptHide($prompt);

This method prompts (using $prompt) user to enter a value/string, typically a password or passphrase.
User input is hidden while typed in.


=item B<passphraseRequired()> - check if private key requires passphrase

  $yes = Control::CLI::passphraseRequired($privateKey);

This method opens the private key provided (DSA or RSA) and verifies whether the key requires a passphrase to be used.
Returns a true (1) value if the key requires a passphrase and false (0) if not.
On failure to open/find the private key provided an undefined value is returned. 


=item B<parseMethodArgs()> - parse arguments passed to a method against list of valid arguments

  %args = Control::CLI::parseMethodArgs($methodName, \@inputArgs, \@validArgs);

This method checks all input arguments against a list of valid arguments and generates a warning message if an invalid argument is found. The warning message will contain the $methodName passed to this function.
Additionally, all valid input arguments are returned as a hash where the hash key (the argument) is set to lowercase.


=item B<suppressMethodArgs()> - parse arguments passed to a method and suppress selected arguments

  %args = Control::CLI::suppressMethodArgs(\@inputArgs, \@suppressArgs);

This method checks all input arguments against a list of arguments to be suppressed. Remaining arguments are returned as a hash where the hash key (the argument) is set to lowercase.


=item B<parse_errmode()> - parse a new value for the error mode and return it if valid or undef otherwise

  $errmode = Control::CLI::parse_errmode($inputErrmode);

This method will check the input error mode supplied to it to ensure that it is a valid error mode.
If one of the valid strings 'die', 'croak' or 'return' it will ensure that the returned $errmode has the string all in lowercase.
For an array ref it will ensure that the first element of the array ref is a code ref.
If the input errmode is found to be invalid in any way, a warning message is printed with carp and an undef value is returned.


=item B<stripLastLine()> - strip and return last incomplete line from string reference provided

  $lastLine = Control::CLI::stripLastLine(\$stringRef);

This method will take a reference to a string and remove and return the last incomplete line, if any. An incomplete line is constituted by any text not followed by a newline (\n).
If the string terminates with a newline (\n) then this method will return an empty string.

=back



=head1 NON BLOCKING POLLING MODE

Non-blocking mode is useful if you want your Perl code to do something else while waiting for a connection to establish or a command to complete instead of just waiting.
It also allows the same (single thread) script to drive the CLI of many host devices in a parallel fashion rather than in a time consuming sequential fashion.
But why not use threads instead ?
The following bullets are from the author's experience with dealing with both approaches:

=over 4

=item *

Writing code with threads is easier than trying to achieve the same thing using a single thread using non-blocking mode

=item *

But code written with threads is harder to troubleshoot

=item *

Code using threads will use a larger memory footprint than a single thread

=item *

Code written using threads can be faster than a single thread in non-blocking mode; however if you have to provide a result at the end, you will have to wait for the slowest thread to complete anyway

=item *

If you need interaction (e.g. sharing variables) or synchronisation (doing the same step across all CLI objects at the same time) then a single thread non-blocking approach is easier to implement. A thread approach would require the use of threads::shared which adds more complexity for sharing variables as well as attempting to keep the child threads synchronized with one another

=item *

If you have ~10-30 threads chances are your code will work well; if you have hundreds of threads then things start to go wrong; some threads will then die unexpectedly and it becomes hell to troubleshoot; your code will then need to become more complex to handle failed threads... (author's experience here is mostly on Windows systems using either ActiveState or Strawberry)

=item *

The Perl distribution you find on most Unix distributions is not always compiled for thread use

=item *

Some Perl modules do not work properly with threads; if you need to use such a module, you will either have to abandon the threads approach or try and fix that module 

=back

This class distribution includes a number of examples on how to achieve the same job using both approaches: (a) using threads & (b) using a single thread in non-blocking mode. You can find these under the examples directory.


=head1 AUTHOR

Ludovico Stevens <lstevens@cpan.org>

=head1 BUGS

Please report any bugs or feature requests to C<bug-control-cli at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Control-CLI>.  I will be notified, and then you'll automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Control::CLI


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Control-CLI>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Control-CLI>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Control-CLI>

=item * Search CPAN

L<http://search.cpan.org/dist/Control-CLI/>

=back


=head1 ACKNOWLEDGEMENTS

A lot of the methods and functionality of this class, as well as some code, is directly inspired from the popular Net::Telnet class. I used Net::Telnet extensively until I was faced with adapting my scripts to run not just over Telnet but SSH as well. At which point I started working on my own class as a way to extend the rich functionality of Net::Telnet over to Net::SSH2 while at the same time abstracting it from the underlying connection type. From there, adding serial port support was pretty straight forward.


=head1 LICENSE AND COPYRIGHT

Copyright 2015 Ludovico Stevens.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

# End of Control::CLI
