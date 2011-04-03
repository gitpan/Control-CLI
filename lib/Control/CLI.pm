package Control::CLI;

use strict;
use warnings;
use Exporter qw(import);
use Carp;
use Term::ReadKey;
use Time::HiRes;

my $Package = "Control::CLI";
our $VERSION = '1.01';
our %EXPORT_TAGS = (
		use	=> [qw(useTelnet useSsh useSerial)],
		prompt	=> [qw(promptClear promptHide)],
		args	=> [qw(parseMethodArgs suppressMethodArgs)],
		_rest	=> [qw(passphraseRequired parse_errmode)],
	);
push @{$EXPORT_TAGS{all}}, @{$EXPORT_TAGS{$_}} foreach keys %EXPORT_TAGS;
Exporter::export_ok_tags('all');

########################################### Global Class Variables ###########################################

my $PollTimer = 100;		# Some connection types require a polling loop; this is the loop sleep timer in ms
my $PollWaitTimer = 100;	# readwait() polling loop timer in millisecs for further input
my $ComPortReadBuffer = 4096;	# Size of serial port read buffers
my $ComReadInterval = 100;	# Timeout between single character reads

my %Default = ( # Hash of default object settings which can be modified on a per object basis
	timeout			=> 10,			# Default Timeout value in secs
	blocking		=> 1,			# Default blocking mode
	return_reference	=> 0,			# Whether methods return data (0) or hard referece to it (1)
	read_attempts		=> 5,			# Empty reads to wait in readwait() before returning
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
	prompt		=> '.*[\?\$%#>]\s?$',		# Default prompt used in login() method
	username_prompt	=> '(?i:username|login)[: ]*$',	# Default username prompt used in login() method
	password_prompt	=> '(?i)password[: ]*$',	# Default password prompt used in login() method
	debug		=> 0,				# Default debug level; 0 = disabled
);

# Debug levels can be set using the debug() method or via debug argument to new() constructor
# Debug levels defined:
# 	0	: No debugging
#	1	: Debugging activated for readwait() + Win32/Device::SerialPort constructor $quiet flag is reset
#		  Note that to clear the $quiet flag, the debug argumet needs to be supplied in Control::CLI::new()
# 	2	: Debugging is activated on underlying Net::SSH2 and Win32::SerialPort / Device::SerialPort
#		  There is no actual debugging for Net::Telnet


my ($UseTelnet, $UseSSH, $UseSerial);


############################################## Required modules ##############################################

$UseTelnet = 1 if eval {require Net::Telnet};	# Make Net::Telnet optional
$UseSSH = 1 if eval {require Net::SSH2};	# Make Net::SSH2 optional
if ($^O eq 'MSWin32') {
	$UseSerial = 1 if eval {require Win32::SerialPort};	# Win32::SerialPort optional on Windows
}
else {
	$UseSerial = 1 if eval {require Device::SerialPort};	# Device::SerialPort optional on Unix
}
croak "$Package: no available module installed to operate on" unless $UseTelnet || $UseSSH || $UseSerial;


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

sub promptClear { # Interactively prompt for a username, in clear text
	my $username = shift;
	my $input;
	print "Enter $username: ";
	chomp($input = ReadLine(0));
	return $input;
}

sub promptHide { # Interactively prompt for a password, input is hidden
	my $password = shift;
	my $input;
	print "Enter $password: ";
	ReadMode('noecho');
	chomp($input = ReadLine(0));
	ReadMode('normal');
	print "\n";
	return $input;
}

sub passphraseRequired { # Inspects a private key to see if it requires a passphrase to be used
	my $privateKey = shift;
	my $passphraseRequired = 0;

	# Open the private key to see if passphrase required.. Net::SSH2 does not do this for us..
	open(my $key, '<', $privateKey) or return;
	while(<$key>) {
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
		carp "$pkgsub Invalid argument \"$argsIn[$i]\"";
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
		carp "$pkgsub Errmode: Undefined argument; ignoring";
		$mode  = undef;
	}
	elsif ($mode =~ /^\s*die\s*$/i) { $mode = 'die' }
	elsif ($mode =~ /^\s*croak\s*$/i) { $mode = 'croak' }
	elsif ($mode =~ /^\s*return\s*$/i) { $mode = 'return' }
	elsif (ref($mode) eq "CODE") {}
	elsif (ref($mode) eq "ARRAY") {
		unless (ref($mode->[0]) eq "CODE") {
			carp "$pkgsub Errmode: First item of array ref must be a code ref; ignoring";
			$mode  = undef;
		}
	}
	else {
		carp "$pkgsub Errmode: Invalid argument '$mode'; ignoring";
		$mode  = undef;
	}
	return $mode;
}


############################################# Constructors/Destructors #######################################

sub new {
	my $pkgsub = "${Package}-new:";
	my $invocant = shift;
	my $class = ref($invocant) || $invocant;
	my (%args, $errmode, $connectionType, $parent, $comPort);
	if (@_ == 1) { # Method invoked with just the connection type argument
		$connectionType = shift;
	}
	else {
		my @validArgs = ('use', 'timeout', 'errmode', 'return_reference', 'prompt', 'username_prompt', 
			    'password_prompt', 'input_log', 'output_log', 'dump_log', 'blocking', 'debug',
			    'prompt_credentials', 'read_attempts', 'read_block_size', 'output_record_separator');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		$connectionType = $args{use};
	}
	$errmode = defined $args{errmode} ? $args{errmode} : $Default{errmode};
	return _error(__LINE__, $errmode, "$pkgsub Connection type must be specified in constructor") unless defined $connectionType;

	if    ($connectionType =~ /^TELNET$/i) {
		croak "$pkgsub Module 'Net::Telnet' required for telnet access" unless $UseTelnet;
		@CLI::ISA = qw(Net::Telnet);
		$parent = Net::Telnet->new();
		$connectionType = 'TELNET';
	}
	elsif ($connectionType =~ /^SSH$/i) {
		croak "$pkgsub Module 'Net::SSH2' required for ssh access" unless $UseSSH;
		@CLI::ISA = qw(Net::SSH2);
		$parent = Net::SSH2->new();
		$connectionType = 'SSH';
	}
	else {
		if ($^O eq 'MSWin32') {
			croak "$pkgsub Module 'Win32::SerialPort' required for serial access" unless $UseSerial;
			@CLI::ISA = qw(Win32::SerialPort);
			$parent = Win32::SerialPort->new($connectionType, !$args{debug})
				or return _error(__LINE__, $errmode, "$pkgsub Cannot open serial port '$connectionType'");
		}
		else {
			croak "$pkgsub Module 'Device::SerialPort' required for serial access" unless $UseSerial;
			@CLI::ISA = qw(Device::SerialPort);
			$parent = Device::SerialPort->new($connectionType, !$args{debug})
				or return _error(__LINE__, $errmode, "$pkgsub Cannot open serial port '$connectionType'");
		}
		$comPort = $connectionType;
		$connectionType = 'SERIAL';
	}
	my $self = {
		# Lower Case ones can be set by user; Upper case ones are set internaly in the class
		TYPE			=>	$connectionType,
		PARENT			=>	$parent,
		BUFFER			=>	undef,
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
		LOGINSTAGE		=>	0,
		LASTPROMPT		=>	undef,
		timeout			=>	$Default{timeout},
		blocking		=>	$Default{blocking},
		return_reference	=>	$Default{return_reference},
		prompt_credentials	=>	$Default{prompt_credentials},
		read_attempts		=>	$Default{read_attempts},
		read_block_size		=>	$Default{read_block_size}{$connectionType},
		ors			=>	$Default{ors},
		errmode			=>	$Default{errmode},
		errmsg			=>	undef,
		prompt			=>	$Default{prompt},
		prompt_qr		=>	qr/$Default{prompt}/,
		username_prompt		=>	$Default{username_prompt},
		username_prompt_qr	=>	qr/$Default{username_prompt}/,
		password_prompt		=>	$Default{password_prompt},
		password_prompt_qr	=>	qr/$Default{password_prompt}/,
		debug			=>	$Default{debug},
		_BLOCKING_READ_TIMEOUT	=>	$Default{timeout}*$PollTimer/10,
	};
	if ($connectionType eq 'SERIAL') { # Adjust read_block_size defaults for Win32::SerialPort & Device::SerialPort
		$self->{read_block_size} = ($^O eq 'MSWin32') ? $Default{read_block_size}{SERIAL_WIN32}
							      : $Default{read_block_size}{SERIAL_DEVICE};
	}
	bless $self, $class;
	foreach my $arg (keys %args) { # Accepted arguments on constructor
		if    ($arg eq 'errmode')			{ $self->errmode($args{$arg}) }
		elsif ($arg eq 'timeout')			{ $self->timeout($args{$arg}) }
		elsif ($arg eq 'read_block_size')		{ $self->read_block_size($args{$arg}) }
		elsif ($arg eq 'blocking')			{ $self->blocking($args{$arg}) }
		elsif ($arg eq 'read_attempts')			{ $self->read_attempts($args{$arg}) }
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

sub DESTROY {} # Empty for now


############################################### Object methods ###############################################

sub connect {	# Connect to host
	my $pkgsub = "${Package}-connect:";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the host[:port] argument
		$args{host} = shift;
		if ($args{host} =~ /^(.+?):(\d+)$/) {
			($args{host}, $args{port}) = ($1, $2);
		}
	}
	else {
		my @validArgs = ('host', 'port', 'username', 'password', 'publickey', 'privatekey', 'passphrase',
			'prompt_credentials', 'baudrate', 'parity', 'databits', 'stopbits', 'handshake', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $promptCredentials = defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	if ($self->{TYPE} eq 'TELNET') {
		return $self->error("$pkgsub No Telnet host provided") unless defined $args{host};
		$self->{PARENT}->errmode('return');
		$self->{PARENT}->timeout($self->{timeout});
		$args{port} = $Default{tcp_port}{TELNET} unless defined $args{port};
		$self->{TCPPORT} = $args{port};
		$self->{PARENT}->port($args{port});
		$self->{PARENT}->open($args{host}) or return $self->error($pkgsub.$self->{PARENT}->errmsg);
	}
	elsif ($self->{TYPE} eq 'SSH') {
		return $self->error("$pkgsub No SSH host provided") unless defined $args{host};
		unless ( (defined $args{publickey} && defined $args{privatekey}) ||
			 (defined $args{username} && defined $args{password}) ) {
			if ($promptCredentials) {
				$args{username} = promptClear('Username') unless defined $args{username};
				$args{password} = promptHide('Password') unless defined $args{password};
			}
			else {
				return $self->error("$pkgsub Public/Private keys or Username/Password required");
			}
		}
		$args{port} = $Default{tcp_port}{SSH} unless defined $args{port};
		$self->{TCPPORT} = $args{port};
		eval { # Need to trap Net::SSH2's errors so that we get desired error mode
			$self->{PARENT}->connect($args{host}, $args{port})
				or return $self->error("$pkgsub SSH unable to connect");
		};
		return $self->error($@) if $@;
		if (defined $args{publickey} && defined $args{privatekey}) { # Use Public Key authentication
			return $self->error("$pkgsub Public Key '$args{publickey}' not found")
				unless -e $args{publickey};
			return $self->error("$pkgsub Private Key '$args{privatekey}' not found")
				unless -e $args{privatekey};
			unless ($args{passphrase}) { # Passphrase not provided
				my $passphReq = passphraseRequired($args{privatekey});
				return $self->error("$pkgsub Unable to read Private key") unless defined $passphReq;
				if ($passphReq) { # Passphrase is required
					if ($promptCredentials) { # We are allowed to prompt for it
						$args{passphrase} = promptHide('Passphrase for Private Key');
					}
					else {
						return $self->error("$pkgsub Passphrase required for Private Key");
					}
				}
			}
			unless ( defined $args{username} ) { # Username not provided
				if ($promptCredentials) { # We are allowed to prompt for it
					$args{username} = promptClear('Username');
				}
				else {
					return $self->error("$pkgsub Username required for publikkey authentication");
				}
			}
			$self->{PARENT}->auth_publickey($args{username}, $args{publickey},
							 $args{privatekey}, $args{passphrase})
				or do {
					return $self->error("$pkgsub SSH unable to publickey authenticate")
						unless defined $args{username} && defined $args{password};
				};
		}
		if ($self->{PARENT}->auth_ok) { # Store the passphrase used if publickey authentication succeded
			$self->{PASSPHRASE} = $args{passphrase} if $args{passphrase};
			$self->{USERNAME} = $args{username};
		}
		else { # Use password authentication unless already authenticated above 
			$self->{PARENT}->auth_password($args{username}, $args{password})
				or return $self->error("$pkgsub SSH unable to password authenticate");
			# Store credentials used
			($self->{USERNAME}, $self->{PASSWORD}) = ($args{username}, $args{password});
		}
		$self->{SSHCHANNEL} = $self->{PARENT}->channel();	# Open an SSH channel
		$self->{PARENT}->blocking(0);				# Make the session non blocking for reads
		$self->{SSHCHANNEL}->pty('vt100');			# Start an interactive terminal on remote host
		$self->{SSHCHANNEL}->shell();				# Start shell on channel
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		$args{handshake} = $Default{handshake} unless defined $args{handshake};
		$args{baudrate} = $Default{baudrate} unless defined $args{baudrate};
		$args{parity} = $Default{parity} unless defined $args{parity};
		$args{databits} = $Default{databits} unless defined $args{databits};
		$args{stopbits} = $Default{stopbits} unless defined $args{stopbits};
		$self->{PARENT}->handshake($args{handshake});
		$self->{PARENT}->baudrate($args{baudrate});
		$self->{PARENT}->parity($args{parity});
		# According to Win32::SerialPort, parity_enable needs to be set when parity is not 'none'...
		$self->{PARENT}->parity_enable(1) unless $args{parity} eq 'none';
		$self->{PARENT}->databits($args{databits});
		$self->{PARENT}->stopbits($args{stopbits});
		$self->{PARENT}->write_settings or return $self->error("$pkgsub Can't change Device_Control_Block: $^E");
		$self->{PARENT}->buffers($ComPortReadBuffer, 0); #Set Read & Write buffers
		$self->{PARENT}->read_interval($ComReadInterval) if $^O eq 'MSWin32';
		$self->{PARENT}->read_char_time(0);     # don't wait for each character
		$self->{HANDSHAKE} = $args{handshake};
		$self->{BAUDRATE} = $args{baudrate};
		$self->{PARITY}	= $args{parity};
		$self->{DATABITS} = $args{databits};
		$self->{STOPBITS} = $args{stopbits};
	}
	else {
		return $self->error("$pkgsub Invalid connection mode");
	}
	return 1;
}


sub read { # Read in data from connection
	my $pkgsub = "${Package}-read:";
	my $self = shift;
	my @validArgs = ('blocking', 'timeout', 'errmode', 'return_reference');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $blocking = defined $args{blocking} ? $args{blocking} : $self->{blocking};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->_read_buffer($returnRef) if $self->{BUFFER};
	return $self->_read_blocking($pkgsub, $timeout, $returnRef) if $blocking;
	return $self->_read_nonblocking($pkgsub, $returnRef);
}


sub readwait { # Read in data initially in blocking mode, then perform subsequent non-blocking reads for more
	my $pkgsub = "${Package}-readwait:";
	my $self = shift;
	my ($bufref, $buffer);
	my $ticks = 0;
	my @validArgs = ('read_attempts', 'blocking', 'timeout', 'errmode', 'return_reference');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $readAttempts = defined $args{read_attempts} ? $args{read_attempts} : $self->{read_attempts};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $blocking = defined $args{blocking} ? $args{blocking} : $self->{blocking};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	# Wait until some data is read in
	$buffer = $self->_read_buffer(0) or do {
		if ($blocking) {
			$buffer = $self->_read_blocking($pkgsub, $timeout, 0)
				or return $self->error($pkgsub.$self->errmsg);
		}
	};
	# Then keep reading until there is nothing more to read..
	while ($ticks++ < $readAttempts) {
		sleep($PollWaitTimer/1000); # Fraction of a sec sleep using Time::HiRes::sleep
		$bufref = $self->_read_nonblocking($pkgsub, 1) or return $self->error($pkgsub.$self->errmsg);
		if (defined $$bufref && length($$bufref)) {
			$buffer .= $$bufref;
			$ticks = 0; # Reset ticks to zero upon successful read
		}
		$self->_dbgMsg(1,"ticks = $ticks\n"); 
	}
	return $returnRef ? \$buffer : $buffer;
}


sub waitfor { # Wait to find pattern in the devie output stream
	my $pkgsub = "${Package}-waitfor:";
	my $self = shift;
	my $timeout = $self->{timeout};
	my $returnRef = $self->{return_reference};
	my ($errmode, @matchpat, @matchpat_qr, $bufref, $buffer, $prematch, $match);
	if (@_ == 1) { # Method invoked with single argument form
		$matchpat[0] = shift;
	}
	else { # Method invoked with multiple arguments form
		my @validArgs = ('match', 'timeout', 'errmode', 'return_reference');
		my @args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		for (my $i = 0; $i < $#args; $i += 2) {
			push @matchpat, $args[$i + 1] if $args[$i] eq 'match';
			$timeout = $args[$i + 1] if $args[$i] eq 'timeout';
			$returnRef = $args[$i + 1] if $args[$i] eq 'return_reference';
			$errmode = parse_errmode($pkgsub, $args[$i + 1]) if $args[$i] eq 'errmode';
		}
	}
	local $self->{errmode} = $errmode if defined $errmode;
	return $self->error("$pkgsub Match pattern provided is undefined") unless @matchpat;
	@matchpat_qr = map {qr/(.*?)($_)/s} @matchpat;	# Convert match patterns into regex
	$buffer = $self->_read_buffer(0) or do {
		$buffer = $self->_read_blocking($pkgsub, $timeout, 0) or return $self->error($pkgsub.$self->errmsg);
	};
	READ: while(1) {
		foreach my $pattern (@matchpat_qr) {
			if ($buffer =~ s/$pattern//) {
				($prematch, $match) = ($1, $2);
				last READ;
			}
		}
		$bufref = $self->_read_blocking($pkgsub, $timeout, 1) or return $self->error($pkgsub.$self->errmsg);
		$buffer .= $$bufref;
	}
	$self->{BUFFER} = \$buffer;
	if ($returnRef) {
		return wantarray ? (\$prematch, \$match) : \$prematch;
	}
	else {
		return wantarray ? ($prematch, $match) : $prematch;
	}
}


sub put { # Send character strings to host switch (no \n appended)
	my $pkgsub = "${Package}-put:";
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

	$self->_put($pkgsub, \$args{string});
}


sub print { # Send CLI commands to host switch (\n appended)
	my $pkgsub = "${Package}-print:";
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

	$self->_put($pkgsub, \$args{line});
}


sub printlist { # Send multiple lines to host switch (\n appended)
	my $pkgsub = "${Package}-printlist:";
	my $self = shift;
	my $output = join($self->{ors}, @_) . $self->{ors};

	$self->_put($pkgsub, \$output);
}


sub login { # Handles basic username/password login for Telnet/Serial login
	my $pkgsub = "${Package}-login:";
	my $self =shift;
	my ($output, $outref, $loginAttempted);
	my @validArgs = ('username', 'password', 'prompt_credentials', 'prompt', 'username_prompt', 'password_prompt',
		    'timeout', 'errmode');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $promptCredentials = defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials};
	my $prompt = defined $args{prompt} ? $args{prompt} : $self->{prompt_qr};
	my $usernamePrompt = defined $args{username_prompt} ? $args{username_prompt} : $self->{username_prompt_qr};
	my $passwordPrompt = defined $args{password_prompt} ? $args{password_prompt} : $self->{password_prompt_qr};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	if ($self->{LOGINSTAGE} eq 'username') { # Resume login from where it was left
		return $self->error("$pkgsub Username required") unless $args{username};
		$self->print(line => $args{username}, errmode => 'return')
			or return $self->error("$pkgsub Unable to send username\n".$self->errmsg);
		$self->{LOGINSTAGE} = '';
		$loginAttempted =1;
	}
	elsif ($self->{LOGINSTAGE} eq 'password') { # Resume login from where it was left
		return $self->error("$pkgsub Password required") unless $args{password};
		$self->print(line => $args{password}, errmode => 'return')
			or return $self->error("$pkgsub Unable to send password\n".$self->errmsg);
		$self->{LOGINSTAGE} = '';
	}
	# Enter login loop..
	do {{
		$outref = $self->_read_blocking($pkgsub, $timeout, 1) or return $self->error($pkgsub.$self->errmsg);
		$output .= $$outref;

		if ($output =~ /$usernamePrompt/) { # Handle username prompt
			return $self->error("$pkgsub Incorrect Username or Password") if $loginAttempted;
			unless ($args{username}) {
				unless ($promptCredentials) {
					$self->{LOGINSTAGE} = 'username';
					return $self->error("$pkgsub Username required");
				}
				$args{username} = promptClear('Username');
			}
			$self->print(line => $args{username}, errmode => 'return')
				or return $self->error("$pkgsub Unable to send username\n".$self->errmsg);
			$self->{LOGINSTAGE} = '';
			$loginAttempted =1;
			$output = '';
			next;
		}
		if ($output =~ /$passwordPrompt/) { # Handle password prompt
			unless ($args{password}) {
				unless ($promptCredentials) {
					$self->{LOGINSTAGE} = 'password';
					return $self->error("$pkgsub Password required");
				}
				$args{password} = promptHide('Password');
			}
			$self->print(line => $args{password}, errmode => 'return')
				or return $self->error("$pkgsub Unable to send password\n".$self->errmsg);
			$self->{LOGINSTAGE} = '';
			$output = '';
			next;
		}
	}} until ($output =~ /($prompt)/);
	$self->{LASTPROMPT} = $1;
	($self->{USERNAME}, $self->{PASSWORD}) = ($args{username}, $args{password}) if $loginAttempted;
	return 1;
}


sub cmd { # Sends a CLI command to host and returns reference to output data string
	my $pkgsub = "${Package}-cmd:";
	my $self = shift;
	my (%args, $output, $outref);
	if (@_ == 1) { # Method invoked with just the command argument
		$args{command} = shift;
	}
	else {
		my @validArgs = ('command', 'prompt', 'timeout', 'errmode', 'return_reference');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $prompt = defined $args{prompt} ? $args{prompt} : $self->{prompt_qr};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	# Flush any unread data which might be pending
	$self->read(blocking => 0);

	# Send the command
	$self->print(line => $args{command}, errmode => 'return')
		or return $self->error("$pkgsub Unable to send CLI command: $args{command}\n".$self->errmsg);

	# Wait for next prompt
	do {
		$outref = $self->read(	blocking => 1,
					timeout => $timeout,
					errmode => 'return',
					return_reference => 1,
		) or return $self->error("$pkgsub Timeout after sending command\n".$self->errmsg);
		$output .= $$outref;
	} until $output =~ s/($prompt)//;
	$self->{LASTPROMPT} = $1;
	$output =~ s/^.+\n//;		# Remove initial echoed command from output
	return $returnRef ? \$output : $output;
}


sub change_baudrate { # Change baud rate of active SERIAL connection
	my $pkgsub = "${Package}-change_baudrate:";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the command argument
		$args{baudrate} = shift;
	}
	else {
		my @validArgs = ('baudrate', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->error("$pkgsub Cannot change baudrate on Telnet/SSH") unless $self->{TYPE} eq 'SERIAL';
	return $self->error("$pkgsub No serial connection established yet") unless defined $self->{BAUDRATE};
	return $self->error("$pkgsub No baudrate specified!") unless defined $args{baudrate};
	return if $args{baudrate} == $self->{BAUDRATE};

	$self->{PARENT}->write_done(1); # Needed to flush writes before closing with Device::SerialPort
	$self->{PARENT}->close;
	if ($^O eq 'MSWin32') {
		$self->{PARENT} = Win32::SerialPort->new($self->{COMPORT}, !$self->{debug})
			or return $self->error("$pkgsub Cannot re-open serial port '$self->{COMPORT}'");
	}
	else {
		$self->{PARENT} = Device::SerialPort->new($self->{COMPORT}, !$self->{debug})
			or return $self->error("$pkgsub Cannot re-open serial port '$self->{COMPORT}'");
	}
	$self->{PARENT}->handshake($self->{HANDSHAKE});
	$self->{PARENT}->baudrate($args{baudrate});
	$self->{PARENT}->parity($self->{PARITY});
	# According to Win32::SerialPort, parity_enable needs to be set when parity is not 'none'...
	$self->{PARENT}->parity_enable(1) unless $self->{PARITY} eq 'none';
	$self->{PARENT}->databits($self->{DATABITS});
	$self->{PARENT}->stopbits($self->{STOPBITS});
	$self->{PARENT}->write_settings or return $self->error("$pkgsub Can't change Device_Control_Block: $^E");
	$self->{PARENT}->buffers($ComPortReadBuffer, 0);		#Set Read & Write buffers
	$self->{PARENT}->read_interval($ComReadInterval) if $^O eq 'MSWin32';
	$self->{PARENT}->read_char_time(0);     # don't wait for each character
	$self->{BAUDRATE} = $args{baudrate};
	return 1;
}


sub input_log { # Log to file all input sent to host
	my $pkgsub = "${Package}-input_log:";
	my ($self, $fh) = @_;

	if ($self->{TYPE} eq 'TELNET') { # For Telnet use methods provided by Net::Telnet
		$fh = $self->{PARENT}->input_log($fh);
		if ($self->{PARENT}->errmsg =~ /problem creating $fh: (.*)/) {
			return $self->error("$pkgsub Unable to open input log file: $1");
		}
		return $fh;
	}
	else { # SSH & SERIAL We implement logging ourselves
		unless (defined $fh and (ref $fh or length $fh)) { # Empty input = stop logging
			$self->{INPUTLOGFH} = undef;
			return;
		}
		if (!ref($fh) and !defined(fileno $fh)) { # Open a new filehandle if input is a filename
			my $logfile = $fh;
			$fh = IO::Handle->new;
			open($fh, '>', "$logfile") or return $self->error("$pkgsub Unable to open input log file: $!");
		}
		select((select($fh), $|=1)[$[]);  # don't buffer writes
		$self->{INPUTLOGFH} = $fh;
		return $fh;
	}
}


sub output_log { # Log to file all output received from host
	my $pkgsub = "${Package}-output_log:";
	my ($self, $fh) = @_;

	if ($self->{TYPE} eq 'TELNET') { # For Telnet use methods provided by Net::Telnet
		$fh = $self->{PARENT}->output_log($fh);
		if ($self->{PARENT}->errmsg =~ /problem creating $fh: (.*)/) {
			return $self->error("$pkgsub Unable to open output log file: $1");
		}
		return $fh;
	}
	else { # SSH & SERIAL We implement logging ourselves
		unless (defined $fh and (ref $fh or length $fh)) { # Empty input = stop logging
			$self->{OUTPUTLOGFH} = undef;
			return;
		}
		if (!ref($fh) and !defined(fileno $fh)) { # Open a new filehandle if input is a filename
			my $logfile = $fh;
			$fh = IO::Handle->new;
			open($fh, '>', "$logfile") or return $self->error("$pkgsub Unable to open output log file: $!");
		}
		select((select($fh), $|=1)[$[]);  # don't buffer writes
		$self->{OUTPUTLOGFH} = $fh;
		return $fh;
	}
}


sub dump_log { # Log hex and ascii for both input & output
	my $pkgsub = "${Package}-dump_log:";
	my ($self, $fh) = @_;

	if ($self->{TYPE} eq 'TELNET') { # For Telnet use methods provided by Net::Telnet
		$fh = $self->{PARENT}->dump_log($fh);
		if ($self->{PARENT}->errmsg =~ /problem creating $fh: (.*)/) {
			return $self->error("$pkgsub Unable to open dump log file: $1");
		}
		return $fh;
	}
	else { # SSH & SERIAL We implement logging ourselves
		unless (defined $fh and (ref $fh or length $fh)) { # Empty input = stop logging
			$self->{DUMPLOGFH} = undef;
			return;
		}
		if (!ref($fh) and !defined(fileno $fh)) { # Open a new filehandle if input is a filename
			my $logfile = $fh;
			$fh = IO::Handle->new;
			open($fh, '>', "$logfile") or return $self->error("$pkgsub Unable to open dump log file: $!");
		}
		select((select($fh), $|=1)[$[]);  # don't buffer writes
		$self->{DUMPLOGFH} = $fh;
		return $fh;
	}
}


sub disconnect { # Disconnect from host
	my $pkgsub = "${Package}-disconnect:";
	my $self = shift;

	$self->{BUFFER} = undef;
	$self->{LOGINSTAGE} = undef;
	if ($self->{TYPE} eq 'TELNET') {
		$self->{PARENT}->close;
		$self->{TCPPORT} = undef;
	}
	elsif ($self->{TYPE} eq 'SSH') {
		$self->{SSHCHANNEL}->close;
		$self->{PARENT}->disconnect();
		$self->{TCPPORT} = undef;
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		$self->{PARENT}->close;
		$self->{HANDSHAKE} = undef;
		$self->{BAUDRATE} = undef;
		$self->{PARITY} = undef;
		$self->{DATABITS} = undef;
		$self->{STOPBITS} = undef;
	}
	else {
		return $self->error("$pkgsub Invalid connection mode");
	}
	return 1;
}


sub close { # Same as disconnect
	my $self = shift;
	$self->disconnect;
}


sub error { # Handle errors according to the object's error mode
	my $self = shift;
	my $errmsg = shift || '';
	my $lineNumber = (caller)[2];

	$self->errmsg($errmsg);
	_error($lineNumber, $self->{errmode}, $errmsg);
}


#################################### Methods to set/read Object variables ####################################

sub timeout { # Set/read timeout
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{timeout};
	if (defined $newSetting) {
		$self->{timeout} = $newSetting;
		$self->{_BLOCKING_READ_TIMEOUT} = $newSetting*$PollTimer/10;
		if ($self->{TYPE} eq 'TELNET') {
			$self->{PARENT}->timeout($newSetting);
		}
	}
	return $currentSetting;
}


sub read_block_size { # Set/read read_block_size for either SSH or SERIAL (not applicable to TELNET)
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{read_block_size};
	$self->{read_block_size} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub blocking { # Set/read blocking/unblocking mode for reading connection
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
	my $pkgsub = "${Package}-errmode:";
	my ($self, $newSetting) = @_;
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
	if (defined $newSetting) {
		$self->{debug} = $newSetting;
		if ($self->{TYPE} eq 'SSH') {
			$self->{PARENT}->debug($newSetting >= 2 ? 1 : 0);
		}
		elsif ($self->{TYPE} eq 'SERIAL') {
			$self->{PARENT}->debug($newSetting >= 2 ? 1 : 0);
		}
	}
	return $currentSetting;
}


################################# Methods to read read-only Object variables #################################

sub parent { # Return the parent object
	my $self = shift;
	return $self->{PARENT};
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


########################################## Internal Private Methods ##########################################

sub _read_buffer { # Internal method to read (and clear) any data cached in object buffer
	my ($self, $returnRef) = @_;
	my $bufref = $self->{BUFFER} or return;
	$self->{BUFFER} = undef;
	return $returnRef ? $bufref : $$bufref;
}


sub _read_blocking { # Internal read method; data must be read or we timeout
	my ($self, $pkgsub, $timeout, $returnRef) = @_;
	my $buffer;

	if ($self->{TYPE} eq 'TELNET') {
		$buffer = $self->{PARENT}->get(Timeout => $timeout) or return $self->error($pkgsub.$self->{PARENT}->errmsg);
		return $self->error("$pkgsub Received eof from connection") unless defined $buffer;
	}
	elsif ($self->{TYPE} eq 'SSH') {
		my @poll = { handle => $self->{SSHCHANNEL}, events => ['in'] };
		unless ($self->{PARENT}->poll($timeout*1000, \@poll) && $poll[0]->{revents}->{in}) {
			return $self->error("$pkgsub SSH connection timeout");
		}
		$self->{SSHCHANNEL}->read($buffer, $self->{read_block_size});
		_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
		_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		if ($^O eq 'MSWin32') { # Win32::SerialPort
			my $inBytes;
			$self->{PARENT}->read_const_time($timeout * 1000);	# Set timeout in millisecs
			($inBytes, $buffer) = $self->{PARENT}->read($self->{read_block_size});
			return $self->error("$pkgsub Serial Port timeout") unless $inBytes;
		}
		else { # Device::SerialPort; we handle polling ourselves
			$self->{PARENT}->read_const_time($PollTimer); # Wait defined millisecs during every read
			my $inBytes;
			my $ticks = 0;
			do {
				if ($ticks++ > $self->{_BLOCKING_READ_TIMEOUT}) {
					return $self->error("$pkgsub Serial port read timeout");
				}
				($inBytes, $buffer) = $self->{PARENT}->read($self->{read_block_size});
			} until $inBytes > 0;
		}
		_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
		_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
	}
	else {
		return $self->error("$pkgsub Invalid connection mode");
	}
	return $returnRef ? \$buffer : $buffer;
}


sub _read_nonblocking { # Internal read method; if no data available return immediately
	my ($self, $pkgsub, $returnRef) = @_;
	my $buffer;

	if ($self->{TYPE} eq 'TELNET') {
		$buffer = $self->{PARENT}->get(Timeout => 0);
	}
	elsif ($self->{TYPE} eq 'SSH') {
		$self->{SSHCHANNEL}->read($buffer, $self->{read_block_size});
		if ($buffer) {
			_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
			_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
		}
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		my $inBytes;
		$self->{PARENT}->read_const_time(1); # Set timeout to nothing (1ms; Win32::SerialPort does not like 0)
		($inBytes, $buffer) = $self->{PARENT}->read($self->{read_block_size});
		if ($buffer) {
			_log_print($self->{INPUTLOGFH}, \$buffer) if defined $self->{INPUTLOGFH};
			_log_dump('<', $self->{DUMPLOGFH}, \$buffer) if defined $self->{DUMPLOGFH};
		}
	}
	else {
		return $self->error("$pkgsub Invalid connection mode");
	}
	return $returnRef ? \$buffer : $buffer;
}


sub _put { # Internal write method
	my ($self, $pkgsub, $outref) = @_;

	if ($self->{TYPE} eq 'TELNET') {
		$self->{PARENT}->put($$outref) or return $self->error($pkgsub.$self->{PARENT}->errmsg);
	}
	elsif ($self->{TYPE} eq 'SSH') {
		print {$self->{SSHCHANNEL}} $$outref;
		_log_print($self->{OUTPUTLOGFH}, $outref) if defined $self->{OUTPUTLOGFH};
		_log_dump('>', $self->{DUMPLOGFH}, $outref) if defined $self->{DUMPLOGFH};
	}
	elsif ($self->{TYPE} eq 'SERIAL') {
		my $countOut = $self->{PARENT}->write($$outref);
		return $self->error("$pkgsub Serial port write failed") unless $countOut;
		return $self->error("$pkgsub Serial port write incomplete") if $countOut != length($$outref);
		_log_print($self->{OUTPUTLOGFH}, $outref) if defined $self->{OUTPUTLOGFH};
		_log_dump('>', $self->{DUMPLOGFH}, $outref) if defined $self->{DUMPLOGFH};
	}
	else {
		return $self->error("$pkgsub Invalid connection mode");
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
	my ($lineNumber, $mode, $errmsg) = @_;

	if (ref($mode) eq "CODE") {
		&$mode($errmsg);
		return;
	}
	elsif (ref($mode) eq "ARRAY") {
		my ($func, @args) = @$mode;
		&$func(@args);
		return;
	}
	elsif ($mode eq 'return') { return }
	elsif ($mode eq 'croak') { croak "\n$errmsg" }
	elsif ($mode eq 'die') { die "\n$errmsg at ", __FILE__, " line $lineNumber\n" }
	else { # should never happen..
		croak "\nInvalid errmode! Defaulting to croak\n$errmsg";
	}
}


sub _dbgMsg {
	my $self = shift;
	if (shift() <= $self->{debug}) {
		my $string1 = shift();
		my $stringRef = shift() || \"";#" Ultraedit hack!
		my $string2 = shift() || "";
		print $string1, $$stringRef, $string2;
	}
}


1
__END__;


######################## User Documentation ##########################
## To format the following documentation into a more readable format,
## use one of these programs: perldoc; pod2man; pod2html; pod2text.

=head1 NAME

Control::CLI - Command Line Interface I/O via any of Telnet, SSH or Serial port

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
	#  authentication is part of the connection process
	$cli->connect(	Host		=> 'hostname',
			Username	=> $username,
			Password	=> $password,
			PublicKey	=> '.ssh/id_dsa.pub',
			PrivateKey	=> '.ssh/id_dsa',
			Passphrase	=> $passphrase,
		     );
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

Win32::SerialPort or Device::SerialPort for Serial port access respectively on Windows and Unix systems

=back

Net::SSH2 only supports SSHv2 and this class will always and only use Net::SSH2 to establish a channel over which an interactive shell is established with the remote host. Both password and publickey authentication are supported.

All the above modules are optional, however if one of the modules is missing then no access of that type will be available.
For instance if Win32::SerialPort is not installed (on a Windows system) but both Net::Telnet and Net::SSH2 are, then Control::CLI will be able to operate over both Telnet and SSH, but not Serial port.
Furthermore, at least one of the above modules needs to be installed, otherwise Control::CLI's constructor will throw an error.

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

=item B<connect()> - connect to host

  $ok = $obj->connect($host[:$port]);

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
  	[Errmode		=> $errmode,]
  );

This method connects to the host device. The connection will use either Telnet, SSH or Serial port, depending on how the object was created with the new() constructor.
On success a true (1) value is returned. On timeout or other connection failures the error mode action is performed. See errmode().
The optional "errmode" argument is provided to override the global setting of the object error mode action.
Which arguments are used depends on the whether the object was created for Telnet, SSH or Serial port. The "host" argument is required by both Telnet and SSH. The other arguments are optional.

=over 4

=item *

For Telnet, two forms are allowed with the following arguments:

  $ok = $obj->connect($host[:$port]);

  $ok = $obj->connect(
  	Host			=> $host,
  	[Port			=> $port,]
  	[Errmode		=> $errmode,]
  );

If not specified, the default port number for Telnet is 23

=item *

For SSH, two forms are allowed with the following arguments:

  $ok = $obj->connect($host[:$port]);

  $ok = $obj->connect(
  	Host			=> $host,
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[PublicKey		=> $publicKey,]
  	[PrivateKey		=> $privateKey,]
  	[Passphrase		=> $passphrase,]
  	[Prompt_credentials	=> $flag,]
  	[Errmode		=> $errmode,]
  );

If not specified, the default port number for SSH is 22.
For SSH password authentication both username & password must be provided.
For SSH public key authentication the username must be provided as well as both the public & private keys which need to be in OpenSSH format. If the private key is protected by a passphrase then the passphrase must also be supplied.
If no username, password, public/private keys, passphrase is provided and prompt_credentials is true then this method will attempt SSH password authentication and prompt user for a username and password to use.
If public/private keys are provided but the username and passphrase (if required by private key) are not, and prompt_credentials is true then this method will prompt for the username and passphrase (if required by private key) and will then attempt SSH public key authentication.
If prompt_credentials is false and a username or password or passphrase is required but not provided then the error mode action is performed. See errmode().
The optional "prompt_credentials" argument is provided to override the global setting of the parameter by the same name which is by default false. See prompt_credentials().


=item *

For Serial port, these arguments are used:

  $ok = $obj->connect(
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Errmode		=> $errmode,]
  );

If arguments are not specified, the defaults are: Baud Rate = 9600, Data Bits = 8, Parity = none, Stop Bits = 1, Handshake = none.
Allowed values for these arguments are the same allowed by underlying Win32::SerialPort / Device::SerialPort:

=over 4

=item *

Baud Rate: Any legal value

=item *

Parity: One of the following: "none", "odd", "even", "mark", "space"

=item *

Data Bits: An integer from 5 to 8

=item *

Stop Bits: Legal values are 1, 1.5, and 2. But 1.5 only works with 5 databits, 2 does not work with 5 databits, and other combinations may not work on all hardware if parity is also used

=item *

Handshake: One of the following: "none", "rts", "xoff", "dtr"

=back

Remember that when connecting over the serial port, the device at the far end is not necessarily alerted that the connection is established. So it is usually necessary to send some character sequence (usually a carriage return) over the serial connection to wake up the far end. This can be achieved with a simple print() immediately after connect().

=back


=item B<read()> - read block of data from object

  $data || $dataref = $obj->read(
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

This method reads a block of data from the object. If blocking is enabled - see blocking() - and no data is available, then the read method will wait for data until expiry of timeout - see timeout() -, then will perform the error mode action. See errmode(). If blocking is disabled and no data is available then the read method will return immediately (in this case the timeout and errmode arguments are not applicable).
The optional arguments are provided to override the global setting of the parameters by the same name for the duration of this method. Note that setting these arguments does not alter the global setting for the object. See also timeout(), blocking(), errmode(), return_reference().
Returns either a hard reference to any data read or the data itself, depending on the applicable setting of "return_reference". See return_reference().


=item B<readwait()> - read in data initially in blocking mode, then perform subsequent non-blocking reads for more

  $data || $dataref = $obj->readwait(
  	[Read_attempts		=> $numberOfReadAttemps,],
  	[Blocking		=> $flag,]
  	[Timeout		=> $secs,],
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

If blocking is enabled - see blocking() - this method implements an initial blocking read followed by a number of non-blocking reads. The intention is that we expect to receive at least some data and then we wait a little longer to make sure we have all the data. This is useful when the input data stream has been fragmented into multiple packets; in this case the normal read() method (in blocking mode) will immediately return once the data from the first packet is received, while the readwait() method will return once all packets have been received. 
For the initial blocking read, if no data is available, the method will wait until expiry of timeout. If a timeout occurs, then the error mode action is performed as with the regular read() method in blocking mode. See errmode().
If blocking is disabled then no initial blocking read is performed, instead the method will move directly to the non-blocking reads (in this case the "timeout" and "errmode" arguments are not applicable).
Once some data has been read or blocking is disabled, then the method will perform a number of non-blocking reads at 0.1 seconds intervals to ensure that any subsequent data is also read before returning. The number of non-blocking reads is dependant on whether more data is received or not but a certain number of consecutive reads with no more data received will make the method return. By default that number is 5 and can be either set via the read_attempts() method or by specifying the optional "read_attempts" argument which will override whatever value is globally set for the object. See read_attempts().
Therefore note that this method will always introduce a delay of 0.1 seconds times the value of "read_attempts" and faster response times can be obtained using the regular read() method.
Returns either a hard reference to data read or the data itself, depending on the applicable setting of return_reference. See return_reference().
The optional arguments are provided to override the global setting of the parameters by the same name for the duration of this method. Note that setting these arguments does not alter the global setting for the object. See also read_attempts(), timeout(), errmode(), return_reference().


=item B<waitfor()> - wait for pattern in the input stream

  $data || $dataref = $obj->waitfor($matchpat);

  ($data || $dataref, $match || $matchref) = $obj->waitfor($matchpat);

  $data || $dataref = $obj->waitfor(
  	[Match			=> $matchpattern1,
  	[Match			=> $matchpattern2,
  	[Match			=> $matchpattern3, ... ]]]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

  ($data || $dataref, $match || $matchref) = $obj->waitfor(
  	[Match			=> $matchpattern1,
  	[Match			=> $matchpattern2,
  	[Match			=> $matchpattern3, ... ]]]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

This method reads until a pattern match or string is found in the input stream, or will timeout if no further data can be read.
In scalar context returns a reference to any data read up to but excluding the matched string.
In list context returns the same reference to data read as well as the actual string which was matched.
On timeout or other failure the error mode action is performed. See errmode().
In the first two forms a single pattern match string can be provided; in the last two forms any number of pattern match strings can be provided and the method will wait until a match is found against any of those patterns. In both cases the pattern match can be a simple string or any valid perl regular expression match string (in the latter case use single quotes when building the string).
In the second form only, the optional arguments are provided to override the global setting of the parameters by the same name for the duration of this method. Note that setting these arguments does not alter the global setting for the object. See also timeout(), errmode(), return_reference().
Returns either hard references for the outputs ($data & $match) or the data itself, depending on the applicable setting of return_reference. See return_reference().
This method is similar (but not identical) to the method of the same name provided in Net::Telnet.


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


=item B<login()> - handle login for Telnet / Serial port 

  $ok = $obj->login(
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Prompt			=> $prompt,]
  	[Username_prompt	=> $usernamePrompt,]
  	[Password_prompt	=> $passwordPrompt,]
  	[Timeout		=> $secs,]
  	[Errmode		=> $errmode,]
  );

This method handles login authentication for Telnet and Serial port access on a generic host (note that for SSH, authentication is part of the connection process).
For this method to succeed the username & password prompts from the remote host must match the default prompts defined for the object or the overrides specified via the optional "username_prompt" & "password_prompt" arguments. By default these regular expressions are set to:

	'(?i:username|login)[: ]*$'
	'(?i)password[: ]*$'

Following a successful authentication, if a valid CLI prompt is received, the method will return a true (1) value. The expected CLI prompt is either the globally set prompt - see prompt() - or the local override specified with the optional "prompt" argument. By default, the following prompt is expected:

	'.*[\?\$%#>]\s?$'

On timeout or failure or if the remote host prompts for the username a second time (the method assumes that the credentials provided were invalid) then the error mode action is performed. See errmode().
If username/password are not provided but are required and prompt_credentials is true, the method will automatically prompt the user for them interactively; otherwise the error mode action is performed. See errmode().
The optional "prompt_credentials" argument is provided to override the global setting of the parameter by the same name which is by default false. See prompt_credentials().


=item B<cmd()> - Sends a CLI command to host and returns output data

  $output || $outputRef = $obj->cmd($cliCommand);

  $output || $outputRef = $obj->cmd(
  	[Command		=> $cliCommand,]
  	[Prompt			=> $prompt,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Errmode		=> $errmode,]
  );

This method sends a CLI command to the host and returns once a new CLI prompt is received from the host. The output record separator - which is usually a newline "\n"; see output_record_separator() - is automatically appended to the command string. If no command string is provided then this method will simply send the output record separator and expect a new prompt back.
Before sending the command to the host, any pending input data from host is read and flushed.
The CLI prompt expected by the cmd() method is either the prompt defined for the object - see prompt() - or the override defined using the optional "prompt" argument.
Either a hard reference to the output or the output itself is returned, depending on the setting of return_reference; see return_reference().
The echoed command is automatically stripped from the output as well as the terminating CLI prompt (the last prompt received from the host device can be obtained with the lastprompt() method).
This means that when sending a command which generates no output, either a null string or a reference pointing to a null string will be returned.
On I/O failure to the host device, the error mode action is performed. See errmode().
If output is no longer received from host and no valid CLI prompt has been seen, the method will timeout - see timeout() - and will then perform the error mode action. See errmode().
The cmd() method is equivalent to the following combined methods:

	$obj->read(Blocking => 0);
	$obj->print($cliCommand);
	$output = $obj->waitfor($obj->prompt);


=item B<change_baudrate()> - Change baud rate on current serial connection

  $ok = $obj->change_baudrate($baudrate);

  $ok = $obj->change_baudrate(
  	BaudRate		=> $baudrate,
  	[Errmode		=> $errmode,]
  );

This method is only applicable to an already established Serial port connection and will return an error if the connection type is Telnet or SSH or if the object type is for Serial but no connection is yet established.
The serial connection is restarted with the new baudrate (in the background, the serial connection is actually disconnected and then re-connected) without losing the current CLI session. If there is a problem restarting the serial port connection at the new baudrate then the error mode action is performed - see errmode().
If the baudrate was successfully changed a true (1) value is returned.
Note that you have to change the baudrate on the far end device before calling this method. Follows an example:

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

	$cli->disconnect;


=item B<input_log()> - log all input sent to host

  $fh = $obj->input_log;

  $fh = $obj->input_log($fh);

  $fh = $obj->input_log($filename);

This method starts or stops logging of all input received from host (e.g. via any of read(), readwait(), waitfor(), cmd() methods).
This is useful when debugging. Because most command interpreters echo back commands received, it's likely all output sent to the host will also appear in the input log. See also output_log().
If no argument is given, the log filehandle is returned. An empty string indicates logging is off. If an open filehandle is given, it is used for logging and returned. Otherwise, the argument is assumed to be the name of a file, the file is opened for logging and a filehandle to it is returned. If the file can't be opened for writing, the error mode action is performed.
To stop logging, use an empty string as the argument.


=item B<output_log()> - log all output received from host

  $fh = $obj->output_log;

  $fh = $obj->output_log($fh);

  $fh = $obj->output_log($filename);

This method starts or stops logging of output sent to host (e.g. via any of put(), print(), printlist(), cmd() methods).
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


=item B<disconnect> - disconnect from host

  $ok = $obj->disconnect;

This method closes the connection. Always returns true.


=item B<close> - disconnect from host

  $ok = $obj->close;

This method closes the connection. It is an alias to disconnect() method. Always returns true.


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
When mode is an $arrayref, the first element of the array must be a &$coderef. Any elements that follow are the arguments to &$coderef. When an error is encountered, the &$coderef is called with its arguments. Using this mode you may have your own subroutine handle errors. If the &$coderef itself returns then the method generating the error returns undefined or an empty list depending on context.
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


=item B<read_block_size()> - set read_block_size for either SSH or Serial port 

  $bytes = $obj->read_block_size;

  $prev = $obj->read_block_size($bytes);

This method gets or sets the read_block_size for either SSH or Serial port access (not applicable to Telnet).
This is the read buffer size used on the underlying Net::SSH2 and Win32::SerialPort / Device::SerialPort read() methods.
The default read_block_size is 4096 for SSH, 1024 for Win32::SerialPort and 255 for Device::SerialPort.


=item B<blocking()> - set blocking mode for read methods

  $flag = $obj->blocking;

  $prev = $obj->blocking($flag);

Determines whether the read(), readwait() or waitfor() methods will wait for data to be received (until expiry of timeout) or return immediately if no data is available. By default blocking is enabled (1). This method also returns the current or previous setting of the blocking mode.


=item B<read_attempts()> - set number of read attempts used in readwait() method

  $numberOfReadAttemps = $obj->read_attempts;

  $prev = $obj->read_attempts($numberOfReadAttemps);

In the readwait() method, determines how many non-blocking read attempts are made to see if there is any further input data coming in after the initial blocking read. By default 5 read attempts are performed, each 0.1 seconds apart.
This method also returns the current or previous value of the setting.


=item B<return_reference()> - set whether read methods should return a hard reference or not 

  $flag = $obj->return_reference;

  $prev = $obj->return_reference($flag);

This method gets or sets the setting for return_reference for the object.
This applies to the read(), readwait(), waitfor() and cmd() methods and determines whether these methods should return a hard reference to any output data or the data itself. By default return_reference is false (0) and the data itself is returned by the read methods, which is a more intuitive behaviour.
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
The following debug levels are defined:

=over 4

=item *

0 : No debugging

=item *

1 : Debugging activated for readwait() + Win32/Device::SerialPort constructor $quiet flag is reset. Note that to clear the $quiet flag, the debug argument needs to be supplied in Control::CLI::new()

=item *

2 : Debugging is activated on underlying Net::SSH2 and Win32::SerialPort / Device::SerialPort; there is no actual debugging for Net::Telnet

=back

=back



=head2 Methods to access Object read-only variables

=over 4

=item B<parent> - return parent object

  $parent_obj = $obj->parent;

Since there are discrepancies in the way that parent Net::Telnet, Net::SSH2 and Win32/Device::SerialPort bless their object in their respective constructors, the Control::CLI class blesses it's own object. The actual parent object is thus stored internally in the Control::CLI class. Normally this should not be a problem since the Control::CLI class is supposed to provide a common layer regardless of whether the underlying class is either Net::Telnet, Net::SSH2 and Win32/Device::SerialPort and there should be no need to access any of the parent class methods directly.
However, exceptions exist. If there is a need to access a parent method directly then the parent object is required. This method returns the parent object.
So, for instance, if you wanted to send a telnet break character (which is specific to telnet only) this is how you would call the relevant Net::Telnet method from a Control::CLI object:

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
	$outref = $cli->cmd("command");
	print $$outerf;

	[...]

	# Send telnet break character using Net::Telnet 's own method
	$cli->parent->break;

	[...]

	$cli->disconnect;

Another example is if you wanted to change the Win32::SerialPort read_interval (by default set to 100 in Control::CLI) and which is not implemented in Device::SerialPort.

	use Control::CLI;
	# Create the object instance for Serial
	$cli = new Control::CLI('COM1');
	# Connect to host
	$cli->connect('hostname');

	# Set Win32::SerialPort's own read_interval method
	$cli->parent->read_interval(300);

	# Send a command and read the resulting output
	$outref = $cli->cmd("command");
	print $$outerf;

	[...]

	$cli->disconnect;


=item B<connection_type> - return connection type for object

  $type = $obj->connection_type;

Returns the connection type of the method: either 'TELNET', 'SSH' or 'SERIAL'


=item B<port> - return the TCP port / COM port for the connection

  $port = $obj->port;

Returns the TCP port in use for Telnet and SSH modes and undef if no connection exists.
Returns the COM port for Serial port mode.


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




=head1 CLASS METHODS

Class Methods which are not tied to an object instance.
By default the Control::CLI class does not import anything since it is object oriented.
The following class methods should therefore be called using their fully qualified package name or else they can be expressly imported when loading this module:

	# Import all class methods listed in this section
	use Control::CLI (:all);

	# Import useTelnet, useSsh & useSerial
	use Control::CLI (:use);

	# Import promptClear & promptHide
	use Control::CLI (:prompt);

	# Import arseMethodArgs suppressMethodArgs
	use Control::CLI (:args);

	# Import just passphraseRequired
	use Control::CLI (passphraseRequired);

	# Import just parse_errmode
	use Control::CLI (parse_errmode);

=over 4

=item B<useTelnet> - can telnet be used ?

  $yes = Control::CLI::useTelnet;

Returns a true (1) value if Net::Telnet is installed and hence Telnet access can be used with this class.


=item B<useSsh> - can telnet be used ?

  $yes = Control::CLI::useSsh;

Returns a true (1) value if Net::SSH2 is installed and hence SSH access can be used with this class.


=item B<useSerial> - can telnet be used ?

  $yes = Control::CLI::useSerial;

Returns a true (1) value if Win32::SerialPort (on Windows) or Device::SerialPort (on non-Windows) is installed and hence Serial port access can be used with this class.


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


=back




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

Copyright 2010 Ludovico Stevens.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

# End of Control::CLI
