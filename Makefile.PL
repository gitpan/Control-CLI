#!/usr/bin/perl

use strict;
use warnings;
use ExtUtils::MakeMaker;

# Scan for TESTPORT argument
my $dpfile = "t/DefaultPort.pm";
my (@passargs, $serialPort);
if (@ARGV) {
	foreach my $arg (@ARGV) {
		my ($key,$value)=split /=/, $arg, 2;
		if ($key eq "TESTPORT") {
			$serialPort = $value;
		}
		else {
			push(@passargs,$arg);
		}
	}
}
@ARGV=@passargs;

if ($serialPort) {
	open (my $default, '>', $dpfile) or die "Can't create $dpfile: $!\n";
	print $default <<EOF;

# Created by Makefile.PL
package DefaultPort;
\$Serial_Test_Port = "$serialPort";
EOF

	close $default;
}
else {
	unlink $dpfile if -e $dpfile;
	print "\nTo enable serial port tests, use:\n";
	print "\tperl Build.PL TESTPORT=<DEVICE>\n";
	print "where <DEVICE> is the serial port to test with\n\n";
}


(my $extutils_numeric_version = $ExtUtils::MakeMaker::VERSION) =~ s/_.+$//;
WriteMakefile(
	NAME		=> 'Control::CLI',
	AUTHOR		=> q{Ludovico Stevens <lstevens@cpan.org>},
	VERSION_FROM	=> 'lib/Control/CLI.pm',
	ABSTRACT	=> 'Command Line Interface I/O over either Telnet or SSH (IPv4 & IPv6) or Serial port',
	($extutils_numeric_version >= 6.3002
		? ('LICENSE'=> 'perl')
		: ()),
	PL_FILES	=> {},
	PREREQ_PM	=> {
		'Exporter'		=> 0,
		'Test::More'		=> 0,
		'Term::ReadKey'		=> 0,
		'Time::HiRes'		=> 0,
		'IO::Handle'		=> 0,
		'IO::Socket::INET'	=> 0,
	},
	BUILD_REQUIRES	=> {
		'Net::Telnet'		=> 0,
		'IO::Interactive'	=> 0,
	},
	dist		=> { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	clean		=> { FILES => 'Control-CLI-*' },
);
