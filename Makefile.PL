#!/usr/bin/perl

use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME		=> 'Control::CLI',
	AUTHOR		=> q{Ludovico Stevens <lstevens@cpan.org>},
	VERSION_FROM	=> 'lib/Control/CLI.pm',
	ABSTRACT	=> 'Command Line Interface I/O via any of Telnet, SSH or Serial port',
	($ExtUtils::MakeMaker::VERSION >= 6.3002
		? ('LICENSE'=> 'perl')
		: ()),
	PL_FILES	=> {},
	PREREQ_PM	=> {
		'Test::More'	=> 0,
		'Term::ReadKey'	=> 0,
		'Time::HiRes'	=> 0,
	},
	dist		=> { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	clean		=> { FILES => 'Control-CLI-*' },
);
