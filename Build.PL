#!/usr/bin/perl

use strict;
use warnings;
use Module::Build;

my $build = Module::Build->new(
		module_name => 'Control::CLI',
		license  => 'perl',
		requires => {
			'Term::ReadKey' => 0,
			'Time::HiRes'	=> 0,
		},
		configure_requires => { 'Module::Build' => 0.36 }
	);
$build->create_build_script;

