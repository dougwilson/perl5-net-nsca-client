use 5.008;
use strict;
use warnings 'all';

use Module::Build 0.31;

my $build = Module::Build->new(
	module_name => 'Net::NSCA::Client',
	license     => 'perl',
	dist_author => 'Douglas Christopher Wilson <doug@somethingdoug.com>',

	meta_merge => {
		resources => {
			homepage   => 'http://github.com/dougwilson/perl5-net-nsca-client/',
			repository => 'git://github.com/dougwilson/perl5-net-nsca-client.git',
		},
		no_index => {
			directory => [qw/inc t xt/],
		},
	},

	# Module that are required for tests in t/
	build_requires => {
		'Test::Class'     => '0.33',
		'Test::Command'   => '0.08',
		'Test::Exception' => '0.03',
		'Test::More'      => '0.94',
		'Test::Requires'  => '0.02',
	},

	# Module that are required
	requires => {
		'perl'                      => '5.008001',
		'Convert::Binary::C'        => '0.74',
		'Data::Rand::Obscure'       => '0.020',
		'Data::Validate::Domain'    => '0.02',
		'Digest::CRC'               => 0,
		'English'                   => 0,
		'IO::Socket::INET'          => 0,
		'Moose'                     => '0.89',
		'MooseX::Clone'             => 0,
		'MooseX::StrictConstructor' => '0.08',
		'MooseX::Types'             => '0.08',
		'Readonly'                  => '1.03',
		'namespace::clean'          => '0.04',
	},

	# Enable tests to be in multi-level directories
	recursive_test_files => 1,

	# Create a LICENSE file
	create_license => 1,

	test_files => 't/*.t xt/*.t',
);

$build->create_build_script;
