use inc::Module::Install;

name     'Net-NSCA-Client';
all_from 'lib/Net/NSCA/Client.pm';
author   'Douglas Christopher Wilson <doug@somethingdoug.com>';
license  'perl';

# Resources
resources homepage   => 'http://github.com/dougwilson/perl5-net-nsca-client/';
resources repository => 'git://github.com/dougwilson/perl5-net-nsca-client.git';

# Modules that are required
requires
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
	'namespace::clean'          => '0.04';

# Modules that are required for tests
test_requires
	'Test::Class'    => '0.33',
	'Test::Most'     => 0,
	'Test::Requires' => '0.02';

# Modules that are required for author tests
author_requires
	'File::Spec'                      => 0,
	'Module::Install'                 => '0.91',
	'Module::Install::AuthorRequires' => '0.02',
	'Module::Install::AuthorTests'    => '0.002',
	'Pod::Coverage'                   => '0.18',
	'Test::CleanNamespaces'           => 0,
	'Test::ConsistentVersion'         => 0,
	'Test::DistManifest'              => 0,
	'Test::MinimumVersion'            => '0.009',
	'Test::Perl::Critic'              => 0,
	'Test::Pod'                       => '1.22',
	'Test::Pod::Content'              => 0,
	'Test::Pod::Coverage'             => '1.08';

# Enable tests to be in multi-level directories
tests_recursive;

# Author tests in xt/
recursive_author_tests('xt');

WriteAll;
