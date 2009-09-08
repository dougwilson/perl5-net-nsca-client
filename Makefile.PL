use inc::Module::Install;

name     'Net-NSCA-Client';
all_from 'lib/Net/NSCA/Client.pm';
author   'Douglas Christopher Wilson <doug@somethingdoug.com>';
license  'perl';

# Modules that are required
requires 'URI'              => 0;
requires 'base'             => 0;
requires 'namespace::clean' => 0;

test_requires 'Test::More' => 0;

# Modules that are required for author tests
author_requires 'Pod::Coverage'           => '0.18';
author_requires 'Test::CleanNamespaces'   => 0;
author_requires 'Test::ConsistentVersion' => 0;
author_requires 'Test::DistManifest'      => 0;
author_requires 'Test::MinimumVersion'    => '0.009';
author_requires 'Test::Perl::Critic'      => 0;
author_requires 'Test::Pod'               => '1.22';
author_requires 'Test::Pod::Content'      => 0;
author_requires 'Test::Pod::Coverage'     => '1.08';

# Enable tests to be in multi-level directories
tests_recursive;

# Author tests in xt/
recursive_author_tests('xt');

WriteAll;
