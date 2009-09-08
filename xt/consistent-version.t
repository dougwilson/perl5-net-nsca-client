#!perl

use 5.008;
use strict;
use warnings 'all';

use Test::More;

# Only authors get to run this test
plan skip_all => 'Set TEST_AUTHOR to enable this test'
	unless $ENV{'TEST_AUTHOR'} || -e 'inc/.author';

plan skip_all => 'Test::ConsistentVersion required to test consistency of version'
	unless eval 'use Test::ConsistentVersion; 1';

# Run tests
Test::ConsistentVersion::check_consistent_versions();

