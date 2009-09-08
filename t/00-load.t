#!perl -T

use Test::More 0.41 tests => 1;

BEGIN {
	use_ok('Net::NSCA::Client');
}

diag("Testing Net::NSCA::Client $Net::NSCA::Client::VERSION, Perl $], $^X");
