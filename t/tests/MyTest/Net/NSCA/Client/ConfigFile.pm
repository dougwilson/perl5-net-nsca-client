package MyTest::Net::NSCA::Client::ConfigFile;

use strict;
use warnings 'all';

use Data::Section '-setup';
use IO::String ();
use Test::Fatal;
use Test::More 0.18;

use base 'MyTest::Class';

sub parse_send_nsca_config : Test(no_plan) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	# Get the parse function
	can_ok($class, 'parse_send_nsca_config');
	my $parser = $class->can('parse_send_nsca_config');

	# Test IO issues
	ok(exception { my $io = IO::String->new; $io->close; $parser->($io) },
		'Invalid file throws error');

	CONFIG:
	for my $config_name (qw[no_encryption_config sample_config]) {
		# Get the expected results
		my $result = eval ${$test->section_data($config_name . '_result')};

		# Get an IO steam for the config
		my $io = $test->_section_io($config_name);

		# Parse the config file
		my $config = $parser->($io);

		# Check against the expected result
		is_deeply($config, $result, "$config_name parsed correctly");
	}

	ok(exception { $parser->($test->_section_io('no_value_config')) }, 'No value throws exception');
	ok(exception { $parser->($test->_section_io('no_name_config')) }, 'No name throws exception');

	ok(exception { $parser->($test->_section_io('unknown_var_config')) },
		'By default unknown var name throws expection');
	ok(exception { $parser->($test->_section_io('unknown_var_config'), is_strict => 1) },
		'Under strict unknown var name throws expection');
	ok(!exception { $parser->($test->_section_io('unknown_var_config'), is_strict => 0) },
		'No strict unknown var name does not throw expection');

	ok(exception { $parser->($test->_section_io('unknown_encryption_config')) },
		'Unknown encryption method throws expection');
}

sub _section_io { IO::String->new($_[0]->section_data($_[1])); }

1;

__DATA__
__[ no_encryption_config ]__
password=number1
encryption_method=0

__[ no_encryption_config_result ]__
{encryption_method => 'none', password => 'number1'}

__[ no_name_config ]__
password=test
encryption_method=1
line of junk

__[ no_value_config ]__
password=
encryption_method=1

__[ sample_config ]__
####################################################
# Sample NSCA Client Config File 
# Written by: Ethan Galstad (nagios@nagios.org)
# 
# Last Modified: 02-21-2002
####################################################


# ENCRYPTION PASSWORD
# This is the password/passphrase that should be used to encrypt the
# outgoing packets.  Note that the nsca daemon must use the same 
# password when decrypting the packet!
# IMPORTANT: You don't want all the users on this system to be able
# to read the password you specify here, so make sure to set
# restrictive permissions on this config file!

#password=



# ENCRYPTION METHOD
# This option determines the method by which the send_nsca client will
# encrypt the packets it sends to the nsca daemon.  The encryption
# method you choose will be a balance between security and performance,
# as strong encryption methods consume more processor resources.
# You should evaluate your security needs when choosing an encryption
# method.
#
# Note: The encryption method you specify here must match the
#       decryption method the nsca daemon uses (as specified in
#       the nsca.cfg file)!!
# Values:
#       0 = None        (Do NOT use this option)
#       1 = Simple XOR  (No security, just obfuscation, but very fast)
#
#       2 = DES
#       3 = 3DES (Triple DES)
#       4 = CAST-128
#       5 = CAST-256
#       6 = xTEA
#       7 = 3WAY
#       8 = BLOWFISH
#       9 = TWOFISH
#       10 = LOKI97
#       11 = RC2
#       12 = ARCFOUR
#
#       14 = RIJNDAEL-128
#       15 = RIJNDAEL-192
#       16 = RIJNDAEL-256
#
#       19 = WAKE
#       20 = SERPENT
#
#       22 = ENIGMA (Unix crypt)
#       23 = GOST
#       24 = SAFER64
#       25 = SAFER128
#       26 = SAFER+
#

encryption_method=1

__[ sample_config_result ]__
{encryption_method => 'xor'}

__[ unknown_encryption_config ]__
password=test
encryption_method=999

__[ unknown_var_config ]__
password=test
cake=lie
