package MyTest::Net::NSCA::Client::InitialPacket;

use strict;
use warnings 'all';

use Test::Exception 0.03;
use Test::More 0.18;

use base 'MyTest::Class';

sub constructor_new : Tests(4) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	# Make a HASH of arguments for constructor
	my %options = (
		initialization_vector => 'thisisnotagoodiv',
	);

	# Make sure new exists
	can_ok $class, 'new';

	# Constructor with HASH
	my $packet = new_ok $class, [%options];

	# Constructor with HASHREF
	$packet = new_ok $class, [\%options];

	dies_ok { $class->new(bad_argument => 1) } 'Constructor dies on non-existant attribute';

	return;
}

sub attribute_initialization_vector : Tests(3) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	can_ok $class, 'initialization_vector';

	# Get a basic packet
	my $packet = $class->new;

	{
		no strict 'refs';
		is length($packet->initialization_vector), 128, 'Default iv is right length';
	}

	# Get a custom packet
	$packet = $class->new(initialization_vector => 'IamBADiv');

	{
		no strict 'refs';
		is length($packet->initialization_vector), 128, 'Custom iv is right length';
	}

	return;
}

sub initial_packet_generation : Tests(9) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	# Make a packet
	my $packet = $class->new;

	# Should stringify to the packet
	unlike "$packet", qr{$class}msx, 'Stringifies to packet';

	# Can we to_string?
	can_ok $class, 'to_string';

	# Stringify is the same as to_string
	is "$packet", $packet->to_string, 'Stringify uses to_string';

	# Decode the packet using the new constructor
	my $decoded_packet = new_ok $class, ["$packet"];

	# Make sure the decoding worked
	is $decoded_packet->initialization_vector, $packet->initialization_vector, 'initialization_vector decoded correctly';
	is $decoded_packet->unix_timestamp       , $packet->unix_timestamp       , 'unix_timestamp decoded correctly';

	# Random bad data fails
	dies_ok { $class->new('I am garbage') } 'Garbage does not decode';

	# Decode packet and check
	$decoded_packet = $class->new($test->_packet);

	# Checking the list
	is $decoded_packet->initialization_vector,
		"\x1B\x04\x75\x77\xED\x09\x1F\x8A\x3C\xC2\x2C\xAC\xE7\x78\xAE\xB3".
		"\xF1\x24\x03\x89\x9C\x75\xE9\x41\x56\x54\x26\xBE\x48\x7C\xAA\x54".
		"\xDE\xFE\xF8\x3F\x87\x85\x94\xA1\x8F\x22\x7C\x1D\x49\x64\xDE\x5A".
		"\xB8\xA3\x27\x6D\x9C\x4D\xCB\x83\x51\x18\x07\x41\xD3\x87\xD2\xD7".
		"\xB8\x2F\xB9\x2F\x4F\x83\xDE\x05\x71\x96\x88\xA9\x13\xA7\x8A\x5E".
		"\x3A\x5F\x38\x95\x9C\x11\x0E\x17\xD9\x89\x57\x5B\x12\x0E\xF7\x39".
		"\xEA\x55\xFB\x56\xD9\x4D\xE6\xC5\xB7\x3C\x9D\x2E\x60\x0C\xA0\x96".
		"\xA0\xA4\x50\x25\x70\x5E\xAA\xD7\xAD\x03\x3C\xB0\x15\x5A\x0D\x2F",
		'initialization_vector decoded correctly';
	is $decoded_packet->unix_timestamp       , 1254605822         , 'unix_timestamp decoded correctly';
}

sub _packet {
	my $packet = <<ENDPACKET;
1B047577ED091F8A3CC22CACE778AEB3F12403899C75E941565426BE487CAA54DEFEF83F878594A
18F227C1D4964DE5AB8A3276D9C4DCB8351180741D387D2D7B82FB92F4F83DE05719688A913A78A
5E3A5F38959C110E17D989575B120EF739EA55FB56D94DE6C5B73C9D2E600CA096A0A45025705EA
AD7AD033CB0155A0D2F4AC7C3FE
ENDPACKET

	# Remove all new lines
	$packet =~ s{[\r\n]+}{}gmsx;

	# Change the hexidecimal to bytes
	$packet =~ s{(..)}{ chr hex $1 }egmsx;

	return $packet;
}

1;
