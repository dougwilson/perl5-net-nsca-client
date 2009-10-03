package Test::Net::NSCA::Client::DataPacket;

use strict;
use warnings 'all';

use Test::Most;

use base 'Test::Class';

sub class { 'Net::NSCA::Client::DataPacket' }

sub startup : Tests(startup) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	# Load the class to test
	eval "use $class";

	die $@ if $@;

	return;
}

sub constructor_new : Tests(5) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	# Make a HASH of arguments for constructor
	my %options = (
		hostname            => 'www.example.net',
		service_description => 'Apache',
		service_message     => 'OK - Apache running',
		service_status      => 0,
	);

	# Make sure new exists
	can_ok $class, 'new';

	# Constructor with HASH
	my $packet = new_ok $class, [%options];

	# Constructor with HASHREF
	$packet = new_ok $class, [\%options];

	dies_ok { $class->new } 'Constructor dies with no options';
	dies_ok { $class->new(bad_argument => 1) } 'Constructor dies on non-existant attribute';

	return;
}

sub data_packet_generation : Tests(no_plan) {
	my ($test) = @_;

	# Get the name of the class we are testing
	my $class = $test->class;

	# Make a HASH of arguments for constructor
	my %options = (
		hostname            => 'www.example.net',
		service_description => 'Apache',
		service_message     => 'OK - Apache running',
		service_status      => 0,
	);

	# Make a packet
	my $packet = $class->new(%options);

	# Should stringify to the packet
	unlike "$packet", qr{$class}msx, 'Stringifies to packet';

	# Can we to_string?
	can_ok $class, 'to_string';

	# Stringify is the same as to_string
	is "$packet", $packet->to_string, 'Stringify uses to_string';

	# Decode the packet using the new constructor
	my $decoded_packet = new_ok $class, ["$packet"];

	# Make sure the decoding worked
	is $decoded_packet->hostname           , $packet->hostname           , 'hostname decoded correctly';
	is $decoded_packet->packet_version     , $packet->packet_version     , 'packet_version decoded correctly';
	is $decoded_packet->service_description, $packet->service_description, 'service_description decoded correctly';
	is $decoded_packet->service_message    , $packet->service_message    , 'service_message decoded correctly';
	is $decoded_packet->service_status     , $packet->service_status     , 'service_status decoded correctly';
	is $decoded_packet->unix_timestamp     , $packet->unix_timestamp     , 'unix_timestamp decoded correctly';

	# Random bad data fails
	dies_ok { $class->new('I am garbage') } 'Garbage does not decode';

	# Decode two packets which should be the same
	foreach my $packet_bytes ($test->_packet1, $test->_packet2) {
		$decoded_packet = $class->new($packet_bytes);

		# Checking the list
		is $decoded_packet->hostname           , 'www.example.com'  , 'hostname decoded correctly';
		is $decoded_packet->packet_version     , 3                  , 'packet_version decoded correctly';
		is $decoded_packet->service_description, 'Test'             , 'service_description decoded correctly';
		is $decoded_packet->service_message    , 'OK - Testing fine', 'service_message decoded correctly';
		is $decoded_packet->service_status     , 0                  , 'service_status decoded correctly';
		is $decoded_packet->unix_timestamp     , 1254600142         , 'unix_timestamp decoded correctly';
	}
}

sub _packet1 {
	my $packet = <<ENDPACKET;
00030000EE9374CB4AC7ADCE00007777772E6578616D706C652E636F6D000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000054
6573740000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000004F4B202D2054657374696E672066696E650000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000
ENDPACKET

	# Remove all new lines
	$packet =~ s{[\r\n]+}{}gmsx;

	# Change the hexidecimal to bytes
	$packet =~ s{(..)}{ chr hex $1 }egmsx;

	return $packet;
}

sub _packet2 {
	my $packet = <<ENDPACKET;
0003ABABEE9374CB4AC7ADCE00007777772E6578616D706C652E636F6D00ABC23445ABC234ADD32
0000000000000000000000000000000000000000000000000000000000000000000000000003054
6573740030303030303030303030000000000000000000000000000000000000000000000000000
0000000000000000000000000000081364235245762475623179462390000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000204F4B202D2054657374696E672066696E650023443645764674600000000000
0000000000000000000000000000000000000000000000000000000000000000000034500000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000045746746734534523460000000000000000000000000000000000000
0000000000000000000000000000000000000000002565645645000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000035635263256352623600000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000035635266645662356000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000003563566456335623630000000000000000000000000000000000000000000000000000
000000000000035635
ENDPACKET

	# Remove all new lines
	$packet =~ s{[\r\n]+}{}gmsx;

	# Change the hexidecimal to bytes
	$packet =~ s{(..)}{ chr hex $1 }egmsx;

	return $packet;
}

1;
