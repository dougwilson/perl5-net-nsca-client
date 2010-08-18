package MyTest::Net::NSCA::Client::DataPacket;

use strict;
use warnings 'all';

use Test::Exception 0.03;
use Test::More 0.18;

use base 'MyTest::Class';

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
000300000D9E4EF14AC7ADCE00007777772E6578616D706C652E636F6D00325437476D61384E374
E4F6C51313334474A6F6E74305177555A3171436A433778645644304C6A34443941443843395154
657374003763596739504D4E466530443875795041754C464A6C7A77446B6F5A48556D6E6C52515
8317379554D6B3233454D74374E5A375037706B3566615645476F724D466E314252647459496930
4E3630347434614C76454A767045375243363252316E46736342586A324B496D44796D793546377
A5A315A364D4B56344F4B202D2054657374696E672066696E65006635526C653749346935627135
564450794D37386A4739636A346975763153756278584478593449584B755433643658567333576
862623677494C5042464754516E6769717138567A433554656E424C456D5059554E3878384B6369
364E49366663547547373047326C57637A3364634A5639433639664D614342697230366D7648625
15042614E4E71465973754D525234326A6D766C666A544F78473238574164627238794570397861
78674343706D6F444375715A334152353646486F304B663548366D61397A37384273486A666A6D6
76E4E79496C64534C6E35556D4B643754737956436A615236687763355559375A796E7031323446
4D3173614846436F39306155464F3849784C6E756648646773545572757238736F4459535462794
5516A4867423278446A46797A61357437616F75524361463748466D6B4D7331596C307833637455
4C6C5A5A446D6D4537377A5953555872326E59756C6671554846505A483871394242567A5035557
37A5175704E785675366174374A56326B30454B5574396571756633354536544D784946576B6877
3369447A656D325938436E6E376E4C4F64573542684150787568524A4F53393139764B4B475A393
761754866326B58796E73685731764E4A657964545230394A3459764D6F4C655245435770394865
7A76666B6347630000
ENDPACKET

	# Remove all new lines
	$packet =~ s{[\r\n]+}{}gmsx;

	# Change the hexidecimal to bytes
	$packet =~ s{(..)}{ chr hex $1 }egmsx;

	return $packet;
}

1;
