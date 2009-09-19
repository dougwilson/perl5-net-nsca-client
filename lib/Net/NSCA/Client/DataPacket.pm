package Net::NSCA::Client::DataPacket;

use 5.008001;
use strict;
use warnings 'all';

###############################################################################
# METADATA
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.001';

###############################################################################
# MOOSE
use Moose 0.89;
use MooseX::StrictConstructor 0.08;

###############################################################################
# MODULES
use Convert::Binary::C 0.74;
use Digest::CRC qw(crc32);
use Readonly 1.03;

###############################################################################
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###############################################################################
# CONSTANTS
Readonly our $MAX_HOSTNAME_LENGTH            => 64;
Readonly our $MAX_SERVICE_DESCRIPTION_LENGTH => 128;
Readonly our $MAX_SERVICE_MESSAGE_LENGTH     => 512;

###############################################################################
# OVERLOADED FUNCTIONS
__PACKAGE__->meta->add_package_symbol(q{&()}  => sub {                  });
__PACKAGE__->meta->add_package_symbol(q{&(""} => sub { shift->to_string });

###############################################################################
# PRIVATE CONSTANTS
Readonly my $BYTES_FOR_16BITS => 2;
Readonly my $BYTES_FOR_32BITS => 4;

###############################################################################
# ATTRIBUTES
has hostname => (
	is  => 'ro',
	isa => 'Str',

	required => 1,
);
has packet_version => (
	is  => 'ro',
	isa => 'Int',

	default       => 3,
	documentation => q{The version of the packet being transmitted},
);
has service_description => (
	is  => 'ro',
	isa => 'Str',

	required => 1,
);
has service_message => (
	is  => 'ro',
	isa => 'Str',

	required => 1,
);
has service_status => (
	is  => 'ro',
	isa => 'Int',

	required => 1,
);
has unix_timestamp => (
	is  => 'ro',
	isa => 'Int',

	required => 1,
);

###############################################################################
# CONSTRUCTOR
around BUILDARGS => sub {
	my ($original_method, $class, @args) = @_;

	if (@args == 0 && !ref $args[0]) {
		# This should be the packet as a string, so get the new
		# args from this string
		@args = _constructor_options_from_string($args[0]);
	}

	# Call the original method
	return $class->$original_method(@args);
};

###############################################################################
# METHODS
sub to_string {
	my ($self) = @_;

	# Create a HASH of the value to be provided to the pack
	my %pack_options = (
		crc32_value     => 0,
		host_name       => $self->hostname,
		packet_version  => $self->packet_version,
		plugin_output   => $self->service_message,
		timestamp       => $self->unix_timestamp,
		return_code     => $self->service_status,
		svc_description => $self->service_description,
	);

	# Get the packer data object
	my $packer = _data_packet_struct();

	# To construct the packet, we will use the pack method from the
	# Convert::Binary::C object
	my $packet = $packer->pack(data_packet_struct => \%pack_options);

	# Calculate the CRC32 value for the packet
	$pack_options{crc32_value} = crc32($packet);

	# Repack the packet with the CRC32 value
	$packet = $packer->pack(data_packet_struct => \%pack_options);

	# Return the packet
	return $packet;
}

###############################################################################
# PRIVATE FUNCTIONS
sub _constructor_options_from_string {
	my ($packet) = @_;

	# Get the packer data object
	my $packer = _data_packet_struct();

	# Unpack the data packet
	my $unpacket = $packer->unpack(data_packet_struct => $packet);

	# Return the options for the constructor
	return (
		hostname            => $unpacket->{host_name      },
		packet_version      => $unpacket->{packet_version },
		service_description => $unpacket->{svc_description},
		service_message     => $unpacket->{plugin_output  },
		service_status      => $unpacket->{return_code    },
		unix_timestamp      => $unpacket->{timestamp      },
	);
}
sub _data_packet_struct {
	# Create a C object
	my $c = _setup_c_object();

	# Add the data_packet_struct structure
	$c->parse(<<"ENDC");
		struct data_packet_struct {
			int16_t   packet_version;
			u_int32_t crc32_value;
			u_int32_t timestamp;
			int16_t   return_code;
			char      host_name[$MAX_HOSTNAME_LENGTH];
			char      svc_description[$MAX_SERVICE_DESCRIPTION_LENGTH];
			char      plugin_output[$MAX_SERVICE_MESSAGE_LENGTH];
		};
ENDC

	# Add the string hooks to all the string members
	foreach my $string_member (qw(host_name svc_description plugin_output)) {
		$c->tag("data_packet_struct.$string_member", Hooks => {
			pack   => [\&_string_randpad_pack, $c->arg(qw(DATA SELF TYPE)), 'data_packet_struct'],
			unpack =>  \&_string_unpack,
		});
	}

	return $c;
}
sub _setup_c_object {
	my ($c) = @_;

	# If no object provided, create a new one
	$c ||= Convert::Binary::C->new;

	# Set the memory structure to store in network order
	$c->ByteOrder('LittleEndian');

	# The alignment always seems to be 4 bytes, so set the alignment here
	$c->Alignment($BYTES_FOR_32BITS);

	# Create a HASH of sizes to types
	my %int_sizes;

	$int_sizes{$c->sizeof('int'          )} = 'int';
	$int_sizes{$c->sizeof('long int'     )} = 'long int';
	$int_sizes{$c->sizeof('long long int')} = 'long long int';
	$int_sizes{$c->sizeof('short int'    )} = 'short int';

	# Check the needed types are present
	if (!exists $int_sizes{$BYTES_FOR_16BITS}) {
		confess 'Your platform does not have any C data type that is 16 bits';
	}
	if (!exists $int_sizes{$BYTES_FOR_32BITS}) {
		confess 'Your platform does not have any C data type that is 32 bits';
	}

	# Now that the sizes are known, set up various typedefs
	$c->parse(sprintf 'typedef %s int16_t;'           , $int_sizes{$BYTES_FOR_16BITS});
	$c->parse(sprintf 'typedef unsigned %s u_int16_t;', $int_sizes{$BYTES_FOR_16BITS});
	$c->parse(sprintf 'typedef %s int32_t;'           , $int_sizes{$BYTES_FOR_32BITS});
	$c->parse(sprintf 'typedef unsigned %s u_int32_t;', $int_sizes{$BYTES_FOR_32BITS});

	# Return the object
	return $c;
}
sub _string_randpad_pack {
	my ($string, $c, $type, $struct) = @_;

	if (defined $struct) {
		$type = sprintf '%s.%s', $struct, $type;
	}

	# Cut off the NULL and anything after it
	($string) = $string =~ m{\A ([^\0]+)}msx;

	# Add NULL to the end of the string
	$string .= chr 0;

	# Get the max length
	my $max_length = $c->sizeof($type);

	# Check if the string is too long
	if ($max_length < length $string) {
		confess sprintf 'The string provided to %s is too long. Max length is %s bytes',
			$type, $max_length - 1;
	}

	# Create an array of letters and numbers
	my @letters_and_numbers = ('a'..'z', 'A'..'Z', '0'..'9');

	# Pad the remaining space with random ASCII characters
	while ($max_length > length $string) {
		$string .= $letters_and_numbers[int rand @letters_and_numbers];
	}

	# Return the string
	return [unpack 'c*', $string];
}
sub _string_unpack {
	my ($c_string_struct) = @_;

	# Return the Perl string
	return pack 'Z*', @{$c_string_struct->{buf}};
}

1;

__END__

=head1 NAME

Net::NSCA::Client::DataPacket - Implements data packet for the NSCA protocol

=head1 VERSION

This documentation refers to L<Net::NSCA::Client::DataPacket> version 0.001

=head1 SYNOPSIS

  use Net::NSCA::Client;
  use Net::NSCA::Client::DataPacket;

  # Create a packet from scratch
  my $packet = Net::NSCA::Client::DataPacket->new(
    hostname            => 'www.example.net,
    service_description => 'Apache',
    service_message     => 'OK - Apache running',
    service_status      => $Net::NSCA::Client::STATUS_OK,
    unix_timestamp      => $iv_timestamp,
  );

  # Create a packet recieved from over the network
  my $recieved_packet = Net::NSCA::Client::DataPacket->new($recieved_data);

=head1 DESCRIPTION

Represents the data packet used in the NSCA protocol.

=head1 CONSTRUCTOR

This is fully object-oriented, and as such before any method can be used, the
constructor needs to be called to create an object to work with.

=head2 new

This will construct a new object.

=over

=item new(%attributes)

C<%attributes> is a HASH where the keys are attributes (specified in the
L</ATTRIBUTES> section).

=item new($attributes)

C<$attributes> is a HASHREF where the keys are attributes (specified in the
L</ATTRIBUTES> section).

=item new($packet_string)

C<$packet_string> is a string of the data packet in the network form.

=back

=head1 ATTRIBUTES

  # Set an attribute
  $object->attribute_name($new_value);

  # Get an attribute
  my $value = $object->attribute_name;

=head2 hostname

B<Required>

This is the host name of the host as listed in Nagios that the service
belongs to.

=head2 packet_version

This is the version of the packet to be sent. A few different NSCA servers use
slightly different version numbers, but the rest of the packet is the same.
If not specified, this will default to 3.

=head2 service_description

B<Required>

This is the service description as listed in Nagios of the service that this
report will be listed under.

=head2 service_message

This is the message that will be given to Nagios.

=head2 service_status

This is the status of the service that will be given to Nagios. It is
recommended to use one of the C<$STATUS_> constants provided by
L<Net::NSCA::Client>.

=head2 unix_timestamp

B<Required>

This is a UNIX timestamp, which is an integer specifying the number of
non-leap seconds since the UNIX epoch.

=head1 METHODS

=head2 to_string

This methods returns the string representation of the data packet. This string
representation is what will be sent over the network.

=head1 DEPENDENCIES

=over

=item * L<Convert::Binary::C> 0.74

=item * L<Digest::CRC>

=item * L<Moose> 0.89

=item * L<MooseX::StrictConstructor> 0.08

=item * L<Readonly> 1.03

=item * L<namespace::clean> 0.04

=back

=head1 AUTHOR

Douglas Christopher Wilson, C<< <doug at somethingdoug.com> >>

=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to C<bug-net-nsca-client at rt.cpan.org>,
or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-NSCA-Client>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

I highly encourage the submission of bugs and enhancements to my modules.

=head1 LICENSE AND COPYRIGHT

Copyright 2009 Douglas Christopher Wilson.

This program is free software; you can redistribute it and/or
modify it under the terms of either:

=over 4

=item * the GNU General Public License as published by the Free
Software Foundation; either version 1, or (at your option) any
later version, or

=item * the Artistic License version 2.0.

=back
