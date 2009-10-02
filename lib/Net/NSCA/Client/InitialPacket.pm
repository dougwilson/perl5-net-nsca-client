package Net::NSCA::Client::InitialPacket;

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
use Crypt::Random;
use Readonly 1.03;

###############################################################################
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###############################################################################
# OVERLOADED FUNCTIONS
__PACKAGE__->meta->add_package_symbol(q{&()}  => sub {                  });
__PACKAGE__->meta->add_package_symbol(q{&(""} => sub { shift->to_string });

###############################################################################
# PRIVATE CONSTANTS
Readonly my $BYTES_FOR_16BITS    => 2;
Readonly my $BYTES_FOR_32BITS    => 4;
Readonly my $TRANSMITTED_IV_SIZE => 128;

###############################################################################
# ATTRIBUTES
has initialization_vector => (
	is  => 'ro',
	isa => 'Str',

	builder => '_build_initialization_vector',
);
has unix_timestamp => (
	is  => 'ro',
	isa => 'Int',

	default => sub { scalar time },
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
		iv        => $self->initialization_vector,
		timestamp => $self->unix_timestamp,
	);

	# Get the packer data object
	my $packer = _init_packet_struct();

	# To construct the packet, we will use the pack method from the
	# Convert::Binary::C object
	my $packet = $packer->pack(init_packet_struct => \%pack_options);

	# Return the packet
	return $packet;
}

###############################################################################
# PRIVATE METHODS
sub _build_initialization_vector {
	my ($self) = @_;

	return Crypt::Random::makerandom(
		Size     => $TRANSMITTED_IV_SIZE,
		Strength => 1,
	);
}

###############################################################################
# PRIVATE FUNCTIONS
sub _constructor_options_from_string {
	my ($packet) = @_;

	# Get the packer data object
	my $packer = _init_packet_struct();

	# Unpack the data packet
	my $unpacket = $packer->unpack(init_packet_struct => $packet);

	# Return the options for the constructor
	return (
		initialization_vector => $unpacket->{iv       },
		unix_timestamp        => $unpacket->{timestamp},
	);
}
sub _init_packet_struct {
	# Create a C object
	my $c = _setup_c_object();

	# Add the init_packet_struct structure
	$c->parse(<<"ENDC");
		struct init_packet_struct {
			char      iv[$TRANSMITTED_IV_SIZE];
			u_int32_t timestamp;
		};
ENDC

	# Tag the IV as a binary string
	$c->tag('init_packet_struct.iv', Format => 'Binary');

	return $c;
}
sub _setup_c_object {
	my ($c) = @_;

	# If no object provided, create a new one
	$c ||= Convert::Binary::C->new;

	# Set the memory structure to store in network order
	$c->ByteOrder('BigEndian');

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

1;

__END__

=head1 NAME

Net::NSCA::Client::InitialPacket - Implements initial packet for the NSCA
protocol

=head1 VERSION

This documentation refers to L<Net::NSCA::Client::InitialPacket> version 0.001

=head1 SYNOPSIS

  use Net::NSCA::Client::InitialPacket;

  # Create a packet from scratch
  my $packet = Net::NSCA::Client::InitialPacket->new(
    initialization_vector => $iv,
    unix_timestamp        => time(),
  );

  # Create a packet recieved from over the network
  my $recieved_packet = Net::NSCA::Client::InitialPacket->new($recieved_data);

=head1 DESCRIPTION

Represents the initial packet used in the NSCA protocol.

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

=head2 initialization_vector

This is a binary string, which is the exact length of the constant
L</$TRANSMITTED_IV_SIZE>. If a string less than this length is provided,
then it is automatically padded with NULLs. If not specified, this will
default to random bytes generated by a L<Crypt::Random>.

=head2 unix_timestamp

This is a UNIX timestamp, which is an integer specifying the number of
non-leap seconds since the UNIX epoch. If not specified, this will default
to the current timestamp, provided by C<time()>.

=head1 METHODS

=head2 to_string

This methods returns the string representation of the initial packet. This
string representation is what will be sent over the network.

=head1 CONSTANTS

Constants provided by this library are protected by the L<Readonly> module.

=head2 C<$TRANSMITTED_IV_SIZE>

This is the length of the L</initialization_vector>.

=head1 DEPENDENCIES

=over

=item * L<Convert::Binary::C> 0.74

=item * L<Crypt::Random>

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
