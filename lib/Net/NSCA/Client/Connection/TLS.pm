package Net::NSCA::Client::Connection::TLS;

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
use English qw(-no_match_vars);

###############################################################################
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###############################################################################
# ATTRIBUTES
has encryption_type => (
	is  => 'rw',
	isa => 'Str',

	default => 'xor',
);

###############################################################################
# METHODS
sub encrypt {
	my ($self, %args) = @_;

	# Splice out the arguments
	my ($byte_stream, $iv, $password) = @args{qw(byte_stream iv password)};

	# Set the encrypted byte stream to the byte stream by default
	my $encrypted_byte_stream = "$byte_stream";

	if ($self->encryption_type eq 'xor') {
		# This is a custom NSCA XOR "encryption"
		$encrypted_byte_stream = $self->_xor_encrypt($byte_stream, $iv, $password);
	}
	else {
		# We will be using Mcrypt for the encryption
		$encrypted_byte_stream = $self->_mcrypt_encrypt($byte_stream, $iv, $password);
	}

	# Return the encrypted byte stream
	return $encrypted_byte_stream;
}

###############################################################################
# PRIVATE METHODS
sub _mcrypt_encrypt {
	my ($self, $byte_stream, $iv, $password) = @_;

	if (!eval { require Mcrypt; 1; }) {
		# The Mcrypt failed to load
		confess sprintf 'To use encryption methods, the Mcrypt library must be present. %s',
			$EVAL_ERROR;
	}

	# Initialize Mcrypt
	my $mcrypt = Mcrypt->new(
		algorithm => $self->encryption_type,
		mode      => 'cfb',
		verbose   => 0,
	);

	if (!defined $mcrypt) {
		# Unable to initialize the Mcrypt
		confess 'Unable to initialize Mcrypt; unknown encryption type %s',
			$self->encryption_type;
	}

	# Convert the byte stream into an array for manipulation
	my @byte_stream = split m{}msx, $byte_stream;

	# Cut or pad the IV to the IV size for the given type
	$iv = (substr $iv, 0, $mcrypt->{IV_SIZE}) . "\0"x($mcrypt->{IV_SIZE} - length $iv);

	# Initialize the encryption
	$mcrypt->init($password, $iv);

	foreach my $byte_index (0..$#byte_stream) {
		# Encrypt each byte
		$byte_stream[$byte_index] = $mcrypt->encrypt($byte_stream[$byte_index]);
	}

	# End the encryption
	$mcrypt->end;

	# Return the manipulated byte stream
	return join q{}, @byte_stream;
}
sub _xor_encrypt {
	my ($self, $byte_stream, $iv, $password) = @_;

	# Make a byte array of the IV
	my @byte_iv = split m{}msx, $iv;

	# Make a byte array of the password if there is a password
	my @byte_password = defined $password ? (split m{}msx, $password) : ();

	# Convert the byte stream into an array for manipulation
	my @byte_stream = split m{}msx, $byte_stream;

	foreach my $byte_index (0..$#byte_stream) {
		# Foreach byte in the byte stream, XOR the byte with the IV
		$byte_stream[$byte_index] ^= $byte_iv[$byte_index % scalar @byte_iv];

		if (defined $password) {
			# If there is a password, XOR the byte with the password
			$byte_stream[$byte_index] ^= $byte_password[$byte_index % scalar @byte_password];
		}
	}

	# Return the manipulated byte stream
	return join q{}, @byte_stream;
}

1;

__END__

=head1 NAME

Net::NSCA::Client::Connection::TLS - Represents the transport layer security on
a connection.

=head1 VERSION

This documentation refers to L<Net::NSCA::Client::Connection::TLS> version
0.001

=head1 SYNOPSIS

  use Net::NSCA::Client::Connection::TLS;

  # Create a new connection TLS
  my $tls = Net::NSCA::Client::Connection::TLS->new(
    encryption_type => $Net::NSCA::Client::Connection::TLS::ENCRYPTION_TYPE_BLOWFISH,
    password        => $my_secret_password,
  );

  # Encrypt a packet
  my $encrypted_packet = $tls->encrypt(
    byte_stream => $data_packet,
    iv          => $iv_salt,
  );

=head1 DESCRIPTION

Represents a connection between the NSCA client and server.

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

=back

=head1 ATTRIBUTES

  # Set an attribute
  $object->attribute_name($new_value);

  # Get an attribute
  my $value = $object->attribute_name;

=head2 encryption_type

This is the type of encryption for this transport layer security object. This
will default to "none".

=head1 METHODS

=head2 encrypt

This will encrypt a byte stream according to the attributes of the object. This
method takes a HASH of arguments with the following keys:

=head3 byte_stream

B<Required>

This is the byte stream to encrypt.

=head3 iv

B<Required>

This is the initialization vector to use when encrypting the byte stream.

=head3 password

This is the password to use for the encryption.

=head1 CONSTANTS

B<TODO: Write this>

=head1 DEPENDENCIES

=over

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
