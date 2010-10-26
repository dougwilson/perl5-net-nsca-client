package Net::NSCA::Client::Connection::TLS;

use 5.008001;
use strict;
use warnings 'all';

###############################################################################
# METADATA
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.008';

###############################################################################
# MOOSE
use Moose 0.89;
use MooseX::StrictConstructor 0.08;

###############################################################################
# MODULES
use Class::MOP ();
use Const::Fast qw(const);
use Try::Tiny;

###############################################################################
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###############################################################################
# PRIVATE CONSTANTS
const my %encryption_method => (
	rijndael_128 => [
		{
			class  => [qw(Crypt::Rijndael)],
			method => sub { shift->_validate_rijndael_128->_rijndael_128_encrypt(@_) },
		},
		{
			class  => [qw(Mcrypt)],
			method => sub { shift->_validate_rijndael_128->_mcrypt_encrypt(@_, 'rijndael-128') },
		},
	],
	xor => [{method => \&_xor_encrypt}],
);

###############################################################################
# ATTRIBUTES
has encryption_type => (
	is  => 'rw',
	isa => 'Str',

	default => 'xor',
);
has password => (
	is  => 'rw',
	isa => 'Str',

	clearer   => 'clear_password',
	predicate => 'has_password',
);

###############################################################################
# METHODS
sub encrypt {
	my ($self, %args) = @_;

	# Splice out the arguments
	my ($byte_stream, $iv) = @args{qw(byte_stream iv)};

	if (!exists $encryption_method{$self->encryption_type}) {
		Moose->throw_error(sprintf 'Unsupported encryption type %s',
			$self->encryption_type);
	}

	# Get encryption method information
	my $methods = $encryption_method{$self->encryption_type};
	my $encrypt;
	my $error;

	METHOD:
	for my $method (@{$methods}) {
		try {
			if (exists $method->{class}) {
				# This method requires some classes to be loaded
				CLASS:
				for my $class (@{$method->{class}}) {
					Class::MOP::load_class($class);
				}
			}

			# Use this method
			$encrypt = $method->{method};
		}
		catch {
			# Record only the first error
			$error = $_ if !defined $error;
		};

		last METHOD if defined $encrypt;
	}

	if (!defined $encrypt) {
		die $error;
	}

	# Encrypt the byte stream
	my $encrypted_byte_stream = $encrypt->($self, $byte_stream, $iv);

	# Return the encrypted byte stream
	return $encrypted_byte_stream;
}

###############################################################################
# PRIVATE METHODS
sub _mcrypt_encrypt {
	my ($self, $byte_stream, $iv, $algorithm) = @_;

	# Create a cipher object
	my $cipher = Mcrypt->new(
		algorithm => $algorithm,
		mode      => 'cfb',
		verbose   => 0,
	);

	# Adjust the IV size
	$iv = _pad_string($iv, $cipher->{IV_SIZE});

	my $key = $self->password;

	if ($cipher->{KEY_SIZE} > length $key) {
		$key .= "\x00" x ($cipher->{KEY_SIZE} - length $key);
	}

	$cipher->init($self->password, $iv);

	my $encrypted_stream = join q{}, map { $cipher->encrypt($_) } split qr{}msx, $byte_stream;

	return $encrypted_stream;
}
sub _rijndael_128_encrypt {
	my ($self, $byte_stream, $iv) = @_;

	# Create a cipher object
	my $cipher = Crypt::Rijndael->new($self->password, Crypt::Rijndael::MODE_ECB());

	# Set the register to the IV
	my $register = _pad_string($iv, $cipher->blocksize);

	# Encrypt the byte stream
	my $encrypted_stream = join q{}, map {
		my $out = $cipher->encrypt($register);

		my $byte = $_ ^ substr $out, 0, 1;

		$register = substr($register, 1) . $byte;

		$byte;
	} split qr{}msx, $byte_stream;

	return $encrypted_stream;
}
sub _validate_rijndael_128 {
	my ($self) = @_;

	if (!$self->has_password || 32 != length $self->password) {
		Moose->throw_error('Rijndael-128 must have a 128-bit password');
	}

	return $self;
}
sub _xor_encrypt {
	my ($self, $byte_stream, $iv) = @_;

	# Make a byte array of the IV
	my @byte_iv = split m{}msx, $iv;

	# Make a byte array of the password if there is a password
	my @byte_password = $self->has_password ? (split m{}msx, $self->password) : ();

	# Convert the byte stream into an array for manipulation
	my @byte_stream = split m{}msx, $byte_stream;

	foreach my $byte_index (0..$#byte_stream) {
		# Foreach byte in the byte stream, XOR the byte with the IV
		$byte_stream[$byte_index] ^= $byte_iv[$byte_index % scalar @byte_iv];

		if ($self->has_password) {
			# If there is a password, XOR the byte with the password
			$byte_stream[$byte_index] ^= $byte_password[$byte_index % scalar @byte_password];
		}
	}

	# Return the manipulated byte stream
	return join q{}, @byte_stream;
}

###############################################################################
# PRIVATE FUNCTIONS
sub _pad_string {
	my ($string, $to_length) = @_;

	if ($to_length < length $string) {
		# Chop the end of the string
		$string = substr $string, 0, $to_length;
	}
	elsif ($to_length > length $string) {
		# Pad with NULL
		$string .= "\x00" x ($to_length - length $string);
	}

	return $string;
}

###############################################################################
# MAKE MOOSE OBJECT IMMUTABLE
__PACKAGE__->meta->make_immutable;

1;

__END__

=head1 NAME

Net::NSCA::Client::Connection::TLS - Represents the transport layer security on
a connection.

=head1 VERSION

This documentation refers to version 0.008

=head1 SYNOPSIS

  use Net::NSCA::Client::Connection::TLS;

  # Create a new connection TLS
  my $tls = Net::NSCA::Client::Connection::TLS->new(
    encryption_type => 'xor',
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
will default to "xor".

=head2 password

This is the password to use for the encryption.

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

=head1 CONSTANTS

B<TODO: Write this>

=head1 DEPENDENCIES

=over

=item * L<Moose|Moose> 0.89

=item * L<MooseX::StrictConstructor|MooseX::StrictConstructor> 0.08

=item * L<namespace::clean|namespace::clean> 0.04

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
