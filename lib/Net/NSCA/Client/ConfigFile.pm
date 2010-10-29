package Net::NSCA::Client::ConfigFile;

use 5.008001;
use strict;
use warnings 'all';

###########################################################################
# METADATA
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.009';

###########################################################################
# MOOSE
use Moose 0.89;
use MooseX::StrictConstructor 0.08;

###########################################################################
# MODULES
use Const::Fast qw(const);
use Try::Tiny;

###########################################################################
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###########################################################################
# PRIVATE CONSTANTS
const my %CONFIG_VARIABLE_ATTRIBUTE => (
	encryption_method => 'encryption_method',
	password          => 'encryption_password',
);
const my %CONFIG_VARIABLE_VALUE => (
	encryption_method => \&_encryption_method_from_number,
	password          => \&_untaint_password,
);
## no critic (ValuesAndExpressions::ProhibitMagicNumbers)
const my %ENCRYPTION_METHOD => (
	0  => 'none',
	1  => 'xor',
	2  => 'des',
	3  => 'triple_des',
	4  => 'cast5',
	5  => 'cast6',
	6  => 'xtea',
	7  => '3_way',
	8  => 'blowfish',
	9  => 'twofish',
	10 => 'loki97',
	11 => 'rc2',
	12 => 'rc4',
	14 => 'rijndael_128',
	15 => 'rijndael_192',
	16 => 'rijndael_256',
	19 => 'wake',
	20 => 'serpent',
	22 => 'enigma',
	23 => 'gost',
	24 => 'safer_k_64',
	25 => 'safer_k_128',
	26 => 'safer_plus',
);

###############################################################################
# ATTRIBUTES
has config_hash => (
	is  => 'ro',
	isa => 'HashRef',

	clearer   => '_clear_config_hash',
	predicate => 'has_config_hash',
);
has encryption_method => (
	is  => 'ro',
	isa => 'Str',

	clearer   => '_clear_encryption_method',
	predicate => 'has_encryption_method',
);
has encryption_password => (
	is  => 'ro',
	isa => 'Str',

	clearer   => '_clear_encryption_password',
	predicate => 'has_encryption_password',
);

###############################################################################
# CONSTRUCTOR
around BUILDARGS => sub {
	my ($original_method, $class, @args) = @_;

	# Call the original method to get args HASHREF
	my $args = $class->$original_method(@args);

	if (exists $args->{from_io}) {
		# Object will be constructed from a file IO
		if (exists $args->{config_hash}) {
			Moose->throw_error('Cannot specify both from_io and config_hash');
		}

		# Remove the IO from the argument list
		my $io = delete $args->{from_io};

		# Parse the file
		my $config = parse_send_nsca_config($io);

		# Set the config_hash
		$args->{config_hash} = $config;
	}

	if (exists $args->{config_hash}) {
		# We need to read out values in the hash into the individual
		# attributes.
		_add_values_from_config_hash(
			config_hash => $args->{config_hash},
			destination => $args,
		);
	}

	return $args;
};

###########################################################################
# FUNCTIONS
sub parse_send_nsca_config {
	my ($io, %args) = @_;

	# Determine if parsing should be strict
	my $is_strict = exists $args{is_strict} ? !!$args{is_strict} : 1;

	if (!$io->opened) {
		Moose->throw_error('Invalid file descripter');
	}

	# Clear errors on the IO handle
	$io->clearerr;

	# Hold the configuration data
	my %config;

	LINE:
	while (defined(my $line = $io->getline)) {
		chomp $line;

		# Skip blank lines and lines that begin with the comment character
		next LINE if length($line) == 0 || q{#} eq substr $line, 0, 1;

		# Split the line into name and value
		my ($name, $value) = split m{=}msx, $line, 2;

		if (!defined $value) {
			Moose->throw_error(
				sprintf 'No variable name specified in config file at line %d',
					$io->input_line_number
			);
		}

		if (!length $value) {
			Moose->throw_error(
				sprintf 'No variable value specified in config file at line %d',
					$io->input_line_number
			);
		}

		if (exists $CONFIG_VARIABLE_VALUE{$name}) {
			try {
				# Transform the value according to a defined rule
				$value = $CONFIG_VARIABLE_VALUE{$name}->($value);
			}
			catch {
				# Rethrow with the line number
				Moose->throw_error(
					sprintf '%s in config file at line %d',
						$_, $io->input_line_number
				);
			};
		}
		elsif ($is_strict) {
			# Under the strict parsing, this is an error
			Moose->throw_error(
				sprintf 'Unknown option specified in config file at line %d',
					$io->input_line_number
			);
		}

		# Save this configuration option
		$config{$name} = $value;
	}

	return \%config;
}

###########################################################################
# PRIVATE FUNCTIONS
sub _add_values_from_config_hash {
	my (%args) = @_;

	# Get the arguments
	my ($config, $destination) = @args{qw[config_hash destination]};

	CONFIG_KEY:
	for my $key (keys %{$config}) {
		if (exists $CONFIG_VARIABLE_ATTRIBUTE{$key}) {
			# Get the attribute name for this key
			my $attr = $CONFIG_VARIABLE_ATTRIBUTE{$key};

			# Set the value in the destination hash
			$destination->{$attr} = $config->{$key};
		}
	}

	return;
}
sub _encryption_method_from_number {
	my ($encryption_number) = @_;

	if (!exists $ENCRYPTION_METHOD{$encryption_number}) {
		Moose->throw_error(
			sprintf 'Invalid encryption method (%d)',
				$encryption_number
		);
	}

	return $ENCRYPTION_METHOD{$encryption_number};
}
sub _untaint_password {
	my ($password) = @_;

	# The password must not be tainted for some encryption modules
	($password) = $password =~ m{\A (.*) \z}msx;

	return $password;
}

###########################################################################
# MAKE MOOSE OBJECT IMMUTABLE
__PACKAGE__->meta->make_immutable;

1;

__END__

=head1 NAME

Net::NSCA::Client::ConfigFile - Represents a configuration file and
provides parsing routines

=head1 VERSION

This documentation refers to version 0.009

=head1 SYNOPSIS

  # Open file as $file
  my $config = Net::NSCA::Client::Config->new(
      from_io => $file,
  );

  if ($config->has_encryption_method) {
      say 'Use encryption ', $config->encryption_method;
  }

=head1 DESCRIPTION

This class provides an interface for reading configuration files for the
NSCA client.

=head1 CONSTRUCTOR

This is fully object-oriented, and as such before any method can be used,
the constructor needs to be called to create an object to work with. The
exception to this is that you may use L</FUNCTIONS> without constructing
any object.

=head2 new

This will construct a new object.

=over

=item new(%attributes)

C<%attributes> is a HASH where the keys are attributes (specified in the
L</ATTRIBUTES> section) plus additional constructor-only keys specified
below.

=item new($attributes)

C<$attributes> is a HASHREF where the keys are attributes (specified in the
L</ATTRIBUTES> section) plus additional constructor-only keys specified
below.

=back

Additional keys that may be provided at construction are as follows:

=head3 from_io

This is a perl IO object that will be parsed and the options specified in
this file will be added to this object on construction. After the object is
constructed, no references to this IO object are kept and it may be closed.
Please also see the note about value overwriting in L</config_hash>.

=head1 ATTRIBUTES

  # Get an attribute
  my $value = $object->attribute_name;

=head2 config_hash

This is a hash reference that contains the raw parsed configuration file.
Some of the key values may have been modified (like C<encryption_method>
is changed from a number to a string).

Note that when this is provided to the constructor, any values found in
this hash that correspond to L</ATTRIBUTES> will cause the attribute values
provided to the constructor to be overwritten. This means the following is
expected:

  # Constructing the object like this
  my $config = Net::NSCA::Client::ConfigFile->new(
      config_hash         => {password => 'config_password'},
      encryption_password => 'my_password',
  );

  # Will cause this test to return true
  is($config->encryption_password, 'config_password',
      'config_hash overwrites encryption_password attribute');

=head2 encryption_method

This holds the encryption method as a string as specified in a configuration
file if L</has_encryption_method> is true.

=head2 encryption_password

This holds the encryption password as a string as specified in a
configuration file if L</has_encryption_password> is true.

=head1 METHODS

=head2 has_encryption_method

This returns a Boolean if there is a value in L</encryption_method>.

=head2 has_encryption_password

This returns a Boolean if there is a value in L</encryption_password>.

=head1 FUNCTIONS

The following are functions and cannot be called as methods of an instance.

=head2 parse_send_nsca_config

This function is a utility to parse the format that F<send_nsca.cfg> uses
(as based on F<send_nsca.c>). The first argument (which is B<required> is
an IO object. After this is a plan hash with the following keys:

=over

=item C<is_strict>

This option can change the parsing mode to strict or not. By default this
is true so the operation is as close to F<send_nsca.c> as possible.

When operating in strict mode, this function will throw an error when a
configuration variable is in the configuration file that is unknown. When
not in strict mode, the variable and the value will be parsed and returned
as-is.

=back

The function returns a hash reference with the keys as the variable names
and the values as their values.

It is important to note that when running under taint mode, the password
value will be untainted.

=head1 DEPENDENCIES

=over

=item * L<Const::Fast|Const::Fast>

=item * L<Moose|Moose> 0.89

=item * L<MooseX::StrictConstructor|MooseX::StrictConstructor> 0.08

=item * L<Try::Tiny|Try::Tiny>

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
