package Net::NSCA::Client::Library;

use 5.008001;
use strict;
use warnings 'all';

###############################################################################
# METADATA
our $AUTHORITY = 'cpan:DOUGDUDE';
our $VERSION   = '0.008';

###############################################################################
# MOOSE TYPE DECLARATIONS
use MooseX::Types 0.08 -declare => [qw(
	Hostname
	InitializationVector
	PortNumber
	Timeout
)];

###############################################################################
# MOOSE TYPES
use MooseX::Types::Moose qw(Int Str);

###############################################################################
# MODULES
use Const::Fast qw(const);
use Data::Validate::Domain 0.02;

###############################################################################
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###############################################################################
# CONSTANTS
const my $HIGHEST_PORT_NUMBER          => 65_535;
const my $INITIALIZATION_VECTOR_LENGTH => 128;
const my $LOWEST_PORT_NUMBER           => 0;

###############################################################################
# TYPE DEFINITIONS
subtype Hostname,
	as Str,
	where { Data::Validate::Domain::is_hostname($_) },
	message { 'Must be a valid hostname' };

subtype InitializationVector,
	as Str,
	where { $INITIALIZATION_VECTOR_LENGTH == length },
	message { 'InitializationVector must be 128 bytes' };

coerce InitializationVector,
	from Str,
		via { substr($_, 0, $INITIALIZATION_VECTOR_LENGTH) . "\0"x($INITIALIZATION_VECTOR_LENGTH - length) };

subtype PortNumber,
	as Int,
	where { $_ >= $LOWEST_PORT_NUMBER && $_ <= $HIGHEST_PORT_NUMBER },
	message { "PortNumber must be between $LOWEST_PORT_NUMBER and $HIGHEST_PORT_NUMBER inclusive" };

subtype Timeout,
	as Int,
	where { $_ > 0 },
	message { 'Timeout must be greater than 0' };

1;

__END__

=head1 NAME

Net::NSCA::Client::Library - Types library

=head1 VERSION

This documentation refers to version 0.008

=head1 SYNOPSIS

  use Net::NSCA::Client::Library qw(InitializationVector);
  # This will import InitializationVector type into your namespace as well as
  # some helpers like to_InitializationVector and is_InitializationVector. See
  # MooseX::Types for more information.

=head1 DESCRIPTION

This module provides types for L<Net::NSCA::Client|Net::NSCA::Client> and
family.

=head1 METHODS

No methods.

=head1 TYPES PROVIDED

=head2 Hostname

This specifies a hostname. This is validated using the
L<Data::Validate::Domain|Data::Validate::Domain> library with the
C<is_hostname> function.

=head2 InitializationVector

This is the type for the initialization vector. This is a 128 byte string that
is padded with trailing zeros. Coerces from a Str by chopping or padding to
128 bytes.

=head2 PortNumber

This is the type for a port number in TCP and UDP.

=head1 DEPENDENCIES

This module is dependent on the following modules:

=over 4

=item * L<Const::Fast|Const::Fast>

=item * L<Data::Validate::Domain|Data::Validate::Domain> 0.02

=item * L<MooseX::Types|MooseX::Types> 0.08

=item * L<MooseX::Types::Moose|MooseX::Types::Moose>

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
