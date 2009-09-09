package Net::NSCA::Client;

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
# ALL IMPORTS BEFORE THIS WILL BE ERASED
use namespace::clean 0.04 -except => [qw(meta)];

###############################################################################
# ATTRIBUTES
has remote_host => (
	is  => 'rw',
	isa => 'Str',

	clearer   => 'clear_remote_host',
	predicate => 'has_remote_host',
);
has remote_port => (
	is  => 'rw',
	isa => 'Int',

	default => 5667,
);

1;

__END__

=head1 NAME

Net::NSCA::Client - Send passive checks to Nagios locally and remotely.

=head1 VERSION

This documnetation refers to L<Net::NSCA::Client> version 0.001

=head1 SYNOPSIS

Currently the main module, L<Net::NSCA::Client> has not been completed and
there is no documentation.

=head1 DESCRIPTION

Send passive checks to Nagios locally and remotely.

=head1 METHODS

=head1 SPECIFICATION

=head2 NSCA PROTOCOL 3

The NSCA protocol is currently at version 3. Simply put, the NSCA protocol is
very simple from the perspective for the C language. The NSCA program has a
C structure that is populated and then sent across the network in raw form.
Below is the definition of the C structure taken from C<common.h> in NSCA
version 2.7.2.

  struct data_packet_struct {
    int16_t   packet_version;
    u_int32_t crc32_value;
    u_int32_t timestamp;
    int16_t   return_code;
    char      host_name[MAX_HOSTNAME_LENGTH];
    char      svc_description[MAX_DESCRIPTION_LENGTH];
    char      plugin_output[MAX_PLUGINOUTPUT_LENGTH];
  };

When the client connects to the server, the server sends a packet with the
following C structure taken from C<common.h> in NSCA version 2.7.2.

  struct init_packet_struct {
    char      iv[TRANSMITTED_IV_SIZE];
    u_int32_t timestamp;
  };

The packet is first completely zeroed, and thus made empty. Next, the packet
is filled randomly with alpha-numeric characters. The C library actually fills
it randomly with ASCII characters between C<0x30> and C<0x7A>. All values are
now filled into the structure (only overwriting what needs to be written,
keeping randomness intact). The C<timestamp> value is set to the same value
that was sent by the server in the initial response and C<crc32_value> is set
to all zeros. The CRC32 is calculated for this packet and stored in the packet.
Next, the packet in encrypted with the specified method (which MUST be exactly
as set in the server) and sent across the network.

=head3 Encryption

=head4 None

When there is no encryption, then the packet is completely unchanged.

=head4 XOR

This is the obfucated method and so is no encryption. This is mearly to attempt
to mask the data to make it harder to see. The packet is first XOR'd with the
IV that was sent by the server, one byte at a time. Once all bytes from the IV
have been used, then it starts again from the first byte of the IV. After this,
the packet is then XOR'd with the provided password and the same steps as
followed by the IV are followed for the password (byte-per-byte, looping).

=head4 All other Encryptions

All other specified encryption methods are performed in cipher feedback (CFB)
mode, at one byte.

=head1 DEPENDENCIES

=over

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

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

  perldoc Net::NSCA::Client

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-NSCA-Client>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-NSCA-Client>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-NSCA-Client>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-NSCA-Client/>

=back

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
