package WEC::MySQL::Client;
use 5.006001;
use strict;
use warnings;
use Carp;

use WEC::MySQL::Connection;
use WEC::MySQL::Constants qw(PORT SOCKET);

our $VERSION = "1.000";
our @CARP_NOT	= qw(WEC::FieldClient WEC::MySQL::Connection);

use base qw(WEC::Client);

my $default_options = {
    %{__PACKAGE__->SUPER::client_options},
    Greeting	=> undef,
    Reject	=> undef,
    User	=> undef,
    Password	=> undef,
    Database	=> undef,
    Compress	=> undef,
};

sub default_options {
    return $default_options;
}

sub connection_class {
    return "WEC::MySQL::Connection::Client";
}

sub init {
    my ($client, $params) = @_;

    if (defined $client->{destination}) {
        $client->{destination} = "tcp://" . $client->{destination} unless
            $client->{destination} =~ m!\A\w+://!;
        $client->{destination} .= ":" . PORT if
            $client->{destination} =~ m!\Atcp://[^:]+$!i;
    } else {
        $client->{destination} = SOCKET;
    }
}

1;
