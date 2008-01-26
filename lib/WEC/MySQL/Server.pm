package WEC::MySQL::Server;
use 5.006001;
use strict;
use warnings;
use Carp;

use WEC::MySQL::Connection;

our $VERSION = "0.01";
our @CARP_NOT	= qw(WEC::FieldServer);

use base qw(WEC::Server);
# use fields qw(thread_id);

my $default_options = {
    %{__PACKAGE__->SUPER::server_options},
    ServerVersion	=> undef,
    Compress		=> undef,
    CheckAccess		=> undef,
    Quit		=> undef,
    SelectDb		=> undef,
    Query 		=> undef,
    FieldList		=> undef,
    CreateDb		=> undef,
    DropDb 		=> undef,
    Refresh		=> undef,
    Shutdown		=> undef,
    Statistics		=> undef,
    ProcessInfo		=> undef,
    ProcessKill		=> undef,
    DebugInfo 		=> undef,
    Ping		=> undef,
    ChangeUser		=> undef,
    BinlogDump		=> undef,
    TableDump		=> undef,
};

sub default_options {
    return $default_options;
}

sub connection_class {
    return "WEC::MySQL::Connection::Server";
}

sub _thread_id {
    return ++shift->{thread_id};
}

1;
