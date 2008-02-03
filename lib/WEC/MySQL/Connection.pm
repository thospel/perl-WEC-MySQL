package WEC::MySQL::Connection;
use 5.006001;
use strict;
use warnings;
use Carp;

use WEC::Connection;
use WEC::MySQL::Constants qw(ENCODED_ZERO ENCODED_NULL MAX3
                             :Commands :Capabilities :FieldTypes :Refresh);

our $VERSION = "1.000";
our @CARP_NOT	= qw(WEC::Connection);

use base qw(WEC::Connection);
#use fields qw(in_state protocol max_packet server_version extension
#              thread_id salt user password database fields charset compress
#              uncompressed_length real_want real_process
#              in_pending compressed_seq_no );

our %name2cabability =
    ("LONG_PASSWORD"	=> LONG_PASSWORD,
     "FOUND_ROWS"	=> FOUND_ROWS,
     "LONG_FLAG"	=> LONG_FLAG,
     "CONNECT_WITH_DB"	=> CONNECT_WITH_DB,
     "NO_SCHEMA"	=> NO_SCHEMA,
     "COMPRESS"		=> COMPRESS,
     "ODBC"		=> ODBC,
     "LOCAL_FILES"	=> LOCAL_FILES,
     "IGNORE_SPACE"	=> IGNORE_SPACE,
     "CHANGE_USER"	=> CHANGE_USER,
     "INTERACTIVE"	=> INTERACTIVE,
     "SSL"		=> SSL,
     "IGNORE_SIGPIPE"	=> IGNORE_SIGPIPE,
     "TRANSACTIONS"	=> TRANSACTIONS);
our %cabability2name = reverse %name2cabability;

our %name2refresh =
    ("GRANT"		=> REFRESH_GRANT,
     "LOG"		=> REFRESH_LOG,
     "TABLES"		=> REFRESH_TABLES,
     "HOSTS"		=> REFRESH_HOSTS,
     "STATUS"		=> REFRESH_STATUS,
     "THREADS"		=> REFRESH_THREADS,
     "SLAVE"		=> REFRESH_SLAVE,
     "MASTER"		=> REFRESH_MASTER,
     "READ_LOCK"	=> REFRESH_READ_LOCK,
     "FAST"		=> REFRESH_FAST,
     "QUERY_CACHE"	=> REFRESH_QUERY_CACHE,
     "QUERY_CACHE_FREE"	=> REFRESH_QUERY_CACHE_FREE,
     "DES_KEY_FILE"	=> REFRESH_DES_KEY_FILE,
     "USER_RESOURCES"	=> REFRESH_USER_RESOURCES);
our %refresh2name = reverse %name2refresh;

# Don't document this. Probably want to change the keys to uppercase later
our %name2command =
    (Sleep	=> SLEEP,
     Quit	=> QUIT,
     SelectDb	=> INIT_DB,
     Query 	=> QUERY ,
     FieldList	=> FIELD_LIST,
     CreateDb	=> CREATE_DB,
     DropDb 	=> DROP_DB ,
     Refresh	=> REFRESH,
     Shutdown	=> SHUTDOWN,
     Statistics	=> STATISTICS,
     ProcessInfo=> PROCESS_INFO,
     Connect 	=> CONNECT ,
     ProcessKill=> PROCESS_KILL,
     DebugInfo 	=> DEBUG,
     Ping	=> PING,
     Time	=> TIME,
     DelayedInsert	=> DELAYED_INSERT,
     ChangeUser => CHANGE_USER ,
     BinlogDump	=> BINLOG_DUMP,
     TableDump	=> TABLE_DUMP,
     ConnectOut	=> CONNECT_OUT);
our %command2name = reverse %name2command;
$name2command{Debug} = DEBUG;
$name2command{InitDb} = INIT_DB;

our %field_type2name =
    (pack("C", DECIMAL)		=> "DECIMAL",
     pack("C", TINY)		=> "TINY",
     pack("C", SHORT)		=> "SHORT",
     pack("C", LONG)		=> "LONG",
     pack("C", FLOAT)		=> "FLOAT",
     pack("C", DOUBLE)		=> "DOUBLE",
     pack("C", NULL)		=> "NULL",
     pack("C", TIMESTAMP)	=> "TIMESTAMP",
     pack("C", LONGLONG)	=> "LONGLONG",
     pack("C", INT24)		=> "INT24",
     pack("C", DATE)		=> "DATE",
     pack("C", TIME)		=> "TIME",
     pack("C", DATETIME)	=> "DATETIME",
     pack("C", YEAR)		=> "YEAR",
     pack("C", NEWDATE)		=> "NEWDATE",
     pack("C", ENUM)		=> "ENUM",
     pack("C", SET)		=> "SET",
     pack("C", TINY_BLOB)	=> "TINY_BLOB",
     pack("C", MEDIUM_BLOB)	=> "MEDIUM_BLOB",
     pack("C", LONG_BLOB)	=> "LONG_BLOB",
     pack("C", BLOB)		=> "BLOB",
     pack("C", VAR_STRING)	=> "VAR_STRING",
     pack("C", STRING)		=> "STRING",
     pack("C", GEOMETRY)	=> "GEOMETRY");
our %name2field_type = reverse %field_type2name;

our @process_fields =
    ({Table	=> "",
      Field	=> "Id",
      MaxLength => 7,
      Type	=> "LONGLONG",
      Decimals	=> 0,
      Flags	=> 1},
     {Table	=> "",
      Field	=> "User",
      MaxLength => 16,
      Type	=> "VAR_STRING",
      Decimals	=> 31,
      Flags	=> 1},
     {Table	=> "",
      Field	=> "Host",
      MaxLength => 64,
      Decimals	=> 31,
      Type	=> "VAR_STRING",
      Flags	=> 1},
     {Table	=> "",
      Field	=> "db",
      MaxLength => 64,
      Type	=> "VAR_STRING",
      Decimals	=> 31,
      Flags	=> 0},
     {Table	=> "",
      Field	=> "Command",
      MaxLength => 16,
      Type	=> "VAR_STRING",
      Decimals	=> 31,
      Flags	=> 1},
     {Table	=> "",
      Field	=> "Time",
      MaxLength => 7,
      Type	=> "VAR_STRING",
      Decimals	=> 31,
      Flags	=> 1},
     {Table	=> "",
      Field	=> "State",
      MaxLength => 30,
      Type	=> "VAR_STRING",
      Decimals	=> 31,
      Flags	=> 0},
     {Table	=> "",
      Field	=> "Info",
      MaxLength => 100,
      Type	=> "VAR_STRING",
      Decimals	=> 31,
      Flags	=> 0});

sub capabilities2string {
    my $val = shift;
    my $string = "";
    my $bit = 1;
    for (0..15) {
        if ($val & $bit) {
            $string .= $cabability2name{$bit} . "|";
            $val &= ~$bit;
        }
        last if !$val;
        $bit <<= 1;
    }
    chop $string;
    return $string;
}

sub pass_hash {
    my $n1  = 1345345333;
    my $n2  = 0x12345671;
    my $add = 7;
    utf8::downgrade(my $pass = shift, 1) || croak "Wide character in password";
    for (unpack("C*", $pass)) {
        next if $_ == ord " " || $_ == ord "\t";
        croak "Add got too big" if $add >= 2**32/255-0x3f;
        $n1 ^= (($n1 & 0x3f) + $add) * $_ + (($n1 & 0xffffff) << 8);
        $n2 += ($n2 & 0x7fffff) << 8 ^ $n1;
        $n2 %= 2**31;
        $add = $add + $_;
    }
    return $n1 & 0x7fffffff, $n2;
}

sub scramble_password {
    my $connection = shift;
    my $password = @_ ? shift : $connection->{password};
    return "" if !defined $password || $password eq "";
    my ($p1, $p2) = pass_hash($password);
    my ($s1, $s2) = pass_hash($connection->{salt});
    my ($seed1, $seed2, $modulus);
    croak "No connection yet, so protocol is still unknown" unless
        defined $connection->{protocol};
    if ($connection->{protocol} == 10) {
        $modulus = 2**30-1;
        $seed1 = ($p1 ^ $s1) % $modulus;
        $seed2 = ($p2 ^ $s2) % $modulus;
    } elsif ($connection->{protocol} == 9) {
        $modulus = 2**25-1;
        $seed1 = ($p1 ^ $s1) % $modulus;
        $seed2 = $seed1 >> 1;
    } else {
        croak "Cannot handle protocol $connection->{protocol}";
    }
    my @out;
    for (1..length $connection->{salt}) {
        $seed1 = ($seed1 * 3 + $seed2)  % $modulus;
        $seed2 = ($seed1 + $seed2 + 33) % $modulus;
        push @out, $seed1 * 31 / $modulus + 64;
    }
    if ($connection->{protocol} == 10) {
        # Make it harder to break
        $seed1 = ($seed1 * 3 + $seed2) % $modulus;
        $seed2 = ($seed1 + $seed2 + 33) % $modulus;
        my $e = int($seed1 * 31 / $modulus);
        $_ ^= $e for @out
    }
    return pack("C*", @out);
}

sub decode_length {
    croak "No value" if $_[0] eq "";
    my $code = ord substr($_[0], 0, 1, "");
    # Normal fields count
    return $code if $code < 251;
    if ($code == 252) {
        croak "Result too short" if length($_[0]) < 2;
        return unpack("v", substr(shift, 0, 2, ""));
    }
    if ($code == 253) {
        croak "Result too short" if length($_[0]) < 3;
        return unpack("V", substr(shift, 0, 3, "") . ENCODED_ZERO);
    }
    if ($code == 254) {
        croak "Result too short" if length($_[0]) < 8;
        $code = unpack("V", substr($_[0], 0, 4, ""));
        $code += 2**32 * unpack("V", substr(shift, 0, 4, ""));
        croak "Cannot handle numbers as big as $code" if $code == $code+1;
        return $code;
    }
    croak "Error code"  if $code == 255;
    croak "NULL/File upload" if $code == 251;
    croak "Assertion: code $code is just too weird";
}

sub decode_string {
    for my $str (shift) {
        for my $pos (shift) {
            my $code = ord substr($_, $pos++, 1);
            if ($code < 251) {
                # nop
            } elsif ($code == 252) {
                $code = unpack("v", substr($str, $pos, 2));
                $pos += 2;
            } elsif ($code == 253) {
                $code = unpack("V", substr($str, $pos, 3) . ENCODED_ZERO);
                $pos += 3;
            } elsif ($code == 254) {
                $code = unpack("V", substr($str, $pos, 4));
                $code += 2**32 * unpack("V", substr($str, $pos+4, 4));
                $pos += 8;
                croak "Cannot handle numbers as big as $code" if
                    $code == $code+1;
            } elsif ($code == 251) {
                croak "NULL/File upload" unless shift;
                return undef;
            } elsif ($code == 255) {
                croak "Error code";
            } else {
                croak "Assertion: code $code is just too weird";
            }
            return substr($str, ($pos += $code)-$code, $code);
        }
    }
}

sub encode_length {
    return pack("C", shift) if defined($_[0]) && $_[0] < 251;
    defined(my $val = shift) || croak "Undefined length";
    return pack("Cv", 252, $val) if $val < 2**16;
    return substr(pack("CV", 253, $val), 0, 4) if $val < 2**24;
    return pack("CVV", 254, $val % 2**32, $val / 2**32);
}

sub encode_string {
    return ENCODED_NULL if !defined $_[0];
    my $len = length $_[0];
    return pack("C", $len) . (utf8::is_utf8($_[0]) ? do {
        my $str = shift;
        utf8::downgrade($str, 1) || croak "Wide character in string";
        $str } : shift) if $len < 251;
    return pack("Cv", 252, $len) . (utf8::is_utf8($_[0]) ? do {
        my $str = shift;
        utf8::downgrade($str, 1) || croak "Wide character in string";
        $str } : shift) if $len < 2**16;
    return substr(pack("CV", 253, $len), 0, 4) .
        (utf8::is_utf8($_[0]) ? do {
            my $str = shift;
            utf8::downgrade($str, 1) || croak "Wide character in string";
            $str } : shift) if $len < 2**24;
    return pack("CVV", 254, $len % 2**32, $len / 2**32) .
        (utf8::is_utf8($_[0]) ? do {
            my $str = shift;
            utf8::downgrade($str, 1) || croak "Wide character in string";
            $str } : shift);
}

sub parse_ok {
    my ($connection, $ok) = @_;
    my %result = (affected	=> decode_length($ok),
                  insert_id	=> decode_length($ok));
    if (0) {
        croak "No status ?" if length($ok) < 2;
        $result{status} = unpack("v", substr($ok, 0, 2, ""));
    }
    if ($ok ne "") {
        my $len = decode_length($ok);
        croak "truncated OK message" if $len > length($ok);
        $result{message} = substr($ok, 0, $len, "");
    }
    croak "Unexpected extra stuff in OK" if $ok ne "";
    return \%result;
}

# From mysql_sub_escape_string in libmysql/libmysql.c
my %quote = 
    (""	  => "'",
     "\0" => '\0',
     "\n" => '\n',
     "\r" => '\r',
     "\\" => "\\\\",
     "'"  => "\\'",
     "\""  => "\\\"",
     "\032" => '\Z');

sub quote {
    shift;
    defined(my $str = shift) || return "NULL";
    return "''" if $str =~ s/(\A|[\0\n\r\\'"\032]|\z)/$quote{$1}/g < 2;#"'])//;
    return $str;
}

sub _quote {
    shift;
    defined() ? 
        s/(\A|[\0\n\r\\'"\032]|\z)/$quote{$1}/g  > 1 || ($_ = "''")# "'])//
        : ($_ = "NULL") for shift
}

sub protocol {
    return shift->{protocol};
}

sub thread_id {
    return shift->{thread_id};
}

sub server_version {
    return shift->{server_version};
}

# Typical: debug, log
sub extension {
    my $connection = shift;
    return keys %{$connection->{extension}} unless @_;
    return $connection->{shift()};
}

# $connection->send($seq_no, $message)
# Only meant for the initial greeting (does not do compress)
sub send {
    my $connection = shift;
    die "Attempt to send on a closed Connection" unless
        $connection->{out_handle};
    die "Message is utf8" if utf8::is_utf8($_[1]);

    my $length = length($_[1]);
    # die "Message too long" if $length >= $connection->{max_packet};
    croak "Message too big for plain send" if $length >= MAX3;

    $connection->send0 if $connection->{out_buffer} eq "";
    $connection->{out_buffer} .= pack('V@3C', $length, shift);
    $connection->{out_buffer} .= shift;
    return;
}

sub send_compressed {
    my $connection = shift;
    my $length = length $_[1];
    croak "This code doesn't do huge packets" if $length > 0.99 * MAX3;
    my $compressed = Compress::Zlib::compress($_[1]);
    if (length $compressed < $length) {
        $connection->{out_buffer} .= 
            pack('V@3CV', length $compressed, ++$_[0] % 256, $length);
        chop $connection->{out_buffer};
        $connection->{out_buffer} .= $compressed;
    } else {
        $connection->{out_buffer} .= pack('V@3Cx3', $length, ++$_[0] % 256);
        $connection->{out_buffer} .= $_[1];
    }
    return;
}

sub thread2connection {
    my ($connection, $thread_id) = @_;
    return $connection if $connection->{thread_id} == $thread_id;
    for my $c ($connection->{parent}->connections) {
        return $c if $c->{thread_id} == $thread_id;
    }
    return;
}

sub database {
    return shift->{database};
}

sub user {
    return shift->{user};
}

package WEC::MySQL::Connection::Client;
use Carp;
use Scalar::Util qw(dualvar weaken);
use WEC::Connection qw(HEADER BODY COMMAND CALLBACK ARG PARENT);
use WEC::MySQL::Constants qw(REC_LEN COMPRESS_LEN PART_MASK MAX3
                             ENCODED_ZERO ENCODED_ERROR BIN_LOG_HEADER_SIZE
                             UNKNOWN_ERROR
                             :Commands :Capabilities);

use constant SEQ_NO	=> 1+PARENT;

our $VERSION = "1.000";
use base qw(WEC::MySQL::Connection);
use fields qw(nr_fields nr_records rows);

*decode_string = \&WEC::MySQL::Connection::decode_string;

sub init_client {
    my $connection = shift;
    $connection->{max_packet}	= 2**24;
    $connection->{host_mpx}	= 0;
    $connection->{peer_mpx}	= 0;
    $connection->begin_handshake;
    $connection->{in_want}	= 1+REC_LEN;
    $connection->{in_process}	= \&greeting_header;
    $connection->{user} = $connection->{options}{User} unless
        defined $connection->{user};
    utf8::downgrade($connection->{user}, 1) || croak "Wide character in user";
    $connection->{password} = $connection->{options}{Password} unless
        defined $connection->{password};
    utf8::downgrade($connection->{password}, 1) ||
        croak "Wide character in password";
    $connection->{database} = $connection->{options}{Database} unless
        defined $connection->{database};
    utf8::downgrade($connection->{database}, 1) ||
        croak "Wide character in database";
    if ($connection->{options}{Compress}) {
        eval { require Compress::Zlib };
        die $@ if $@ && $connection->{options}{Compress} > 0;
        $connection->{compress} = $connection->{options}{Compress};
    }
}

sub uncork {
    my $connection = shift;
    croak "Not corked" unless $connection->{cork};
    croak "Cannot uncork while handshake still in progress" if
        $connection->{handshaking};
    if (@{$connection->{cork}} == 0) {
        $connection->{cork} = undef;
        return;
    }
    my $cork = $connection->{cork};
    $connection->{cork} = undef;
    while (@$cork) {
        if (($cork->[0][COMMAND] & ~ PART_MASK) == CHANGE_USER &&
            ref $cork->[0][ARG] eq "ARRAY") {
            $cork->[0][ARG][1] = $connection->scramble_password($cork->[0][ARG][1]);
            $cork->[0][ARG] = pack "Z*Z*Z*", @{$cork->[0][ARG]};
        }
        $connection->send_command(@{shift @$cork});
    }

    if (@{$connection->{answers}} && $connection->{answers}[0][COMMAND] == QUIT) {
        $connection->{ExpectEOF} = 1;
        $connection->eat_input;
        $connection->close_on_empty("quit");
    }
    return;
}

sub greeting_header {
    my $connection = shift;
    my ($length, $seq_no, $protocol) =
        unpack('V@3CC', substr($_, 0, $connection->{in_want}, ""));
    $protocol == 10 || croak "Only handle MySQL protocol 10, not $protocol";
    $connection->{protocol} = $protocol;
    croak "Unexpected record number $seq_no" if $seq_no;
    $connection->{in_want}	= $length-1;
    $connection->{in_process}	= \&greeting_body;
}

sub greeting_body {
    my $connection = shift;

    (@$connection{qw(server_version thread_id salt)},
     my $caps, $connection->{charset}, my $status, my $more) =
        unpack("Z*VZ*vCva", substr($_, 0, $connection->{in_want}, "") . "s");
    croak "Unexpected short greeting" if $more eq "";
    $connection->{extension} = my %extensions;
    $extensions{$1}++ while $connection->{server_version} =~ s/-(\w+)\z//;
    my $with_db = $caps & CONNECT_WITH_DB && defined $connection->{database} ?
        CONNECT_WITH_DB : 0;
    if ($connection->{compress} && !($caps & COMPRESS)) {
        croak "Server doesn't support compression" if 
            $connection->{compress} > 0;
        $connection->{compress} = 0;
    }
    $connection->send
        (1, pack('vV@5Z*a*' . ($with_db ? "xa*" : ""),
                 LONG_PASSWORD | LONG_FLAG | TRANSACTIONS |
                 $with_db | ($connection->{compress} ? COMPRESS : 0),
                 $connection->{max_packet},
                 defined $connection->{user} ? $connection->{user} : "",
                 $connection->scramble_password,
                 $connection->{database}));
    $connection->{in_want}	= REC_LEN;
    $connection->{in_process}	= \&ack_header;
    unshift(@{$connection->{cork}},
            [INIT_DB, \&must_succeed, $connection->{database}]) if
                defined $connection->{database} && !$with_db;
}

sub ack_header {
    my $connection = shift;
    my ($length, my $seq_no) =
        unpack('V@3C', substr($_, 0, $connection->{in_want}, ""));
    $seq_no ==2 || croak "Unexpected sequence number $seq_no (expected 2)";
    $connection->{in_want}	= $length & MAX3;
    $connection->{in_process}	= \&ack_body;
}

sub ack_body {
    my $connection = shift;
    my $ack = substr($_, 0, $connection->{in_want}, "");
    # print STDERR WEC::Connection::hex_show($ack, length $ack), "\n";
    croak "Weird zero length ac" if $ack eq "";
    unless (substr($ack, 0, 1) eq ENCODED_ZERO) {
        my ($code, $error, $msg) = unpack("Cva*", $ack);
        croak "Unknown ack response code $code" unless $code == 255;
        croak "Short error message" if length($ack) < 3;
        if ($connection->{options}{Reject}) {
            $connection->{options}{Reject}->($connection,
                                             dualvar($error, $msg));
        } else {
            warn("Connection to MySQL database failed: $msg\n");
        }
        $connection->_close("reject", dualvar($error, $msg));
        return;
    }
    if ($connection->{compress}) {
        $connection->{compressed_seq_no}= 0;
        $connection->{in_pending}	= "";
        $connection->{in_want}		= COMPRESS_LEN;
        $connection->{in_process}	= \&compressed_header;
        $connection->{real_want}	= REC_LEN;
        $connection->{real_process}	= \&command_header;
    } else {
        $connection->{in_want}		= REC_LEN;
        $connection->{in_process}	= \&command_header;
    }
    $connection->end_handshake;
}

sub compressed_header {
    my $connection = shift;
    # main::diag("Reading " . WEC::Connection::hex_show(substr($_, 0, $connection->{in_want}), $connection->{in_want}));
    my ($length, $seq_no, $u_len) =
        unpack('V@3CV',
               substr($_, 0, $connection->{in_want}, "") . ENCODED_ZERO);
    $seq_no == ++$connection->{compressed_seq_no} % 256 ||
        croak "Unexpected compressed seq_no $seq_no (expected $connection->{compressed_seq_no})";
    $connection->{uncompressed_length} = $u_len;
    $connection->{in_want} = $length & MAX3 || die "Zero length packet";
    # main::diag("$connection->{in_want} expands to $u_len");
    $connection->{in_process} = \&compressed_body;
}

# Basically uncompress the incoming stream and run the normal processor on the
# result.
sub compressed_body {
    my $connection = shift;
    my $in_before = length($connection->{in_pending});
    for ($connection->{in_pending} .=
         $connection->{uncompressed_length} ? Compress::Zlib::uncompress(substr($_, 0, $connection->{in_want}, "")) : substr($_, 0, $connection->{in_want}, "")) {
        # main::diag("Pending: " . WEC::Connection::hex_show($connection->{in_pending}, length $connection->{in_pending}));
        # defined || croak "Could not uncompress packet";
        $connection->{uncompressed_length} == 0 ||
            length == $connection->{uncompressed_length} + $in_before ||
            croak "Inconsistent decompress length";

        # Quick check for stall
        return if $connection->{in_want} > length;

        $connection->{in_want}		= $connection->{real_want};
        $connection->{in_process}	= $connection->{real_process};
        # print(STDERR "During: ", WEC::Connection::hex_show($_, length), "\n"),
        while ($connection->{in_want} <= length) {
            $connection->{in_process}->($connection);
            return unless $connection->{in_process};
            if ($connection->{in_process} == \&command_header) {
                $_ eq "" ||
                    croak "Unexpected stuff left in decompressed packet";
                $connection->{in_want} == REC_LEN ||
                    croak "Unexpected machine length";
                $connection->{compressed_seq_no} = 0;
            }
        }
        $connection->{real_want}	= $connection->{in_want};
        $connection->{real_process}	= $connection->{in_process};
        $connection->{in_want}		= COMPRESS_LEN;
        $connection->{in_process}	= \&compressed_header;
    }
}

sub command_header {
    my $connection = shift;
    my ($length, $seq_no) =
        unpack('V@3C', substr($_, 0, $connection->{in_want}, ""));
    $seq_no == ++$connection->{answers}[0][SEQ_NO]%256 || 
        $connection->{compress} && $seq_no == 0 &&
        # Also only should be so on error
        ($connection->{answers}[0][COMMAND] == INIT_DB ||
         $connection->{answers}[0][COMMAND] == PROCESS_INFO ||
         $connection->{answers}[0][COMMAND] == PROCESS_KILL ||
         ($connection->{answers}[0][COMMAND] & ~ PART_MASK) == QUERY ||
         $connection->{answers}[0][COMMAND] == CREATE_DB ||
         $connection->{answers}[0][COMMAND] == DROP_DB ||
         $connection->{answers}[0][COMMAND] == REFRESH ||
         $connection->{answers}[0][COMMAND] == CHANGE_USER ||
         $connection->{answers}[0][COMMAND] == BINLOG_DUMP ||
         $connection->{answers}[0][COMMAND] == DEBUG
         ) || croak "Unexpected sequence number $seq_no (expected $connection->{answers}[0][SEQ_NO])";
    $connection->{in_want}	= $length & MAX3;
    if ($connection->{answers}[0][COMMAND] == FIELD_LIST) {
        $connection->{fields}		= "";
        $connection->{in_process}	= \&fields;
        $connection->{in_state}		= BODY;
    } elsif (($connection->{answers}[0][COMMAND] & ~ PART_MASK) == TABLE_DUMP) {
        $connection->{in_process}	= \&tdump;
        $connection->{in_state}		= BODY;
        $connection->{fields}		= undef;
        $connection->{rows}		= [];
    } else {
        $connection->{in_process}	= \&command_body;
    }
}

my %plain =
    (
     -2				=> 1,
     QUERY()			=> 1,
     QUERY | PART_MASK()	=> 1,
     INIT_DB()			=> 1,
     CREATE_DB()		=> 1,
     DROP_DB()			=> 1,
     REFRESH()			=> 1,
     PROCESS_KILL()		=> 1,
     PING()			=> 1,
     CHANGE_USER()		=> 1,
     );
my %complex =
    (QUERY()			=> 1,
     QUERY | PART_MASK()	=> 1,
     PROCESS_INFO()		=> 1,
     PROCESS_INFO | PART_MASK()	=> 1,
     TABLE_DUMP()		=> 1,
     TABLE_DUMP | PART_MASK()	=> 1,
     );

# Called like $connection->_error($cause, $packet)
sub _error {
    my $connection = shift;
    my ($errno, $msg);
    defined $connection->{protocol} || croak "No protocol set";
    if ($connection->{protocol} == 10) {
        croak "Short error message" if length($_[1]) < 3;
        ($errno, $msg) = unpack("xva*", $_[1]);
    } elsif ($connection->{protocol} == 9) {
        croak "Short error message" if length($_[1]) < 1;
        $errno = UNKNOWN_ERROR;
        $msg = substr($_[1], 1);
    } else {
        croak "Unknown protocol $connection->{protocol}";
    }
    $connection->{in_want}	= REC_LEN;
    $connection->{in_process}	= \&command_header;
    warn("$_[0]: $msg\n") unless $connection->{answers}[0][CALLBACK];
    $connection->_callback("-error", dualvar($errno, $msg));
    if (@{$connection->{answers}} &&
        $connection->{answers}[0][COMMAND] == QUIT) {
        $connection->{ExpectEOF} = 1;
        $connection->eat_input;
        $connection->close_on_empty("quit");
    }
}

sub command_body {
    my $connection = shift;
    my $result = substr($_, 0, $connection->{in_want}, "");
    croak "Unexpected short command response" if $result eq "";
    defined(my $command = $connection->{answers}[0][COMMAND]) ||
        croak "Unsolicited MySQL server message";
    if ($command == STATISTICS && substr($result, 0, 1) ne ENCODED_ERROR) {
        # Single string
        $connection->{in_want}	= REC_LEN;
        $connection->{in_process} = \&command_header;
        $connection->_callback(text => $result);
        if (@{$connection->{answers}} &&
            $connection->{answers}[0][COMMAND] == QUIT) {
            $connection->{ExpectEOF} = 1;
            $connection->eat_input;
            $connection->close_on_empty("quit");
        }
    } elsif (my $code = ord substr($result, 0, 1, "")) {
        if ($code < 251) {
            # Normal fields count
        } elsif ($code == 251) {
            croak "File upload";
        } elsif ($code == 252) {
            croak "Result too short" if length($result) < 2;
            $code = unpack("v", substr($result, 0, 2, ""));
        } elsif ($code == 253) {
            croak "Result too short" if length($result) < 3;
            $code = unpack("V", substr($result, 0, 3, "") . ENCODED_ZERO);
        } elsif ($code == 254) {
            if ($result eq "") {
                if ($command == SHUTDOWN) {
                    $connection->{in_want}	= REC_LEN;
                    $connection->{in_process}	= \&table;
                    $connection->{in_state}	= HEADER;
                    $connection->{rows} = [];
                    return;
                }
                if ($command == DEBUG) {
                    $connection->{in_want}	= REC_LEN;
                    $connection->{in_process}	= \&command_header;
                    $connection->_callback("none");
                    if (@{$connection->{answers}} &&
                        $connection->{answers}[0][COMMAND] == QUIT) {
                        $connection->{ExpectEOF} = 1;
                        $connection->eat_input;
                        $connection->close_on_empty("quit");
                    }
                    return;
                }
            }
            croak "Result too short" if length($result) < 8;
            $code = unpack("V", substr($result, 0, 4, ""));
            $code += 2**32 * unpack("V", substr($result, 0, 4, ""));
            croak "Cannot handle numbers as big as $code" if $code == $code+1;
        } elsif ($code == 255) {
            $connection->_error("Command failed", ENCODED_ERROR() . $result);
            return;
        } else {
            croak "Assertion: code $code is just too weird";
        }
        if ($complex{$command}) {
            if ($result eq "") {
                $connection->{nr_records} = undef;
            } else {
                # Records seems to get returned as extra data for
                # SHOW FIELDS IN... , and seems to represent how many rows
                # are in the table
                $connection->{nr_records} = decode_length($result);
                $result eq "" || croak "Unexpected extra stuff in packet";
            }
            $connection->{nr_fields}	= $code;
            $connection->{fields}	= "";
            $connection->{in_want}	= REC_LEN;
            $connection->{in_process}	= \&fields;
            $connection->{in_state}	= HEADER;
        } else {
            croak "Unexpected complex response to command $command";
        }
    } else {
        # Plain ok
        croak "Unexpected plain response to command $command" unless
            $plain{$command};
        $connection->{in_want}	= REC_LEN;
        $connection->{in_process} = \&command_header;
        $connection->_callback(ok => $result);
        if (@{$connection->{answers}} &&
            $connection->{answers}[0][COMMAND] == QUIT) {
            $connection->{ExpectEOF} = 1;
            $connection->eat_input;
            $connection->close_on_empty("quit");
        }
    }
}

sub decode_fields {
    my $pos = 0;
    my (@fields, $tmp);
    for (shift) {
        my $default = shift;
        while ($pos < length) {
            push @fields, \my %field;
            $field{Table} = decode_string($_, $pos);
            $field{Field} = decode_string($_, $pos);
            $tmp = decode_string($_, $pos);
            length($tmp) == 3 ||
                croak "Unexpected MaxLength length (", unpack("H*", $tmp), ")";
            $field{MaxLength} = unpack("V", $tmp . ENCODED_ZERO);
            $tmp = decode_string($_, $pos);
            $field{Type} = $field_type2name{$tmp} ||
                croak "Unknown field type (", unpack("H*", $tmp), ")";
            $tmp = decode_string($_, $pos);
            length($tmp) == 3 ||
                croak "Unexpected Flags length (", unpack("H*", $tmp), ")";
            # Should check cap before, or just derive from length
            ($field{Flags}, $field{Decimals}) = unpack("vC", $tmp);
            $field{Default}= decode_string($_, $pos, 1) if $default;
        }
        $pos == length || croak "Bad field string";
    }
    return \@fields;
}

sub fields {
    my $connection = shift;
    my $want = $connection->{in_want};
    goto BODY if $connection->{in_state} == BODY;
    while (1) {
        # Header
        ($want, my $seq_no) = unpack('V@3C', substr($_, 0, REC_LEN, ""));
        $seq_no == ++$connection->{answers}[0][SEQ_NO] % 256 ||
            croak "Unexpected sequence number $seq_no (expected $connection->{answers}[0][SEQ_NO])";
        $want &= MAX3 or die "Zero length packet";
        if ($want > length) {
            $connection->{in_want}	= $want;
            $connection->{in_state}	= BODY;
            return;
        }
      BODY:
        if ($want == 1 &&
            substr($_, 0, 1) eq "\xfe") {
            substr($_, 0, 1, "");
            $connection->{in_want}	= REC_LEN;
            if ($connection->{answers}[0][COMMAND] == FIELD_LIST()) {
                $connection->{in_want}		= REC_LEN;
                $connection->{in_process}	= \&command_header;
                $connection->_callback
                    (fields => decode_fields($connection->{fields}, 1));
                $connection->{fields} = undef;
                if (@{$connection->{answers}} &&
                    $connection->{answers}[0][COMMAND] == QUIT) {
                    $connection->{ExpectEOF} = 1;
                    $connection->eat_input;
                    $connection->close_on_empty("quit");
                }
            } else {
                # print STDERR "Switch to table\n";
                @{$connection->{fields} = decode_fields($connection->{fields})} == $connection->{nr_fields} ||
                    croak "Unexpected number of fields (expected $connection->{nr_fields}, got ", scalar @{$connection->{fields}}, ")";
                $connection->{in_process}	= \&table;
                $connection->{in_state}		= HEADER;
                $connection->{rows}		= [];
            }
            return;
        }
        if ($connection->{fields} eq "" && substr($_, 0, 1) eq ENCODED_ERROR) {
            # Should only be possible on FIELD_LIST
            $connection->{answers}[0][COMMAND] == FIELD_LIST ||
                croak "Error on non FIELD_LIST";
            $connection->_error("FIELD_LIST failed", substr($_, 0, $want, ""));
            return;
        }
        $connection->{fields} .= substr($_, 0, $want, "");
        if (length() < REC_LEN) {
            $connection->{in_want}	= REC_LEN;
            $connection->{in_state}	= HEADER;
            return;
        }
    }
}

sub table {
    my $connection = shift;
    my $want = $connection->{in_want};
    goto BODY if $connection->{in_state} == BODY;
    while (1) {
        # Header
        ($want, my $seq_no) = unpack('V@3C', substr($_, 0, REC_LEN, ""));
        # print STDERR "Table seq no $seq_no\n";
        $seq_no == ++$connection->{answers}[0][SEQ_NO] % 256 ||
            croak "Unexpected sequence number $seq_no";
        $want &= MAX3;
        if ($want > length) {
            $connection->{in_want}	= $want;
            $connection->{in_state}	= BODY;
            if ($connection->{answers}[0][COMMAND] & PART_MASK &&
                $connection->{answers}[0][CALLBACK] &&
                @{$connection->{rows}}) {
                croak "Unexpected message @{$connection->{rows}}" if
                    $connection->{answers}[0][COMMAND] == SHUTDOWN;
                $connection->{answers}[0][CALLBACK]->($connection, "+table", $connection->{fields}, $connection->{rows});
                $connection->{rows} = [];
            }
            return;
        }
      BODY:
        if ($want == 1 && substr($_, 0, 1) eq "\xfe") {
            substr($_, 0, 1, "");
            $connection->{in_want}	= REC_LEN;
            $connection->{in_process}	= \&command_header;
            if ($connection->{answers}[0][COMMAND] == SHUTDOWN) {
                croak "Unexpected message @{$connection->{rows}}" if
                    @{$connection->{rows}};
                croak "Unexpected fields" if defined $connection->{fields};
                $connection->{ExpectEOF} = 1;
                $connection->_callback("none");
            } else {
                $connection->_callback
                    ("table", $connection->{fields}, $connection->{rows});
            }
            $connection->{fields} = $connection->{rows} = undef;
            if (@{$connection->{answers}} &&
                $connection->{answers}[0][COMMAND] == QUIT) {
                $connection->{ExpectEOF} = 1;
                $connection->eat_input;
                $connection->close_on_empty("quit");
            }
            return;
        }
        my $buf_len = length;
        my @row;
        for my $i (1..$connection->{nr_fields}) {
            # print STDERR "Processing field $i: ", unpack("H*", $_), "\n";
            my $len = ord substr($_, 0, 1, "");
            if ($len < 251) {
                push @row, substr($_, 0, $len, "");
            } elsif ($len == 251) {
                # NULL
                push @row, undef;
            } elsif ($len == 252) {
                croak "Result too short" if length() < 2;
                push @row, substr($_, 0, unpack("v", substr $_, 0, 2, ""), "");
            } elsif ($len == 253) {
                croak "Result too short" if length() < 3;
                push @row, substr($_, 0, unpack("V", substr($_, 0, 3, "") .
                                                ENCODED_ZERO), "");
            } else {
                croak "Too long ($len), not yet handled";
            }
        }
        $buf_len - length() == $want || croak "Inconsistent removal";
        push @{$connection->{rows}}, \@row;
        if (length() < REC_LEN) {
            $connection->{in_state}	= HEADER;
            $connection->{in_want}	= REC_LEN;
            if ($connection->{answers}[0][COMMAND] & PART_MASK &&
                $connection->{answers}[0][CALLBACK] &&
                @{$connection->{rows}}) {
                croak "Unexpected message @{$connection->{rows}}" if
                    $connection->{answers}[0][COMMAND] == SHUTDOWN;
                $connection->{answers}[0][CALLBACK]->($connection, "+table", $connection->{fields}, $connection->{rows});
                $connection->{rows} = [];
            }
            return;
        }
    }
}

sub tdump {
    my $connection = shift;
    my $want = $connection->{in_want};
    goto BODY if $connection->{in_state} == BODY;
    while (1) {
        # Header
        ($want, my $seq_no) =
            unpack('V@3C', substr($_, 0, REC_LEN, ""));
        $seq_no == ++$connection->{answers}[0][SEQ_NO] % 256 ||
            croak "Unexpected sequence number $seq_no";
        $want &= MAX3;
        if ($want > length) {
            $connection->{in_want}	= $want;
            $connection->{in_state}	= BODY;
            if ($connection->{answers}[0][COMMAND] & PART_MASK &&
                $connection->{answers}[0][CALLBACK] &&
                @{$connection->{rows}}) {
                unless (defined($connection->{fields})) {
                    $connection->{fields} = shift @{$connection->{rows}};
                    return unless @{$connection->{rows}};
                }
                $connection->{answers}[0][CALLBACK]->($connection, "+table_dump", $connection->{fields}, $connection->{rows});
                $connection->{rows} = [];
            }
            return;
        }
      BODY:
        if ($want == 0) {
            $connection->{in_want}	= REC_LEN;
            $connection->{in_process}	= \&command_header;
            $connection->{fields} = shift @{$connection->{rows}} unless
                defined($connection->{fields});
            defined($connection->{fields}) ||
                croak "No table creation prefix";
            $connection->_callback
                ("table_dump", $connection->{fields}, $connection->{rows});
            $connection->{rows} = $connection->{fields} = undef;
            if (@{$connection->{answers}} &&
                $connection->{answers}[0][COMMAND] == QUIT) {
                $connection->{ExpectEOF} = 1;
                $connection->eat_input;
                $connection->close_on_empty("quit");
            }
            return;
        } elsif ($connection->{answers}[0][SEQ_NO] == 1 && 
                 substr($_, 0, 1) eq "\xff") {
            $connection->_error("TABLE_DUMP failed", substr($_, 0, $want, ""));
            return;
        }
        push @{$connection->{rows}}, substr($_, 0, $want, "") if
            $connection->{answers}[0][CALLBACK];
        if (length() < REC_LEN) {
            $connection->{in_state}	= HEADER;
            $connection->{in_want}	= REC_LEN;
            if ($connection->{answers}[0][COMMAND] & PART_MASK &&
                $connection->{answers}[0][CALLBACK] &&
                @{$connection->{rows}}) {
                unless (defined($connection->{fields})) {
                    $connection->{fields} = shift @{$connection->{rows}};
                    return unless @{$connection->{rows}};
                }
                $connection->{answers}[0][CALLBACK]->($connection, "+table_dump", $connection->{fields}, $connection->{rows});
                $connection->{rows} = [];
            }
            return;
        }
    }
}

sub select_db {
    my $connection = shift;
    if (@_ == 2 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(INIT_DB, shift, utf8::is_utf8($_[0]) ? do {
            my $db = shift;
            utf8::downgrade($db, 1) ||
                croak "Wide character in database";
            $db;
        } : shift);
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    defined(my $db = delete $params{Database}) ||
        croak "Undefined database";
    croak "select_db has no ", join(", ", keys %params), " parameter" if
        %params;
    utf8::downgrade($db, 1) || croak "Wide character in database";
    $connection->send_command(INIT_DB, $callback, $db, $parent);
}

sub create_db {
    my $connection = shift;
    warn("create_db callback can be lost\n");
    if (@_ == 2 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(CREATE_DB, shift, utf8::is_utf8($_[0]) ? do {
            my $arg = shift;
            utf8::downgrade($arg, 1) ||
                croak "Wide character in create_db argument";
            $arg;
        } : shift);
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    defined(my $db = delete $params{Database}) ||
        croak "Undefined database";
    croak "create_db has no ", join(", ", keys %params), " parameter" if
        %params;
    utf8::downgrade($db, 1) || croak "Wide character in database";
    $connection->send_command(CREATE_DB, $callback, $db, $parent);
}

sub drop_db {
    my $connection = shift;
    warn("drop_db callback can be lost\n");
    if (@_ == 2 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(DROP_DB, shift, utf8::is_utf8($_[0]) ? do {
            my $arg = shift;
            utf8::downgrade($arg, 1) ||
                croak "Wide character in drop_db argument";
            $arg;
        } : shift);
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    defined(my $db = delete $params{Database}) ||
        croak "Undefined database";
    croak "drop_db has no ", join(", ", keys %params), " parameter" if
        %params;
    utf8::downgrade($db, 1) || croak "Wide character in database";
    $connection->send_command(DROP_DB, $callback, $db, $parent);
}

sub query {
    my $connection = shift;
    if (@_ == 2 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(QUERY, shift, utf8::is_utf8($_[0]) ? do {
            my $arg = shift;
            utf8::downgrade($arg, 1) ||
                croak "Wide character in query";
            $arg;
        } : shift);
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    my $query	 = delete $params{Query};
    my $command  = delete $params{Partial} ? QUERY | PART_MASK : QUERY;
    croak "query has no ", join(", ", keys %params), " parameter" if %params;
    utf8::downgrade($query, 1) || croak "Wide character in query";
    $connection->send_command($command, $callback, $query, $parent);
}

*command = \&query;

sub debug_info {
    my $connection = shift;
    if (@_ == 1 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(DEBUG, shift, "");
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    croak "debug_info has no ", join(", ", keys %params), " parameter" if %params;
    $connection->send_command(DEBUG, $callback, "", $parent);
}

sub ping {
    my $connection = shift;
    if (@_ == 1 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(PING, shift, "");
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    croak "ping has no ", join(", ", keys %params), " parameter" if %params;
    $connection->send_command(PING, $callback, "", $parent);
}

sub statistics {
    my $connection = shift;
    if (@_ == 1 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(STATISTICS, shift, "");
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    croak "statistics has no ", join(", ", keys %params), " parameter" if
        %params;
    $connection->send_command(STATISTICS, $callback, "", $parent);
}

sub process_info {
    my $connection = shift;
    if (@_ == 1 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(PROCESS_INFO, shift, "");
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    my $command  =
        delete $params{Partial} ? PROCESS_INFO | PART_MASK : PROCESS_INFO;
    croak "process_info has no ", join(", ", keys %params), " parameter" if %params;
    $connection->send_command(PROCESS_INFO, $callback, "", $parent);
}

sub string2refresh {
    defined(my $string = shift) || croak "Undefined refresh flags";
    $string =~ s/\A\s+//;
    $string =~ s/\s+\z//;
    return 0+$string if $string =~ /\A\d+\z/;
    my $flags = 0;
    $flags |= $name2refresh{$_} || croak "Unknown refresh bit $_" for
        split/\s*\|\s*/, uc($string);
    return $flags;
}

# Ok
sub refresh {
    my $connection = shift;
    if (@_ == 2 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        my $flags = string2refresh($_[1]);
        croak "Cannot handle refresh flags $flags >= 256" if $flags >= 256;
        $connection->send_command(REFRESH, shift, pack("C", $flags));
    } else {
        my %params = @_;
        my $callback = delete $params{Callback};
        my $parent   = delete $params{Parent};
        my $flags = string2refresh(delete $params{Flags});
        croak "refresh has no ", join(", ", keys %params), " parameter" if
            %params;
        croak "Cannot handle refresh flags $flags >= 256" if $flags >= 256;
        $connection->send_command
            (REFRESH, $callback, pack("C", $flags), $parent);
    }
}

# Ok
sub field_list {
    # Wildcards seem buggy in the server (in 4.0.20). Just only send \0
    my ($connection, $callback, $table) = @_;
    my $parent;
    if (@_ != 3 || defined $callback && !ref $callback eq "CODE") {
        shift;
        my %params = @_;
        $callback = delete $params{Callback};
        $parent   = delete $params{Parent};
        $table	  = delete $params{Table};
        croak "field_list has no ", join(", ", keys %params), " parameter" if
            %params;
    }
    defined($table) || croak "Undefined table";
    utf8::downgrade($table, 1) || croak "Wide character in table";
    $connection->send_command
        (FIELD_LIST, $callback, pack("Z*x", $table), $parent);
}

# Ok
sub process_kill {
    my $connection = shift;
    if (@_ == 2 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        defined(my $pid = $_[1]) || croak "Undefined pid";
        $pid =~ /\A\d+\z/ || croak "process_kill argument is not a number";
        $pid < 2**32 || croak "pid is too big";
        $connection->send_command(PROCESS_KILL, shift, pack("V", $pid));
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    defined(my $pid = delete $params{Pid}) || croak "Undefined pid";
    croak "field_list has no ", join(", ", keys %params), " parameter" if
        %params;
    $pid =~ /\A\d+\z/ || croak "process_kill argument is not a number";
    $pid < 2**32 || croak "pid is too big";
    $connection->send_command
        (PROCESS_KILL, $callback, pack("V", $pid), $parent);
    # We could detect if this is suicide and do a expectEOF, but
    # we'll assume suicide is normally unwanted and let things error
}

# Ok
sub change_user {
    my $connection = shift;
    no warnings "uninitialized";
    if (@_ == 4 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        my $callback = shift;
        my $id =
            defined $connection->{protocol} || $_[1] eq "" ?
            pack("Z*Z*Z*",
                 utf8::is_utf8($_[0]) ? do {
                     my $user = shift;
                     utf8::downgrade($user, 1) ||
                         croak "Wide character in user";
                     $user;
                 } : shift,
                 $connection->scramble_password(shift),
                 utf8::is_utf8($_[0]) ? do {
                     my $db = shift;
                     utf8::downgrade($db, 1) ||
                         croak "Wide character in database";
                     $db;
                 } : shift) :
                     [utf8::is_utf8($_[0]) ? do {
                         my $user = shift;
                         utf8::downgrade($user, 1) ||
                             croak "Wide character in user";
                         $user;
                     } : shift, utf8::is_utf8($_[0]) ? do {
                         my $pw = shift;
                         utf8::downgrade($pw, 1) ||
                             croak "Wide character in password";
                         $pw;
                     } : shift, utf8::is_utf8($_[0]) ? do {
                         my $db = shift;
                         utf8::downgrade($db, 1) ||
                             croak "Wide character in database";
                         $db;
                     } : shift];
        $connection->send_command(CHANGE_USER, $callback, $id);
        return;
    }
    my %params = @_;
    my $callback = delete $params{Callback};
    my $parent   = delete $params{Parent};
    my $user	 = delete $params{User};
    my $password = delete $params{Password};
    my $db	 = delete $params{Database};
    croak "change_user has no ", join(", ", keys %params), " parameter" if
        %params;
    utf8::downgrade($user, 1)     || croak "Wide character in user";
    utf8::downgrade($password, 1) || croak "Wide character in password";
    utf8::downgrade($db, 1)	  || croak "Wide character in database";
    my $id =
        defined $connection->{protocol} || $password eq "" ?
        pack("Z*Z*Z*", $user, $connection->scramble_password($password), $db) :
        [$user, $password, $db];
    $connection->send_command(CHANGE_USER, $callback, $id, $parent);
}

sub binlog_dump {
    my $connection = shift;
    if (@_ == 5 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        my $callback = shift;
        my $position = shift || BIN_LOG_HEADER_SIZE;
        croak("The position in the binary log can't be less than ",
              BIN_LOG_HEADER_SIZE) if $position < BIN_LOG_HEADER_SIZE;
        my $dump = pack("VvVa*", $position, shift, shift,
                        utf8::is_utf8($_[0]) ? do {
                            my $file = shift;
                            utf8::downgrade($file, 1) ||
                                croak "Wide character in filename";
                            $file;
                        } : shift);
        $connection->send_command(BINLOG_DUMP, $callback, $dump);
        return;
    }
    my %params = @_;
    my $callback= delete $params{Callback};
    my $parent  = delete $params{Parent};
    my $pos	= delete $params{Position};
    my $flags	= delete $params{Flags};
    my $id	= delete $params{Slave};
    my $file	= delete $params{File};
    my $command =
        delete $params{Partial} ? BINLOG_DUMP | PART_MASK : BINLOG_DUMP;
    croak "binlog_dump has no ", join(", ", keys %params), " parameter" if %params;
    utf8::downgrade($file, 1) || croak "Wide character in filename";
    $connection->send_command($command, $callback,
                              pack("VvVa*", $pos, $flags, $id, $file), 
                              $parent);
}

# Ok
sub table_dump {
    my $connection = shift;
    if (@_ == 3 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        my $callback = shift;
        my $db = shift;
        utf8::downgrade($db, 1) || croak "Wide character in database name";
        croak "database name length >= 256" if length($db) >= 256;
        my $table = shift;
        utf8::downgrade($table, 1) || croak "Wide character in table name";
        croak "table name length >= 256" if length($table) >= 256;
        $connection->send_command(TABLE_DUMP, $callback,
                                  pack("C/a*C/a*", $db, $table));
        return;
    }
    my %params = @_;
    my $callback= delete $params{Callback};
    my $parent  = delete $params{Parent};
    my $db	= delete $params{Database};
    my $table	= delete $params{Table};
    my $command =
        delete $params{Partial} ? TABLE_DUMP | PART_MASK : TABLE_DUMP;
    croak "table_dump has no ", join(", ", keys %params), " parameter" if %params;

    utf8::downgrade($db, 1) || croak "Wide character in database name";
    croak "database name length >= 256" if length($db) >= 256;
    utf8::downgrade($table, 1) || croak "Wide character in table name";
    croak "table name length >= 256" if length($table) >= 256;

    $connection->send_command($command, $callback,
                              pack("C/a*C/a*", $db, $table), $parent);
}

sub quit {
    my $connection = shift;
    # never answers, so no callback
    croak "quit expects no arguments" if @_;
    $connection->send_command(QUIT, undef, "");
    return unless !$connection->{cork} && @{$connection->{answers}} == 1;
    $connection->{ExpectEOF} = 1;
    $connection->eat_input;
    $connection->close_on_empty("quit");
}

# Ok
sub shutdown {
    my $connection = shift;
    if (@_ == 1 && (!defined $_[0] || ref $_[0] eq "CODE")) {
        $connection->send_command(SHUTDOWN, shift, "");
    } else {
        my %params = @_;
        my $callback = delete $params{Callback};
        my $parent   = delete $params{Parent};
        croak "shutdown has no ", join(", ", keys %params), " parameter" if
            %params;
        $connection->send_command(SHUTDOWN, $callback, "", $parent);
    }
    $connection->{ExpectEOF} = 1 if
        !$connection->{cork} && @{$connection->{answers}} == 1;
}

sub prepare {
    my $connection = shift;
    my $str = shift;
    $str =~ s/%/%%/g;
    my $result = "";
    while ($str =~ s/\A([^\'\"\\?:]*(?:(?:'[^\'\\]*(?:(?:''|\\.)[^\'\\]*)*'(?!\')|"[^\"\\]*(?:(?:""|\\.)[^\"\\]*)*"(?!\")|:(?!\d))[^\'\"\\?:]*)*)(?:\?|:(\d+))//s) {	# "
        $result .= $1 . (defined($2) ? "%$2\$s" : "%s");
    }
    return bless [$result . $str, $connection], "WEC::MySQL::Statement";
}

# Called as: multi_packet($target, $pre, $big_string)
use constant ENCODED_MAX3 => pack("V", MAX3);
sub multi_packet {
    for my $target (shift) {
        my $i = MAX3-length($_[0]);
        $target .= ENCODED_MAX3() . shift;
        $target .= substr($_[0], 0, $i);
        my $seq_no = 0;
        my $length = length($_[0]) - MAX3;
        while ($i <= $length) {
            $target .= pack('V@3C', MAX3, ++$seq_no % 256);
            $target .= substr($_[0], $i, MAX3);
            $i += MAX3;
        }
        $target .= pack('V@3C', $length-$i+MAX3, ++$seq_no % 256);
        $target .= substr($_[0], $i);
        return $seq_no;
    }
}

# Called as $connection->send_command($command_id, $callback, $arg ?, $parent?)
sub send_command {
    my $connection = shift;
    die "Attempt to send on a closed Connection" unless
        $connection->{out_handle};
    my $parent = $_[3];
    if ($connection->{cork}) {
        push @{$connection->{cork}}, [shift, shift, shift, $parent || ()];
        if ($parent) {
            my $event = $connection->{cork}[-1];
            weaken($event->[PARENT]);
            $parent->{events}{$event} = $event;
        }
        return;
    }

    die "Message is utf8" if utf8::is_utf8($_[2]);

    my $length = 1+length($_[2]);
    # die "Message too long" if $length >= $connection->{max_packet};

    $connection->send0 if $connection->{out_buffer} eq "";
    if ($connection->{compress}) {
        my $msg;
        if ($length >= MAX3) {
            multi_packet($msg, pack("C", $_[0] & ~PART_MASK), $_[2]);
        } else {
            $msg = pack('VC', $length, $_[0] & ~PART_MASK) . $_[2];
        }
        my $seq_no = -1;
        $connection->send_compressed($seq_no, substr($msg, 0, 2**20, "")) while
            length $msg > 2**20;
        $connection->send_compressed($seq_no, $msg);
        push(@{$connection->{answers}}, 
             [shift, shift, undef, $parent, $seq_no]);
    } elsif ($length >= MAX3) {
        my $seq_no = multi_packet($connection->{out_buffer},
                                  pack("C", $_[0] & ~PART_MASK), $_[2]);
        push(@{$connection->{answers}}, 
             [shift, shift, undef, $parent, $seq_no]);
    } else {
        $connection->{out_buffer} .= pack('VC', $length, $_[0] & ~PART_MASK);
        $connection->{out_buffer} .= $_[2];
        push(@{$connection->{answers}}, [shift, shift, undef, $parent, 0]);
    }
    if ($parent) {
        my $event = $connection->{answers}[-1];
        weaken($event->[PARENT]);
        $parent->{events}{$event} = $event;
    }
}

package WEC::MySQL::Connection::Server;
use Carp;
use WEC::Connection qw(COMMAND ARG PARENT HEADER BODY);
use WEC::MySQL::Constants qw(LATIN1 REC_LEN COMPRESS_LEN 
                             ENCODED_ZERO ENCODED_ERROR
                             UNKNOWN_ERROR MAX3
                             NOT_SUPPORTED_YET SPECIFIC_ACCESS_DENIED_ERROR
                             :Capabilities :Commands);

our $VERSION = "1.000";
use base qw(WEC::MySQL::Connection);
use fields qw(host);

# Maybe for Server SEQ_NO should be ARG, or PARENT (currently unused)
use constant SEQ_NO	=> 1+PARENT;

*encode_length = \&WEC::MySQL::Connection::encode_length;
*encode_string = \&WEC::MySQL::Connection::encode_string;

sub init_server {
    my $connection	= shift;
    $connection->{host_mpx}	= 0;
    $connection->{peer_mpx}	= 0;
    $connection->{max_packet}	= 2**24;
    $connection->{protocol}	= 10;
    $connection->{charset}	= LATIN1;
    $connection->{extension}	= {};
    $connection->{server_version} = $connection->{options}{ServerVersion} ||
        "WEC::MySQL$VERSION";
    $connection->begin_handshake;
    $connection->{in_want}	= 0;
    $connection->{in_process}	= \&send_greeting;
    if ($connection->{options}{Compress}) {
        eval { require Compress::Zlib };
        die $@ if $@ && $connection->{options}{Compress} > 0;
        $connection->{compress} = $connection->{options}{Compress};
    }
}

# Replace by something that generates *real* randomness ?
sub gen_salt {
    return pack("C*", map 33+rand(94), 1..8);
}

sub send_greeting {
    my $connection = shift;
    $connection->send(0, pack("CZ*VZ*vCx15", $connection->{protocol},
                              join("-", $connection->{server_version}, keys %{$connection->{extension}}),
                              $connection->{thread_id} ||= $connection->{parent}->_thread_id,
                              $connection->{salt} ||= $connection->gen_salt,
                              LONG_FLAG | CONNECT_WITH_DB |
                              ($connection->{compress} ? COMPRESS : 0),
                              $connection->{charset}));
    $connection->{in_want}	= REC_LEN;
    $connection->{in_state}	= HEADER;
    $connection->{in_process}	= \&auth;
}

sub auth {
    my $connection = shift;
    my $want = $connection->{in_want};
    if ($connection->{in_state}	== HEADER) {
        ($want, my $seq_no) = unpack('V@3C', substr($_,0,$want,""));
        $seq_no == 1 || croak "Unexpected seq_no $seq_no";
        $want &= MAX3 or die "Zero length packet";
        if ($want > length) {
            $connection->{in_want} = $want;
            $connection->{in_state} = BODY;
            return;
        }
    }
    (my $caps, $want, $connection->{user}, my $password) =
        unpack('vV@5Z*a*', substr($_, 0, $want, ""));
    if ($connection->{compress} && !($caps & COMPRESS)) {
        croak "Client doesn't support compression" if 
            $connection->{compress} > 0;
        $connection->{compress} = 0;
    }
main::diag("Compression is now $connection->{compress}");
    $connection->{host} =
        $connection->{peer_address} =~ m!\Aunix://!     ? "localhost" :
        $connection->{peer_address} =~ m!\Atcp://(.*):! ? $1 :
        croak "Could not determine hostname from $connection->{peer_address}";
    $connection->{database} = $1 if $password =~ s/\0(.*)//sg;
    $connection->{max_packet} = ($want & MAX3) || 2**24;

    # Must set up FSM before callback in case it e.g. switches to eating
    $connection->{in_state}	= HEADER;
    if ($connection->{compress}) {
        $connection->{compressed_seq_no}= -1;
        $connection->{in_pending}	= "";
        $connection->{in_want}		= COMPRESS_LEN;
        $connection->{in_process}	= \&compressed_header;
        $connection->{real_want}	= 1+REC_LEN;
        $connection->{real_process}	= \&execute;
    } else {
        # Fakes the seq_no starting point
        $connection->{compressed_seq_no}= 0;
        $connection->{in_want}	= 1+REC_LEN;
        $connection->{in_process}	= \&execute;
    }

    $connection->{answers} = [[-2, undef, undef, undef, 1]];
    local $connection->{compress} = 0;
    if ($connection->{options}{CheckAccess}) {
        $connection->{options}{CheckAccess}->($connection, $connection->{user}, $connection->{host}, $password, $connection->{database});
    } else {
        $connection->send_error(NOT_SUPPORTED_YET, "Login is not supported (yet)");
    }
    return unless $connection->{out_handle};
    # When fixing this, remember that under compress the first packet should 
    # NOT be compresed, but the rest should be. Tricky since after this point
    # the localized $connection->{compress} will get restored
    croak "No answer" if @{$connection->{answers}} && $connection->{answers}[0][COMMAND] != -1;

    $connection->end_handshake;
}

sub compressed_header {
    my $connection = shift;
    my ($length, $seq_no, $u_len) =
        unpack('V@3CV',
               substr($_, 0, $connection->{in_want}, "") . ENCODED_ZERO);
    $seq_no == ++$connection->{compressed_seq_no} % 256 ||
        croak "Unexpected compressed seq_no $seq_no (expected $connection->{compressed_seq_no})";
    $connection->{uncompressed_length} = $u_len;
    $connection->{in_want} = $length & MAX3 || die "Zero length packet";
    # main::diag("$connection->{in_want} expands to $u_len");
    $connection->{in_process} = \&compressed_body;
}

# Basically uncompress the incoming stream and run the normal processor on the
# result.
sub compressed_body {
    my $connection = shift;
    my $in_before = length($connection->{in_pending});
    for ($connection->{in_pending} .=
         $connection->{uncompressed_length} ? Compress::Zlib::uncompress(substr($_, 0, $connection->{in_want}, "")) : substr($_, 0, $connection->{in_want}, "")) {
        main::diag("Pending: " . WEC::Connection::hex_show($connection->{in_pending}, length $connection->{in_pending}));
        # defined || croak "Could not uncompress packet";
        $connection->{uncompressed_length} == 0 ||
            length == $connection->{uncompressed_length} + $in_before ||
            croak "Inconsistent decompress length";

        # Quick check for stall
        return if $connection->{in_want} > length;

        $connection->{in_want}		= $connection->{real_want};
        $connection->{in_process}	= $connection->{real_process};
        # print(STDERR "During: ", WEC::Connection::hex_show($_, length), "\n"),
        while ($connection->{in_want} <= length) {
            $connection->{in_process}->($connection);
            return unless $connection->{in_process};
            if ($connection->{in_process} == \&execute && 
                $connection->{in_state} == HEADER) {
                $_ eq "" ||
                    croak "Unexpected stuff left in decompressed packet";
                $connection->{in_want} == 1+REC_LEN ||
                    croak "Unexpected machine length";
                $connection->{compressed_seq_no} = -1;
            }
        }
        $connection->{real_want}	= $connection->{in_want};
        $connection->{real_process}	= $connection->{in_process};
        $connection->{in_want}		= COMPRESS_LEN;
        $connection->{in_process}	= \&compressed_header;
    }
}

sub execute {
    my $connection = shift;
    my $want = $connection->{in_want};
    if ($connection->{in_state}	== HEADER) {
        ($want, my $seq_no, my $command) =
            unpack('V@3CC', substr($_, 0, $want, ""));
        $seq_no == 0 || croak "Unexpected seq_no $seq_no";
        $connection->{fields} = $command;
        $want &= MAX3 or die "Zero length packet";
        if (--$want > length) {
            $connection->{in_want} = $want;
            $connection->{in_state} = BODY;
            return;
        }
    }

    $connection->{in_want}	= 1+REC_LEN;
    $connection->{in_state}	= HEADER;

    my $command = $connection->{fields};
    push(@{$connection->{answers}}, [$command, undef, undef, undef, $connection->{compressed_seq_no}]);
    # print STDERR "Execute $command2name{$command}\n";
    if (my $fun =
        $connection->{options}{$command2name{$command} ||
                                   croak "Unknown command $command"}) {
        if ($command == QUERY ||
            $command == CREATE_DB || $command == DROP_DB) {
            $fun->($connection, substr($_, 0, $want, ""));
        } elsif ($command == INIT_DB) {
            my $db = substr($_, 0, $want, "");
            my $answer = $connection->{answers}[-1];
            $fun->($connection, $db);
            $connection->{database} = $db if
                $answer->[ARG] && substr($answer->[ARG], 0, 1) eq ENCODED_ZERO;
        } elsif ($command == REFRESH) {
            $want == 1 || croak "Wrong size argument to Refresh";
            $fun->($connection, ord substr($_, 0, $want, ""));
        } elsif ($command == QUIT) {
            $want == 0 || croak "Argument to Quit";
            # $connection->extend;
            $fun->($connection);
            if (@{$connection->{answers}} &&
                $connection->{answers}[0][COMMAND] == QUIT) {
                $connection->{answers}[0][COMMAND] = -1;
                $connection->send_close;
            }
            return;
        } elsif ($command == SHUTDOWN || $command == STATISTICS ||
                 $command == PROCESS_INFO || $command == DEBUG ||
                 $command == PING) {
            $want == 0 || croak "Argument to $command2name{$command}";
            $fun->($connection);
        } elsif ($command == PROCESS_KILL) {
            $want == 4 || croak "Wrong size argument to ProcessKill";
            $fun->($connection, unpack("V", substr($_, 0, $want, "")));
        } elsif ($command == CHANGE_USER) {
            ($connection->{user}, my $pass, $connection->{database}) =
                unpack("Z*Z*Z*", substr($_, 0, $want, ""));
            $fun->($connection, $connection->{user}, $connection->{host}, $pass, $connection->{database});
        } elsif ($command == FIELD_LIST) {
            $fun->($connection, unpack("Z*a*", substr($_, 0, $want, "")));
        } elsif ($command == TABLE_DUMP) {
            my ($database, $table, $rest) =
                unpack("C/a*C/a*a", substr($_, 0, $want, "") . "z");
            $rest eq "z" || croak "Badly encode TableDump";
            $fun->($connection, $database, $table);
        } elsif ($command == BINLOG_DUMP) {
            $want >= 10 || croak "Wrong size argument to BINLOG_DUMP";
            $fun->($connection, unpack("VvVa*", substr($_, 0, $want, "")));
        } else {
            substr($_, 0, $want, "");
            $connection->send_error(NOT_SUPPORTED_YET, "$command2name{$command} is not supported (yet)");
        }
    } elsif ($command == QUIT) {
        $want == 0 || croak "Argument to Quit";
        # $connection->extend;
        if (@{$connection->{answers}} == 1) {
            $connection->{answers}[0][COMMAND] = -1;
            $connection->send_close;
        }
        return;
    } elsif ($command == PING) {
        $want == 0 || croak "Argument to Ping";
        $connection->send_ok;
    } elsif ($command == CHANGE_USER) {
        ($connection->{user}, my $password, $connection->{database}) =
            unpack("Z*Z*Z*", substr($_, 0, $want, ""));
        ($connection->{options}{CheckAccess} || croak "No CheckAccess, so how come you're logged in ?")->($connection, $connection->{user}, $connection->{host}, $password, $connection->{database});
    } elsif ($command == PROCESS_INFO) {
        $want == 0 || croak "Argument to ProcessInfo";
        # Maybe should do some access check...
        $connection->send_simple_process_info;
    } elsif ($command == PROCESS_KILL) {
        $want == 4 || croak "Wrong size argument to ProcessKill";
        my $pid = unpack("V", substr($_, 0, $want, ""));
        if ($pid == $connection->{thread_id}) {
            # Suicide is always allowed
            $connection->kill;
        } else {
            # Kill is by default not allowed
            # Check if this is the right message --Ton
            $connection->send_error(SPECIFIC_ACCESS_DENIED_ERROR,
                                    "Access denied. You need the PROCESS privilege for this operation");
        }
    } else {
        substr($_, 0, $want, "");
        $connection->send_error(NOT_SUPPORTED_YET, "$command2name{$command} is not supported (yet)");
    }
    croak "No answer to ", $command2name{$command} || "Command $command" if
        $connection->{answers} && @{$connection->{answers}} &&
        $connection->{answers}[0][COMMAND] != -1;
}

sub pre_send {
    my $answer = shift;
    my $length = length $_[0];
    if ($length >= MAX3) {
        my $i = 0;
        $length -= MAX3;
        while ($i <= $length) {
            $answer->[ARG] .= pack('V@3C', MAX3, ++$answer->[SEQ_NO] % 256);
            $answer->[ARG] .= substr($_[0], $i, MAX3);
            $i += MAX3;
        }
        $answer->[ARG] .= pack('V@3C', $length-$i+MAX3, ++$answer->[SEQ_NO] % 256);
        $answer->[ARG] .= substr(shift, $i);
    } else {
        $answer->[ARG] .= pack('V@3C', $length, ++$answer->[SEQ_NO] % 256);
        $answer->[ARG] .= shift;
    }
    return;
}

sub flush {
    my ($connection, $answer) = @_;
    if ($connection->{compress}) {
        utf8::downgrade($answer->[ARG], 1) || croak "Wide character in packet";
        my $seq_no = unpack("x3C", $answer->[ARG]) - 1;
        if ($connection->{answers}[0] != $answer) {
            die "Boem";
            return;
        }
        $connection->send0 if $connection->{out_buffer} eq "";
        $connection->send_compressed($seq_no, substr($answer->[ARG], 0, 2**20, "")) while length $answer->[ARG] > 2**20;
        $connection->send_compressed($seq_no, $answer->[ARG]);
        shift @{$connection->{answers}};
    } else {
        return unless $connection->{answers}[0] == $answer;
        $connection->send0 if $connection->{out_buffer} eq "";
    }
    while (@{$connection->{answers}} && $connection->{answers}[0][ARG]) {
        utf8::downgrade($connection->{answers}[0][ARG], 1) || 
            croak "Wide character in packet";
        $connection->{out_buffer} .= $connection->{answers}[0][ARG];
        $connection->{answers}[0][ARG] = undef;
        shift @{$connection->{answers}};
    }
    if (@{$connection->{answers}} &&
        $connection->{answers}[0][COMMAND] == QUIT) {
        $connection->{answers}[0][COMMAND] = -1;
        $connection->send_close;
    }
}

sub under_send {
    my $connection = shift;
    die "Attempt to send on a closed Connection" unless
        $connection->{out_handle};
    die "Message is utf8" if utf8::is_utf8($_[1]);

    my $length = length($_[1]);
    # die "Message too long" if $length >= $connection->{max_packet};
    if ($length >= MAX3) {
        if ($connection->{compress}) {
            croak "Not implemented (yet)";
        }
        my $i = 0;
        $length -= MAX3;
        while ($i <= $length) {
            $_ .= pack('V@3C', MAX3, ++shift->[SEQ_NO] % 256);
            $_ .= substr($_[0], $i, MAX3);
            $i += MAX3;
        }
        $_ .= pack('V@3C', $length-$i+MAX3, ++shift->[SEQ_NO] % 256);
        $_ .= substr($_[0], $i);
        return;
    }

    if ($connection->{compress}) {
        croak "Not implemented (yet)";
    } else {
        $_ .= pack('V@3C', $length, ++shift->[SEQ_NO] % 256);
        $_ .= shift;
    }
    return;
}

sub send_shutdown {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" ? shift : $connection->{answers}[-1];
    $answer->[COMMAND] == SHUTDOWN ||
        croak("Cannot reply with send_shutdown to command ",
              $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]");
    pre_send($answer, "\xfe");
    pre_send($answer, "\xfe");
    $connection->flush($answer);
}

sub send_debugged {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" ? shift : $connection->{answers}[-1];
    $answer->[COMMAND] == DEBUG ||
        croak("Cannot reply with send_debugged to command ",
              $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]");
    pre_send($answer, "\xfe");
    $connection->flush($answer);
}

sub send_statistics {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" ? shift : $connection->{answers}[-1];
    $answer->[COMMAND] == STATISTICS ||
        croak("Cannot reply with send_statistics to command ",
              $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]");
    croak "Empty answer " if $_[0] eq "";
    croak "Answer looks like an error" if substr($_[0], 0, 1) eq ENCODED_ERROR;

    pre_send($answer, shift);
    $connection->flush($answer);
}

# Called as $connection->send_ok(?$answer,? $affected, $insert_id, $msg)
sub send_ok {
    my $connection = shift;
    die "Attempt to send on a closed Connection" unless
        $connection->{out_handle};
    my $answer = ref $_[0] ? shift : $connection->{answers}[-1];
    croak "Cannot reply ok to ", $command2name{$answer->[COMMAND]} || "Command $answer->[COMMAND]" unless $plain{$answer->[COMMAND]};

    my $packet = ENCODED_ZERO;
    $packet .= defined $_[0] ? encode_length(shift) : (shift, ENCODED_ZERO);
    $packet .= defined $_[0] ? encode_length(shift) : (shift, ENCODED_ZERO);
    # Add status here
    if (defined $_[0]) {
        $packet .= encode_length(length $_[0]);
        $packet .= shift;
        utf8::downgrade($packet, 1) || croak "Wide character in message";
    }
    pre_send($answer, $packet);
    $connection->flush($answer);
}

# Called as $connection->send_error(?$answer,? $dualvar) or
# $connection->send_error(?$answer,? $errno, $err_msg)
sub send_error {
    my $connection = shift;
    die "Attempt to send on a closed Connection" unless
        $connection->{out_handle};
    my $answer = ref $_[0] ? shift : $connection->{answers}[-1];
    croak "Cannot reply to QUIT" if
        $answer->[COMMAND] == QUIT || $answer->[COMMAND] == -1;

    defined(my $err = shift) || croak "Undefined error number";
    my $packet = ENCODED_ERROR();
    defined $connection->{protocol} || croak "No protocol set";
    if ($connection->{protocol} == 10) {
        $packet .= pack("v", $err+0 || UNKNOWN_ERROR);
    } elsif ($connection->{protocol} != 9) {
        croak "Unknown protocol $connection->{protocol}";
    }
    defined(my $msg = @_ ? shift : $err) || croak "Undefined error message";
    utf8::downgrade($msg, 1) || croak "Wide character in error message";
    $packet .= $msg;

    if ($answer->[COMMAND] == -2 || $answer->[COMMAND] == CHANGE_USER) {
        my $i = 0;
        $i++ until ($connection->{answers}[$i] ||
                    croak "Target answer is not on the stack") == $answer;
        splice(@{$connection->{answers}}, $i+1, 0, [QUIT]);
    }
    pre_send($answer, $packet);
    $connection->flush($answer);
}

sub send_fields {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY"  && @{$_[0]} && !ref $_[0][0] ?
        shift : $connection->{answers}[-1];
    my $default =
        $answer->[COMMAND] == QUERY || $answer->[COMMAND] == PROCESS_INFO ? 0 :
        $answer->[COMMAND] == FIELD_LIST ? 1 :
        croak "Cannot reply with send_fields to command ", $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]";

    pre_send($answer, encode_length(scalar @{$_[0]})) if !$default;
    my $packet = "";
    my $flag_format = defined($connection->{protocol}) ?
        $connection->{protocol} == 10 ? "vC" :
        $connection->{protocol} ==  9 ? "CC" :
        croak "Unknown protocol $connection->{protocol}" :
        croak "No protocol set";
    my ($tmp, $field_start);
    for my $field (@{shift()}) {
        $field_start = length $packet;
        $packet .= encode_string($field->{Table});
        $packet .= encode_string($field->{Field});
        $packet .= encode_string(substr(pack("V", $field->{MaxLength}), 0, 3));
        defined($tmp = $name2field_type{$field->{Type}}) ||
            croak "Unknown field type $field->{Type}";
        $packet .= encode_string($tmp);
        $packet .= encode_string(pack($flag_format,
                                      $field->{Flags}, $field->{Decimals}));
        $packet .= encode_string($field->{Default}) if $default;
        if (length($packet) >= $connection->{max_packet}) {
            # croak "Single field entry above max packet size" if !$field_start;
            $tmp = substr($packet, $field_start, length($packet)-$field_start, "");
            pre_send($answer, $packet);
            $packet = $tmp;
        }
    }
    pre_send($answer, $packet) if $packet ne "";
    pre_send($answer, "\xfe");
    $connection->flush($answer) if $default;
}

sub send_table {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" && @{$_[0]} && !ref $_[0][0] ?
        shift : $connection->{answers}[-1];
    $answer->[COMMAND] == QUERY || $answer->[COMMAND] == PROCESS_INFO ||
        croak "Cannot reply with send_table to command ", $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]";

    my $fields = shift;
    my $nr_cols = @$fields;
    $connection->send_fields($answer, $fields);
    for my $row (@{shift()}) {
        my $packet = "";
        @$row == $nr_cols || croak "Inconsistent number of columns ($nr_cols column declarations, but ", scalar @$row, " rows)";
        $packet .= encode_string($_) for @$row;

        # croak "Single field entry above max packet size" if
        #     length($packet) >= $connection->{max_packet};
        pre_send($answer, $packet);
    }
    pre_send($answer, "\xfe");
    $connection->flush($answer);
}

sub send_process_info {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" && @{$_[0]} && !ref $_[0][0] ?
        shift : $connection->{answers}[-1];
    $answer->[COMMAND] == PROCESS_INFO ||
        croak "Cannot reply with send_process_info to command ", $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]";
    $connection->send_table($answer, \@process_fields, shift);
}

sub send_simple_process_info {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" && @{$_[0]} && !ref $_[0][0] ?
        shift : $connection->{answers}[-1];
    $answer->[COMMAND] == PROCESS_INFO ||
        croak "Cannot reply with send_process_info to command ", $command2name{$answer->[COMMAND]} || "command $answer->[COMMAND]";
    $connection->send_table($answer, \@process_fields, [map {
        my $c = $_;
        # What if COMMAND is -1 ? -2 ? --Ton
        # Do something with Time/State/Info --Ton
        # We display the last pending command so that user etc. will be right
        [@$c{qw(thread_id user host database)}, @{$c->{answers}} ? $command2name{$c->{answers}[-1][COMMAND]} || $c->{answers}[-1][COMMAND] : undef, 0, undef, undef];
    } $connection->{parent}->connections]);
}

sub send_table_dump {
    my $connection = shift;
    my $answer = ref $_[0] eq "ARRAY" && @{$_[0]} && !ref $_[0][0] ?
        shift : $connection->{answers}[-1];

    for my $blob (@_) {
        #croak "Single field entry above max packet size" if
        #    length($blob) >= $connection->{max_packet};
        croak "Empty blob" if $blob eq "";
        pre_send($answer, $blob);
    }
    pre_send($answer, "");
    $connection->flush($answer);
}

sub host {
    return shift->{host};
}

package WEC::MySQL::Statement;
our $VERSION = "1.000";

sub execute {
    my $statement = shift;
    my $connection = $statement->[1];
    return $connection->query(shift, sprintf($statement->[0], map $connection->quote($_), @_)) if !defined $_[0] || ref $_[0] eq "CODE";
    my %params = @_;
    return $connection->query(Query => sprintf($statement->[0], map $connection->quote($_), @{delete $params{Args} || []}), %params);
}

1;

__END__

pieces of the code are derived from Net::MySQL
