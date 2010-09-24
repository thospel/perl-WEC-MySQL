use 5.008_001;
use strict;
use warnings;

use POSIX qw(ECONNRESET);

use WEC::MySQL::Client;
use WEC::MySQL::Server;
use WEC::MySQL::Connection;
use WEC::MySQL::Constants qw(ACCESS_DENIED_ERROR SPECIFIC_ACCESS_DENIED_ERROR
                             BAD_DB_ERROR PARSE_ERROR
                             MASTER_FATAL_ERROR_READING_BINLOG
                             DBACCESS_DENIED_ERROR NO_SUCH_THREAD);

use WEC::Test (TraceLine => 0,
               Class => "WEC::MySQL", Parts => [qw(Connection Client Server)]);
my $show_threads = 0;

sub show_thread {
    return unless $show_threads;
    my $thread = shift->thread_id;
    diag("Thread $thread did " . shift);
}

my (%client_args, $early_send);
sub test_op {
    # diag("@{[caller]}");
    my $partial = shift;
    my $pre;
    if ($partial eq "pre") {
        $pre = shift;
        $partial = shift;
    }
    my ($op, @a) = @_;
    for (0..$partial) {
        my @args;
        if ($_) {
            @args = ($_ > 1 ? (Partial => 1) : (), Callback => @a);
        } else {
            @args = map $a[2*$_], 0..@a/2;
        }
        $pre->($_) if $pre;
        WEC->init;
        $hit = 0;
        $client = WEC::MySQL::Client->new
            (%client_args,
             Greeting => sub {
                 is(++$hit, 1);
                 my $c = shift;
                 show_thread($c, $op);
                 if (!$early_send) {
                     $c->$op(@args);
                     $c->quit;
                 }
             },
             Close => sub {
                 is(++$hit, 3);
                 $client = undef;
                 unloop;
             });
        if ($early_send) {
            my $c = $client->connect;
            @warnings = ();
            local $SIG{__WARN__} = sub { push @warnings, shift };
            $c->$op(@args);
            $c->quit;
            if ($op eq "create_db" || $op eq "drop_db") {
                is(@warnings, 1);
                is($warnings[0], "$op callback can be lost\n", "Proper warning");
            } else {
                diag(join("", @warnings)) if @warnings;
                is(@warnings, 0, "No warnings");
            }
        } else {
            $client->connect;
        }
        warn_loop();
        is($hit, 3, "Got all events");
        if (!$early_send && ($op eq "create_db" || $op eq "drop_db")) {
            is(@warnings, 1);
            is($warnings[0], "$op callback can be lost\n", "Proper warning");
            diag(join("", @warnings)) if @warnings != 1;
        } else {
            diag(join("", @warnings)) if @warnings;
            is(@warnings, 0, "No warnings");
        }
        check_fd;
        check_objects;
    }
}

sub test_prepare {
    # diag("@{[caller]}");
    my $partial = shift;
    my $pre;
    if ($partial eq "pre") {
        $pre = shift;
        $partial = shift;
    }
    my ($callback, $pattern, %a) = @_;
    for (0..$partial) {
        my @args;
        if ($_) {
            @args = ($_ > 1 ? (Partial => 1) : (), Callback => $callback, %a);
        } else {
            @args = ($callback, exists $a{Args} ? @{$a{Args}} : ());
        }
        # diag("pattern=$pattern,args=@args");
        $pre->($_) if $pre;
        WEC->init;
        $hit = 0;
        $client = WEC::MySQL::Client->new
            (%client_args,
             Greeting => sub {
                 is(++$hit, 1);
                 my $c = shift;
                 show_thread($c, "query $pattern");
                 if (!$early_send) {
                     my $sth = $c->prepare($pattern);
                     $sth->execute(@args);
                     $c->quit;
                 }
             },
             Close => sub {
                 is(++$hit, 3);
                 $client = undef;
                 unloop;
             });
        if ($early_send) {
            my $c = $client->connect;
            @warnings = ();
            local $SIG{__WARN__} = sub { push @warnings, shift };
            my $sth = $c->prepare($pattern);
            $sth->execute(@args);
            $c->quit;
            diag(join("", @warnings)) if @warnings;
            is(@warnings, 0, "No warnings");
        } else {
            $client->connect;
        }
        warn_loop();
        is($hit, 3, "Got all events");
        diag(join("", @warnings)) if @warnings;
        is(@warnings, 0, "No warnings");
        check_fd;
        check_objects;
    }
}

my $table = "wec_test";
my $fill_count;
sub fill {
    my $c = shift;
    if (--$fill_count < 0) {
        $c->quit;
        return;
    }
    if (shift ne "ok") {
        diag("Failed to insert: @_");
        fail("Failed to insert: @_");
        $c->quit;
        return;
    }
    my $str = "insert into $table values(NULL, 'foo$fill_count')";
    for (1..9999) {
        last if --$fill_count < 0;
        $str .= ",(NULL, 'foo$fill_count')";
    }
    $c->query(\&fill, $str);
}

my $file;
my @files = ($ENV{HOME} ? ("$ENV{HOME}/conf/test_mysql.id", "$ENV{HOME}/test_mysql.id") : (), "t/test_mysql.id", "test_mysql.id");
for (@files) {
    next unless -f  && -r _;
    require $_;
    $file = $_;
    last;
}
$file || die "Could not find a file with mysql ids out of @files";
our ($destination, $user, $password, $database, $scratch_database, $startup);

%client_args = ($destination ? (Destination => $destination) : (),
                User	 => $user,
                Password => $password,
                Database => $database,
                Compress => undef);

# Basic connectivity test
WEC->init;
$hit = 0;
$client = WEC::MySQL::Client->new
    (%client_args,
     Greeting => sub {
         $hit++;
         is(@_, 1, "One argument");
         my $c = shift;
         isa_ok($c, "WEC::MySQL::Connection");
         show_thread($c, "unclean quit");
         is($c->quote("def\0\n\r\\'\"\032abc"),"'def\\0\\n\\r\\\\\\'\\\"\\Zabc'",
            "proper quoting");
         is($c->quote(undef), "NULL", "proper quoting of undef");
         is($c->quote(""), "''", "proper quoting of empty string");
         is($c->quote("\0"), "'\\0'", "proper quoting of \\0");
         my $a = "def\0\n\r\\'\"\032abc";
         $c->_quote($a);
         is($a, "'def\\0\\n\\r\\\\\\'\\\"\\Zabc'", "proper _quoting");
         $a = undef;
         $c->_quote($a);
         is($a, "NULL", "proper quoting of undef");
         $a = "";
         $c->_quote($a);
         is($a, "''", "proper quoting of empty string");
         $a = "\0";
         $c->_quote($a);
         is($a, "'\\0'", "proper quoting of \\0");
         $client = undef;
         unloop;
     });
$client->connect;
loop;
is($hit, 1, "Got all events");
check_fd;
check_objects;

# Try a clean quit too
WEC->init;
$hit = 0;
$client = WEC::MySQL::Client->new(%client_args,
                                  Greeting => sub {
                                      is(++$hit, 1);
                                      my $c = shift;
                                      $c->quit;
                                      like($c->thread_id, qr/\A\d+\z/);
                                      show_thread($c, "clean quit");
                                  },
                                  Close => sub {
                                      is(++$hit, 2);
                                      is(@_, 3, "Three args");
                                      isa_ok(shift, "WEC::MySQL::Client");
                                      isa_ok(shift, "WEC::MySQL::Connection");
                                      is(shift, "quit");
                                      $client = undef;
                                      unloop;
                                  });
$client->connect;
loop;
is($hit, 2, "Got all events");
check_fd;
check_objects;

# Now try a callback
WEC->init;
$hit = 0;
$client = WEC::MySQL::Client->new
    (%client_args,
     Greeting => sub {
         is(++$hit, 1);
         my $c = shift;
         $c->ping(sub {
             is(++$hit, 2);
             is(@_, 3, "Three args");
             my $c = shift;
             isa_ok($c, "WEC::MySQL::Connection");
             is(shift, "ok");
             my $ok = $c->parse_ok(shift);
             is_deeply($ok, {
                 affected  => 0,
                 insert_id => 0,
             });
         });
         show_thread($c, "cleaner quit");
         $c->quit;
     },
     Close => sub {
         is(++$hit, 3);
         $client = undef;
         unloop;
     });
$client->connect;
loop;
is($hit, 3, "Got all events");
check_fd;
check_objects;

for my $compressed (1) {
    local $client_args{Compress} = $compressed;
    for my $early (0, 1) {
        $early_send = $early;
        # Same thing using test_op
        test_op(1, ping => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "ok");
            my $ok = $c->parse_ok(shift);
            is_deeply($ok, {
                affected  => 0,
                insert_id => 0,
            });
        });

        # Ok, we can actually DO things. Now systematically test ops
        {
            my $db = $client_args{Database};
            local $client_args{Database} = undef;
            test_op(1, select_db => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "ok");
                my $ok = $c->parse_ok(shift);
                is_deeply($ok, {
                    affected  => 0,
                    insert_id => 0,
                });
            }, Database => $db);

            test_op(1, select_db => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "-error");
                my $err = shift;
                if ($err == DBACCESS_DENIED_ERROR) {
                    pass("Access denied");
                    like($err, qr/Access denied for user: .* to database 'ThisDatabaseShouldReallyNotExist'/);
                } elsif ($err == BAD_DB_ERROR) {
                    pass("Unknown database");
                    like($err, qr/Unknown database 'ThisDatabaseShouldReallyNotExist'/);
                } else {
                    fail("Unexpected errno $err");
                }
            }, Database => "ThisDatabaseShouldReallyNotExist");
        }

        test_op(2, query => sub {
            is(++$hit, 2);
            is(@_, 4, "Four args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "table");
            is_deeply(shift, [{Table => "",
                               Field => "5+3",
                               MaxLength => 17,
                               Type => "LONGLONG",
                               Flags => 1, Decimals => 0}], "proper fields");
            is_deeply(shift, [['8']], "Proper table values");
        }, Query => "SELECT 5+3");

        test_op(pre => sub {
            test_op(0, query => sub {
                is(++$hit, 2);
            }, Query => "drop table $table");
        }, 2, query => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "ok");
            my $ok = $c->parse_ok(shift);
            is_deeply($ok, {
                affected  => 0,
                insert_id => 0,
            });
        }, Query => "create table $table (id int auto_increment, foo varchar(20) unique, primary key(id))");

        my $i = 0;
        test_op(pre => sub {
            test_op(0, query => sub {
                is(++$hit, 2);
            }, Query => "delete from $table where foo = 'foo'");
        }, 2, query => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "ok");
            my $ok = $c->parse_ok(shift);
            is_deeply($ok, {
                affected  => 1,
                insert_id => ++$i,
            });
        }, Query => "insert into $table values(NULL, 'foo')");

        my $j = $i+1;
        my $test_string = pack("C*", 0..255);
        for my $test_content ($test_string =~ /.{1,18}/sg) {
            # diag("Content=$test_content(" . unpack("H*", $test_content) . ")");
            test_op(0, query => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "ok");
                my $ok = $c->parse_ok(shift);
                is_deeply($ok, {
                    affected  => 1,
                    insert_id => $j,
                });
            }, Query => "insert into $table values('$j', " . WEC::MySQL::Connection->quote($test_content) . ")");

            test_op(2, query => sub {
                is(++$hit, 2);
                is(@_, 4, "Four args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "table");
                is_deeply(shift, [{
                    'Table' => 'wec_test',
                    'Type' => 'LONG',
                    'Field' => 'id',
                    'Flags' => 16899,
                    'Decimals' => 0,
                    'MaxLength' => 11
                    }, {
                        'Table' => 'wec_test',
                        'Type' => 'VAR_STRING',
                        'Field' => 'foo',
                        'Flags' => 16392,
                        'Decimals' => 0,
                        'MaxLength' => 20
                        }], "Correct table declaration");
                is_deeply(shift, [[$j, $test_content]], "Got back quoted content");
            }, Query => "SELECT * FROM $table WHERE id='$j'");
            test_op(0, query => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "ok");
                my $ok = $c->parse_ok(shift);
                is_deeply($ok, {
                    affected  => 1,
                    insert_id => 0,
                });
            }, Query => "DELETE FROM $table WHERE id='$j'");
        }

        test_op(2, query => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "-error");
            my $err = shift;
            is($err+0, PARSE_ERROR, "proper errno");
            like($err, qr/You have an error in your SQL syntax/);
        }, Query => "insert into $table values(NULL, 'bar'); insert into $table values(NULL, 'baz')");

        test_op(1, field_list => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "fields");
            is_deeply(shift, [{Table	=> "wec_test",
                               Field	=> "id",
                               MaxLength	=> 11,
                               Type		=> "LONG",
                               Flags	=> 16899,
                               Decimals	=> 0,
                               Default	=> "0"},
                              {Table => "wec_test",
                               Field => "foo",
                               MaxLength => 20,
                               Type => "VAR_STRING",
                               Flags => 16392,
                               Decimals	=> 0,
                               Default => undef}],
                      "proper fields");
        }, Table => $table);

        if ($scratch_database) {
            my $created;
            test_op(pre => sub {
                # Drop test database just in case
                test_op(0, query => sub {
                    is(++$hit, 2);
                }, Query => "DROP DATABASE `$scratch_database`");
            }, 1, create_db => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                my $code = shift;
                if ($code eq "ok") {
                    $created = 1;
                    my $ok = $c->parse_ok(shift);
                    is_deeply($ok, {
                        affected  => 1,
                        insert_id => 0,
                    });
                } elsif ($code eq "-error") {
                    $created = 0;
                    my $err = shift;
                    is($err+0, DBACCESS_DENIED_ERROR, "Access denied");
                    like($err, qr/Access denied for user: .* to database '\Q$scratch_database\E'/);
                } else {
                    diag("Unexpected arguments $code @_");
                    fail("Unexpected arguments $code @_");
                }
            }, Database => $scratch_database);

            test_op(pre => sub {
                # Create test database just in case
                test_op(0, query => sub {
                    is(++$hit, 2);
                }, Query => "CREATE DATABASE `$scratch_database`");
            }, 1, drop_db => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                my $code = shift;
                if ($code eq "ok") {
                    $created = 1;
                    my $ok = $c->parse_ok(shift);
                    is_deeply($ok, {
                        affected  => 0,
                        insert_id => 0,
                    });
                } elsif ($code eq "-error") {
                    $created = 0;
                    my $err = shift;
                    is($err+0, DBACCESS_DENIED_ERROR, "Access denied");
                    like($err, qr/Access denied for user: .* to database '\Q$scratch_database\E'/);
                } else {
                    diag("Unexpected arguments $code @_");
                    fail("Unexpected arguments $code @_");
                }
            }, Database => $scratch_database);
        }

        test_op(1, refresh => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            my $code = shift;
            if ($code eq "ok") {
                my $ok = $c->parse_ok(shift);
                is_deeply($ok, {
                    affected  => 0,
                    insert_id => 0,
                });
            } elsif ($code eq "-error") {
                # No permission
                my $err = shift;
                is($err+0, SPECIFIC_ACCESS_DENIED_ERROR);
                like($err, qr/Access denied. You need the RELOAD privilege for this operation/);
            } else {
                fail("Unexpected number arguments $code @_");
            }
        }, Flags => 0);

        # Skip shutdown

        test_op(1, statistics => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "text");
            like(shift, qr/Uptime: \d+/);
        });

        test_op(2, process_info => sub {
            is(++$hit, 2);
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            if (@_ == 3) {
                is(shift, "table", "Tabular response");
                is_deeply(shift, [{Table	=> "",
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
                                   Flags	=> 0}],
                          "proper fields");
                my $procs = shift;
                my $thread = $c->thread_id;
                isa_ok($procs, "ARRAY", "Is an array reference");
                isa_ok($procs->[0], "ARRAY", "Elements are array references");
                my @procs = grep $_->[0] == $thread, @$procs;
                is(@procs, 1, "Exactly one process handles me");
                $procs = $procs[0];
                is($procs->[3], $database, "Correct current database");
                if ($procs->[4] eq "Processlist") {
                    pass("Obviously running myself");
                } elsif ($procs->[4] eq "ProcessInfo") {
                    pass("Obviously running fake server");
                } else {
                    diag("Unexpected action $procs->[4]");
                    fail("Unexpected action $procs->[4]");
                }
                is($procs->[6], undef, "no state");
                is($procs->[7], undef, "no info");
            } elsif (@_ == 2) {
                is(shift, "-error", "error");
                my $err = shift;
                is($err+0, SPECIFIC_ACCESS_DENIED_ERROR);
                like($err, qr/Access denied\. You need the PROCESS privilege for this operation/);
            } else {
                fail("Unexpected code @_");
            }
        });

        my $thread = undef;
        WEC->init;
        $hit = 0;
        $client = WEC::MySQL::Client->new
            (%client_args,
             Greeting => sub {
                 is(++$hit, 1);
                 my $c = shift;
                 $thread = $c->thread_id;
                 $c->process_kill(sub {
                     is(++$hit, 2);
                     is(@_, 3, "Three args");
                     my $c = shift;
                     isa_ok($c, "WEC::MySQL::Connection");
                     is(shift, "ok");
                     my $ok = $c->parse_ok(shift);
                     is_deeply($ok, {
                         affected  => 0,
                         insert_id => 0,
                     });
                 }, $thread);
                 show_thread($c, "process kill");
                 $c->quit;
             },
             Close => sub {
                 is(++$hit, 3);
                 $client = undef;
                 unloop;
             });
        $client->connect;
        loop;
        is($hit, 3, "Got all events");
        check_fd;
        check_objects;

        # The previous thread id shouldn't be reused by now
        test_op(1, process_kill => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            my $code = shift;
            if ($code eq "ok") {
                fail("Successfully killed an unexpected thread");
                diag("*************************\nKilled some random thread in your mysql server. This should never happen. Please contact the module author and tell him about your mysql version\n*************************");
                # Don't try to continue, or we might do it again.
                exit;
            }
            is($code, "-error", "error");
            my $err = shift;
            is($err+0, NO_SUCH_THREAD);
            like($err, qr/Unknown thread id: $thread/);
        }, Pid => $thread);

        test_op(1, debug_info => sub {
            is(++$hit, 2);
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            if (@_ == 2) {
                is(shift, "-error");
                my $err = shift;
                is($err+0, SPECIFIC_ACCESS_DENIED_ERROR);
                like($err, qr/Access denied\. You need the SUPER privilege for this operation/);
            } elsif (@_ == 1) {
                pass("One arg");
                is(shift, "none");
                diag("debug info should have been added to your mysql error log");
            } else {
                fail("Unexpected number of args @_");
            }
        });

        # We already tested ping

        {
            my $db = $client_args{Database};
            local $client_args{Database} = undef;
            test_op(1, change_user => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "ok");
                my $ok = $c->parse_ok(shift);
                is_deeply($ok, {
                    affected  => 0,
                    insert_id => 0,
                });
            }, User => $user, Password => $password, Database => $db);

            test_op(1, change_user => sub {
                is(++$hit, 2);
                is(@_, 3, "Three args");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "-error");
                my $err = shift;
                if ($err == DBACCESS_DENIED_ERROR) {
                    like($err, qr/Access denied for user: .* to database 'ThisDatabaseShouldReallyNotExist'/);
                } elsif ($err == BAD_DB_ERROR) {
                    like($err, qr/Unknown database 'ThisDatabaseShouldReallyNotExist'/);
                } else {
                    fail("Unexpected error $err");
                }
            }, User => $user, Password => $password,
                    Database => "ThisDatabaseShouldReallyNotExist");
        }

        # We don't know what a valid binlog_dump is, so only test an invalid one
        test_op(1, binlog_dump => sub {
            is(++$hit, 2);
            is(@_, 3, "Three args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "-error", "Did not work");
            my $err = shift;
            if ($err == SPECIFIC_ACCESS_DENIED_ERROR) {
                like($err, qr/Access denied. You need the REPLICATION SLAVE privilege for this operation/);
            } elsif ($err == MASTER_FATAL_ERROR_READING_BINLOG) {
                like($err, qr/Binary log is not open/);
            } else {
                diag("Unexpected error $err");
                fail("Unexpected error $err");
            }
        }, Position => 0, Flags => 0, Slave => 0, File => "ThisFileShouldReallyNotExist");

        {
            my $db = $client_args{Database};
            local $client_args{Database} = undef;

            test_op(1, table_dump => sub {
                is(++$hit, 2);
                is(@_, 4, "Four arguments");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "table_dump", "Table dump");
                is(shift, "CREATE TABLE `wec_test` (
  `id` int(11) NOT NULL auto_increment,
  `foo` varchar(20) default NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `foo` (`foo`)
) TYPE=MyISAM");
                isa_ok(shift, "ARRAY", "array of blocks");
            }, Database => $db, Table => $table);

            test_op(2, table_dump => sub {
                is(++$hit, 2);
                is(@_, 3, "Three arguments");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                is(shift, "-error");
                my $err = shift;
                is($err+0, 1146);
                like($err, qr/Table 'ThisDatabaseShouldReallyNotExist\.wec_test' doesn\'t exist/);
            }, Database => "ThisDatabaseShouldReallyNotExist", Table => $table);
        }

        if ($startup) {
            diag("\nWill now try to shut down the server.\nDon't define \$startup in your test_mysql.id if you don't want this");
            my $stopped;
            test_op(1, shutdown => sub {
                is(++$hit, 2);
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                if (@_ == 2) {
                    pass("Shutdown failed");
                    $stopped = 0;
                    is(shift, "-error", "error");
                    my $err = shift;
                    is($err+0, SPECIFIC_ACCESS_DENIED_ERROR, "Access denied");
                    like($err, qr/Access denied. You need the SHUTDOWN privilege for this operation/);
                    diag("Shutdown failed: $err");
                } elsif (@_ == 1) {
                    $stopped = 1;
                    pass("Shutdown done");
                    is(shift, "none");
                } else {
                    fail("Unexpected arguments @_");
                }
            });
            if ($stopped) {
                diag("Restarting server");
                sleep 5;
                if (my $rc = system($startup)) {
                    fail("Restart returned $rc");
                    diag("Unexpected returncode $rc from $startup. Giving up\nPlease restart the server by hand");
                    exit;
                }
                sleep 5;

                # See if server is back
                test_op(1, ping => sub {
                    is(++$hit, 2);
                });
                if ($hit != 3) {
                    fail("Server restart failed");
                    diag("Failed to restart the server");
                    exit;
                }
            }
        }

        if (0) {
            test_op(1, process_info => sub {
                is(++$hit, 2);
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                use Data::Dumper;
                diag(Dumper(\@_));
            });
        }
        test_prepare(1, sub {
            is(++$hit, 2);
            is(@_, 4, "Four arguments");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "table");
            is_deeply(shift, [{
                'Table' => '',
                'Type' => 'DOUBLE',
                'Field' => "'5'+'3'",
                'Flags' => 1,
                'Decimals' => 31,
                'MaxLength' => 23,
            }]);
            is_deeply(shift, [["8"]]);
        }, "select ?+?", Args => [5, 3]);

        test_prepare(1, sub {
            is(++$hit, 2);
            is(@_, 4, "Four arguments");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            is(shift, "table");
            is_deeply(shift, [{
                'Table' => '',
                'Type' => 'DOUBLE',
                'Field' => "'5'+'3'",
                'Flags' => 1,
                'Decimals' => 31,
                'MaxLength' => 23,
            }]);
            is_deeply(shift, [["8"]]);
        }, "select :2+:1", Args => [3, 5]);
    }
}

$early_send = 0;
# Do some serious table filling
my $fills = 10000;
$fill_count = $fills;
WEC->init;
$hit = 0;
$client = WEC::MySQL::Client->new
    (%client_args,
     Greeting => sub {
         is(++$hit, 1);
         my $c = shift;
         fill($c, "ok");
     },
     Close => sub {
         is(++$hit, 2);
         $client = undef;
         unloop;
     });
$client->connect;
loop;
is($hit, 2, "Got all events");
check_fd;
check_objects;

for my $compressed (1) {
    local $client_args{Compress} = $compressed;
    for my $early (0, 1) {
        $early_send = $early;
        my ($f, $run, $parts);
        test_op(pre => sub {
            $f = $parts = 0;
            $run = shift;
        }, 2, query => sub {
            is(++$hit, 2);
            is(@_, 4, "Four args");
            my $c = shift;
            isa_ok($c, "WEC::MySQL::Connection");
            my $code = shift;
            is_deeply(shift, [{Table	=> "wec_test",
                               Field	=> "id",
                               MaxLength=> 11,
                               Type	=> "LONG",
                               Flags	=> 16899,
                               Decimals	=> 0},
                              {Table	=> "wec_test",
                               Field	=> "foo",
                               MaxLength=> 20,
                               Type	=> "VAR_STRING",
                               Flags	=> 16392,
                               Decimals	=> 0}],
                      "proper fields");
            my $rows = shift;
            isa_ok($rows, "ARRAY");
            $f += @$rows;
            if ($code eq "table") {
                is($f, 1+$fills, "Expected number of rows");
                if ($run == 2 && !$compressed) {
                    # diag("parts=$parts");
                    ok($parts, "Multipart return");
                } else {
                    is($parts, 0, "Single part return");
                }
            } elsif ($code eq "+table") {
                is($run, 2, "Only on partial request");
                ok(@$rows, "More than zero rows");
                $parts++;
                $hit--;
            } else {
                diag("Unexpected code $code @_");
                fail("unexpected code $code");
            }
        }, Query => "select * from $table");

        {
            my $db = $client_args{Database};
            local $client_args{Database} = undef;

            my $expect_blocks;
            test_op(pre => sub {
                $f = $parts = 0;
                $run = shift;
            }, 2, table_dump => sub {
                is(++$hit, 2);
                is(@_, 4, "Four arguments");
                my $c = shift;
                isa_ok($c, "WEC::MySQL::Connection");
                my $code = shift;
                is(shift, "CREATE TABLE `wec_test` (
  `id` int(11) NOT NULL auto_increment,
  `foo` varchar(20) default NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `foo` (`foo`)
) TYPE=MyISAM");
                my $blocks = shift;
                isa_ok($blocks, "ARRAY", "array of blocks");
                $f += @$blocks;
                if ($code eq "table_dump") {
                    $expect_blocks = $f if $run == 0;
                    is($f, $expect_blocks, "Expected number of blocks");
                    if ($run == 2) {
                        # diag("parts=$parts");
                        ok($parts, "Multipart return");
                    } else {
                        is($parts, 0, "Single part return");
                    }
                    # diag("$f blocks");
                } elsif($code eq "+table_dump") {
                    is($run, 2, "Only on partial request");
                    ok(@$blocks, "More than zero rows");
                    exit unless @$blocks;
                    $parts++;
                    $hit--;
                } else {
                    diag("Unexpected code $code @_");
                    fail("unexpected code $code");
                }
            }, Database => $db, Table => $table);
        }
    }
}

$early_send = 0;

sub wide {
    local $SIG{__WARN__} = sub { push @warnings, shift };
    is(@warnings, 0, "No warnings yet");
    my $c = shift;
    eval { $c->select_db(undef, chr(256)) };
    like($@, qr!Wide character in database at t/TestKernel.pm!);
    eval { $c->query(undef, chr(256)) };
    like($@, qr!Wide character in query at t/TestKernel.pm!);
    eval { $c->field_list(undef, chr(256)) };
    like($@, qr!Wide character in table at t/TestKernel.pm!);

    eval { $c->create_db(undef, chr(256)) };
    like($@, qr!Wide character in create_db argument at t/TestKernel.pm!);
    is(@warnings, 1);
    is($warnings[0], "create_db callback can be lost\n");
    @warnings = ();

    eval { $c->drop_db(undef, chr(256)) };
    like($@, qr!Wide character in drop_db argument at t/TestKernel.pm!);
    is(@warnings, 1);
    is($warnings[0], "drop_db callback can be lost\n");
    @warnings = ();

    eval { $c->change_user(undef, chr(256), undef, undef) };
    like($@, qr!Wide character in user at t/TestKernel.pm!);
    eval { $c->change_user(undef, undef, chr(256), undef) };
    like($@, qr!Wide character in password at t/TestKernel.pm!);
    eval { $c->change_user(undef, undef, undef, chr(256)) };
    like($@, qr!Wide character in database at t/TestKernel.pm!);
    eval { $c->binlog_dump(undef, 0, 0, 0, chr(256)) };
    like($@, qr!Wide character in filename at t/TestKernel.pm!);
    eval { $c->table_dump(undef, chr(256), "") };
    like($@, qr!Wide character in database name at t/TestKernel.pm!);
    eval { $c->table_dump(undef, "", chr(256)) };
    like($@, qr!Wide character in table name at t/TestKernel.pm!);
}

WEC->init;
$hit = 0;
@warnings = ();
$client = WEC::MySQL::Client->new
    (%client_args,
     Greeting => sub {
         is(++$hit, 1);
         my $c = shift;
         wide($c);
         $c->quit;
     },
     Close => sub {
         is(++$hit, 2);
         $client = undef;
         unloop;
     });
wide($client->connect);
loop;
is($hit, 2, "Got all events");
check_fd;
check_objects;

WEC->init;
eval { WEC::MySQL::Client->new(User => chr(256))->connect };
like($@, qr"Wide character in user at t/TestKernel.pm");
eval { WEC::MySQL::Client->new(Password => chr(256))->connect };
like($@, qr"Wide character in password at t/TestKernel.pm");
eval { WEC::MySQL::Client->new(Database => chr(256))->connect };
like($@, qr"Wide character in database at t/TestKernel.pm");
check_fd;
check_objects;

# Test a connection failure
WEC->init;
$hit = 0;
$client = WEC::MySQL::Client->new
    (User => $user,
     Password => "BadPass" . ($password || ""),
     Close => sub {
         is(++$hit, 1);
         is(@_, 4);
         isa_ok(shift, "WEC::MySQL::Client", "Proper client");
         isa_ok(shift, "WEC::MySQL::Connection", "Proper connection");
         is(shift, "reject", "Proper error");
         my $err = shift;
         is($err+0, ACCESS_DENIED_ERROR());
         like($err, qr/Access denied for user: .* \(Using password: YES\)/);
         $client = undef;
         unloop();
     });
$client->connect;
warn_loop;
is(@warnings, 1, "One warning");
like($warnings[0], qr/Connection to MySQL database failed: Access denied for user: .* \(Using password: YES\)/, "proper warning");
is($hit, 1, "Got all events");
check_fd;
check_objects;

# Test Reject callback failure
WEC->init;
$hit = 0;
$client = WEC::MySQL::Client->new
    (User => $user,
     Password	=> "BadPass" . ($password || ""),
     Reject	=> sub {
         is(++$hit, 1);
         is(@_, 2, "Two args");
         isa_ok(shift, "WEC::MySQL::Connection");
         my $err = shift;
         is($err+0, ACCESS_DENIED_ERROR(), "proper error code");
         like($err, qr"Access denied for user: .* \(Using password: YES\)");
     },
     Close => sub {
         is(++$hit, 2);
         is(@_, 4);
         isa_ok(shift, "WEC::MySQL::Client", "Proper client");
         isa_ok(shift, "WEC::MySQL::Connection", "Proper connection");
         is(shift, "reject", "Proper error");
         my $err = shift;
         is($err+0, ACCESS_DENIED_ERROR());
         like($err, qr/Access denied for user: .* \(Using password: YES\)/);
         $client = undef;
         unloop();
     });
$client->connect;
loop;
is($hit, 2, "Got all events");
check_fd;
check_objects;

my ($pushed, $cause);
sub hit_c {
    $hit++;
    isa_ok(shift, "WEC::MySQL::Connection");
    is(shift, "-close", "close callback");
    if ($cause eq "reject") {
        is(@_, 2, "Four args");
        is(shift, "reject", "Cause reject");
        my $err = shift;
        is($err+0, ACCESS_DENIED_ERROR(), "Proper errorcode");
        like($err, qr"Access denied for user: .* \(Using password: YES\)");
    } elsif ($cause eq "eof") {
        if (@_ == 2) {
            is(shift, "eof", "Cause eof");
            is(shift, $!=ECONNRESET);
        } elsif (@_ == 1) {
            is(shift, "quit", "Explicit quit");
        } else {
            diag("Unexpected close cause @_");
            fail("Unexpected close cause @_");
        }
    } else {
        fail("Unknown cause $cause");
    }
}

sub push_work {
    my $c = shift;
    $c->select_db(\&hit_c, "foo");	$pushed++;
    $c->query(\&hit_c, "foo");		$pushed++;
    $c->field_list(\&hit_c, "foo");	$pushed++;
    $c->create_db(\&hit_c, "foo");	$pushed++;
    $c->drop_db(\&hit_c, "foo");	$pushed++;
    $c->shutdown(\&hit_c);		$pushed++;
    $c->statistics(\&hit_c);		$pushed++;
    $c->process_info(\&hit_c);		$pushed++;
    $c->process_kill(\&hit_c, 0);	$pushed++;
    $c->debug_info(\&hit_c);		$pushed++;
    $c->ping(\&hit_c);			$pushed++;
    $c->change_user(\&hit_c, "foo", "bar", "baz");	$pushed++;
    $c->binlog_dump(\&hit_c, 0, 0, 0, "foo");		$pushed++;
    $c->table_dump(\&hit_c, "foo", "bar");		$pushed++;
}

if ($hit == 2) {
    # Push work and let connect fail. We should get close callbacks
    WEC->init;
    $pushed = 0;
    $cause = "reject";
    $hit = 0;
    $client = WEC::MySQL::Client->new
        (User 		=> $user,
         Password	=> "BadPass" . ($password || ""),
         Reject	=> sub {
             is(++$hit, 1);
             is(@_, 2, "Two args");
             isa_ok(shift, "WEC::MySQL::Connection");
             my $err = shift;
             is($err+0, ACCESS_DENIED_ERROR(), "proper error code");
             like($err, qr"Access denied for user: .* \(Using password: YES\)");
         },
         Close => sub {
             is(++$hit, 2+$pushed);
             is(@_, 4);
             isa_ok(shift, "WEC::MySQL::Client", "Proper client");
             isa_ok(shift, "WEC::MySQL::Connection", "Proper connection");
             is(shift, "reject", "Proper error");
             my $err = shift;
             is($err+0, ACCESS_DENIED_ERROR());
             like($err, qr/Access denied for user: .* \(Using password: YES\)/);
             $client = undef;
             unloop();
         });
    {
        @warnings = ();
        local $SIG{__WARN__} = sub { push @warnings, shift };
        push_work($client->connect);
        is(@warnings, 2, "create and drop warn");
    }
    loop;
    is($hit, 2+$pushed, "Got all events");
    check_fd;
    check_objects;
}

# Push work after a quit. We should get close callbacks
WEC->init;
$hit = 0;
$pushed = 0;
$cause = "eof";
$client = WEC::MySQL::Client->new
    (%client_args,
     Greeting => sub {
         is(++$hit, 1);
         my $c = shift;
         $c->quit;
         push_work($c);
     },
     Close => sub {
         is(++$hit, 2+$pushed);
         isa_ok(shift, "WEC::MySQL::Client");
         isa_ok(shift, "WEC::MySQL::Connection");
         if (@_ == 2) {
             is(shift, "eof");
             is(shift, $! = ECONNRESET);
         } elsif (@_ == 1) {
             is(shift, "quit");
         } else {
             diag("Unexpected close reason @_");
             fail("Unexpected close reason @_");
         }
         $client = undef;
         unloop;
     });
$client->connect;
warn_loop;
is(@warnings, 2, "create and drop warn");
is($hit, 2+$pushed, "Got all events");
check_fd;
check_objects;

1;
