#!/usr/bin/perl -w -T
#-----------------------------------------------------------------------------
#
#  Copyright (c) 2017 Ryan C. Gordon.
#
#  This software is provided 'as-is', without any express or implied warranty.
#  In no event will the authors be held liable for any damages arising from
#  the use of this software.
#
#  Permission is granted to anyone to use this software for any purpose,
#  including commercial applications, and to alter it and redistribute it
#  freely, subject to the following restrictions:
#
#  1. The origin of this software must not be misrepresented; you must not
#  claim that you wrote the original software. If you use this software in a
#  product, an acknowledgment in the product documentation would be
#  appreciated but is not required.
#
#  2. Altered source versions must be plainly marked as such, and must not be
#  misrepresented as being the original software.
#
#  3. This notice may not be removed or altered from any source distribution.
#
#      Ryan C. Gordon <icculus@icculus.org>
#
#-----------------------------------------------------------------------------

use strict;          # don't touch this line, nootch.
use warnings;        # don't touch this line, either.
use IO::Select;      # bleh.
use POSIX;           # bloop.

# Version of IcculusGopher. Change this if you are forking the code.
my $version = 'v0.0.1';

#-----------------------------------------------------------------------------#
#             CONFIGURATION VARIABLES: Change to suit your needs...           #
#-----------------------------------------------------------------------------#

# The processes path is replaced with this string, for security reasons, and
#  to satisfy the requirements of Taint mode. Make this as simple as possible.
my $safe_path = '/usr/bin:/usr/local/bin';

# This is the directory that contains the handler programs.
my $gopherspace = '/gopherspace/';

# This is the hostname that clients should use to connect to this server.
my $gopherhost = 'gopher.icculus.org';

# This is the TCP port that clients should use to connect to this server.
# This is mostly used when daemonized. Specify the port on which to listen for
#  incoming connections. The RFC standard Gopher port is 70.
my $gopherport = 70;


# Turn the process into a daemon. This will handle creating/answering socket
#  connections, and forking off children to handle them. This flag can be
#  toggled via command line options (--daemonize, --no-daemonize, -d), but
#  this sets the default. Daemonizing tends to speed up processing (since the
#  script stays loaded/compiled), but may cause problems on systems that
#  don't have a functional fork() or IO::Socket::IP package. If you don't
#  daemonize, this program reads requests from stdin and writes results to
#  stdout, which makes it suitable for command line use or execution from
#  inetd and equivalents.
my $daemonize = 0;

# Set this to immediately drop priveledges by setting uid and gid to these
#  values. Set to undef to not attempt to drop privs. You will probably need
#  to leave these as undef and run as root (risky!) if you plan to enable
#  $the use_homedir variable, below.
#my $wanted_uid = undef;
#my $wanted_gid = undef;
my $wanted_uid = 1056;  # (This is the uid of "finger" ON _MY_ SYSTEM.)
my $wanted_gid = 971;   # (This is the gid of "iccfinger" ON _MY_ SYSTEM.)

# This is only used when daemonized. Specify the maximum number of Gopher
#  requests to service at once. A separate child process is fork()ed off for
#  each request, and if there are more requests then this value, the extra
#  clients will be made to wait until some of the current requests are
#  serviced. 5 to 10 is usually a good number. Set it higher if you get a
#  massive amount of Gopher requests simultaneously.
my $max_connects = 10;

# This is how long, in seconds, before an idle connection will be summarily
#  dropped. This prevents abuse from people hogging a connection without
#  actually sending a request, without this, enough connections like this
#  will block legitimate ones. At worst, they can only block for this long
#  before being booted and thus freeing their connection slot for the next
#  guy in line. Setting this to undef lets people sit forever, but removes
#  reliance on the IO::Select package. Note that this timeout is how long
#  the user has to complete the read_request() function, so don't set it so
#  low that legitimate lag can kill them. The default is usually safe.
my $read_timeout = 15;

# Set this to non-zero to log all Gopher requests via the standard Unix
#  syslog facility (requires Sys::Syslog qw(:DEFAULT setlogsock) ...)
my $use_syslog = 1;

# This is the maximum size, in bytes, that a Gopher request can be. This is
#  to prevent malicious Gopher clients from trying to fill all of system
#  memory.
my $max_request_size = 1024;

# This is what is reported to the Gopher client if a request is bogus.
my $no_report_string = "Nothing to report.";

#-----------------------------------------------------------------------------#
#     The rest is probably okay without you laying yer dirty mits on it.      #
#-----------------------------------------------------------------------------#


sub read_request {
    my $retval = '';
    my $count = 0;
    my $s = undef;
    my $elapsed = undef;
    my $starttime = undef;

    if (defined $read_timeout) {
        $s = new IO::Select();
        $s->add(fileno(STDIN));
        $starttime = time();
        $elapsed = 0;
    }

    while (1) {
        if (defined $read_timeout) {
            my $ready = scalar($s->can_read($read_timeout - $elapsed));
            return undef if (not $ready);
            $elapsed = (time() - $starttime);
        }

        my $ch;
        my $rc = sysread(STDIN, $ch, 1);
        return undef if ($rc != 1);
        if ($ch ne "\015") {
            return $retval if ($ch eq "\012");
            $retval .= $ch;
            $count++;
            return $retval if ($count >= $max_request_size);
        }
    }

    return undef;  # shouldn't ever hit this.
}

sub send_gopher_menu {
    my ($itemtype, $str, $selector, $host, $port) = @_;
    $itemtype = 'i' if not defined $itemtype;
    $str = '' if not defined $str;
    $selector = '' if not defined $selector;
    $host = 'error.host' if not defined $host;
    $port = 1 if not defined $port;
    print("$itemtype$str\t$selector\t$host\t$port\r\n");
}

sub gopher_mainline {
    my $query_string = read_request();

    my $syslog_text;
    if (not defined $query_string) {
        $syslog_text = "input timeout on gopher request. Dropped client.\n";
        print($syslog_text);  # tell the client, if they care.
        syslog("info", $syslog_text) if ($use_syslog);
    } else {
        $syslog_text = "gopher request: \"$query_string\"\n";
        $syslog_text =~ s/%/%%/g;
        if ($use_syslog) {
            syslog("info", $syslog_text) or die("Couldn't write to syslog: $!\n");
        }

        my ($program, $sep, $args) = $query_string =~ /\A(.*?)(\/|\Z)(.*)\Z/;
        $program = undef if $program eq '.';
        $program = undef if $program eq '..';
        $program = undef if $program eq '~';
        $program = 'default' if not defined $program or $program eq '';

        if ($program eq 'version') {
            send_gopher_menu('i', $version);
	} else {
            my $exe = "$gopherspace/$program";
            if ( -f $exe ) { 
                $ENV{'GOPHERSPACE'} = $gopherspace;
                $ENV{'GOPHERHOST'} = $gopherhost;
                $ENV{'GOPHERPORT'} = $gopherport;
                { exec $exe, $args; };
                syslog("info", "Failed to execute '$exe': $!");
            }
            send_gopher_menu('3', $no_report_string);
            return 1;
        }
    }

    return 0;
}


sub syslog_and_die {
    my $err = shift;
    $err .= "\n";
    $err =~ s/%/%%/g;
    syslog("info", $err) if ($use_syslog);
    die($err);
}


sub go_to_background {
    use POSIX 'setsid';
    open STDIN,'/dev/null' or syslog_and_die("Can't read '/dev/null': $!");
    open STDOUT,'>/dev/null' or syslog_and_die("Can't write '/dev/null': $!");
    # fork once, so launching process regains control.
    defined(my $pid=fork) or syslog_and_die("Can't fork: $!");
    exit if $pid;
    # become session group leader, so we have no controlling terminal.
    setsid or syslog_and_die("Can't start new session: $!");
    # fork again; group leader (and chance of controlling terminal) vanishes.
    defined($pid=fork) or syslog_and_die("Can't fork: $!");
    exit(0) if $pid;
    open STDERR,'>&STDOUT' or syslog_and_die("Can't duplicate stdout: $!");
    chdir('/') or syslog_and_die("Can't chdir to '/': $!");
    syslog("info", "Daemon process is now detached") if ($use_syslog);
}


sub drop_privileges {
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
    $ENV{'PATH'} = $safe_path;
    $) = $wanted_gid if (defined $wanted_gid);
    $> = $wanted_uid if (defined $wanted_uid);
}


sub signal_catcher {
    my $sig = shift;
    syslog("info", "Got signal $sig. Shutting down.") if ($use_syslog);
    exit 0;
}


my @kids;
use POSIX ":sys_wait_h";
sub reap_kids {
    my $i = 0;
    my $x = scalar(@kids);
    while ($i < scalar(@kids)) {
        my $rc = waitpid($kids[$i], &WNOHANG);
        if ($rc != 0) {  # reaped a zombie.
            splice(@kids, $i, 1); # take it out of the array.
        } else {  # still alive, try next one.
            $i++;
        }
    }

    $SIG{CHLD} = \&reap_kids;  # make sure this works on crappy SysV systems.
}


sub daemon_upkeep {
    #return if not defined $digest_frequency;

    #my $curtime = time();
    #if ($curtime >= $next_plan_digest) {
    #    do_digests();
    #    $next_plan_digest += ($digest_frequency * 60);
    #}
}


# Mainline.

foreach (@ARGV) {
    $daemonize = 1, next if $_ eq '--daemonize';
    $daemonize = 1, next if $_ eq '-d';
    $daemonize = 0, next if $_ eq '--no-daemonize';
    die("Unknown command line \"$_\".\n");
}

if ($use_syslog) {
    use Sys::Syslog qw(:DEFAULT setlogsock);
    setlogsock("unix");
    openlog("gopherd", "user") or die("Couldn't open syslog: $!\n");
}


my $retval = 0;
if (not $daemonize) {
    drop_privileges();
    exit(gopher_mainline());
}

# The daemon.

if ($use_syslog) {
    syslog("info", "IcculusGopher daemon $version starting up...");
}

go_to_background();

# reap zombies from client forks...
$SIG{CHLD} = \&reap_kids;
$SIG{TERM} = \&signal_catcher;
$SIG{INT} = \&signal_catcher;

use IO::Socket::IP;
my $listensock = IO::Socket::IP->new(LocalHost => '::',
			               LocalPort => $gopherport,
                                       Type => SOCK_STREAM,
                                       ReuseAddr => 1,
                                       Listen => $max_connects);

syslog_and_die("couldn't create listen socket: $!") if (not $listensock);

my $selection = new IO::Select( $listensock );
drop_privileges();

if ($use_syslog) {
    syslog("info", "Now accepting connections (max $max_connects" .
                    " simultaneous on port $gopherport).");
}

while (1)
{
    # prevent connection floods.
    daemon_upkeep(), sleep(1) while (scalar(@kids) >= $max_connects);

    # if timed out, do upkeep and try again.
    daemon_upkeep() while not $selection->can_read(10);

    # we've got a connection!
    my $client = $listensock->accept();
    if (not $client) {
        syslog("info", "accept() failed: $!") if ($use_syslog);
        next;
    }

    my $ip = $client->peerhost();
    syslog("info", "connection from $ip") if ($use_syslog);

    my $kidpid = fork();
    if (not defined $kidpid) {
        syslog("info", "fork() failed: $!") if ($use_syslog);
        close($client);
        next;
    }

    if ($kidpid) {  # this is the parent process.
        close($client);  # parent has no use for client socket.
        push @kids, $kidpid;
    } else {
        $ENV{'TCPREMOTEIP'} = $ip;
        close($listensock);   # child has no use for listen socket.
        local *FH = $client;
        open(STDIN, '<&', *FH) or syslog_and_die("no STDIN reassign: $!");
        open(STDERR, '>&', *FH) or syslog_and_die("no STDERR reassign: $!");
        open(STDOUT, '>&', *FH) or syslog_and_die("no STDOUT reassign: $!");
        my $retval = gopher_mainline();
        close($client);
        exit $retval;  # kill child.
    }
}

close($listensock);  # shouldn't ever hit this.
exit $retval;

# end of IcculusGopher_daemon.pl ...

