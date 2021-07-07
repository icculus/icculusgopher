# IcculusGopher

This is a simple Gopher server.

Read more about Gopher here: https://en.wikipedia.org/wiki/Gopher_(protocol)

To use it:

- Edit the variables at the top of the script if you want, but the defaults
  are probably fine.
- By default, it looks for programs to run in "/gopherspace" ... make sure
  the scripts from this source tree's gopherspace directory are there, or
  wherever you edited the script to look.
- Run the script as root:
  ```bash
  sudo ./IcculusGopher_daemon.pl -d
  ```

You have to run as root since it wants to bind TCP port 70. After startup,
the script will drop privileges. You can also run as a non-root user without
the -d to make it take a request on stdin and reply on stdout before exiting,
if you'd rather xinetd handle connections and ports for you.

The first part of a connection's request's selector will be used to decide
what program to run to serve a response, and hands off the connect to that
program with a fork/exec call. If a blank request comes in, a program named
"default" is chosen.

These environment variables set for the handler program:

- `GOPHERSPACE`: where the programs are run from ("/gopherspace" by default).
- `GOPHERHOST`: The current server's hostname, for use in replies that are
  intended to direct the client to the same server.
- `GOPHERPORT`: The port the Gopher server is listening on, for use in replies
  that are intended to direct the client to the same server.

The handler program runs as the (non-root) user that is specified at the top
of IcculusGopher_daemon.pl.

The handling program is launched with the desired selector as its only command
line argument, with the program name stripped off the front. So if the client
asked for "music/pop/taylor_swift" then the daemon runs something like...

```bash
export GOPHERSPACE=/gopherspace
export GOPHERHOST=gopher.icculus.org
export GOPHERPORT=70
/gopherspace/music/pop/taylor_swift
```

...and what the handler does is entirely up to it. Note that handlers are
expected to transmit well-formed Gopher responses. It's not a complicated
protocol; refer to the provided example programs.

Basic logging is done to the syslog.

Questions? Ask me.  icculus@icculus.org

--ryan.

