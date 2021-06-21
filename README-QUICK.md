# Pound Quick Build

Pound is a C language program. To build Pound from source code, install the prerequisite tools and libraries on your system then build using the hints shown below.

## Prerequisites (Debian)

    sudo apt install build-essential
    sudo apt install libssl-dev
    sudo apt install libpcre3-dev
    sudo apt install linux-headers-$(uname -r)
    sudo apt install autoconf

See also <https://linux.debian.devel.narkive.com/s8mlB5Xw/pcre-package-naming>.

### Build

    1) ./bootstrap
    2) ./configure --with-maxbuf=8192
    3) make all
       3.1) makes poundctl
       3.2) makes pound
       3.3) ldd pound
    4) sudo make install-strip
       4.1) installs /usr/local/bin/poundctl
       4.2) installs /usr/local/sbin/pound
       4.3) installs /usr/local/share/man/man8/poundctl.8
       4.4) installs /usr/local/share/man/man8/pound.8
    5) Manually review 'etc' samples and install, as needed.
       5.1) installed-list.sh - lists installed files.
       5.2) installed-test.sh - runs pound for testing.

### Standard make targets

- **all**: Compile the entire program. (default target)

- **install**: Compile the program and copy the executables, libraries, and so on to the file names where they should reside for actual use.

- **install-strip**: Like install, but strip the executable files while installing them.

- **uninstall**: Delete all the installed files—the copies that the ‘install’ and ‘install-*’ targets create. 

- **clean**: Delete all files in the current directory that are normally created by building the program.

- **distclean**: Delete all files in the current directory (or created by this makefile) that are created by configuring or building the program.

- **dist**: Create a distribution tar file for this program.

- **check**: Perform self-tests (if any). 

- **installcheck**: Perform installation tests (if any).

- **installdirs**: It’s useful to add a target named ‘installdirs’ to create the directories where files are installed, and their parent directories.

### Installation Paths

    /etc/pound/
    /etc/rsyslog.d/30-pound.conf
    /usr/local/share/man/man8/pound.8
    /usr/local/share/man/man8/poundctl.8
    /usr/local/bin/poundctl
    /usr/local/sbin/pound
    /var/chroot/pound/
    /var/log/pound/
    /var/run/pound.pid
    /var/run/pound/poundctl.socket

### Daemon Paths

    SystemD: /etc/systemd/system/pound.service
    SystemV: /etc/default/pound
    SystemV: /etc/init.d/pound
    SystemV: /etc/rc?.d/*pound

### Git Status / Clean

    git status -u
    git remote show origin
    git ls-files . --ignored --exclude-standard --others
    git clean -xn
    git clean -xfd
