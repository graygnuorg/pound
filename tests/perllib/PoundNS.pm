# This file is part of pound testsuite
# Copyright (C) 2024 Sergey Poznyakoff
#
# Pound is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Pound is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pound.  If not, see <http://www.gnu.org/licenses/>.

package PoundNS;
use parent 'Net::DNS::Nameserver';
use Carp;
use threads;
use IO::Socket::IP;
use File::stat;

# This module modifies internals of Net::DNS::Nameserver, therefore it
# is not guaranteed that it will work with any other version than that
# for which it has been written.
croak 'unsupported version of Net::DNS::Nameserver'
    unless $Net::DNS::Nameserver::VERSION == 1990;

sub TCP_server {
    my ($self, $listen) = @_;
    my $select = IO::Select->new($listen);

    while (1) {
	local $! = 0;
        scalar(my @ready = $select->can_read(2)) or do {
	    redo if $!{EINTR};	## retry if aborted by signal
	    last if $!;
        };

        foreach my $socket (@ready) {
	    if ($socket == $listen) {
		$select->add($listen->accept);
	        next;
	    }
	    if (my $buffer = Net::DNS::Nameserver::read_tcp($socket, $self->{Verbose})) {
		threads->create(sub {
		    $self->TCP_connection($socket, $buffer)
	        })->detach();
	    } else {
		close($socket);
	        $select->remove($socket);
	    }
        }
    }
}

sub UDP_server {
    my ($self, $socket) = @_;
    my $select = IO::Select->new($socket);

    while (1) {
	local $! = 0;
	scalar(my @ready = $select->can_read(2)) or do {
	    redo if $!{EINTR};	## retry if aborted by signal
	    last if $!;
        };

        foreach my $client (@ready) {
	    my $buffer = Net::DNS::Nameserver::read_udp($client, $self->{Verbose});
	    threads->create(sub {
		$self->UDP_connection( $client, $buffer)
	    })->detach();
        }
    }
}

sub ReplyHandler {
    my $self = shift;
    my $st = stat($self->{PoundZoneFile})
	or croak "can't stat $self->{PoundZoneFile}: $!";
    if ($st->mtime > $self->{PoundZoneTime}) {
	$self->ReadZoneFile($self->{PoundZoneFile});
	$self->{PoundZoneTime} = $st->mtime;
    }
    return $self->SUPER::ReplyHandler(@_);
}

sub write_zone_file {
    my $file = shift;
    my $text = join("\n", @_);
    open(my $fh, '>', $file) or die "can't open $file: $!";
    print $fh $text;
    close $fh;
}

sub ZoneUpdate {
    my $self = shift;
    write_zone_file($self->{PoundZoneFile}, @_);
}

sub new {
    my ($class, $zonefile) = @_;
    $zonefile //= 'fakedns.zone';
    unless (-e $zonefile) {
	write_zone_file $zonefile, <<\EOT
$ORIGIN example.org.
@   IN SOA  mname rname 1 2h 1h 2w 1h
EOT
	;
    }
    my $self = $class->SUPER::new(ZoneFile => $zonefile);
    $self->{PoundZoneFile} = $zonefile;
    return $self;
}

sub start_server {
    my ($self, $ip, $timeout) = @_;
    $ip //= '127.0.0.1';
    $timeout //= 10;
    
    my $tcp_socket = IO::Socket::IP->new(
	LocalAddr => $ip,
	Proto	  => "tcp",
	Listen	  => SOMAXCONN,
	Type	  => SOCK_STREAM)
	or croak "tcp socket: $!";
    my $udp_socket = IO::Socket::IP->new(
	LocalAddr => $ip,
	Proto	  => "udp",
	Type	  => SOCK_DGRAM)
	or croak "udp socket: $!";
		
    threads->create(sub {
        $self->TCP_server($tcp_socket, 0, $timeout)
    })->detach();
    threads->create(sub {
        $self->UDP_server($udp_socket, 0, $timeout)
    })->detach();
    return ($udp_socket->sockport, $tcp_socket->sockport);
}

1;
