#!perl

use strict;
use warnings;
use feature qw( say );

use IO::Socket::INET;
use DDP;
use Time::HiRes qw/usleep/;

my $socket = IO::Socket::INET->new(
    PeerAddr => '192.168.158.205:5577',
    Proto => 'tcp',
);

# REGISTRATION

die "cannot connect to the server $!\n" unless $socket;
print "connected to the server\n";

# data to send to a server
my $req = reg();
my $size = $socket->send($req);
print "sent data of length $size\n";

# notify server that request has been sent
#shutdown($socket, 1);

# receive a response of up to 1024 characters from server
my $response = "";
$socket->recv($response, 1024);
say "received response: ".hexify($response);
#say "received response: $response / ".unpack('HHH', $response);

if (hexify($response) eq '80 00 00') {
    say 'REGISTRATION OKAY!';
}
else {
    say 'REGISTRATION NOT OKAY!';
}

usleep 20000;

# AUTHORIZATION

# data to send to a server
my $req = auth();
my $size = $socket->send($req);
print "sent data of length $size\n";

# notify server that request has been sent
#shutdown($socket, 1);



# receive a response of up to 1024 characters from server
my $response = "";
$socket->recv($response, 1024);
say "received response: ".hexify($response);



$socket->close();


sub hexify {
    return join(" " => map { sprintf('%02x', ord $_) } split(//, $_[0]));
}

# 06 01 0A 04 00 00 00 01 10 10 00 49 09 78 10 03 F2 FF
sub unhexify { join "" => map { chr hex } split / /, $_[0] }



sub auth {
    return unhexify('06 0f 10 29 69 57 96 79 49 09 78 06 06 26 04 0a 02 06 d3');
    return unhexify('06 01 0f 04 00 00 00 00 00 03 19 40 06 04 40 02 ff 00');
    return chr(6).chr(1)
        .chr(2) # length
        .chr(4).chr(34)
        ;
}

sub reg {
    return unhexify('06 00 10 00 00 00 08 09 78 03 00 06 06 26 04 0a 02 06 d3');
    return unhexify('06 00 06 12 34 56 BA 09 78 10 03 24 C3');
    return chr(6).chr(0).chr(4)
        .chr(12).chr(34).chr(56) # password
        .chr(190) #config byte
        ;
}


__END__

#tie $x,Net::TCP,0,'finger' or die $!;

my $obj = Net::TCP->new({
    desthost => '192.168.148.205',
    destport => 5577,
}) or die $!;

my $ok = $obj->connect or die $!;

say "connect ok? $ok";


my $length = chr(4);
$x = chr(6).chr(0).$length
        .chr(12).chr(34).chr(56) # password
        .chr(190) #config byte
        ;
print $y while defined($y = $x);
untie $x;