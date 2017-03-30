#!perl

# docker build -t zvt . && docker run -v "$(pwd)":/app zvt perl -w /app/req_auth.pl 228.95

use strict;
use warnings;
use feature qw( say );

use IO::Socket::INET;
use DDP;
use Time::HiRes qw/usleep/;

my $socket = IO::Socket::INET->new(
    PeerAddr => '192.168.158.205:5577',
    Proto    => 'tcp',
);


die "cannot connect to the server $!\n" unless $socket;
print "connected to the server\n";


# REGISTRATION
sendtoterminal($socket, '06 00', '00 00 00 08 09 78 03 00 06 06 26 04 0A 02 06 D3');
my $response = receive($socket);
die "got no okay :-(" if $response->{type} ne '80 00';

# awaiting reg answer, should be analyzed ...
$response = receive($socket);

# send okay
sendtoterminal($socket, '80 00');

# request AUTHORIZATION
my $amount = $ARGV[0] || 0.02;
my $amount_hex = uc sprintf("%012d", $amount * 100) =~ s/(.{2})/$1 /gr;
say $amount_hex;
sendtoterminal($socket, '06 01', '04 '.$amount_hex.'19 40 06 04 40 02 FF 00');
$response = receive($socket);
die "got no okay :-(" if $response->{type} ne '80 00';


$socket->close();


sub hexify { join" " => map { sprintf('%02x', ord $_) } split //, $_[0] }

# 06 01 0A 04 00 00 00 01 10 10 00 49 09 78 10 03 F2 FF
sub unhexify { join "" => map { chr hex } split / /, $_[0] }



sub sendtoterminal {
    my ($socket, $type, $data) = @_;
    $data ||= '';
    my $request = unhexify($type).chr(length unhexify($data)).unhexify($data);
    my $size = $socket->send($request);
    say "sent data of length $size: ".hexify($request);
}

sub receive {
    my ($socket) = @_;
    my $response = "";
    $socket->recv( $response, 3 );
    my $type = substr( $response, 0, 2 );
    my $length = ord substr( $response, 2, 1 );
    my $data = "";
    $socket->recv( $data, $length ) if $length;

    say "received data: ".hexify($response).' '.hexify($data);

    return {
        type   => hexify($type),
        length => $length,
        data   => hexify($data),
    };
}


