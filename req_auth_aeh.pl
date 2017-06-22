#!perl

# docker build -t zvt . && docker run -v "$(pwd)":/app zvt perl -w /app/req_auth.pl 228.95

use strict;
use warnings;
use feature qw( say );

use DDP;

use AnyEvent;
use AnyEvent::Handle;

$| = 1;
my $cv = AnyEvent->condvar;
my $status = 0;
my $amount = $ARGV[0] || 0.02;
die "amount $amount is greater than allowed value (9999999999.99)" if $amount > 9999999999.99;
authenticate($amount, \&dumpall);


$cv->recv;
say "DONE";


sub authenticate {
    my ($amount, $cb) = @_;
    
    my ($response, $body);

    my $handle; $handle = AnyEvent::Handle->new(
        connect     => [ '192.168.158.205', 5577 ],
        on_error    => sub {
            $cb->('ERROR: $!');
            $handle->destroy;
            $cv->send;
        },
        on_eof      => sub {
            $cb->('DONE', $response, $body);
            $handle->destroy;
            $cv->send;
        },
        on_connect  => sub {
            dumpall('on_connect', @_);
        },
        on_connect_error  => sub {
            dumpall('on_connect_error', @_);
        },
    );

    $handle->push_write(
        terminaldata(
            [qw{06 00}],
            [qw{00 00 00 08 09 78 03 00 06 06 26 04 0A 02 06 D3}],
        ),
    );

    $handle->on_read(sub {
        shift->unshift_read(chunk => 3, sub {
            my ($handle, $response) = @_;
            my $type = substr( $response, 0, 2 );
            my $length = ord substr( $response, 2, 1 );
            say 'TYPE: '.join(" " => @{ hexify($type) }).'  '
                .'LENGTH: '.join(" " => @{ hexify(substr( $response, 2, 1 )) });

            # now read the payload
            if ($length > 0) {
                shift->unshift_read (chunk => $length, sub {
                    my ($handle, $data) = @_;
                    say 'DATA: '.join(" " => @{ hexify($data) });
                    handle_answer($handle, $type, $data);
                    # $cv->send();
                });
            }
        });
    });
}

sub handle_answer {
    my ($handle, $type, $data) = @_;
    my $hextype = hexify_str($type);
    say 'HEXTYPE: '.$hextype;
    if ($hextype eq '80 00') {
        say 'got OKAY'; # no data expected
        if ($status eq 'auth_requested') {
            # return $cv->send;
        }
        return;
    }
    if ($hextype eq '06 0F') {
        say 'Registration completed';
        # TODO: data should be checked!
        # return $cv->send();

        $handle->push_write(terminaldata([qw{80 00}], [])); # okay
        # request authorization:
        my @amount_hex = ( uc(sprintf("%012d", int($amount * 100))) =~ m/../g );
        $status = 'auth_requested';
        $handle->push_write(
            terminaldata(
                [qw{06 01}],
                ['04', @amount_hex, qw{19 40 06 04 40 02 FF 00}],
            ),
        );
        return;
    }
    # $cv->send();
}


sub hexify { [map { uc sprintf('%02x', ord $_) } split //, $_[0]] }
sub hexify_str { join " ", @{ hexify(@_) } }

# 06 01 0A 04 00 00 00 01 10 10 00 49 09 78 10 03 F2 FF
sub unhexify { join "" => map { chr hex } @{$_[0]} }



sub sendtoterminal {
    my ($fh, $type, $data) = @_;
    syswrite $fh, terminaldata($type, $data);
}

sub terminaldata {
    my ($type, $data) = @_;
    $data ||= [];
    return unhexify($type).chr(length unhexify($data)).unhexify($data);
}

sub dumpall {
    p @_;
}

