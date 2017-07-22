#!perl

# docker build -t zvt . && docker run -v "$(pwd)":/app zvt perl -w /app/req_auth.pl 228.95

use strict;
use warnings;
use feature qw( say );

use DDP;

use AnyEvent;
use AnyEvent::Handle;
use Net::ZVT::DataObjects;

$| = 1;
my $status = {
    master              => 0,
    status              => {},
};

my $password = [qw{00 00 00}];

my $intermediate_status_values = {
      0 => { english => 'PT is waiting for amount-confirmation',    german => 'BZT wartet auf Betragsbestätigung', },
      1 => { english => 'Please watch PIN-Pad',                     german => 'Bitte Anzeigen auf dem PIN-Pad beachten', },
      2 => { english => 'Please watch PIN-Pad',                     german => 'Bitte Anzeigen auf dem PIN-Pad beachten', },
      3 => { english => 'Not accepted',                             german => 'Vorgang nicht möglich', },
      4 => { english => 'PT is waiting for response from FEP',      german => 'BZT wartet auf Antwort vom FEP', },
      7 => { english => 'Card not admitted',                        german => 'Karte nicht zugelassen', },
      8 => { english => 'Card unknown / undefined',                 german => 'Karte unbekannt / undefiniert', },
      9 => { english => 'Expired card',                             german => 'Karte verfallen', },
     10 => { english => 'Insert card',                              german => 'Karte einstecken', },
     11 => { english => 'Please remove card!',                      german => 'Bitte Karte entnehmen!', },
     12 => { english => 'Card not readable',                        german => 'Karte nicht lesbar', },
     13 => { english => 'Processing error',                         german => 'Vorgang abgebrochen', },
     14 => { english => 'Please wait...',                           german => 'Vorgang wird bearbeitet. Bitte warten ...', },
     16 => { english => 'Invalid card',                             german => 'Karte ungültig', },
     18 => { english => 'System malfunction',                       german => 'Systemfehler', },
     19 => { english => 'Payment not possible',                     german => 'Zahlung nicht möglich', },
     20 => { english => 'Credit not sufficient',                    german => 'Guthaben nicht ausreichend', },
     21 => { english => 'Incorrect PIN',                            german => 'Geheimzahl falsch', },
     23 => { english => 'Please wait...',                           german => 'Bitte warten...', },
     24 => { english => 'PIN try limit exceeded',                   german => 'Geheimzahl zu oft falsch', },
     25 => { english => 'Card-data incorrect',                      german => 'Kartendaten falsch', },
     27 => { english => 'Approved. Please fill-up',                 german => 'Autorisierung erfolgt. Bitte tanken', },
     28 => { english => 'Approved. Please take goods',              german => 'Zahlung erfolgt. Bitte Ware entnehmen', },
     29 => { english => 'Declined',                                 german => 'Autorisierung nicht möglich', },
     67 => { english => 'Not accepted. Please remove card!',        german => 'Vorgang nicht möglich. Bitte Karte entnehmen!', },
     77 => { english => 'Processing error',                         german => 'Vorgang abgebrochen', },
     85 => { english => 'Incorrect PIN. Please remove card!',       german => 'Geheimzahl falsch. Bitte Karte entnehmen!', },
    210 => { english => 'Connecting dial-up',                       german => 'DFÜ-Verbindung wird hergestellt', },
};

my $cv = AnyEvent->condvar;
my $amount = $ARGV[0] || 0.02;
die "amount $amount is greater than allowed value (9999999999.99)" if $amount > 9999999999.99;
authenticate($amount, \&dumpall);


$cv->recv;
say "DONE";
p $status;

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
            [@{$password}, get_config_byte(), qw{09 78 03 00 06 06 26 04 0A 02 06 D3}],
        ),
    );
    $status->{master} = 'registration';

    $handle->on_read(sub {
        shift->unshift_read(chunk => 3, sub {
            my ($handle, $response) = @_;
            my $type = substr( $response, 0, 2 );
            my $length = ord substr( $response, 2, 1 );
            say 'TYPE: '.join(" " => @{ hexify($type) }).'  '
                .'LENGTH: '.join(" " => @{ hexify(substr( $response, 2, 1 )) });

            if ($length == 0xFF) {
                # next two bytes define length
                shift->unshift_read(chunk => 2, sub {
                    my ($handle, $data) = @_;
                    
                    $length = unpack q(S), $data;
                    if ($length > 0) {
                        shift->unshift_read(chunk => $length, sub {
                            my ($handle, $data) = @_;
                            say 'DATA: '.join(" " => @{ hexify($data) });
                            handle_answer($handle, $type, $data);
                        });
                    }
                });
            }
            elsif ($length > 0) {
                # now read the payload
                shift->unshift_read(chunk => $length, sub {
                    my ($handle, $data) = @_;
                    say 'DATA: '.join(" " => @{ hexify($data) });
                    handle_answer($handle, $type, $data);
                });
            }
            else {
                handle_answer($handle, $type, '');
            }
        });
    });
}

sub handle_answer {
    my ($handle, $type, $data) = @_;
    my $hextype = hexify_str($type);

    if ($hextype eq '80 00') {
        say 'GOT OKAY'; # no data expected
        if ($status->{master} eq 'auth_requested') {
            # return $cv->send;
        }
        return;
    }

    if ($hextype eq '06 0F') {
        say 'COMPLETION';
        say 'MASTER STATUS: '.$status->{master};
        if ($status->{master} eq 'registration') {
            say 'Registration completed';
            # TODO: data should be checked!
            # return $cv->send();
            send_okay($handle);

            # request authorization:
            my @amount_hex = ( uc(sprintf("%012d", int($amount * 100))) =~ m/../g );
            $status->{master} = 'auth_requested';
            $handle->push_write(
                terminaldata(
                    [qw{06 01}],
                    ['04', @amount_hex, qw{19 40 06 04 40 02 FF 00}],
                ),
            );
            return;
        }

        if ($status->{master} eq 'auth_requested') {
            say 'Authorization completed';
            send_okay($handle);
            $handle->on_drain(sub { $cv->send; });
            return;
        }
    }

    if ($hextype eq '06 1E') {
        say 'ABORT!';
        $cv->send;
    }

    # intermediate status information
    if ($hextype eq '04 FF') {
        say 'INTERMEDIATE STATUS INFORMATION ... (needs to be parsed)';
        # see chapter 3.7 (page 124)
        my $intermediate_status = ord substr $data, 0, 1;
        say $intermediate_status_values->{$intermediate_status}->{german} || 'Unbekannter Status.';
        if (length $data > 1) {
            my $timeout = ord substr $data, 1, 1;
            my $tlv = Net::ZVT::DataObjects::TLV->new({ data => substr $data, 2 });
            my $result = $tlv->parse();
            p $result if not exists $intermediate_status_values->{$intermediate_status};
        }
        else {
            say 'DATA too short:';
            p $data;
        }
        send_okay($handle);
    }

    # status information
    if ($hextype eq '04 0F') {
        say 'STATUS INFORMATION ... (needs to be parsed)';
        # see chapter 3 (page 114)
        send_okay($handle);

        $status->{status} = parse_status($data);
        say 'STATUS: ';
        p $status->{status};
        # $cv->send;
    }
    
    # print line
    if ($hextype eq '06 D1') {
        # see chapter Print line (page 122)
        my ($attribute, $text) = split //, $data, 2;
        my $tinfo = { attribute => $attribute, text => $text };
        p $tinfo;
    }

    # print text-block
    if ($hextype eq '06 D3') {
        # see chapter Print text block 06 D3 (page 123)
        my $tlv = Net::ZVT::DataObjects::TLV->new({ data => substr $data, 1 });
        my $result = $tlv->parse();
        # p $result;
        use Data::Dumper;
        print Dumper($result);
    }
}


sub parse_status {
    my ($data) = @_;
    my $dataobject = Net::ZVT::DataObjects->new({ data => $data });
    return $dataobject->parse();
}

sub send_okay {
    say 'SEND: OKAY';
    shift->push_write(terminaldata([qw{80 00}], []));
}


sub hexify { [map { uc sprintf('%02x', ord $_) } split //, $_[0]] }
sub hexify_str { my $sep = $_[1] || q( ); uc unpack("H*", shift) =~ s/(..)(?!$)/$1$sep/gr }

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

sub get_config_byte {
    # return qw{08}; # no receipt print by ECR
    return qw{8A}; # receipt print by ECR == 10001010
}