#!perl

# docker build -t zvt . && docker run -v "$(pwd)":/app zvt perl -w /app/req_auth.pl 228.95

use strict;
use warnings;
use feature qw( say );

use DDP;

use AnyEvent;
use AnyEvent::Handle;

$| = 1;
my $status = {
    master              => 0,
    status              => {},
};


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
            [qw{00 00 00 08 09 78 03 00 06 06 26 04 0A 02 06 D3}],
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

            # now read the payload
            if ($length > 0) {
                shift->unshift_read(chunk => $length, sub {
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

    if ($hextype eq '80 00') {
        say 'GOT OKAY'; # no data expected
        if ($status->{master} eq 'auth_requested') {
            # return $cv->send;
        }
        return;
    }

    if ($hextype eq '06 0F') {
        say 'COMPLETION';
        if ($status->{master} eq 'registration') {
            say 'Registration completed';
            # TODO: data should be checked!
            # return $cv->send();
            send_okay($handle);

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
    }

    if ($hextype eq '06 1E') {
        say 'ABORT!';
        $cv->send;
    }

    # intermediate status information
    if ($hextype eq '04 FF') {
        say 'INTERMEDIATE STATUS INFORMATION ... (needs to be interpreted)';
        # see chapter 3.7 (page 124)
        my $intermediate_status = ord substr $data, 0, 1;
        say $intermediate_status_values->{$intermediate_status}->{german};
        send_okay($handle);
    }

    # status information
    if ($hextype eq '04 0F') {
        say 'STATUS INFORMATION ... (needs to be interpreted)';
        # see chapter 3 (page 114)
        send_okay($handle);

        $status->{status} = interprete_status($data);
        $cv->send;
    }
    
    # print line
    if ($hextype eq '06 D1') {
        # see chapter Print line
    }

    # print text-block
    if ($hextype eq '06 D3') {
        # see chapter Print text block 06 D3
    }


}


sub interprete_status {
    my ($data) = @_;
    my $status_result = {};
    my $pos = 0;

    while ($pos < length $data) {
say '**** '.__LINE__."  POS: $pos";
        my $bmp_number = ord substr $data, $pos, 1;
say 'BMP number = '.$bmp_number;
last if $bmp_number < 1;
        if ($bmp_number == 39) {
            $status_result->{result_code} = substr $data, $pos + 1, 1;
            $pos += 2;
        }
        if ($bmp_number == 4) {
            $status_result->{amount} = substr $data, $pos + 1, 6;
            $pos += 7;
        }
        if ($bmp_number == 11) {
            $status_result->{trace} = substr $data, $pos + 1, 3;
            $pos += 4;
        }
        if ($bmp_number == 55) {
            $status_result->{orig_trace} = substr $data, $pos + 1, 3;
            $pos += 4;
        }
        if ($bmp_number == 12) {
            $status_result->{time} = substr $data, $pos + 1, 3;
            $pos += 4;
        }
        if ($bmp_number == 13) {
            $status_result->{date} = substr $data, $pos + 1, 2;
            $pos += 3;
        }
        if ($bmp_number == 14) {
            $status_result->{expiry_date} = substr $data, $pos + 1, 2;
            $pos += 3;
        }
        if ($bmp_number == 23) {
            $status_result->{seq_no} = substr $data, $pos + 1, 2;
            $pos += 3;
        }
        if ($bmp_number == 25) {
            $status_result->{payment_type} = substr $data, $pos + 1, 1;
            $pos += 2;
        }
        if ($bmp_number == 34) {
            my $len = (ord(substr $data, $pos + 1, 1) - 240) * 10 + ord(substr $data, $pos + 2, 1) - 240;
            $status_result->{ef_id} = substr $data, $pos + 3, $len;
            $pos += 3 + $len;
        }
        if ($bmp_number == 41) {
            $status_result->{terminal_id} = substr $data, $pos + 1, 4;
            $pos += 5;
        }
        if ($bmp_number == 59) {
            $status_result->{aid} = substr $data, $pos + 1, 8;
            $pos += 9;
        }
        if ($bmp_number == 73) {
            $status_result->{currency_code} = substr $data, $pos + 1, 2;
            $pos += 3;
        }
        if ($bmp_number == 76) {
            my $len = (ord(substr $data, $pos + 1, 1) - 240) * 10 + ord(substr $data, $pos + 2, 1) - 240;
            $status_result->{blocked_goods_groups} = substr $data, $pos + 3, $len;
            $pos += 3 + $len;
        }
        if ($bmp_number == 135) {
            $status_result->{receipt_no} = substr $data, $pos + 1, 2;
            $pos += 3;
        }
        if ($bmp_number == 138) {
            $status_result->{card_type} = substr $data, $pos + 1, 1;
            $pos += 2;
        }
        if ($bmp_number == 140) {
            $status_result->{card_type_id} = substr $data, $pos + 1, 1;
            $pos += 2;
        }
        if ($bmp_number == 154) {
            my $len = (ord(substr $data, $pos + 1, 1) - 240) * 100 + (ord(substr $data, $pos + 2, 1) - 240) * 10 + ord(substr $data, $pos + 3, 1) - 240;
            $status_result->{failed_payment_records} = substr $data, $pos + 4, $len;
            $pos += 4 + $len;
        }
        if ($bmp_number == 186) {
            $status_result->{aid_pair} = substr $data, $pos + 1, 5;
            $pos += 6;
        }
        if ($bmp_number == 42) {
            $status_result->{vu_number} = substr $data, $pos + 1, 15;
            $pos += 16;
        }
        if ($bmp_number == 60) {
            my $len = (ord(substr $data, $pos + 1, 1) - 240) * 100 + (ord(substr $data, $pos + 2, 1) - 240) * 10 + ord(substr $data, $pos + 3, 1) - 240;
            $status_result->{additional_text} = substr $data, $pos + 4, $len;
            $pos += 4 + $len;
        }
        if ($bmp_number == 160) {
            $status_result->{result_code_as} = substr $data, $pos + 1, 1;
            $pos += 2;
        }
        if ($bmp_number == 136) {
            $status_result->{turnover_no} = substr $data, $pos + 1, 3;
            $pos += 4;
        }
        if ($bmp_number == 6) { # TLV container
            $status_result->{tlv_container} = substr $data, $pos + 1;
            last;
        }
    }
say '**** '.__LINE__;
    return $status_result;
}


sub send_okay {
    say 'SEND: OKAY';
    shift->push_write(terminaldata([qw{80 00}], []));
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

