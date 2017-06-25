package Net::ZVT::DataObjects;

use strict;
use warnings;
use Net::ZVT::DataObjects::TLV;

my $byteformat = sub {
    my ($length, $data) = @_;
    return substr($data, 1, $length), 1 + $length;
};

my $bcdformat = sub {
    my ($length, $data) = @_;
    return uc(unpack "H*", substr $data, 1, $length), $length + 1;
};

my $llvarformat = sub {
    my ($data) = @_;
    my $len = (ord(substr $data, 1, 1) - 240) * 10 + ord(substr $data, 2, 1) - 240;
    return substr($data, 2, $len), 3 + $len;
};

my $lllvarformat = sub {
    my ($data) = @_;
    my $len = (ord(substr $data, 1, 1) - 240) * 100 + (ord(substr $data, 2, 1) - 240) * 10 + ord(substr $data, 3, 1) - 240;
    return substr($data, 4, $len), 4 + $len;
};

my $tlvformat = sub {
    my ($data) = @_;
    my $tlv = Net::ZVT::DataObjects::TLV->new({ data => substr $data, 1 });
    my ($data_length, $length_bytes) = $tlv->get_length();
    return $tlv->parse(), 1 + $length_bytes + $data_length;
};


my $bitmaps = {
    0x01 => {
        format      => [ $byteformat, 1 ],
        name        => 'timeout',
        description => "binary time-out"
    },
    0x02 => {
        format      => [ $byteformat, 1 ],
        name        => 'max_status_infos',
        description => "binary max.status infos"
    },
    0x03 => {
        format      => [ $byteformat, 1 ],
        name        => 'service_byte',
        description => "binary service-byte"
    },
    0x04 => {
        format      => [ $bcdformat, 6 ],
        name        => 'amount',
        description => "Amount",
        convert     => sub { return sprintf "%.02f", $_[0] / 100 },
    },
    0x05 => {
        format      => [ $byteformat, 1 ],
        name        => 'pump_nr',
        description => "binary pump-Nr."
    },
    0x06 => {
        format      => [ $tlvformat ], 
        name        => 'tlv',
        description => "TLV"
    },
    0x0B => {
        format      => [ $bcdformat, 3 ],
        name        => 'trace_number',
        description => "trace-number",
        convert     => sub { return $_[0] + 0 },
    },
    0x0C => {
        format      => [ $bcdformat, 3 ],
        name        => 'time',
        description => "Time",
        convert     => sub { return $_[0] =~ s/(..)(?!$)/$1:/gr },
    },
    0x0D => {
        format      => [ $bcdformat, 2 ],
        name        => 'date_day',
        description => "date, MM DD (see AA)",
        convert     => sub { return $_[0] =~ s/(..)(?!$)/$1-/gr },
    },
    0x0E => {
        format      => [ $bcdformat, 2 ],
        name        => 'card_expire',
        description => "expiry-date, YY MM"
    },
    0x17 => {
        format      => [ $bcdformat, 2 ],
        name        => 'card_sequence_number',
        description => "card sequence-number",
        convert     => sub { return $_[0] + 0 },
    },
    0x19 => {
        format      => [ $byteformat, 1 ],
        name        => 'type',
        description => "binary status-byte/payment-type/card-type"
    },
    0x22 => {
        format      => [ $llvarformat ], 
        name        => 'card_number',
        description => "card_number, PAN / EF_ID, 'E' used to indicate masked numeric digit",
    },
    0x23 => {
        format      => [ $llvarformat ], 
        name        => 'track_2',
        description => "track 2 data, 'E' used to indicate masked numeric digit1"
    },
    0x24 => {
        format      => [ $lllvarformat ], 
        name        => 'track_3',
        description => "track 3 data, 'E' used to indicate masked numeric digit1"
    },
    0x27 => {
        format      => [ $byteformat, 1 ],
        name        => 'result_code',
        description => "binary result-code"
    },
    0x29 => {
        format      => [ $bcdformat, 4 ],
        name        => 'tid',
        description => "TID"
    },
    0x2A => {
        format      => [ $byteformat, 15 ],
        name        => 'vu',
        description => "ASCII VU-number"
    },
    0x2D => {
        format      => [ $llvarformat ], 
        name        => 'track_1',
        description => "track 1 data"
    },
    0x2E => {
        format      => [ $lllvarformat ], 
        name        => 'sync_chip_data',
        description => "sychronous chip data"
    },
    0x37 => {
        format      => [ $bcdformat, 3 ],
        name        => 'trace_number_original',
        description => "trace-number of the original transaction for reversal"
    },
    0x3A => {
        format      => [ $bcdformat, 2 ],
        name        => 'cvv',
        description => 'the field cvv is optionally used for mail order'
    },
    0x3B => {
        format      => [ $byteformat, 8 ],
        name        => 'aid',
        description => "AID authorisation-attribute"
    },
    0x3C => {
        format      => [ $lllvarformat ], 
        name        => 'additional',
        description => "additional-data/additional-text"
    },
    0x3D => {
        format      => [ $bcdformat, 3 ],
        name        => 'password',
        description => "Password"
    },
    0x49 => {
        format      => [ $bcdformat, 2 ],
        name        => 'currency_code',
        description => "currency code"
    },
    0x60 => {
        format      => [ $lllvarformat ], 
        name        => 'totals',
        description => "individual totals"
    },
    0x87 => {
        format      => [ $bcdformat, 2 ],
        name        => 'receipt',
        description => "receipt-number",
        convert     => sub { return $_[0] + 0 },
    },
    0x88 => {
        format      => [ $bcdformat, 3 ],
        name        => 'turnover',
        description => "turnover record number",
        convert     => sub { return $_[0] + 0 },
    },
    0x8A => {
        format      => [ $byteformat, 1 ],
        name        => 'card_type',
        description => "binary card-type (card-number according to ZVT-protocol; comparison 8C)"
    },
    0x8B => {
        format      => [ $llvarformat ], 
        name        => 'card_name',
        description => "card-name"
    },
    0x8C => {
        format      => [ $byteformat, 1 ],
        name        => 'card_operator',
        description => "binary card-type-ID of the network operator (comparison 8A)"
    },
    0x92 => {
        format      => [ $lllvarformat ], 
        name        => 'offline_chip',
        description => "additional-data ec-Cash with chip offline"
    },
    0x9A => {
        format      => [ $lllvarformat ], 
        name        => 'geldkarte',
        description => "Geldkarte payments-/ failed-payment record/total record Geldkarte"
    },
    0xA0 => {
        format      => [ $byteformat, 1 ],
        name        => 'result_code_as',
        description => "binary result-code-AS"
    },
    0xA7 => {
        format      => [ $llvarformat ], 
        name        => 'chip_ef_id',
        description => "chip-data, EF_ID"
    },
    0xAA => {
        format      => [ $bcdformat, 3 ],
        name        => 'date',
        description => "date YY MM DD (see 0D)"
    },
    0xAF => {
        format      => [ $lllvarformat ], 
        name        => 'ef_info',
        description => "EF_Info"
    },
    0xBA => {
        format      => [ $byteformat, 5 ],
        name        => 'aid_param',
        description => "binary AID-parameter"
    },
    0xD0 => {
        format      => [ $byteformat, 1 ],
        name        => 'algo_key',
        description => "binary algorithm-Key"
    },
    0xD1 => {
        format      => [ $llvarformat ], 
        name        => 'offset',
        description => "card offset/PIN-data"
    },
    0xD2 => {
        format      => [ $byteformat, 1 ],
        name        => 'direction',
        description => "binary direction"
    },
    0xD3 => {
        format      => [ $byteformat, 1 ],
        name        => 'key_position',
        description => "binary key-position"
    },
    0xE0 => {
        format      => [ $byteformat, 1 ],
        name        => 'input_min',
        description => "binary min. length of the input"
    },
    0xE1 => {
        format      => [ $llvarformat ], 
        name        => 'iline1',
        description => "text2 line 1"
    },
    0xE2 => {
        format      => [ $llvarformat ], 
        name        => 'iline2',
        description => "text2 line 2"
    },
    0xE3 => {
        format      => [ $llvarformat ], 
        name        => 'iline3',
        description => "text2 line 3"
    },
    0xE4 => {
        format      => [ $llvarformat ], 
        name        => 'iline4',
        description => "text2 line 4"
    },
    0xE5 => {
        format      => [ $llvarformat ], 
        name        => 'iline5',
        description => "text2 line 5"
    },
    0xE6 => {
        format      => [ $llvarformat ], 
        name        => 'iline6',
        description => "text2 line 6"
    },
    0xE7 => {
        format      => [ $llvarformat ], 
        name        => 'iline7',
        description => "text2 line 7"
    },
    0xE8 => {
        format      => [ $llvarformat ], 
        name        => 'iline8',
        description => "text2 line 8"
    },
    0xE9 => {
        format      => [ $byteformat, 1 ],
        name        => 'max_input_length',
        description => "binary max. length of the input"
    },
    0xEA => {
        format      => [ $byteformat, 1 ],
        name        => 'input_echo',
        description => "binary echo the Input"
    },
    0xEB => {
        format      => [ $byteformat, 8 ],
        name        => 'mac',
        description => "binary MAC over text 1 and text 2"
    },
    0xF0 => {
        format      => [ $byteformat, 1 ],
        name        => 'display_duration',
        description => "binary display-duration"
    },
    0xF1 => {
        format      => [ $llvarformat ], 
        name        => 'line1',
        description => "text1 line 1"
    },
    0xF2 => {
        format      => [ $llvarformat ], 
        name        => 'line2',
        description => "text1 line 2"
    },
    0xF3 => {
        format      => [ $llvarformat ], 
        name        => 'line3',
        description => "text1 line 3"
    },
    0xF4 => {
        format      => [ $llvarformat ], 
        name        => 'line4',
        description => "text1 line 4"
    },
    0xF5 => {
        format      => [ $llvarformat ], 
        name        => 'line5',
        description => "text1 line 5"
    },
    0xF6 => {
        format      => [ $llvarformat ], 
        name        => 'line6',
        description => "text1 line 6"
    },
    0xF7 => {
        format      => [ $llvarformat ], 
        name        => 'line7',
        description => "text1 line 7"
    },
    0xF8 => {
        format      => [ $llvarformat ], 
        name        => 'line8',
        description => "text1 line 8"
    },
    0xF9 => {
        format      => [ $byteformat, 1 ],
        name        => 'beeps',
        description => "binary number of beep-tones"
    },
    0xFA => {
        format      => [ $byteformat, 1 ],
        name        => 'status',
        description => "binary status"
    },
    0xFB => {
        format      => [ $byteformat, 1 ],
        name        => 'ok_required',
        description => "binary confirmation the input with <OK> required"
    },
    0xFC => {
        format      => [ $byteformat, 1 ],
        name        => 'dialog_control',
        description => "binary dialog-control"
    },
};

=head1 METHODS

=head2 new({data => $data})

Creates a new Data Object object that can be inspected with the parse method.

=cut

sub new {
    my $class = shift;
    my $options = shift || {};

    return bless $options, $class;
}

=head2 parse

Parses the data string and returns a hash reference containing name => value pairs of the data objects.

=cut

sub parse {
    my $self = shift;
    my $data = $self->{data};
    my $result = {};
    my $pos = 0;

    while ($pos < length $data) {
        my $bitmap_number = ord substr $data, $pos, 1;
        die "The bitmap number ".uc(unpack("H*", $bitmap_number))." does not exist." if not exists $bitmaps->{ $bitmap_number };

        my $bitmap_definition = $bitmaps->{ $bitmap_number };

        my $coderef = shift @{ $bitmap_definition->{format} };
        ($result->{ $bitmap_definition->{name} }, my $length) = $coderef->(@{ $bitmap_definition->{format} }, substr $data, $pos);
        $pos += $length;

        if (exists $bitmap_definition->{convert}) {
            $result->{ $bitmap_definition->{name} } = $bitmap_definition->{convert}->($result->{ $bitmap_definition->{name} });
        }
    }
    return $result;
}

1;