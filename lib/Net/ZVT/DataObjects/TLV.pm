package Net::ZVT::DataObjects::TLV;

use strict;

=head1 METHODS

=head2 new({data => $data})

Creates a new TLV container object that can be inspected with the other methods.

=cut

sub new {
    my $class = shift;
    my $options = shift || {};

    return bless $options, $class;
}

=head2 get_data

Returns the pure data string.

=cut

sub get_data {
    my $self = shift;
    my ($len, $pos) = $self->get_length();
    return substr $self->{data}, $pos, $len;
}

=head2 parse

Returns the parsed data as hash reference.

=cut

sub parse {
    my $self = shift;
    my $data = $self->get_data();
    my $result = {};
    my $pos = 0;

    while ($pos < length $data) {
        # read tag
        my $tag = ord substr($data, $pos++, 1);
        my $class_type = (qw/ universal application context-specific private /)[$tag >> 6];
        my $primitive_data_object = $tag >> 5 & 0b1 ? 0 : 1;
        my $tagnumber = $tag & 0b11111;
        if ($tagnumber == 0b11111) {
            # tag number in next byte(s)
            $tagnumber = 0;
            while (my $byte = ord substr($data, $pos++, 1)) {
                $tagnumber <<= 7;
                $tagnumber += $byte & 0x7F;
                last if !($byte >> 7);
            }
            $tagnumber = '1F '._hexify_str($tagnumber);
        }
        else {
            $tagnumber >>= 1;
            $tagnumber = _hexify_str($tagnumber);
        }
        print "tagnumber: $tagnumber\n";

        # read length and data
        my $tlvdata = substr($data, $pos);
        my $sub_tlv = Net::ZVT::DataObjects::TLV->new({ data => substr($data, $pos) });
        my ($datalength, $length_bytes) = $sub_tlv->get_length();
        
        if ($primitive_data_object) {
            push @{ $result->{$tagnumber} ||= [] }, $sub_tlv->get_data();
        }
        else {
            # recursive data extraction for constructed data objects:
            push @{ $result->{$tagnumber} ||= [] }, $sub_tlv->parse();
        }
        
        $pos += $length_bytes + $datalength;
    }
    return $result;
}

=head2 get_length

Returns an array containing the length of the data part as the first value and the length
of the length section (1 to 3 bytes) as the seconds value.

=cut

sub get_length {
    my $self = shift;
    my $len = ord substr $self->{data}, 0, 1;
    return ($len,                                     1)  if $len < 0x80;
    return (ord(substr $self->{data}, 1, 1),          2)  if $len == 0x81; # one length-byte follows
    return (unpack(q(S), substr $self->{data}, 1, 2), 3)  if $len == 0x82; # two length-bytes follow
    die q(invalid tlv container length definition);
}

sub _hexify_str { my $sep = $_[1] || q( ); uc unpack("H*", shift) =~ s/(..)(?!$)/$1$sep/gr }

1;