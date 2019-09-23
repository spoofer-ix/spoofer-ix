#!/usr/bin/perl
#
# $Id: reserved.pm,v 1.1 2016/01/05 01:22:09 pphick Exp $

package reserved;

use strict;
use warnings;
use Net::Patricia;

sub new
{
    my $class = shift;
    my $pt = new Net::Patricia;
    $pt->add_string("0.0.0.0/8", "0.0.0.0/8");
    $pt->add_string("1.1.1.0/24", "1.1.1.0/24");
    $pt->add_string("10.0.0.0/8", "10.0.0.0/8");
    $pt->add_string("100.64.0.0/10", "100.64.0.0/10");
    $pt->add_string("127.0.0.0/8", "127.0.0.0/8");
    $pt->add_string("169.254.0.0/16", "169.254.0.0/16");
    $pt->add_string("172.16.0.0/12", "172.16.0.0/12");
    $pt->add_string("192.0.0.0/24", "192.0.0.0/24");
    $pt->add_string("192.0.2.0/24", "192.0.2.0/24");
    $pt->add_string("192.88.99.0/24", "192.88.99.0/24");
    $pt->add_string("192.168.0.0/16", "192.168.0.0/16");
    $pt->add_string("198.18.0.0/15", "198.18.0.0/15");
    $pt->add_string("198.51.100.0/24", "198.51.100.0/24");
    $pt->add_string("203.0.113.0/24", "203.0.113.0/24");
    $pt->add_string("224.0.0.0/4", "224.0.0.0/4");
    $pt->add_string("240.0.0.0/4", "240.0.0.0/4");
    my $self = {_pt => $pt };
    bless $self, $class;
    return $self;
}

sub check
{
    my ($self, $addr) = @_;
    my $pt = $self->{_pt};
    return 1 if(defined($pt->match_string($addr)));
    return 0;
}

1;
