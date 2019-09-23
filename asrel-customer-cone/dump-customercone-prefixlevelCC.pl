#!/usr/bin/env perl
#
# build customer cone prefixes by including all prefixes announced by
# customer cone ASes in a given customer cone.
#
# mjl

use strict;
use warnings;
use Data::Dumper;
use lib '.';
use reserved;

die  "usage: dump-customercone-prefixes.pl <ppdc-ases> <prefix2as>"
    if scalar(@ARGV) != 2;

my ($ppdc_ases, $prefixes) = @ARGV;

my %ascones;
my %clique;
my %as2pref;

my $reserved = new reserved;

if($prefixes =~ /\.bz2$/)
{
    open(PREFIXES, "bzcat $prefixes |") or die "could not open $prefixes";
}
else
{
    open(PREFIXES, $prefixes) or die "could not open $prefixes";
}
while(<PREFIXES>)
{
    chomp;
    next if(/^#/);

    if(/^(.+?)\s+(\d+)\s+(.+)$/)
    {
	my ($net, $len, $ases) = ($1, $2, $3);
	my $pref = sprintf("%s/%d", $net, $len);

	next if($len < 8 || $len > 24);
	next if($reserved->check($pref));

	foreach my $as (split(/_/, $ases))
	{
	    push @{$as2pref{$as}}, $pref;
	}
    }
}    
close PREFIXES;

if($ppdc_ases =~ /\.bz2$/)
{
    open(PPDC, "bzcat $ppdc_ases |") or die "could not open $ppdc_ases";
}
else
{
    open(PPDC, $ppdc_ases) or die "could not open $ppdc_ases";
}
while(<PPDC>)
{
    chomp;
    if(/^\d+ .+$/)
    {
	my ($asn, @cone) = split(/ /);
	my %prefixes;
	foreach my $as (@cone)
	{
	    next if(!defined($as2pref{$as}));
	    $prefixes{$_} = 1 foreach (@{$as2pref{$as}});
	}
	print "$asn " . join(' ', keys %prefixes) . "\n";
    }
}
close PPDC;

exit 0;
