#! /usr/bin/env perl

#+
# NAME:
# PURPOSE:
# CALLING SEQUENCE:
#	dump-customercone-prefixes.pl <all-paths> <as-rel>:
# INPUTS:
#	<all-paths>     YYYYMMDD.all-paths[.bz2] file produced by
#	                build-all-paths.pl
#	<as-rel>        YYYYMMDD.all-paths[.bz2] file produced by asrank.pl
# OUTPUTS:
#	Prints prefix info to standard output.
# PROCEDURE:
#	Usually output is piped to output file YYYYMMDD.ppdc-prefix.txt
#	(see as-rank-ribs.sh)
# MODIFICATION HISTORY:
#	DEC-2015, Paul Hick (UCSD/CAIDA; pphick@caida.org)
#		Based on Matthews version
#-

use strict;
use warnings;

use Getopt::Long;
use reserved;

my %clique;
my $limit = 0;
my $result = GetOptions("limit=i" => \$limit);

die  "usage: dump-customercone-prefixes.pl <all-paths> <as-rel>" if $result != 0 && $#ARGV < 0;

my ($paths, $rels) = @ARGV;

my %r;
open(RELS, $rels =~ /\.bz2$/ ? "bzcat $rels |" : "$rels") or die "could not open $rels";
while(<RELS>) {
    chomp;
    if (/^#/) {
	if (/^# inferred clique: (.+)$/) {
	    $clique{$_} = 1 for split(/ /, $1);
	}
	next;
    }

    if (/^(\d+)\|(\d+)\|(.+)$/) {
	$r{$1}{$2} = $3;
	$r{$2}{$1} = ($3 == -1 ? 1 : $3);
    }
}
close RELS;

my $reserved = new reserved;
my $x = 0;
my %prefixes;
open(PATHS, $paths =~ /\.bz2$/ ? "bzcat $paths |" : "$paths") or die "could not open $paths";
while (<PATHS>) {
    chomp;
    next if /^#/;

    my @row = split(/ /);
    my ($aspath, $prefix) = ($row[1], $row[2]);
    if ($prefix =~ /^\d+\.\d+\.\d+\.\d+\/(\d+)$/) {
	next if $1 < 8 || $1 > 24;
	next if $reserved->check($prefix);
    } else {
	next;
    }

    my @aspath = split(/\|/, $aspath);
    next if @aspath == 0;

    my @ases;
    my $last = 600;
    for my $i (0 .. $#aspath-1) {
	my ($a, $b) = ($aspath[$i], $aspath[$i+1]);
	if (!defined($r{$a}{$b}) || $r{$a}{$b} == 0) {
	    $last = defined($r{$a}{$b}) ? 0 : 600;
	    next;
	}

	my $r = $r{$a}{$b};
	if ($r != $last) {
	    @ases = ();
	    push @ases, $a if $last == 0;
	    $last = $r;
	}

	if ($r == -1) {
	    $prefixes{$_}{$prefix} = 1 for @ases;
	    push @ases, $b;
	}
    }
    $prefixes{$aspath[$#aspath]}{$prefix} = 1;
    last if $limit > 0 && ++$x == $limit;
}
close PATHS;

my $total = scalar(keys %prefixes);

print "# inferred clique: " .  join(' ', sort {$a <=> $b} keys %clique) . "\n";
print "# total size: $total\n";

for my $as (sort {$a <=> $b} keys %prefixes) {
    print "$as";
    print " $_" for keys %{$prefixes{$as}};
    print "\n";
}

exit 0;
