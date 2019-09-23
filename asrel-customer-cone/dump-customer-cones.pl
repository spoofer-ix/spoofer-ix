#!/usr/bin/perl
#
# $Id: dump-customer-cones.pl,v 1.1 2015/02/18 19:50:48 pphick Exp $

use strict;
use warnings;
use Getopt::Long;

my %r;      # relationships
my %cc;     # customer cone size for each AS
my %pc;     # peer cone size for each AS
my %ccr;    # ASes reached through customer neighbour
my %clique; # hash table identifying clique

my $paths;
my $skipvp = '';
my $ppdc = '';
my $result = GetOptions("paths=s" => \$paths,
			"ppdc" => \$ppdc,
			"skipvp" => \$skipvp);
if($result != 0 && $#ARGV < 0)
{
    print STDERR
	"usage: dump-customer-cones.pl" .
	" [--ppdc] [--paths file] <rels> [mode]\n";
    exit -1;
}
my $rels = $ARGV[0];
my $mode = ($#ARGV >= 1 ? $ARGV[1] : "count");

sub build_customer_cone($$);
sub build_customer_cone($$)
{
    my ($cone, $a) = @_;
    return if(defined($cone->{$a}));
    $cone->{$a} = 1;
    foreach my $b (keys %{$r{$a}})
    {
        build_customer_cone($cone, $b) if($r{$a}{$b} == -1);
    }
    return;
}

# for each AS, assemble its peer cone, assuming peers supply each other all
# customer routes
sub build_peer_cones
{
    foreach my $x (keys %cc)
    {
	$pc{$x}{$_} = 1 foreach (keys %{$cc{$x}});
	foreach my $y (keys %{$r{$x}})
	{
	    next if($r{$x}{$y} != 0);
	    $pc{$x}{$_} = 1 foreach (keys %{$cc{$y}});
	}
    }
    return;
}

sub cust_rank($$)
{
    my ($a, $b) = @_;
    my $ac = scalar(keys %{$cc{$a}});
    my $bc = scalar(keys %{$cc{$b}});
    return -1 if($ac > $bc);
    return  1 if($ac < $bc);
    return -1 if($a < $b);
    return  1 if($a > $b);
    return 0;
}

sub peer_rank($$)
{
    my ($a, $b) = @_;
    my ($ac, $bc);

    $ac = scalar(keys %{$pc{$a}});
    $bc = scalar(keys %{$pc{$b}});
    return -1 if($ac > $bc);
    return  1 if($ac < $bc);

    $ac = scalar(keys %{$cc{$a}});
    $bc = scalar(keys %{$cc{$b}});
    return -1 if($ac > $bc);
    return  1 if($ac < $bc);    

    return -1 if($a < $b);
    return  1 if($a > $b);
    return 0;
}

sub ccr_rank($$$)
{
    my ($x, $a, $b) = @_;
    $a = scalar(keys %{$ccr{$x}{$a}});
    $b = scalar(keys %{$ccr{$x}{$b}});
    return -1 if($a > $b);
    return  1 if($a < $b);
    return 0;
}

open(RELS, $rels =~ /\.bz2$/ ? "bzcat $rels |" : "$rels") or die "could not open $rels";
while(<RELS>)
{
    chomp;
    if(/^#/)
    {
	if(/^# inferred clique: (.+)$/)
	{
	    $clique{$_} = 1 foreach (split(/ /, $1));
	}
	next;
    }

    if(/^(\d+)\|(\d+)\|(.+)$/)
    {
	$cc{$1}{$1} = 1;
	$cc{$2}{$2} = 1;
	$r{$1}{$2} = $3;
	$r{$2}{$1} = ($3 == -1 ? 1 : $3);
    }
}
close RELS;

# for each AS, assemble its customer cone
if(!defined($paths))
{
    foreach my $x (keys %r)
    {
	$cc{$x}{$x} = 1;
	foreach my $y (keys %{$r{$x}})
	{
	    build_customer_cone(\%{$cc{$x}}, $y) if($r{$x}{$y} == -1);
	}
    }
}
else
{
    open(PATHS, $paths =~ /\.bz2$/ ? "bzcat $paths |" : "$paths") or die "could not open $paths";
    while(<PATHS>)
    {
	chomp;
	next if(/^#/);
	my @bits = split(/\|/);
	next if(scalar(@bits) == 0);
	my @ases;
	my $last = 600;

	foreach my $i (0 .. $#bits-1)
	{
	    my ($a, $b) = ($bits[$i], $bits[$i+1]);
	    if(!defined($r{$a}{$b}) || $r{$a}{$b} == 0)
	    {
		$last = defined($r{$a}{$b}) ? 0 : 600;
		next;
	    }

	    my $r = $r{$a}{$b};
	    if($r != $last)
	    {
		@ases = ();
		if((!$ppdc || $last == 0) && ($i != 0 || !$skipvp))
		{
		    push @ases, $a
		}
		$last = $r;
	    }

	    if($r == -1)
	    {
		$cc{$_}{$b} = 1 foreach(@ases);
		push @ases, $b;
		$ccr{$ases[$_]}{$ases[$_+1]}{$b} = 1 foreach (0 .. $#ases-1);
	    }
	    elsif(!$ppdc)
	    {
		$cc{$b}{$_} = 1 foreach(@ases);
		unshift @ases, $b;
	    }
	}
    }
    close PATHS;
}

my $total = scalar(keys %cc);

print "# inferred clique: " .
    join(' ', sort {$a <=> $b} keys %clique) . "\n";
print "# total size: $total\n";

if($mode eq "count" || $mode eq "ases")
{
    foreach my $x (sort cust_rank keys %cc)
    {
	if($mode eq "count")
	{
	    my $cc = scalar(keys %{$cc{$x}});
	    printf "%d %d %.1f\n", $x, $cc, $cc * 100 / $total;
	}
	elsif($mode eq "ases")
	{
	    print "$x";
	    foreach my $y (sort {$a <=> $b} keys %{$cc{$x}})
	    {
		print " $y";
	    }
	    print "\n";
	}
    }
}
elsif($mode eq "ccr")
{
    foreach my $x (sort cust_rank keys %cc)
    {
	my %cs;
	foreach my $y (keys %{$r{$x}})
	{
	    $cs{$y} = 1 if($r{$x}{$y} == -1);
	}
	next if(scalar(keys %cs) == 0);
	print "$x";
	foreach my $y (sort { ccr_rank($x, $a, $b) } keys %cs)
	{
	    next if(scalar(keys %{$ccr{$x}{$y}}) == 0);
	    printf(" %d:%d", $y, scalar(keys %{$ccr{$x}{$y}}));
	}
	print "\n";
    }
}
elsif($mode eq "peercones-count" || $mode eq "peercones-ases")
{
    build_peer_cones();
    foreach my $x (sort peer_rank keys %pc)
    {
	if($mode eq "peercones-count")
	{
	    my $pc = scalar(keys %{$pc{$x}});
	    printf "%d %d %.1f\n", $x, $pc, $pc * 100 / $total;
	}
	elsif($mode eq "peercones-ases")
	{
	    print "$x";
	    foreach my $y (sort {$a <=> $b} keys %{$pc{$x}})
	    {
		print " $y";
	    }
	    print "\n";
	}
    }
}
elsif($mode eq "merge")
{
    my %comb;
    foreach my $i (1 .. $#ARGV)
    {
	my $as = $ARGV[$i];
	$comb{$_} = 1 foreach (keys %{$cc{$as}});
    }

    my $cc = scalar(keys %comb);
    printf "%d %.1f\n", $cc, $cc * 100 / $total;
}
elsif($mode eq "clique-custcone-cumulative")
{
    my @ccrank = sort cust_rank keys %clique;
    my %comb;

    my $x = $ccrank[0];
    $comb{$_} = 1 foreach (keys %{$cc{$x}});
    delete $clique{$x};

    my $cc = scalar(keys %comb);
    printf "%d %d %.1f\n", $x, $cc, $cc * 100 / $total;

    while(scalar(keys %clique) > 0)
    {
	my $max_as;
	my $max_val = -1;
	foreach my $x (keys %clique)
	{
	    my $val = 0;
	    foreach my $y (keys %{$cc{$x}})
	    {
		$val++ if(!defined($comb{$y}));
	    }
	    if($max_val < $val)
	    {
		$max_val = $val;
		$max_as  = $x;
	    }
	}
	last if($max_val < 1);

	$comb{$_} = 1 foreach (keys %{$cc{$max_as}});
	delete $clique{$max_as};
	my $cc = scalar(keys %comb);
	printf "%d %d %.1f\n", $max_as, $cc, $cc * 100 / $total;
    }
}
elsif($mode eq "clique-peercone")
{
    build_peer_cones();
    foreach my $x (sort peer_rank keys %clique)
    {
	my $pc = scalar(keys %{$pc{$x}});
	printf "%d %d %.1f\n", $x, $pc, $pc * 100 / $total;
    }
}
