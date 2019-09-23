#!/usr/bin/perl
#
# $Id: as-numbers-assigned.pl,v 1.1 2015/02/13 01:04:35 pphick Exp $
#
# this script takes the following two files as input:
#
# http://www.iana.org/assignments/as-numbers/as-numbers-1.csv
# http://www.iana.org/assignments/as-numbers/as-numbers-2.csv

use strict;
use warnings;

my $start;
my $end;

foreach my $file (@ARGV)
{
    open(FILE, $file) or die "could not read $file";
    while(<FILE>)
    {
	if(/\s*(.+?)\s*$/)
	{
	    my @bits = split(/,/, $1);
	    next if(scalar(@bits) < 2 || !($bits[0] =~ /^\d/));
	    if($bits[1] =~ /^Assigned/)
	    {
		if($bits[0] =~ /^(\d+)$/)
		{
		    if(defined($end) && $end + 1 == $1)
		    {
			$end = $1;
		    }
		    else
		    {
			print "$start $end\n" if(defined($end));
			$start = $end = $1;
		    }
		}
		elsif($bits[0] =~ /^(\d+)-(\d+)$/)
		{
		    if(defined($end) && $end + 1 == $1)
		    {
			$end = $2;
		    }
		    else
		    {
			print "$start $end\n" if(defined($end));
			$start = $1;
			$end = $2;
		    }
		}
	    }
	}
    }
    close FILE;
}

print "$start $end\n";
