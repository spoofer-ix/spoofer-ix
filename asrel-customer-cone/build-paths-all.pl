#! /usr/bin/env perl

#+
# NAME:
#	build-paths-all.pl
# PURPOSE:
#	Extracts all paths from rib.*.paths.bz2 files created
#	by asrank-download.pl.
# CALLING SEQUENCE:
#	build-paths-all.pl /data/external/YYYYMMDD
# INPUTS:
#	All rib.*.paths.bz2 files in collector subdirectores
#	in /data/external/YYYYMMDD
# OUTPUT:
#	Paths printed to standard output in format:
#	<collector>|<path-count> <path>
# PROCEDURE:
#	Output is usually piped into file YYYYMMDD.all-paths
#	(see as-rank-ribs.sh)
# MODIFICATION HISTORY:
#	DEC-2015, Paul Hick (UCSD/CAIDA; pphick@caida.org)
#		Based on Matthews version in /data/external/as-rank-ribs
#-

use strict;
use warnings;

die "usage: build-paths-all.pl <path>" unless @ARGV == 1;

my $path = $ARGV[0];
$path .= '/' unless $path =~ /\/$/;
die "'$path' does not exist" unless -d $path;

# The */ after $path in find forces find to search subdirectories
# in $path (one for each collector), and avoid picking up 
# *.paths.bz2 files in $path itself.

my @files = split /\n/, `find $path*/ -name "*.paths.bz2" -print `;

my %collectors;
for (@files) {	# key: directory; value: filename
	push @{$collectors{$1}}, $2 if /^$path(.+)\/(.+)$/;
}

for my $name (sort keys %collectors) {
	my %paths;
	for my $file (@{$collectors{$name}}) {
		my $fullname = "$path$name/$file";
		open(PATHS, $fullname =~ /\.bz2$/ ? "bzcat $fullname |" : "$fullname") or die "could not read $fullname";
		while (<PATHS>) {
			chomp;
			$paths{$_}++;
		}
		close PATHS;
	}

	print "$name|$paths{$_} $_\n" for keys %paths;
}
