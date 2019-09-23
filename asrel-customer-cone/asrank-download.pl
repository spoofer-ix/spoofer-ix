#!/usr/bin/perl
#
# $Id: asrank-download.pl,v 1.24 2014/07/03 17:38:17 mjl Exp $
#
# a script to download BGP data given a date and then create appropriate files.
# mjl
#

use strict;
use warnings;
use Getopt::Long qw(GetOptions);

sub extract_date;
sub parse_AS;
sub paths_filename;
sub ignore_filename;
sub ipv4_prefix;
sub ipv6_prefix;
sub size_ton;

sub usage
{
    print STDERR "usage: asrank-download.pl [--download-only] [--rib-paths-only] \$date\n";
    return;
}

my $forks = 1;
my $days = 5;
my $credits = 0;
my $base_dir;
my $download_only = '';
my $ribpaths_only = '';
my $bzip2 = "pbzip2";
my $result = GetOptions("base-dir=s" => \$base_dir,
			"bzip2=s" => \$bzip2,
			"credits=i" => \$credits,
			"days=i" => \$days,
			"download-only" => \$download_only,
			"forks=i" => \$forks,
			"rib-paths-only" => \$ribpaths_only);
if(!$result || $#ARGV != 0)
{
    usage();
    exit -1;
}

if($forks > 1)
{
    eval {
	require Parallel::ForkManager;
	Parallel::ForkManager->import();
    };
    if($@ ne "") {
	print STDERR "Parallel::ForkManager not found.  --forks=$forks?\n";
	exit -1;
    }
}

my $date_yyyymmdd = $ARGV[0];
my ($date_yyyy, $date_mm);

if($date_yyyymmdd =~ /^(\d{4})(\d{2})\d{2}$/)
{
    ($date_yyyy, $date_mm) = ($1, $2);
    if($date_mm < 1 || $date_mm > 12)
    {
	usage();
	exit -1;
    }
}
else
{
    usage();
    exit -1;
}

my %cols;
open(COLS, "BGPCollectors.txt") or die "could not open BGPCollectors.txt";
while(<COLS>)
{
    chomp;
    next if(/^#/);

    my $str = $_;
    $str = $1 if($str =~ /(.+?)\s+\#/);
    my @bits = split(/ /, $str);
    next if(scalar(@bits) != 4);
    my ($site, $name, $type, $url) = @bits;
    $cols{$name}{$type}[0] = $site;
    $cols{$name}{$type}[1] = $url;
}
close COLS;

my %col_files;
foreach my $col (sort keys %cols)
{
    my %files;
    my ($url, $site, $url_dir);

    foreach my $type (sort data_type_sort keys %{$cols{$col}})
    {
	# make sure the files hash is empty
	%files = ();

	$site = $cols{$col}{$type}[0];
	$url  = $cols{$col}{$type}[1];
	printf("%s %s\n", $col, $url);

	$url_dir = sprintf("%s/%4d.%02d/", $url, $date_yyyy, $date_mm);
	$url_dir .= "RIBS/" if($site eq "routeviews" && $type eq "rib");

	my $cmd = sprintf("wget -4 -nv -O - %s", $url_dir);
	my %all;
	open(WGET, "$cmd 2>/dev/null |") or die "could not read directory";
	while(<WGET>)
	{
	    my $line = $1 if(/(^.+?)[\s\r\n]*$/);
	    my ($file, $size);
	    if($site eq "routeviews")
	    {
		my @td;
		while($line =~ /<td.*?>(.*?)<\/td>/g) { push @td, $1; }
		next if(scalar(@td) != 5);
		if($td[1] =~ /(oix-.+?\d{4}-\d{2}-\d{2}-\d{4}\.dat\.bz2)/ ||
		   $td[1] =~ /(oix-.+?\d{4}-\d{2}-\d{2}-\d{4}\.bz2)/ ||
		   $td[1] =~ /(route-views3.+?\d{4}-\d{2}-\d{2}-\d{4}\.dat.bz2)/ ||
		   $td[1] =~ /(rib\.\d{8}\.\d{4}\.bz2)/)
		{
		    $file = $1;
		    $size = $1 if($td[3] =~ /(\S+)\s*$/);
		}
	    }
	    else
	    {
		if($line =~ /(bview\.\d{8}\.\d{4}\.gz)/)
		{
		    $file = $1;
		    $size = $1 if($line =~ /(\S+)$/);
		}
		elsif($line =~ /(view\.\d{8}\.\d{4}\.gz)/)
		{
		    $file = $1;
		    $size = $1 if($line =~ /(\S+)$/);
		}
	    }
	    $all{$file} = size_ton($size) if(defined($file) && defined($size));
	}
	close WGET;

	my $x = 0; my $c = 0;
	foreach my $file (sort rib_date_sort keys %all)
	{
	    my ($y, $m, $d, $t) = extract_date($file);
	    my $rib_yyyymmdd = sprintf("%04d%02d%02d", $y, $m, $d);
	    next if($rib_yyyymmdd < $date_yyyymmdd + $x + $c);
	    if($rib_yyyymmdd > $date_yyyymmdd + $x + $c) {
		last if($credits < $rib_yyyymmdd - $date_yyyymmdd - $x - $c);
		my $used = $rib_yyyymmdd - $date_yyyymmdd - $x - $c;
		$c += $used; $credits -= $used;
	    }

	    #empty file with bzip/gzip header
	    next if($all{$file} == 14 || $all{$file} == 40);
	    $files{$file} = $x;
	    last if(++$x == $days);
	}
	last if($x == $days);
    }

    next if(scalar(keys %files) < $days);

    my $dir = sprintf("%s", defined($base_dir) ? "$base_dir/" : "");
    $dir .= "$date_yyyymmdd/$site/$col";
    system("mkdir -p $dir");

    foreach my $file (sort {$files{$a} <=> $files{$b}} keys %files)
    {
	$col_files{$dir}{$file} = 1;
	next if(-r "$dir/$file");
	my $cmd = sprintf("wget -q -4 -nv -O %s/%s %s/%s",
			  $dir, $file, $url_dir, $file);
	print "==> $cmd\n";
	system($cmd);
    }
}

exit 0 if($download_only);

my $pm;
$pm = new Parallel::ForkManager($forks) if($forks > 1);

foreach my $dir (sort keys %col_files)
{
    foreach my $file (sort keys %{$col_files{$dir}})
    {
	my ($type, $zcat);
	if($file =~ /^oix-.+?.bz2$/)
	{
	    $type = "ship";
	    $zcat = "bzcat";
	}
	elsif($file =~ /^route-views3-.+?.bz2$/)
	{
	    $type = "ship";
	    $zcat = "bzcat";
	}
	elsif($file =~ /^rib\..+?\.bz2$/)
	{
	    $type = "rib";
	    $zcat = "bzcat";
	}
	elsif($file =~ /^bview\..+?\.gz$/)
	{
	    $type = "rib";
	    $zcat = "gzcat";
	}
	elsif($file =~ /^view\..+?\.gz$/)
	{
	    $type = "ship";
	    $zcat = "gzcat";
	}
	else
	{
	    print STDERR "$file not in expected format\n";
	    exit -1;
	}

	my $data_file = "$dir/$file";
	my $path_file = paths_filename($data_file);
	my $ignore_file = ignore_filename($data_file);
	next if(-r $path_file);

	print "$type $path_file\n";

	if(defined($pm)) {
	    $pm->start and next;
	}
	open(PATHS, "| $bzip2 -c >$path_file") or die
	    "could not write to $path_file";
	open(IGNORE, "| $bzip2 -c >$ignore_file") or die
	    "could not write to $ignore_file";

	if($type eq "rib")
	{
	    open(BGP, "$zcat $data_file | bgpdump -m - 2>/dev/null |") or
		die "could not read $data_file";
	    while(<BGP>)
	    {
		chomp;
		if(/^TABLE_DUMP.?\|\d+\|B\|(.+?)\|.+?\|(.+?)\|(.+?)\|(.+?)\|.+/)
		{
		    my ($peer, $prefix, $path, $ot) = ($1, $2, $3, $4);
		    next if($prefix =~ /\/0$/);
		    next if(!($path =~ /^[\d\s\.]*\d$/));

		    if($ot eq "IGP") { $ot = "i"; }
		    elsif($ot eq "INCOMPLETE") { $ot = "?"; }
		    elsif($ot eq "EGP") { $ot = "e"; }

		    my @path;
		    my $skip = 0;
		    my @raw_path = split(/\s+/, $path);
		    foreach my $i (0 .. $#raw_path)
		    {
			my $as = parse_AS($raw_path[$i]);
			if(!defined($as))
			{
			    print IGNORE "$_\n";
			    $skip = 1;
			    last;
			}
			push @path, $as if($i == 0 || ($path[$#path] != $as));
		    }
		    next if($skip != 0);

		    printf PATHS "%s %s %s %s\n", join("|", @path), $prefix, $ot, $peer;
		}
		else
		{
		    print IGNORE "$_\n";
		}
	    }
	    close BGP;
	}
	elsif($type eq "ship")
	{
	    my $path_index = 0;
	    my $peer_index = 0;
	    my $pref_index = 3;
	    my $prefix;

	    open(BGP, "$zcat $data_file |") or die "could not open $data_file";
	    while(<BGP>)
	    {
		my $line = $_; $line = $1 if(/^(.+?)[\r\n]+$/);
		if($path_index == 0)
		{
		    if($line =~ /^(.+)Next Hop(.+)Path$/)
		    {
			$peer_index = length $1;
			$path_index = (length $1) + 8 + (length $2);
		    }
		    if($line =~ /^(.+)Destination/)
		    {
			$pref_index = length $1;
		    }
		    next;
		}

		# * is symbol for valid route, > is symbol for best route.
		if(!/^\*/ && !/^\>/) {
		    print IGNORE "$line\n";
		    next;
		}

		my $pfx_overflow = 0;
		if($pref_index > length $line) {
		    print IGNORE "$line\n";
		    next;
		}
		my $raw_pref = substr $line, $pref_index;
		if($raw_pref =~ /^([^ ]+) /)
		{
		    $prefix = $1;
		    if(!defined($prefix)) {
			print IGNORE "$line\n";
			next;
		    }
		    $pfx_overflow = (length $prefix) - 16 if(length $prefix > 16);
		    if(!($prefix =~ /\/\d+$/) && $prefix =~ /^(\d+)\./)
		    {
			if($1 < 128)    { $prefix = "$prefix/8";  }
			elsif($1 < 192) { $prefix = "$prefix/16"; }
			elsif($1 < 224) { $prefix = "$prefix/24"; }
		    }
		}

		if($path_index + $pfx_overflow > length $line) {
		    print IGNORE "$line\n";
		    next;
		}

		my $raw_peer = substr $line, $peer_index + $pfx_overflow;
		my $peer;
		if($raw_peer =~ /^([\d\.]+)\s/) {
		    $peer = $1;
		} else {
		    print IGNORE "$line\n";
		    next;
		}

		my $raw_path = substr $line, $path_index + $pfx_overflow;
		if($raw_path =~ /^\s*([\d\s]*\d .)$/) {
		    $raw_path = $1;
		} else {
		    print IGNORE "$line\n";
		    next;
		}

		my @raw_path = split(/\s+/, $raw_path);
		my $ot = pop @raw_path; # discard the origin code

		my $skip = 0;
		my @path;
		push @path, $raw_path[0];
		foreach my $i (1 .. $#raw_path)
		{
		    my $as = $raw_path[$i];
		    if(!($as =~ /^\d+$/))
		    {
			$skip = 1;
			last;
		    }
		    elsif($as != $path[$#path])
		    {
			push @path, $as;
		    }
		}
		if($skip != 0) {
		    print IGNORE "$line\n";
		    next;
		}

		printf PATHS "%s %s %s %s\n", join('|', @path), $prefix, $ot, $peer;
	    }
	    close BGP;
	}

	close PATHS;
	close IGNORE;

	if(defined($pm)) {
	    $pm->finish;
	}
    }
}

if(defined($pm)) {
    $pm->wait_all_children;
}

exit 0 if($ribpaths_only);

my %collv;
my %all_paths;
my %stable_paths;
my %prefix2as;
foreach my $dir (sort keys %col_files)
{
    my %col_paths;
    foreach my $file (sort keys %{$col_files{$dir}})
    {
	my ($y, $m, $d, $t) = extract_date($file);
	my $dstr = sprintf("%d%02d%02d", $y, $m, $d);

	my $path_file = paths_filename("$dir/$file");
	next if(!-r $path_file);
	open(PATHS, "bzcat $path_file |") or die "could not read $path_file";
	my %paths;
	while(<PATHS>)
	{
	    chomp;
	    if(/^(.+?) (.+?) .+? (.+)$/)
	    {
		my ($path, $prefix, $col) = ($1, $2, $3);
		my ($v, $o);

		if(ipv4_prefix($prefix))    { $v = 4; }
		elsif(ipv6_prefix($prefix)) { $v = 6; }
		else {
		    print STDERR "unknown $prefix in $path_file: |$_|\n";
		    next;
		}

		if($path =~ /\|?(\d+)$/) { $o = $1; }
		else {
		    print STDERR "unknown path $path\n";
		    next;
		}

		$collv{$dir}{$v}{$dstr} = 1;
		$prefix2as{$v}{$prefix}{$o} = 1;

		next if(defined($paths{$v}{$path}));
		$paths{$v}{$path} = 1;
		$all_paths{$v}{$path} = 1;
		$col_paths{$col}{$v}{$path}++;
	    }
	}
	close PATHS;
    }

    foreach my $col (keys %col_paths)
    {
	foreach my $v (keys %{$col_paths{$col}})
	{
	    foreach my $path (keys %{$col_paths{$col}{$v}})
	    {
		next if($col_paths{$col}{$v}{$path} != $days);
		$stable_paths{$v}{$path} = 1;
	    }
	}
    }
}

foreach my $v (4, 6)
{
    my $header = "";
    foreach my $dir (sort keys %collv)
    {
	next if(!defined($collv{$dir}{$v}));
	my @bits = split(/\//, $dir);
	my ($proj, $coll) = ($bits[$#bits-1], $bits[$#bits]);
	foreach my $date (sort {$a <=> $b} keys %{$collv{$dir}{$v}})
	{
	    $header .= "# source:topology|BGP|$date|$proj|$coll\n";
	}
    }

    if(defined($all_paths{$v}))
    {
	my $file = sprintf("%s", defined($base_dir) ? "$base_dir/" : "");
	$file .= "$date_yyyymmdd/$date_yyyymmdd.paths";
	$file .= "6" if($v == 6);
	open(ALL_PATHS, ">$file") or die "could not open $file";
	print ALL_PATHS $header;
	while(my ($path, $value) = each %{$all_paths{$v}})
	{
	    print ALL_PATHS "$path\n";
	}
	close ALL_PATHS;
    }

    if(defined($stable_paths{$v}))
    {
	my $file = sprintf("%s", defined($base_dir) ? "$base_dir/" : "");
	$file .= "$date_yyyymmdd/$date_yyyymmdd.stable.paths";
	$file .= "6" if($v == 6);
	open(STABLE_PATHS, ">$file") or die "could not open $file";
	print STABLE_PATHS $header;
	while(my ($path, $value) = each %{$stable_paths{$v}})
	{
	    print STABLE_PATHS "$path\n";
	}
	close STABLE_PATHS;
    }

    if(defined($prefix2as{$v}))
    {
	my $file = sprintf("%s", defined($base_dir) ? "$base_dir/" : "");
	$file .= "$date_yyyymmdd/$date_yyyymmdd.prefix2as";
	$file .= "6" if($v == 6);
	open(PREFIX2AS, ">$file") or die "could not open $file";
	print PREFIX2AS $header;
	while(my ($prefix, $value) = each %{$prefix2as{$v}})
	{
	    my @ases = sort {$a <=> $b} keys %{$prefix2as{$v}{$prefix}};
	    my ($net, $len) = split(/\//, $prefix);
	    print PREFIX2AS "$net\t$len\t$ases[0]";
	    print PREFIX2AS "_$ases[$_]" foreach (1 .. $#ases);
	    print PREFIX2AS "\n";
	}
	close PREFIX2AS;
    }
}

exit 0;

sub data_type_sort($$)
{
    my ($a, $b) = @_;
    my %map;
    $map{"rib"} = 0;
    $map{"ship"} = 1;
    return -1 if($map{$a} < $map{$b});
    return  1 if($map{$a} > $map{$b});
    return 0;
}

sub extract_date($)
{
    my ($x) = @_;
    return ($1, $2, $3, $4)
	if($x =~ /oix-.+?(\d{4})-(\d{2})-(\d{2})-(\d{4})\.dat\.bz2/);
    return ($1, $2, $3, $4)
	if($x =~ /oix-.+?(\d{4})-(\d{2})-(\d{2})-(\d{4})\.bz2/);
    return ($1, $2, $3, $4)
	if($x =~ /rib\.(\d{4})(\d{2})(\d{2})\.(\d{4})\.bz2/);
    return ($1, $2, $3, $4)
	if($x =~ /bview\.(\d{4})(\d{2})(\d{2})\.(\d{4})\.gz/);
    return ($1, $2, $3, $4)
	if($x =~ /view\.(\d{4})(\d{2})(\d{2})\.(\d{4})\.gz/);
    return ($1, $2, $3, $4)
	if($x =~ /route-views3-.+?(\d{4})-(\d{2})-(\d{2})-(\d{4})\.dat\.bz2/);
    return undef;
}

sub rib_date_sort($$)
{
    my ($a, $b) = @_;
    my ($a_y, $a_m, $a_d, $a_t) = extract_date($a);
    my ($b_y, $b_m, $b_d, $b_t) = extract_date($b);
    return -1 if($a_y < $b_y); return  1 if($a_y > $b_y);
    return -1 if($a_m < $b_m); return  1 if($a_m > $b_m);
    return -1 if($a_d < $b_d); return  1 if($a_d > $b_d);
    return -1 if($a_t < $b_t); return  1 if($a_t > $b_t);
    return 0;
}

sub parse_AS($)
{
    my ($as) = @_;
    return (($1 * 65536) + $2) if($as =~ /^(\d+)\.(\d+)$/);
    return $as if($as =~ /^\d+$/);
    return undef;
}

sub paths_filename($)
{
    my ($data_file) = @_;
    return "$1.paths.bz2" if($data_file =~ /^(.+?\/oix-.+?)\.dat.bz2$/ ||
			     $data_file =~ /^(.+?\/oix-.+?)\.bz2$/ ||
			     $data_file =~ /^(.+?\/rib\..+?)\.bz2$/ ||
			     $data_file =~ /^(.+?\/route-views3-.+?)\.dat.bz2$/ ||
			     $data_file =~ /^(.+?\/bview\..+?)\.gz$/ ||
			     $data_file =~ /^(.+?\/view\..+?)\.gz$/);
    return undef;
}

sub ignore_filename($)
{
    my ($data_file) = @_;
    return "$1.ignore.bz2" if($data_file =~ /^(.+?\/oix-.+?)\.dat.bz2$/ ||
			      $data_file =~ /^(.+?\/oix-.+?)\.bz2$/ ||
			      $data_file =~ /^(.+?\/rib\..+?)\.bz2$/ ||
			      $data_file =~ /^(.+?\/route-views3-.+?)\.dat.bz2$/ ||
			      $data_file =~ /^(.+?\/bview\..+?)\.gz$/ ||
			      $data_file =~ /^(.+?\/view\..+?)\.gz$/);
    return undef;
}

sub path_origin_sort($$)
{
    my ($x, $y) = @_;
    my ($xo, $yo);

    if($x =~ /\|?(\d+)$/) { $xo = $1; }
    if($y =~ /\|?(\d+)$/) { $yo = $1; }

    if(defined($xo) && defined($yo)) {
	return -1 if($xo < $yo);
	return  1 if($xo > $yo);
	return  0;
    }

    return $x cmp $y;
}

sub ipv4_prefix($)
{
    my ($x) = @_;
    return 1 if($x =~ /^\d+\.\d+\.\d+\.\d+\/\d+$/);
    return 0;
}

sub ipv6_prefix($)
{
    my ($x) = @_;
    return 1 if($x =~ /^[\dabcdef:]+\/\d+$/);
    return 0;
}

sub size_ton($)
{
    my ($x) = @_;
    return ($1 * 1048576) if($x =~ /(?:>|^)(\d.*)M(?:<|$)/);
    return ($1 * 1024) if($x =~ /(?:>|^)(\d.*)K(?:<|$)/);
    return $x;
}
