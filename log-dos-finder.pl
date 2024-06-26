#!/usr/bin/perl
# A tool that can help to find sensible parameters for configuring mod_evasive,
# fail2ban, or other DoS detectors for your particular website, based on
# existing server logs. Your goal would be to scan your current set of log
# files, and find parameters that don't result in real visitors or benign
# crawlers being banned, while catching the obvious bad bots. Optimal parameters
# may depend on the size and design of your site.
#
# This script analyses server log files, and will report cases where:
# - the same IP accessed the same URL more than a certain number of times
#   within a certain timespan.
#   This is similar to DOSPageCount and DOSPageInterval in mod_evasive.
# - the same IP did more than a certain number of requests on any URLs within
#   a certain timespan.
#   This is similar to DOSSiteCount and DOSSiteInterval in mod_evasive.
# Mind that "timespan" does not necessarily mean a fixed interval (see the help
# text and the below remark).
#
# Supported log formats are hard-coded and currently only the ones I ever had to
# deal with are supported. Pull requests for either more common formats, or a
# way to specify any format as a parameter, are welcome.
#
# REMARKS
# A common misconception is that mod_evasive counts requests within fixed-length
# time windows. Its documentation even makes it seem as such. WRONG: look at the
# source code and you'll see it uses a much simpler approach. A single timer is
# kept per IP or IP+URL. These timers start counting back from zero EVERY time a
# new request comes in, regardless of whether the new request falls within the
# interval (hit count is incremented) or not. The hit count is only reset when 2
# consecutive requests are further apart than the specified interval.
# For instance if you set an interval of 2 seconds and a count of 10, then
# indeed the detector will trip if a visitor does 10 requests within 2 seconds.
# However, it will also trip if the visitor does 10 requests each with 1.9s in
# between, spanning a total time of more than 17 seconds, so be very careful
# when configuring these parameters.
#
# Note that just like mod_evasive, we don't care about response codes. If a bot
# is dumb enough to keep on doing HTTP requests despite getting a 301 redirect
# each time and then doing the HTTPS request, it will hit the threshold twice as
# fast, and deservedly so. Stupid bots.
#
# Also note that even in default mode, this will not behave exactly like
# 'classic' mod_evasive (source code from 2017/02), which is inconsistent in
# initialising request counts depending on whether a key is newly added to the
# tree or reset when count is reset. I didn't bother replicating this behaviour
# because it is bad behaviour.
# Moreover, since this script has a 1-second granularity for logs, sub-second
# accuracy is lost and this can also cause differences between actually running
# mod_evasive and analysing logs with this script. Of course mod_evasive also
# has 1-second granularity, but the timing of when it is activated can make a
# difference.
#
# And last but not least, if an IP does not use a Keep-Alive connection, but
# spawns new connections all the time, then those requests will usually be
# handled by different Apache workers. Those have each their own mod_evasive
# instance with their own database, and they will not trigger the thresholds as
# soon as you may expect. This script however does not know what log lines come
# from different connections, hence again it may report cases that mod_evasive
# wouldn't. This is a weakness of mod_evasive that can be mitigated by using
# something like fail2ban instead, that acts on log files.
#
#################################
# Copyright 2024 Alexander Thomas
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#################################

use strict;
use warnings;
use IO::Uncompress::Gunzip;
use List::Util qw(max);
use Time::Piece;


############################
### PARAMETERS ###

# Defaults cater for the mod_evasive style mode; for windowed mode I would
# recommend longer intervals.

# Let me use this comment to state that mod_evasive's Page default of 2 reqs in
# 1 second is way too trigger-happy and will likely annoy real visitors,
# especially if they have less than perfect motor skills and often hit buttons
# or keys twice.
my $defaultPageIntervalSecs = 3;
my $defaultPageCount = 12;
# Also here, I don't want to punish someone who causes a short burst. It's only
# when they keep on going that I want to act.
my $defaultSiteIntervalSecs = 2;
my $defaultSiteCount = 240;

# Default log format, either 0 for standard Apache logs or 1 for custom stuff
# my hosting provider happened to use. TODO: allow configuring any log format.
my $logFormat = 0;

# Size of the request databases above which we'll start pruning them to keep
# memory usage within bounds.
my $scanSize = 160;

# How often we want to prune each database, longer periods incur less overhead
# hence might be faster, but will let the databases consume more memory.
my $prunePeriod = 10;

# Regexes for ignoring lines in the logs. Any line whose request string
# matches any of these regexes, will be skipped as if the line wasn't there.
my @logIgnoreReq = (
	qr'/cgi-bin/test/respond.pl\?i=',
);


#######################
sub usage
{
	print <<__END__;
log-dos-finder by Dr. Lex, 2024/06.
Detect cases in log files where the same IP performed a given number of
requests on the same URL within a certain time, or a given number of requests
on any URL within a certain time. How the timespan is treated, depends on
whether the -w option is used, see below.

USAGE: log-dos-finder.pl [options] logfile [logfile2 ..]
  logfiles must be Apache-style access log, either in plain text format or
  gzipped. If you specify multiple files, make sure to go from old to new.
Dates in the logs must be in strptime format "%d/%b/%Y:%H:%M:%S %z".

The script can work in 2 modes, depending on the -w argument:
1. Default: same approach as classic mod_evasive. When a request is seen from
   the same IP or IP/URL combination as previously, and that previous one was
   less than INTERVAL seconds ago, a counter is incremented. If the counter
   exceeds COUNT, it is considered a DoS. If last request was at least INTERVAL
   secs ago, the counter is reset.
2. True windowed mode: timestamps of all requests occurring within less than
   INTERVAL seconds are kept. A DoS event is considered to happen when there
   are more than COUNT requests inside this window.
   (This is how I, and probably many others, expected mod_evasive to work
   judging from its documentation, but it does not. Perhaps other DoS detectors
   do work like this, which is why I provide this mode.)

OPTIONAL ARGUMENTS:
  -h: show usage and exit.
  -w: true windowed mode. Do not enable this if you want to simulate classic
     mod_evasive behaviour. See explanation above.
  -i INTERVAL_P (default: ${defaultPageIntervalSecs}),
  -n COUNT_P (default ${defaultPageCount}): parameters for requests from the same IP accessing
     the same URL.
     Related to DOSPageInterval, resp. DOSPageCount from mod_evasive.
  -I INTERVAL_S (default: ${defaultSiteIntervalSecs}),
  -N COUNT_S (default ${defaultSiteCount}), similar as n, i; but then for any URL.
     Related to DOSSiteInterval, resp. DOSSiteCount from mod_evasive.
  -q: include query parameters in URLs for same-URL matches (mod_evasive does
     not, hence this script by default also ignores them).
  -F FMT: specify log format; FMT must be either 0 (default, apache2 'common'
     or 'combined' formats), 1 (apache2 'vhost_combined' format), or 2 (like
     'combined', but with 2 extra values after the first field).
  -v: verbose mode, more progress reporting and extra statistics.
__END__
}


my $startTime = time;
my ($intervalSecsP, $countThreshP) = ($defaultPageIntervalSecs, $defaultPageCount);
my ($intervalSecsS, $countThreshS) = ($defaultSiteIntervalSecs, $defaultSiteCount);
my $bIgnQuery = 1;
my $bWindow;
my $bVerbose;

while(@ARGV && $ARGV[0] =~ /^-/) {
	if($ARGV[0] eq '--') {
		shift;
		last;
	}
	my $opts = substr($ARGV[0], 1);
	shift;
	foreach my $opt (split('', $opts)) {
		if($opt eq 'h') {
			usage();
			exit;
		}
		elsif($opt eq 'w') {
			$bWindow = 1;
		}
		elsif($opt eq 'i') {
			$intervalSecsP = shift;
			if(! defined $intervalSecsP || $intervalSecsP !~ /^\d+$/ || $intervalSecsP < 1) {
				die "ERROR: -i argument must be followed by a strictly positive integer.\n";
			}
		}
		elsif($opt eq 'n') {
			$countThreshP = shift;
			if(! defined $countThreshP || $countThreshP !~ /^\d+$/ || $countThreshP < 1) {
				die "ERROR: -n argument must be followed by by a strictly positive integer.\n";
			}
		}
		elsif($opt eq 'I') {
			$intervalSecsS = shift;
			if(! defined $intervalSecsS || $intervalSecsS !~ /^\d+$/ || $intervalSecsS < 1) {
				die "ERROR: -I argument must be followed by a strictly positive integer.\n";
			}
		}
		elsif($opt eq 'N') {
			$countThreshS = shift;
			if(! defined $countThreshS || $countThreshS !~ /^\d+$/ || $countThreshS < 1) {
				die "ERROR: -N argument must be followed by by a strictly positive integer.\n";
			}
		}
		elsif($opt eq 'F') {
			$logFormat = shift;
			if(! defined $logFormat || $logFormat !~ /^[01]$/) {
				die "ERROR: -F argument must be followed by either 0 or 1.\n";
			}
		}
		elsif($opt eq 'q') {
			$bIgnQuery = 0;
		}
		elsif($opt eq 'v') {
			$bVerbose = 1;
		}
		else {
			print STDERR "WARNING: ignoring unknown option '${opt}'\n";
		}
	}
}
die "ERROR: first argument must be log file\n" if($#ARGV < 0);

my $output = '';

# Stuff everything in here for same page accesses.
# Keys: "$ip,$url", values: anonymous array with either:
# - (default mode) [first seen timestamp, count, last seen timestamp]; or:
# - ($bWindow mode) [timestamps of requests that fall within $intervalSecsP].
my %pageDatabase;
# highScores contains anonymous arrays [score, duration].
my (%hitsP, %highScoresP, %hitFilesP, %recurringP);
# Same for site accesses, keys are simply "$ip" here.
my %siteDatabase;
my (%hitsS, %highScoresS, %hitFilesS, %recurringS);

# Garbage collection drops all keys whose values array has no relevant dates anymore.
my ($iterP, $iterS) = (0) x 2;
my $lineCount = 0;

while(@ARGV) {
	my $logFile = shift;
	print STDERR "Analysing file: ${logFile}...\n" if($bVerbose);
	my $fileHandle;
	if($logFile =~ /\.gz$/i) {
		$fileHandle = new IO::Uncompress::Gunzip $logFile or die "ERROR: cannot unzip file ${logFile}: $^E";
	}
	else {
		open($fileHandle, '<', $logFile) or die "ERROR: cannot open file ${logFile}: $^E";
	}

	foreach my $line (<$fileHandle>) {
		chomp($line);
		$lineCount++;

		$line =~ s/\\\"/&quot;/g;  # protection against malformed crappy bot junk
		# Mind that $ip may actually be a hostname if the server is configured to look them up,
		# but this shouldn't matter as long as things remain consistent.
		my ($ip, $id, $user, $date, $req, $ret, $rest);
		if($logFormat == 0) {
			# Apache2 'combined':
			#   $host $id $user [$date] "$req" $ret $size "$ref" "$agent"
			# or 'common':
			#   $host $id $user [$date] "$req" $ret $size
			($ip, $id, $user, $date, $req, $ret, $rest) =
				($line =~ /^(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\S+) (.*)$/);
		}
		elsif($logFormat == 1) {
			# Apache2 'vhost_combined'. Obviously you may want to split up log files per vhost
			# before processing them with this script.
			#   $vhost:$port $host $id $user [$date] "$req" $ret $size "$ref" "$agent"
			my $crap;
			($crap, $ip, $id, $user, $date, $req, $ret, $rest) =
				($line =~ /^(\S+) (\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\S+) (.*)$/);
		}
		elsif($logFormat == 2) {
			# Format as was used by 34SP shared hosting.
			#   $host $domain? $fulldomain? $id $user [$date] "$req" $ret $size "$ref" "$agent"
			my $crap;
			($ip, $crap, $crap, $id, $user, $date, $req, $ret, $rest) =
				($line =~ /^(\S+) (\S+) (\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\S+) (.*)$/);
		}

		next if($req !~ /^[A-Z]+ /);
		my $skip = 0;
		foreach my $re (@logIgnoreReq) {
			if($req =~ $re) {
				$skip = 1;
				last;
			}
		}
		next if($skip);

		my ($reqType, $url) = split(/ /, $req);
		next if(! defined $reqType);
		$url =~ s/\?.*// if($bIgnQuery);
		# Strip trailing / unless the path is "/"
		$url =~ s/(.)\/$/$1/;
		my $tStamp = parseDate($date);

		# Same page hits by same IP
		updateDatabase($tStamp, $logFile, "${ip},${url}", $ip, $intervalSecsP, $countThreshP,
			\$iterP, \%pageDatabase, \%hitsP, \%hitFilesP, \%highScoresP, \%recurringP);
		# General site hits by same IP
		updateDatabase($tStamp, $logFile, $ip, $ip, $intervalSecsS, $countThreshS,
			\$iterS, \%siteDatabase, \%hitsS, \%hitFilesS, \%highScoresS, \%recurringS);
	}

	close($fileHandle);
}

my $elapsed = time - $startTime;

if($bVerbose) {
	print "Analysed a total of ${lineCount} lines in ${elapsed} seconds.\n";
	print "Detecting ${countThreshP} same-URL requests or more ".
		($bWindow ? "within a window of ${intervalSecsP}s" :
		"occurring with less than ${intervalSecsP}s between each other") .".\n";
	print "Detecting ${countThreshS} requests or more ".
		($bWindow ? "within a window of ${intervalSecsS}s" :
		"occurring with less than ${intervalSecsS}s between each other") .".\n";
}
my $wantNewline;
foreach my $ip (sort { $hitsP{$a} <=> $hitsP{$b} } keys %hitsP) {
	print "${ip} last reached Page threshold at ". gmtime($hitsP{$ip}) ."  in log file ${hitFilesP{$ip}}\n";
	print "    It scored a maximum of ". $highScoresP{$ip}->[0] .
	      " requests within ". $highScoresP{$ip}->[1] ."s\n";
	print "    It came back ${recurringP{$ip}} times.\n" if($recurringP{$ip});
	print "    It also scored in the Site category, see below.\n" if($highScoresS{$ip});
	$wantNewline = 1;
}
foreach my $ip (sort { $hitsS{$a} <=> $hitsS{$b} } keys %hitsS) {
	if($wantNewline) {
		print "\n";
		$wantNewline = 0;
	}
	print "${ip} last reached Site threshold at ". gmtime($hitsS{$ip}) ."  in log file ${hitFilesS{$ip}}\n";
	print "    It scored a maximum of ". $highScoresS{$ip}->[0] .
	      " requests within ". $highScoresS{$ip}->[1] ."s\n";
	print "    It came back ${recurringS{$ip}} times.\n" if($recurringS{$ip});
	print "    It also scored in the Page category, see above.\n" if($highScoresP{$ip});
}


###########################################################################

sub parseDate
# Return epoch seconds for date string.
# Assuming dates have format "07/Jun/2024:00:36:26 +0000"
# Or in strptime notation: "%d/%b/%Y:%H:%M:%S %z"
{
	my $str = shift;
	my $date = Time::Piece->strptime($str, "%d/%b/%Y:%H:%M:%S %z");
	return $date->epoch;
}

sub updateDatabase
# Update occurrence database and record cases where thresholds are exceeded.
# $tStamp is epoch time for the event being considered;
# $logFile identifies the file from which the event originates;
# $id is an identifier for the entity causing the event;
# $key is the database entry key, representing access of a resource by $id;
# $interval is the number of seconds over which we count events;
# $thresh is the number of events that is considered a hit;
# $iterRef is a reference to the garbage collection counter for this DB;
# the rest are references to hashes to the actual data structures.
# (Obviously this is where OOP would be nice, but Perl has no decent OOP.)
{
	my ($tStamp, $logFile, $key, $id, $interval, $thresh,
	    $iterRef, $databaseRef, $hitsRef, $hitFilesRef, $highScoresRef, $recurRef) = @_;

	my ($entryAdded, $numHits, $duration);
	if(! defined $databaseRef->{$key}) {
		$databaseRef->{$key} = $bWindow ? [$tStamp] : [$tStamp, 1, $tStamp];
		$entryAdded = 1;
		$numHits = 1;
		$duration = 0;
	}
	else {
		my $stampsRef = $databaseRef->{$key};
		if($bWindow) {
			# Drop any stamps falling outside the interval
			shift(@$stampsRef) while(@$stampsRef && ($tStamp - $stampsRef->[0] >= $interval));
			push(@$stampsRef, $tStamp);
			$numHits = scalar(@$stampsRef);
		}
		else {  # like classic mod_evasive
			if($tStamp - $stampsRef->[2] < $interval) {
				$stampsRef->[1]++;
			}
			else {
				$stampsRef->[0] = $tStamp;
				$stampsRef->[1] = 1;
			}
			$stampsRef->[2] = $tStamp;
			$numHits = $stampsRef->[1];
		}
		# Add 1 second due to the granularity
		$duration = 1 + $stampsRef->[-1] - $stampsRef->[0];
	}
	# Yes, this code flow allows for the shoot-yourself-in-the-foot case where
	# $thresh == 1 hence every request is considered a DoS.
	if($numHits >= $thresh) {
		$recurRef->{$id}++ if($hitsRef->{$id} && $tStamp - $hitsRef->{$id} > $interval);
		$hitsRef->{$id} = $tStamp;
		$hitFilesRef->{$id} = $logFile;
		if(! defined $highScoresRef->{$id} || $numHits > $highScoresRef->{$id}->[0]) {
			$highScoresRef->{$id} = [$numHits, $duration];
		}
	}

	# Cleanup: remove old items (this is expensive, so don't do it every time).
	# Just look at the newest stamp of each entry (i.e., always the last one).
	return if(scalar(keys %$databaseRef) <= $scanSize);
	if($entryAdded && ++$$iterRef % $prunePeriod == 0) {
		my $expireStamp = $tStamp - $interval;
		while(my ($k, $stamps) = each(%$databaseRef)) {
			delete $databaseRef->{$k} if($stamps->[-1] <= $expireStamp);
		}
	}
}
