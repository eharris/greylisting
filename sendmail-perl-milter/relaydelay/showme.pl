#!/usr/bin/perl

#############################################################################
#
# File: showme.pl
#
# Version: 0.01
# 
# Programmer: Evan J. Harris <eharris@puremagic.com>
#
# Description:
#   Will display the most commonly needed fields of matching records
#   matching a single specified value in the greylist database.
#
# References:
#   For Greylisting info, see http://projects.puremagic.com/greylisting/
#
# Notes:
#   This is a quick and dirty implementation, and no doubt can be made
#   much nicer, but it works pretty good as-is.
#
# Bugs:
#   None known.
#
#
# *** Copyright 2003-2004 by Evan J. Harris - All Rights Reserved ***
# *** No warranties expressed or implied, use at your own risk    ***
#
#############################################################################

use Errno qw(ENOENT);
use DBI;

use strict;

###############################################
# Our global settings file
###############################################
my $config_file = "/etc/mail/relaydelay.conf";


#################################################################
# Our global settings that may be overridden from the config file
#################################################################

# If you do/don't want to see debugging messages printed to stdout,
#   then set this appropriately.
my $verbose = 0;

# Database connection params
my $database_type = 'mysql';
my $database_name = 'relaydelay';
my $database_host = 'localhost';
my $database_port = 3306;
my $database_user = 'db_user';
my $database_pass = 'db_pass';


#############################################################
# End of options for use in external config file
#############################################################

# Set this to nonzero if you wish to optimize the active table
#   after deleting the rows moved to the reporting table.
my $optimize_active_table = 1;

# Global vars that should probably not be in the external config file
my $global_dbh;
my $config_loaded;


#######################################################################
# Database functions
#######################################################################

sub db_connect($) {
  my $verbose = shift;

  return $global_dbh if (defined $global_dbh);

  my $dsn = "DBI:$database_type:database=$database_name:host=$database_host:port=$database_port";
  print "DBI Connecting to $dsn\n" if $verbose;

  # Note: We do all manual error checking for db errors
  my $dbh = DBI->connect($dsn, $database_user, $database_pass, 
                         { PrintError => 0, RaiseError => 1 });

  $global_dbh = $dbh;
  return $global_dbh;
}

sub db_disconnect {
  $global_dbh->disconnect() if (defined $global_dbh);
  $global_dbh = undef;
  return 0;
}


sub load_config() {

  # make sure the config is only loaded once per instance
  return if ($config_loaded);

  print "Loading Config File: $config_file\n" if ($verbose);

  # Read and setup our configuration parameters from the config file
  my($msg);
  my($errn) = stat($config_file) ? 0 : 0+$!;
  if ($errn == ENOENT) { $msg = "does not exist" }
  elsif ($errn)        { $msg = "inaccessible: $!" }
  elsif (! -f _)       { $msg = "not a regular file" }
  elsif (! -r _)       { $msg = "not readable" }
  if (defined $msg) { die "Config file $config_file $msg" }

  open INFILE, "<$config_file";
  while (<INFILE>) {
    my $tstr = $_;
    if ($tstr =~ /\A\s*(\$database_\w+)\s*=/) {
      eval $tstr;
      if ($@ ne '') { die "Error in config file $config_file: $@" }
    }
  }

  $config_loaded = 1;
}

sub usage() {
  print "Usage:\n"
    .   "  $0 [-v] <ip|from|to> <searchstring>\n\n"
    .   "Note: All string comparisons are done case insensitive\n\n"
    .   "Examples:\n"
    .   "  $0 ip 10.1.1\n"
    .   "     - Shows all records with an IP matching '10.1.1.*'\n"
    .   "  $0 from test.org\n"
    .   "     - Shows all records with 'test.org' anywhere in the from field\n"
    .   "  $0 to test.org\n"
    .   "     - Shows all records with 'test.org' anywhere in the to field\n"
    .   "\n";
  exit;
}

sub max($$) {
  return $_[1] if ($_[1] > $_[0]);
  return $_[0];
}


BEGIN:
{
  my $verbose = 0;
  my $rectype;

  # load config file before we start
  load_config();

  # parse command line params
  while (my $param = shift) {
    $verbose = 1 if ($param eq "-v");
    if (substr($param, 0, 1) ne "-") {
      $rectype = lc($param);
      last;
    }
  }
  usage() if ($rectype !~ /\A(ip|from|to)\Z/);
  my $fieldval = shift;
  my $options = shift;
  $options = "" unless $options;

  if ($rectype eq "ip") {
    $fieldval .= '%';
    $rectype = "relay_ip";
  }
  else {
    $fieldval = '%' . $fieldval . '%';
    $rectype = "mail_from" if $rectype eq "from";
    $rectype = "rcpt_to" if $rectype eq "to";
  }

  # connect to the database 
  my $dbh = db_connect(0);
  die "$DBI::errstr\n" unless($dbh);

  my $arrayref = $dbh->selectall_arrayref("SELECT relay_ip, mail_from, rcpt_to, blocked_count, passed_count, aborted_count, origin_type, create_time, last_update FROM relaytofrom WHERE $rectype LIKE " . $dbh->quote($fieldval) . "$options");
  
  # find the max col widths
  my @widths;
  foreach my $colsref (@$arrayref) {
    for (my $loop = 0; $loop < 9; $loop++) {
      $widths[$loop] = max($widths[$loop], length($colsref->[$loop]));
    }
  }

  my $lines = 0;
  foreach my $colsref (@$arrayref) {
    $lines++;
    print "|";
    printf(" %-*s |", $widths[0], $colsref->[0]);
    for (my $loop = 1; $loop < 7; $loop++) {
      printf(" %*s |", $widths[$loop], $colsref->[$loop]);
    }
    print " " . substr($colsref->[7], 5) . " |";
    print " " . substr($colsref->[8], 4, 2) . "-" . substr($colsref->[8], 6, 2) . " " 
      . substr($colsref->[8], 8, 2) . ":" . substr($colsref->[8], 10, 2) . ":" . substr($colsref->[8], 12, 2) . " |";
    print "\n";
  }
  print " * $lines rows found * \n";
}


