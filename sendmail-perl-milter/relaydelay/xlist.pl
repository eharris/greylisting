#!/usr/bin/perl

#############################################################################
#
# File: xlist.pl
#
# Version: 0.01
# 
# Programmer: Evan J. Harris <eharris@puremagic.com>
#
# Description:
#   Will create manual white or blacklist entries in the greylist database,
#   with some basic checking to ensure this isn't a duplicate, and to 
#   expire existing rows that would match.
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
# *** Copyright 2003 by Evan J. Harris --- All Rights Reserved ***
# *** No warranties expressed or implied, use at your own risk ***
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

sub usage {
  my $error = shift;
  if (defined $error) {
    print "$error\n\n";
  }
  print "Usage:\n"
    .   "  $0 <black|white> <ip|from|to> <fromaddr|ip|network>\n\n"
    .   "Note: networks must be specified in incomplete form, i.e. 10.2 = 10.2.0.0/16\n"
    .   "  NEVER whitelist on the 'from' address, since it is easily forged.\n\n"
    .   "Examples:\n\n"
    .   "$0 white ip 10\n"
    .   "  -- Whitelist all mail from systems on the private 10.x.x.x network\n"
    .   "$0 white to sales\@somedomain.com\n"
    .   "  -- Whitelist mail sent to the sales address to avoid possible delays\n"
    .   "$0 black from aspamdomain.com\n"
    .   "  -- Blacklist all mail with a from address at aspamdomain.com\n";
  exit;
}


BEGIN:
{
  my $never = "'0000-00-00 00:00:00'";
  my $always = "'9999-12-31 23:59:59'";


  # load config file before we start
  load_config();

  # parse command line params
  my $direction = lc(shift);
  usage("Error: First parameter must be either black or white.") if ($direction !~ /\A(black|white)\Z/);
  my $rectype = lc(shift);
  usage("Error: Second parameter must be a valid field type.") if ($rectype !~ /\A(ip|from|to|relay_ip|mail_from|rcpt_to)\Z/);
  $rectype = "relay_ip" if ($rectype eq "ip");
  $rectype = "mail_from" if ($rectype eq "from");
  $rectype = "rcpt_to" if ($rectype eq "to");
  my $fieldval = lc(shift);

  if (length($fieldval) < 2) {
    print "Error!  Field parameter too short!\n";
    exit;
  }

  if ($rectype eq "mail_from" and $direction eq "white") {
    print "Whitelisting of from addresses is not allowed!\n";
    exit;
  }
  if ($rectype eq "relay_ip" and $fieldval !~ /\A(\d+)(|\.(\d+)(|\.(\d+)(|\.(\d+))))\Z/) {
    if ($1 < 1 or $1 > 255 or $2 > 255 or $3 > 255 or $4 > 255) {
      print "IP is invalid format!\n";
      exit;
    }
  }
  my $block_expires = ($direction eq "white" ? $never : $always);

  # connect to the database 
  my $dbh = db_connect(0);
  die "$DBI::errstr\n" unless($dbh);

  # Make sure there isn't a similar manual entry already.
  my $rows = $dbh->selectrow_array("SELECT id FROM relaytofrom WHERE record_expires > NOW() AND $rectype = ? "
    . " AND origin_type = 'MANUAL' ", undef, $fieldval);
  if ($rows > 0) {
    print "Similar Record already exists!  Aborting.\n";
    exit;
  }

  # Insert the wildcard row (blacklist or whitelist)
  my $rows = $dbh->do("INSERT INTO relaytofrom (create_time, record_expires, block_expires, $rectype) "
      . " VALUES (NOW(), $always, $block_expires, " . $dbh->quote($fieldval) . ")") or die;

  # Make sure it inserted ok
  if ($rows != 1) {
    print "Error inserting record.\n";
    die;
  } 
  else {
    my $rowid = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    print "Inserted row $rowid\n";

    # expire any old records that match
    # - find records that may be similar (do real similarity testing later, this is wide pass)
    my $sth = $dbh->prepare("SELECT id, $rectype FROM relaytofrom WHERE record_expires > NOW() "
      . " AND $rectype LIKE " . $dbh->quote('%' . $fieldval . '%'));
    $sth->execute();
    my $rows = 0;
    while (my @cols = $sth->fetchrow_array()) {
      next if ($cols[0] == $rowid);  # Don't expire the row we just inserted
      $cols[1] = lc($cols[1]);   # Make sure the comparisons are lowercase
      my $doexpire = 0;

      if ($rectype eq "relay_ip" and substr($cols[1], 0, length($fieldval)) eq $fieldval) {
        $doexpire = 1;
      }
      else {
        # expire if is an exact match, with or without surrounding angle brackets
        $doexpire = 1 if ($fieldval =~ /\A.+@.+\Z/ and ($cols[1] eq "<$fieldval>" or $cols[1] eq "$fieldval"));
        # expire if is a username@ match
        $doexpire = 1 if ($fieldval =~ /@\Z/ and substr($cols[1], 0, length($fieldval) + 1) eq "<$fieldval");
        # expire if is a partial domain match
        $doexpire = 1 if ($fieldval !~ /@/ and 
          (   substr($cols[1], - (length($fieldval) + 2)) eq ".$fieldval>" 
           or substr($cols[1], - (length($fieldval) + 2)) eq "\@$fieldval>"
           or substr($cols[1], - (length($fieldval) + 1)) eq ".$fieldval"
           or substr($cols[1], - (length($fieldval) + 1)) eq "\@$fieldval"));
      }
      if ($doexpire) {
        $rows += $dbh->do("UPDATE relaytofrom SET record_expires = NOW() WHERE id = $cols[0]");
      }
    }
    $sth->finish();
    print "Expired $rows rows\n";
  }

}


