#!/usr/bin/perl

#############################################################################
#
# File: db_maintenance.pl
#
# Version: 1.0
# 
# Programmer: Evan J. Harris <eharris@puremagic.com>
#
# Description:
#   Performs nightly cleanup and maintenace on the greylisting database
#   as created from dbdef.sql.  Will copy all rows out of the main 
#   relaytofrom table into the reporting table, and then delete the
#   expired ones from the main table.  Not required for the implementation,
#   but helps keep the active database smaller/faster without losing any
#   data that may be useful for profiling.
#
# References:
#   For Greylisting info, see http://projects.puremagic.com/greylisting/
#   For SMTP info, see RFC821, RFC1891, RFC1893
#
# Notes:
#   - The new parameters chunk_size and sleep_secs helps limit the impact 
#     that the maintenance has on the db, since the db intensive copy/delete
#     queries lock the db during their execution.  If your db is very large,
#     you will want to set these accordingly.
#   - If you want to optimize the active table (relaytofrom), keep in mind
#     that it will cause the table to be locked from updates for a few 
#     seconds to several minutes depending on table size and speed of the
#     db machine and the network connection to it.
#   - May also be run more or less often than nightly if desired.
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
my $verbose = 1;

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

# Set this to the chunk size you want to process records in
my $chunk_size = 1000;

# Set this to the number of seconds to sleep between copy/delete
#   chunks (so other clients can get some work done)
my $sleep_secs = 1;

# Set this to nonzero if you wish to optimize the active table
#   after deleting the rows moved to the reporting table.
my $optimize_active_table = 0;

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
                         { PrintError => 0, RaiseError => $verbose });

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

  print "Loading Config File: $config_file\n";

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


BEGIN:
{
  # load config file before we start
  load_config();

  # Flush output at every write
  $| = 1;

  # connect to the database 
  my $dbh = db_connect(1);
  die "$DBI::errstr\n" unless($dbh);

  # Get the current DB server time for use in later queries (minus one second to 
  #   work around possible race)
  my $now = $dbh->selectrow_array("SELECT NOW()");
  print "DB Server Time: $now\n";

  my $highest_id = $dbh->selectrow_array("SELECT MAX(id) FROM relaytofrom");
  print "Highest ID: $highest_id\n";

  my $first = 1;
  my $last = 0;
  my $copied = 0;
  my $deleted = 0;
  while ($last < $highest_id) {
  
    # Query to find out what the last id was that will be copied in this iteration
    my $ids = $dbh->selectcol_arrayref("SELECT id FROM relaytofrom WHERE id >= $first ORDER BY id LIMIT $chunk_size");

    my $maxindex = $#$ids;
    $last = $$ids[$maxindex];
    $copied += $maxindex + 1;
    print "Last Row: $last";

    # Copy selected row range to the reporting table, replacing any existing rows
    $dbh->do("REPLACE INTO relayreport SELECT * FROM relaytofrom WHERE id >= $first AND id <= $last");
    print " - Copied: " . ($maxindex + 1);

    my $rows = $dbh->do("DELETE FROM relaytofrom WHERE record_expires < '$now' AND origin_type = 'AUTO' AND id <= $last");
    $rows += 0;
    $deleted += $rows;
    print " - Deleted: $rows\n";

    sleep($sleep_secs);

    $first = $last + 1;
  }

  print "\nSummary: \n";
  print "  Total Copied: $copied\n";
  print "  Total Deleted: $deleted\n";

  if ($optimize_active_table) {
    $dbh->do("OPTIMIZE TABLE relaytofrom");
    print "Optimized active table.\n";
  }

}


