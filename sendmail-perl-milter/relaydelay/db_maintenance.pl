#!/usr/bin/perl

#############################################################################
#
# File: db_maintenance.pl
#
# Version: 0.01
# 
# Programmer: Evan J. Harris <eharris@puremagic.com>
#
# Description:
#   Performs nightly cleanup and maintenace on the greylisting database
#   as created from dbdef.sql.  Will copy all rows out of the main 
#   relaytofrom table into the reporting table, and then delete the
#   expired ones from the main table.  Not required for the implementation,
#   but helps keep the database smaller.
#
# References:
#   For Greylisting info, see http://projects.puremagic.com/greylisting/
#   For SMTP info, see RFC821, RFC1891, RFC1893
#
# Notes:
#   - If you want to optimize the active table (relaytofrom), keep in mind
#     that it will cause the table to be locked from updates for a few
#     seconds or minutes depending on table size and speed of db machine.
#   - May also be run more or less often than nightly if desired.
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

  # connect to the database 
  my $dbh = db_connect(1);
  die "$DBI::errstr\n" unless($dbh);

  # copy ALL rows to the reporting table, replacing any existing rows
  my $rows = $dbh->do("REPLACE INTO relayreport SELECT * FROM relaytofrom");
  print "$rows copied/updated to reporting table\n";

  # delete any rows that expired more than an hour ago
  my $rows = $dbh->do("DELETE FROM relaytofrom WHERE record_expires < NOW() - INTERVAL 1 HOUR AND origin_type = 'AUTO'");
  print "$rows expired rows deleted from active table\n";

  # optimize the active table
  #$dbh->do("OPTIMIZE TABLE relaytofrom");
  #print "Optimized active table.\n";

}


