use ExtUtils::testlib;

use Sendmail::Milter;
use Socket;
use Errno qw(ENOENT);

use DBI;
#use Sys::Hostname;

use strict;


# Our global settings file
my $config_file = "/etc/mail/relaydelay.conf";



# Define the vars we will use from the config file
my $database_type = 'mysql';
my $database_name = 'relaydelay';
my $database_host = 'localhost';
my $database_host = '127.0.0.1';
my $database_port = 3306;
my $database_user = 'milter';
my $database_pass = 'milter';

# This determines how many seconds we will block inbound mail that is
#   from a previously unknown [ip,from,to] triplet.
my $delay_mail_secs = 3600;  # One hour

# This determines how many seconds of life are given to a record that is
#   created from a new mail [ip,from,to] triplet.
#   NOTE: See Also: update_record_life and update_record_life_secs.
my $auto_record_life_secs = 4 * 3600;  # 4 hours

# True if we should update the life of a record when passing a mail
my $update_record_life = 1;
# How much life (in secs) to give to a record we are updating from an
#   allowed (passed) email.  Only useful if update_record_life is
#   enabled.
my $update_record_life_secs = 30 * 24 * 3600;  # 30 days

my $blacklist_check_relay_ip = 1;
my $whitelist_check_relay_ip = 1;
my $whitelist_check_recipient = 1;
my $whitelist_check_sender = 1;
my $whitelist_check_sender_domain = 1;



# Global vars
my $global_dbh;
my $config_loaded;



# Possible dynamic blocking at firewall level
#iptables -A dynamic_smtp_blocks -s $relay_ip -j DROP
# And empty the list
#iptables -F dynamic_smtp_blocks

#######################################################################
# Database functions
#######################################################################

sub db_connect($) {
  my $verbose = shift;

  return $global_dbh if (defined $global_dbh);
  #my $driver = 'mysql';
  #my $database = '';
  #my $host = '127.0.0.1';
  #my $host = 'localhost';
  #my $user = '';
  #my $password = '';

  my $dsn = "DBI:$database_type:database=$database_name:host=$database_host:port=$database_port";
  print "DBI Connecting to $dsn\n" if $verbose;

  my $dbh = DBI->connect($dsn,
                         $database_user,
                         $database_pass,
                         { RaiseError => 1 });
  #print "DBI Connect Completed.\n";

  $global_dbh = $dbh;

  return $global_dbh;
}

sub db_disconnect {
  $global_dbh->disconnect() if (defined $global_dbh);
  $global_dbh = undef;
  return 0;
}

sub DoSingleValueQuery($)
{ 
  my $query = shift;

  my $dbh = db_connect(0);
  die "$DBI::errstr\n" unless($dbh);
  my $sth = $dbh->prepare($query);
  my $rv = $sth->execute()
    or die "Can't execute the query: $sth->errstr";
  # retrieve the first row returned
  my @array = $sth->fetchrow_array();
  # and terminate the query
  my $rc = $sth->finish;
  # return the first value in the first row
  return $array[0];
}

sub DoStatement($)
{
  my $query = shift;

  my $dbh = db_connect(0);
  die "$DBI::errstr\n" unless($dbh);
  my $rows_affected = $dbh->do($query);
}


#
#  Each of these callbacks is actually called with a first argument
#  that is blessed into the pseudo-package Sendmail::Milter::Context. You can
#  use them like object methods of package Sendmail::Milter::Context.
#
#  $ctx is a blessed reference of package Sendmail::Milter::Context to something
#  yucky, but the Mail Filter API routines are available as object methods
#  (sans the smfi_ prefix) from this
#
sub envfrom_callback
{
  my $ctx = shift;
  my @args = @_;

  #print "  Passed Sender: $args[0]\n";
  #print "my_envfrom:\n";
  #print "   + args: '" . join(', ', @args) . "'\n";

  # Save the envelope sender string
  my $mail_from = $args[0];
  $ctx->setpriv(\$mail_from);

  return SMFIS_CONTINUE;
}


sub abort_callback
{
  my $ctx = shift;

  # Clear any private data we may have set on this context.
  $ctx->setpriv(undef);

  return SMFIS_CONTINUE;
}


sub envrcpt_callback
{
  my $ctx = shift;
  my @args = @_;

  # Make sure we have the config information
  load_config();

  # Get the database handle
  my $dbh = db_connect(0);
  die "$DBI::errstr\n" unless($dbh);

  # Get the time in seconds
  my $timestamp = time();

  # Get the hostname (needs a module that is not necessarily installed)
  #my $hostname = hostname();

  print "\n";

  # Get the stored envelope sender
  my $context_data_ref = $ctx->getpriv();
  # And deallocate the context data
  $ctx->setpriv(undef);

  my $mail_from = ${$context_data_ref};
  my $rcpt_to = $args[0];

  print "Stored Sender: $mail_from\n";
  print "Passed Recipient: $rcpt_to\n";

  #print "my_envrcpt:\n";
  #print "   + args: '" . join(', ', @args) . "'\n";
  # other useful, but unneeded values
  #my $tmp = $ctx->getsymval("{j}");  print "localservername = $tmp\n";
  #my $tmp = $ctx->getsymval("{i}");  print "queueid = $tmp\n";
  #my $from_domain = $ctx->getsymval("{mail_host}");  print "from_domain = $tmp\n";
  #my $tmp = $ctx->getsymval("{rcpt_host}");  print "to_domain = $tmp\n";
        
  # Get the remote hostname and ip in the form "[ident@][hostname] [ip]"
  my $tmp = $ctx->getsymval("{_}");  
  my ($relay_ip, $relay_name, $relay_ident, $relay_maybe_forged);
  if ($tmp =~ /\A(\S*@|)(\S*) ?\[(.*)\]( \(may be forged\)|)\Z/) {
    $relay_ident = $1;
    $relay_name = $2;
    $relay_ip = $3;
    $relay_maybe_forged = (length($4) > 0 ? 1 : 0);
  }
  print "  Relay: $tmp\n";
  print "  RelayIP: $relay_ip - RelayName: $relay_name - RelayIdent: $relay_ident - Forged: $relay_maybe_forged\n";
        
  # declare our info vars
  my $rowid;

  # Collect the rest of the info for our checks
  my $mail_mailer = $ctx->getsymval("{mail_mailer}");
  my $sender      = $ctx->getsymval("{mail_addr}");
  my $rcpt_mailer = $ctx->getsymval("{rcpt_mailer}");
  my $recipient   = $ctx->getsymval("{rcpt_addr}");
  my $queue_id    = $ctx->getsymval("{i}");

  print "  From: $sender - To: $recipient\n";
  print "  InMailer: $mail_mailer - OutMailer: $rcpt_mailer - QueueID: $queue_id\n";

  # Only do our processing if the inbound mailer is an smtp variant.
  #   A lot of spam is sent with the null sender address <>.  Sendmail reports 
  #   that as being from the local mailer, so we have a special case that needs
  #   handling.
  if (! ($mail_mailer =~ /smtp\Z/i) && $mail_from ne "<>") {
    # we aren't using an smtp-like mailer, so bypass checks
    print "  Mail delivery is not using an smtp-like mailer.  Skipping checks.\n";
    return SMFIS_CONTINUE;
  }

  # Check for relay ip blacklisting, followed by whitelisting (by host or net)
  if ($blacklist_check_relay_ip || $whitelist_check_relay_ip) {
    my $tstr = $relay_ip;
    for (my $loop = 0; $loop < 4; $loop++) {
      # - See if this relay is black- or white-listed
      my $query = "SELECT id FROM relaytofrom "
        .         "  WHERE record_expires > NOW() "
        .         "    AND relay_ip = " . $dbh->quote($tstr)
        .         "    AND mail_from = '' "
        .         "    AND rcpt_to = '' ";
      if ($blacklist_check_relay_ip) {
        $rowid = DoSingleValueQuery($query . " AND block_expires > NOW()");
        if ($rowid > 0) {
          print "  Blacklisted Relay.  Skipping checks and rejecting the mail.\n";
          goto DELAY_MAIL;
        }
      }
      if ($whitelist_check_relay_ip) {
        $rowid = DoSingleValueQuery($query . " AND block_expires < NOW()");
        if ($rowid > 0) {
          print "  Whitelisted Relay.  Skipping checks and passing the mail.\n";
          goto PASS_MAIL;
        }
      }
      # Remove the last octet for the next test
      $tstr =~ s/\A(.*)\.\d+\Z/$1/;
    }
  }

  # - See if this recipient is wildcard whitelisted, and bypass checks if so
  if ($whitelist_check_recipient) {
    my $query = "SELECT id FROM relaytofrom "
      .         "  WHERE record_expires > NOW() "
      .         "    AND relay_ip  = '' "
      .         "    AND mail_from = '' "
      .         "    AND rcpt_to   = " . $dbh->quote($rcpt_to)
      .         "    AND block_expires <= NOW() ";
    $rowid = DoSingleValueQuery($query);
    if ($rowid > 0) {
      print "  Whitelisted Recipient.  Skipping checks and passing the mail.\n";
      goto PASS_MAIL;
    }
  }

  # - See if this sender is wildcard whitelisted, and bypass checks if so
  if ($whitelist_check_sender) {
    my $query = "SELECT id FROM relaytofrom "
      .         "  WHERE record_expires > NOW() "
      .         "    AND relay_ip  = '' "
      .         "    AND mail_from = " . $dbh->quote($mail_from)
      .         "    AND rcpt_to   = '' "
      .         "    AND block_expires <= NOW() ";
    $rowid = DoSingleValueQuery($query);
    if ($rowid > 0) {
      print "  Whitelisted Sender.  Skipping checks and passing the mail.\n";
      goto PASS_MAIL;
    }
  }

  # - See if the sender domain is wildcard whitelisted, and bypass checks if so (only if address contains a domain part)
  if ($whitelist_check_sender_domain) {
    my $tstr = $rcpt_to;
    if ($tstr =~ s/(@.*)\Z/$1/) {
      my $query = "SELECT id FROM relaytofrom "
        .         "  WHERE record_expires > NOW() "
        .         "    AND relay_ip  = '' "
        .         "    AND mail_from = '' "
        .         "    AND rcpt_to   = " . $dbh->quote($tstr)
        .         "    AND block_expires < NOW() ";
      $rowid = DoSingleValueQuery($query);
      if ($rowid > 0) {
        print "  Whitelisted Sender Domain.  Skipping checks and passing the mail.\n";
        goto PASS_MAIL;
      }
    }
  }

  # Check to see if we already know this [ip,from,to] set
  my $query = "SELECT id FROM relaytofrom "
    .         "  WHERE record_expires > NOW() "
    .         "    AND relay_ip  = " . $dbh->quote($relay_ip)
    .         "    AND mail_from = " . $dbh->quote($mail_from)
    .         "    AND rcpt_to   = " . $dbh->quote($rcpt_to);
  $rowid = DoSingleValueQuery($query);
  if ($rowid > 0) {
    # see if the block expiration of this entry has passed
    if (DoSingleValueQuery("SELECT NOW() > block_expires FROM relaytofrom WHERE id = $rowid")) {
      # has expired, so pass the mail
      print "  Email is known and block has expired.  Passing the mail.\n";
      goto PASS_MAIL;
    }
    else {
      # the email is known, but the block has not expired.  So return a tempfail.
      print "  Email is known but block has not expired.  Issuing a tempfail.\n";
      goto DELAY_MAIL;
    }
  }
  else {
    # This is a new and unknown email, so create a tracking record, but make sure we don't create duplicates
    DoStatement("LOCK TABLE relaytofrom WRITE");
    # we haven't reset $query, so we can reuse it (since it is exactly the same)
    $rowid = DoSingleValueQuery($query);
    if ($rowid > 0) {
      # A record already exists, which is unexpected at this point.  unlock tables and give a temp failure
      DoStatement("UNLOCK TABLE");
      print "  Error: Row already exists while attempting to insert.  Issuing a tempfail.\n";
      goto DELAY_MAIL;
    }

    # Ok, we've verified the row doesn't already exist, so insert one
    my $sth = $dbh->prepare("INSERT INTO relaytofrom "
      . "        (id,relay_ip,mail_from,rcpt_to,block_expires                           ,record_expires                                ,blocked_count,passed_count,origin_type,create_time) "
      . " VALUES ( 0,       ?,        ?,      ?,NOW() + INTERVAL $delay_mail_secs SECOND,NOW() + INTERVAL $auto_record_life_secs SECOND,            1,           0,     'AUTO',      NOW())");
    # insert the row
    $sth->execute($relay_ip, $mail_from, $rcpt_to) or die "Can't Execute: $sth->errstr";
    my $rc = $sth->finish;
    # And release the table lock
    DoStatement("UNLOCK TABLE");

    print "  New mail row successfully inserted.  Issuing a tempfail.\n";
    # and now jump to normal blocking actions
    goto DELAY_MAIL;
  }


  #KILL_MAIL:
  DELAY_MAIL:
  # Increment the blocked count (if rowid is defined)
  DoStatement("UPDATE relaytofrom SET blocked_count = blocked_count + 1 WHERE id = $rowid") if (defined $rowid);
  # FIXME - And do mail logging

  # Set the reply code to a unique message (for debugging)
  $ctx->setreply("451", "4.7.1", "Please try again later (TEMPFAIL)");
  # Issue a temporary failure for this message.  Connection may or may not continue.
  return SMFIS_TEMPFAIL;


  PASS_MAIL:
  # Do database bookkeeping (if rowid is defined)
  if (defined $rowid) {
    # Increment the passed count
    DoStatement("UPDATE relaytofrom SET passed_count = passed_count + 1 WHERE id = $rowid");

    # A special update to end the life of this record, if the sender is the null sender
    #   (Spammers send from this a lot, and it should only be used for bounces.  This
    #   Makes sure that only one (or a couple, small race) of these gets by per delay.
    if (DoSingleValueQuery("SELECT origin_type = 'AUTO' FROM relaytofrom WHERE id = $rowid")) {
      if ($mail_from eq "<>") {
        #print "  Mail is from NULL sender.  Updating it to end its life.\n";
        DoStatement("UPDATE relaytofrom SET record_expires = NOW() WHERE id = $rowid");
      }
      # If this record was automatic, then update the lifetime (if configured that way)
      elsif ($update_record_life) {
        DoStatement("UPDATE relaytofrom SET record_expires = NOW() + INTERVAL $update_record_life_secs SECOND WHERE id = $rowid");
      }
    }
  }
  # FIXME - And do mail logging
 
  # And indicate the message should be passed.
  return SMFIS_CONTINUE;
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
  eval `cat $config_file`;
  #do $config_file;
  if ($@ ne '') { die "Error in config file $config_file: $@" }

  $config_loaded = 1;
}




my %my_callbacks =
(
#	'connect' =>	\&connect_callback,
#	'helo' =>	\&helo_callback,
	'envfrom' =>	\&envfrom_callback,
	'envrcpt' =>	\&envrcpt_callback,
#	'header' =>	\&header_callback,
#	'eoh' =>	\&eoh_callback,
#	'body' =>	\&body_callback,
#	'eom' =>	\&eom_callback,
	'abort' =>	\&abort_callback,
#	'close' =>	\&close_callback,
);

BEGIN:
{
  if (scalar(@ARGV) < 2) {
    print "Usage: perl $0 <name_of_filter> <path_to_sendmail.cf>\n";
    exit;
  }

  my $conn = Sendmail::Milter::auto_getconn($ARGV[0], $ARGV[1]);

  print "Found connection info for '$ARGV[0]': $conn\n";

  if ($conn =~ /^local:(.+)$/) {
    my $unix_socket = $1;

    if (-e $unix_socket) {
      print "Attempting to unlink UNIX socket '$conn' ... ";

      if (unlink($unix_socket) == 0) {
        print "failed.\n";
        exit;
      }
      print "successful.\n";
    }
  }

  if (not Sendmail::Milter::auto_setconn($ARGV[0], $ARGV[1])) {
    print "Failed to detect connection information.\n";
    exit;
  }

  # Make sure there are no errors in the config file before we start
  load_config();

  # Make sure we can connect to the database 
  my $dbh = db_connect(1);
  die "$DBI::errstr\n" unless($dbh);
  # and disconnect again, since the callbacks won't have access to the handle
  db_disconnect();

  #
  #  The flags parameter is optional. SMFI_CURR_ACTS sets all of the
  #  current version's filtering capabilities.
  #
  #  %Sendmail::Milter::DEFAULT_CALLBACKS is provided for you in getting
  #  up to speed quickly. I highly recommend creating a callback table
  #  of your own with only the callbacks that you need.
  #

  if (not Sendmail::Milter::register($ARGV[0], \%my_callbacks, SMFI_CURR_ACTS)) {
    print "Failed to register callbacks for $ARGV[0].\n";
    exit;
  }

  print "Starting Sendmail::Milter $Sendmail::Milter::VERSION engine.\n";

  if (Sendmail::Milter::main()) {
    print "Successful exit from the Sendmail::Milter engine.\n";
  }
  else {
    print "Unsuccessful exit from the Sendmail::Milter engine.\n";
  }
}

