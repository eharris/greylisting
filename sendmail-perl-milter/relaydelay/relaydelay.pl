#!/usr/bin/perl -w

##############################################################################
#
# File: relaydelay.pl
#
# Version: 0.04
# 
# Programmer: Evan J. Harris <eharris@puremagic.com>
#
# Description:
#   Sendmail::Milter interface for active blocking of spam using the 
#   Greylisting method.  Also incorporates some additional checks and 
#   methods for better blocking spam.
#
# References:
#   For Greylisting info, see http://projects.puremagic.com/greylisting/
#   For SMTP info, see RFC821, RFC1891, RFC1893
#
# Notes:
#   - Probably should store the mail_from and rcpt_to fields in the db in 
#     reversed character order.  This would make reporting on subdomain 
#     matches be able to be indexed.
#
# Bugs:
#   None known.
#
#
# *** Copyright 2003 by Evan J. Harris --- All Rights Reserved ***
# *** No warranties expressed or implied, use at your own risk ***
#
##############################################################################

use Sendmail::Milter;
use Socket;
use POSIX qw(strftime);
use Errno qw(ENOENT);

use DBI;

use strict;

#############################################################################
# Our global settings file, may be overridden if passed as a command line
#   parameter to the main relaydelay.pl script.
#############################################################################
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

# Set this to indicate the milter "name" that this milter will be 
#   identified by.  This must match the first parameter from the 
#   INPUT_MAIL_FILTER definition in the sendmail.mc configuration.
my $milter_filter_name = 'relaydelay';

# This parameter determines how the milter interfaces with the libmilter
#   API.  Normally, if using a milter on the same machine that is running
#   sendmail, it will be something like 'local:/var/run/relaydelay.sock', 
#   but if you want to run the milter on a different machine than is running 
#   sendmail, you will need to specify how to connect to that copy of 
#   sendmail by setting this to indicate the machine and port that the 
#   remote sendmail is listening for connections on with something 
#   similar to 'inet:2526@sendmail.server.org'.
# This parameter must match the S= option in the INPUT_MAIL_FILTER
#   definition in the sendmail.mc file.
my $milter_socket_connection = 'local:/var/run/relaydelay.sock';

# Where the pid file should be stored for relaydelay
my $relaydelay_pid_file = '/var/run/relaydelay.pid';

# Set this to something nonzero to limit the number of children that the 
#   milter will spawn.  Since children are never recycled (there seems 
#   to be a problem doing that with Sendmail::Milter), threads,
#   once created, will exist until the milter is shutdown.  Each thread
#   also consumes a database connection, so limiting db connections and
#   memory footprint are both good reasons to set this.
# If your mail server handles a large amount of mail, you may need to 
#   increase this limit to avoid blocking, but the default limit is
#   already pretty high, and should be sufficient for all but very 
#   large sites.
# Setting to zero makes the number of threads unlimited.
my $maximum_milter_threads = 40;

# This determines how many seconds we will block inbound mail that is
#   from a previously unknown [ip,from,to] triplet.  If it is set to
#   zero, incoming mail associations will be learned, but no deliveries
#   will be tempfailed.  Use a setting of zero with caution, as it
#   will learn spammers as well as legitimate senders.
#   If it is set to a negative number (like -1), then the mail will
#   be tempfailed the first time it is seen, but accepted thereafter.
my $delay_mail_secs = 58 * 60;  # 58 Minutes

# This determines how many seconds of life are given to a record that is
#   created from a new mail [ip,from,to] triplet.  Note that the window
#   created by this setting for passing mails is reduced by the amount
#   set for $delay_mail_secs.
# NOTE: See Also: update_record_life and update_record_life_secs.
my $auto_record_life_secs = 5 * 3600;  # 5 hours

# True if we should update the life of a record when passing a mail
#   This should generally be enabled, unless the normal lifetime
#   defined by $auto_record_life_secs is already a large value.
my $update_record_life = 1;

# How much life (in secs) to give to a record we are updating from an
#   allowed (passed) email.  Only useful if update_record_life is
#   enabled.
# The default is 36 days, which should be enough to handle messages that
#   may only be sent once a month, or on things like the first Monday
#   of the month (which sometimes means 5 weeks).  Plus, we add a day
#   for a delivery buffer.
my $update_record_life_secs = 36 * 24 * 3600;

# If you have very large amounts of traffic and want to reduce the number of 
#   queries the db has to handle (and don't need these features), then these
#   wildcard checks can be disabled.  Just set them to 0 if so.
# If both are enabled, relay_ip is considered to take precedence, and is 
#   checked first.  A match there will ignore the rcpt checks.
my $check_wildcard_relay_ip = 1;
my $check_wildcard_rcpt_to = 1;

# Set this to a nonzero value if you want to wait until after the DATA
#   phase before issuing the TEMPFAIL for delayed messages.  If this
#   is undefined or zero, then messages will be failed after the RCPT
#   phase in the smtp session.  Setting this will cause more traffic,
#   which should be unneccessary, but increases the fault tolerance for
#   some braindead mailers that don't check the status codes except at
#   the end of a message transaction.  It does expose a couple of 
#   liabilities, in that the blocking will only occur if the LAST recipient
#   in a multi-recipient message is currently blocked.  If the last
#   recipient is not blocked, the message will go through, even if some
#   recipients are supposed to be blocked.  Generally discouraged.
my $tempfail_messages_after_data_phase = 0;

# Set this to a nonzero value if you wish to do triplet lookups disregarding
#   the last octet of the relay ip.  This helps workaround the case of
#   more than one delivering MTA being used to deliver a particular email.
#   Practically all setups that are that way have the pool of delivering
#   MTA's on the same /24 subnet, so that's what we use.
my $do_relay_lookup_by_subnet = 1;

# Set this to 0 if you wish to disable the automatic maintenance of the
#   relay_ip -> relay_name reference table.  Could save an insert 
#   and an update, depending on circumstances.
my $enable_relay_name_updates = 1;

# Enable this to do some rudimentary syntax checking on the passed mail_from
#   address.  This may exclude some valid addresses, so we leave it as an
#   option that can be disabled.
my $check_envelope_address_format = 1;

# Set this to true if you wish to disable checking and just pass
#   mail when the db connection fails.  Otherwise, we will reject
#   all the mail with a tempfail if we are unable to check the 
#   status for it in the db.
# If you are pretty good about keeping your system well maintained, then it is
#   recommended to leave this disabled.  But if it's possible that the db may go
#   down without anyone noticing for a significant amount of time, then this
#   should probably be enabled.
my $pass_mail_when_db_unavail = 0;

# Set this to true if you want to try to track locally originated mail
#   so that replies are not delayed.  This adds a couple queries to the
#   db overhead for each local mail processed, so use with caution.
#   Also considers mail sent from whitelisted IP's and authenticated
#   senders as local in case we are acting as a smarthost for them.
my $reverse_mail_tracking = 1;
  
# This controls the lifetime of the automatic reverse whitelisting of
#   senders that we have seen locally originated mail sent to.  Only 
#   used if $reverse_mail_tracking is enabled.
my $reverse_mail_life_secs = 4 * 24 * 3600;  # 4 Days


#############################################################
# End of options for use in external config file
#############################################################


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


#############################################################################
#
# Milter Callback Functions:
#
#  Each of these callbacks is actually called with a first argument
#  that is blessed into the pseudo-package Sendmail::Milter::Context. You can
#  use them like object methods of package Sendmail::Milter::Context.
#
#  $ctx is a blessed reference of package Sendmail::Milter::Context to something
#  yucky, but the Mail Filter API routines are available as object methods
#  (sans the smfi_ prefix) from this
#
#############################################################################

# I wasn't going to originally have a envfrom callback, but since the envelope
# sender doesn't seem to be available through other methods, I use this to
# save it so we can get it later.  We also make sure the config file is loaded.

sub envfrom_callback
{
  my $ctx = shift;
  my @args = @_;

  my $mail_from = $args[0];

  if ($check_envelope_address_format) {
    # Get the mailer type
    my $mail_mailer = $ctx->getsymval("{mail_mailer}");
    
    # Only do format checks if the inbound mailer is an smtp variant.
    if ($mail_mailer !~ /smtp\Z/i) {
      # we aren't using an smtp-like mailer, so bypass checks
      #print "Envelope From: Mail delivery is not using an smtp-like mailer.  Skipping checks.\n" if ($verbose);
    }
    else {
      # Check the envelope sender address, and make sure is well-formed.
      #   If is invalid, then issue a permanent failure telling why.
      # NOTE: Some of these tests may exclude valid addresses, but I've only seen spammers
      #   use the ones specifically disallowed here, and they sure don't look valid.  But,
      #   since the SMTP specs do not strictly define what is allowed in an address, I
      #   had to guess by what "looked" normal, or possible.
      my $tstr = $args[0];
      if ($tstr =~ /\A<(.*)>\Z/) {  # Remove outer angle brackets
        $tstr = $1;
        # Note: angle brackets are not required, as some legitimate things seem to not use them
      }
      # Check for embedded whitespace
      if ($tstr =~ /[\s]/) {
        $ctx->setreply("501", "5.1.7", "Malformed envelope from address: contains whitespace");
        return SMFIS_REJECT;
      }
      # Check for embedded brackets, parens, quotes, slashes, pipes (doublequotes are used at yahoo)
      if ($tstr =~ /[<>\[\]\{\}\(\)'"`\/\\\|]/) {
        $ctx->setreply("501", "5.1.7", "Malformed envelope from address: invalid punctuation characters");
        return SMFIS_REJECT;
      }
      # Any chars outside of the range of 33 to 126 decimal (we check as every char being within that range)
      #   Note that we do not require any chars to be in the string, this allows the null sender
      if ($tstr !~ /\A[!-~]*\Z/) {
        $ctx->setreply("501", "5.1.7", "Malformed envelope from address: contains invalid characters");
        return SMFIS_REJECT;
      }
      # FIXME there may be others, but can't find docs on what characters are permitted in an address

      # Now validate parts of sender address (but only if it's not the null sender)
      if ($tstr ne "") {
        my ($from_acct, $from_domain) = split("@", $tstr, 2);
        if ($from_acct eq "") {
          $ctx->setreply("501", "5.1.7", "Malformed envelope from address: user part empty");
          return SMFIS_REJECT;
        }
        if ($from_domain eq "") {
          $ctx->setreply("501", "5.1.7", "Malformed envelope from address: domain part empty");
          return SMFIS_REJECT;
        }
        if ($from_domain =~ /@/) {
          $ctx->setreply("501", "5.1.7", "Malformed envelope from address: too many at signs");
          return SMFIS_REJECT;
        }
        # make sure the domain part is well-formed.
        #if ($from_domain !~ /\A[\w\-]+\.([\w\-]+\.)*[0-9a-zA-Z]+\Z/) {  # Use this to require 2 domain parts
        if ($from_domain !~ /\A([\w\-]+\.)*[\w\-]+\Z/) {
          $ctx->setreply("501", "5.1.7", "Malformed envelope from address: domain part invalid");
          return SMFIS_REJECT;
        }
      }
    }
  }

  # Save our private data (since it isn't available in the same form later)
  #   The format is a comma seperated list of rowids (or zero if none),
  #     followed by the envelope sender followed by the current envelope
  #     recipient (or empty string if none) seperated by nulls
  #   I would have really rather used a hash or other data structure, 
  #     but when I tried it, Sendmail::Milter seemed to choke on it
  #     and would eventually segfault.  So went back to using a scalar.
  my $privdata = "0\x00$mail_from\x00";
  $ctx->setpriv(\$privdata);

  return SMFIS_CONTINUE;
}


# The eom callback is called after a message has been successfully passed.
# It is also the only callback where we can change the headers or body.
# NOTE: It is only called once for a message, even if that message
#   had multiple recipients.  We have to handle updating the row for each
#   recipient here, and it takes a bit of trickery.
# NOTE: We will always get either an abort or an eom callback for any
#   particular message, but never both.

sub eom_callback
{
  my $ctx = shift;

  # Get our status and check to see if we need to do anything else
  my $privdata_ref = $ctx->getpriv();
  # Clear our private data on this context
  $ctx->setpriv(undef);

  print "  IN EOM CALLBACK - PrivData: " . ${$privdata_ref} . "\n" if ($verbose);

  my $dbh = db_connect(0) or goto DB_FAILURE;

  # parse and store the data
  my $rowids;
  my $mail_from;
  my $rcpt_to;

  # save the useful data
  if (${$privdata_ref} =~ /\A([\d,]+)\x00(.*)\x00(.*)\Z/) {
    $rowids = $1;
    $mail_from = $2;
    $rcpt_to = $3;
  }
  
  # If and only if this message should be delayed, but for some reason couldn't be done 
  #   at the rcpt_to stage, then do it here.  (This happens in cases where the 
  #   delivery attempt looks like it is a SMTP callback, which needs to wait for
  #   after the DATA phase to issue the tempfail)
  #   (We use a special rowid value of 00 to indicate a needed block)
  if ($rowids eq "00") {
    # Set the reply code to the normal default, but with a modified text part.
    #   I added the (TEMPFAIL) so it is easy to tell in the syslogs if the failure was due to
    #     the processing of the milter, or if it was due to other causes within sendmail
    #     or from the milter being inaccessible/timing out.
    $ctx->setreply("451", "4.7.1", "Please try again later (TEMPFAIL)");
    
    # Issue a temporary failure for this message.  Connection may or may not continue
    #   with delivering other mails.
    return SMFIS_TEMPFAIL;
  }

  # Only if we have some rowids, do we update the count of passed messages
  if ($rowids > 0) {
    # split up the rowids and update each in turn
    my @rowids = split(",", $rowids);
    foreach my $rowid (@rowids) {
      $dbh->do("UPDATE relaytofrom SET passed_count = passed_count + 1 WHERE id = $rowid") or goto DB_FAILURE;
      print "  * Mail successfully processed.  Incremented passed count on rowid $rowid.\n" if ($verbose);

      # If configured to do so, then update the lifetime (only on AUTO records)
      #   If this was from the null-sender, don't update, as have already expired the record, and don't want to reset.
      if ($update_record_life and $mail_from ne "<>") {
        # This is done here rather than the rcpt callback since we don't know until now that
        #   the delivery is completely successful (not spam blocked or nonexistant user, or 
        #   other failure out of our control)
        $dbh->do("UPDATE relaytofrom SET record_expires = NOW() + INTERVAL $update_record_life_secs SECOND "
          . " WHERE id = $rowid AND origin_type = 'AUTO'") or goto DB_FAILURE;
      }
    }
  }

  # Add a header to the message (if desired)
  #if (not $ctx->addheader("X-RelayDelay", "By kinison")) { print "  * Error adding header!\n"; }

  # And we handled everything successfully, so continue
  return SMFIS_CONTINUE;

  DB_FAILURE:
  # Had a DB error.  Handle as configured.
  print "ERROR: Database Call Failed!\n  $DBI::errstr\n";
  db_disconnect();  # Disconnect, so will get a new connect next mail attempt
  return SMFIS_CONTINUE if ($pass_mail_when_db_unavail);
  return SMFIS_TEMPFAIL;
}


# The abort callback is called even if the message is rejected, even if we
#   are the one that rejected it.  So we ignore it unless we were passing
#   the message and need to increment the aborted count to know something
#   other than this milter caused it to fail.
# However, there is an additional gotcha.  The abort callback may be called
#   before we have a RCPT TO.  In that case, we also ignore it, since we
#   haven't yet done anything in the database regarding the message.
# NOTE: It is only called once for a message, even if that message
#   had multiple recipients.  We have to handle updating the row for each
#   recipient here, and it takes a bit of trickery.
sub abort_callback
{
  my $ctx = shift;

  # Get our status and check to see if we need to do anything else
  my $privdata_ref = $ctx->getpriv();
  # Clear our private data on this context
  $ctx->setpriv(undef);

  print "  IN ABORT CALLBACK - PrivData: " . ${$privdata_ref} . "\n" if ($verbose);

  # parse and store the data
  my $rowids;
  my $mail_from;
  my $rcpt_to;

  # save the useful data
  if (${$privdata_ref} =~ /\A([\d,]+)\x00(.*)\x00(.*)\Z/) {
    $rowids = $1;
    $mail_from = $2;
    $rcpt_to = $3;
  }
  
  # only increment the aborted_count if have some rowids 
  #   (this means we didn't expect/cause an abort, but something else did)
  if ($rowids > 0) {
    # Ok, we need to update the db, so get a handle
    my $dbh = db_connect(0) or goto DB_FAILURE;
  
    # split up the rowids and update each in turn
    my @rowids = split(",", $rowids);
    foreach my $rowid (@rowids) {
      $dbh->do("UPDATE relaytofrom SET aborted_count = aborted_count + 1 WHERE id = $rowid") or goto DB_FAILURE;
      print "  * Mail was aborted.  Incrementing aborted count on rowid $rowid.\n" if ($verbose);

      # Check for the special case of no passed messages, means this is probably a 
      #   spammer, and we should expire the record so they have to go through the
      #   whitelisting process again the next time they try.  BUT ONLY IF THIS
      #   IS AN AUTO RECORD.
      # If we find that it is such a record, update the expire time to now
      my $rows = $dbh->do("UPDATE relaytofrom SET record_expires = NOW() "
        . " WHERE id = $rowid AND origin_type = 'AUTO' AND passed_count = 0") or goto DB_FAILURE;
      if ($rows > 0) {
        print "  * Mail record had no successful deliveries.  Expired record on rowid $rowid.\n" if ($verbose);
      }
    }
  }

  return SMFIS_CONTINUE;

  DB_FAILURE:
  # Had a DB error.  Handle as configured.
  print "ERROR: Database Call Failed!\n  $DBI::errstr\n";
  db_disconnect();  # Disconnect, so will get a new connect next mail attempt
  return SMFIS_CONTINUE if ($pass_mail_when_db_unavail);
  return SMFIS_TEMPFAIL;
}


# This function is called in all the instances when we want to create a reverse
#   whitelist entry for recipients of oubound mail so they will not be delayed
#   when they reply.  This is where we do the necessary checks and create
#   the record.
# If there already exists only one active record of the right type, but where 
#   the block has not yet expired, then we update it so the block expires 
#   immediately.  This is so internal people can force mail to come through by 
#   sending a mail to the sender.  It would be nice if we could update all
#   matching rows, but that is too prone to abuse by spammers who may know
#   posting patterns from mailing lists and such.
# Since we have no way of knowing if another different type of record may allow
#   the return mail to pass, sometimes the reverse record we create isn't 
#   necessary, but they'll age off fairly quickly.
# If any sql calls fail, we either ignore them or simply return, since these 
#   updates aren't critical to the mail handling process.
sub reverse_track($$$)
{
  my $dbh = shift;
  my $mail_from = shift;
  my $rcpt_to = shift;

  my $query = "SELECT id FROM relaytofrom WHERE record_expires > NOW() AND mail_from = ? AND rcpt_to = ?";
  my $sth = $dbh->prepare($query) or return;
  # Note the reversed from and to fields! 
  $sth->execute($rcpt_to, $mail_from) or return;
  my $rowid = $sth->fetchrow_array();
  my $nextrowid = $sth->fetchrow_array();
  $sth->finish();

  if (defined($rowid) and !defined($nextrowid)) {
    # There's only one matching row, so if it's auto, and not already unblocked, unblock it.
    my $rows = $dbh->do("UPDATE relaytofrom SET block_expires = NOW() "
      . " WHERE block_expires > NOW() AND origin_type = 'AUTO' AND id = $rowid");
    print "  Reverse tracking row updated to unblock.  rowid: $rowid\n" if ($verbose and $rows > 0);
  }
  return if (defined($rowid));

  # If got here, then need to create a reverse record
  $sth = $dbh->prepare("INSERT INTO relaytofrom "
    . " (relay_ip,mail_from,rcpt_to,block_expires,record_expires,origin_type,create_time) "
    . " VALUES (NULL,?,?,NOW(),NOW() + INTERVAL $reverse_mail_life_secs SECOND,'AUTO',NOW())");
  # Note the reversed from and to fields! 
  $sth->execute($rcpt_to, $mail_from);
  $sth->finish;
  if ($verbose) {
    # Get the rowid for the debugging message
    $rowid = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    print "  Reverse tracking row successfully inserted for the recipient of this mail.  rowid: $rowid\n";
  }
}


# Here we perform the bulk of the work, since here we have individual recipient
#   information, and can act on it.

sub envrcpt_callback
{
  my $ctx = shift;
  my @args = @_;

  # Get the time in seconds
  my $timestamp = time();

  # Get the hostname (needs a module that is not necessarily installed)
  #   Not used (since I don't want to depend on it)
  #my $hostname = hostname();

  print strftime("\n=== %Y-%m-%d %H:%M:%S ===\n", localtime($timestamp)) if ($verbose);

  # declare our info vars
  my $rowid;
  my $rowids;
  my $mail_from;

  # Get the stored envelope sender and rowids
  my $privdata_ref = $ctx->getpriv();
  my $rcpt_to = $args[0];

  # save the useful data
  if (${$privdata_ref} =~ /\A([\d,]+)\x00(.*)\x00(.*)\Z/) {
    $rowids = $1;
    $mail_from = $2;
  }
  if (! defined $rowids) {
    print "ERROR: Invalid privdata in envrcpt callback!\n";
    print "  PRIVDATA: " . ${$privdata_ref} . "\n";
  }
  
  print "Stored Sender: $mail_from\n" if ($verbose);
  print "Passed Recipient: $rcpt_to\n" if ($verbose);

  # Get the database handle (after got the privdata)
  my $dbh = db_connect(0) or goto DB_FAILURE;
  
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
  my $relay_name_reversed = reverse($relay_name);
        
  # Collect the rest of the info for our checks
  my $mail_mailer = $ctx->getsymval("{mail_mailer}");
  my $sender      = $ctx->getsymval("{mail_addr}");
  my $rcpt_mailer = $ctx->getsymval("{rcpt_mailer}");
  my $recipient   = $ctx->getsymval("{rcpt_addr}");
  my $queue_id    = $ctx->getsymval("{i}");
  my $authen      = $ctx->getsymval("{auth_authen}");
  my $authtype    = $ctx->getsymval("{auth_type}");
  my $ifaddr      = $ctx->getsymval("{if_addr}");

  print "  Relay: $tmp - If_Addr: $ifaddr\n" if ($verbose);
  print "  RelayIP: $relay_ip - RelayName: $relay_name - RelayIdent: $relay_ident - PossiblyForged: $relay_maybe_forged\n" if ($verbose);
  print "  From: $sender - To: $recipient\n" if ($verbose);
  print "  InMailer: $mail_mailer - OutMailer: $rcpt_mailer - QueueID: $queue_id\n" if ($verbose);

  # Only do our processing if the inbound mailer is an smtp variant.
  #   A lot of spam is sent with the null sender address <>.  Sendmail reports 
  #   that and other "local looking" from addresses as using the local mailer, 
  #   even though they are coming from off-site.  So we have to exclude the 
  #   "local" mailer from the checks since it lies.
  if (($mail_mailer !~ /smtp\Z/i) and ($mail_mailer !~ /\Alocal\Z/i)) {
    # we aren't using an smtp-like mailer, so bypass checks
    print "  Mail delivery is not using an smtp-like mailer.  Skipping checks.\n" if ($verbose);
    reverse_track($dbh, $mail_from, $rcpt_to) if ($reverse_mail_tracking and $rcpt_mailer !~ /\Alocal\Z/i);
    goto PASS_MAIL;
  }

  # Check to see if the mail is looped back on a local interface and skip checks if so
  if ($ifaddr eq $relay_ip) {
    print "  Mail delivery is sent from a local interface.  Skipping checks.\n" if ($verbose);
    reverse_track($dbh, $mail_from, $rcpt_to) if ($reverse_mail_tracking and $rcpt_mailer !~ /\Alocal\Z/i);
    goto PASS_MAIL;
  }

  # Only do our processing if the mail client is not authenticated in some way
  if (defined($authen) and $authen ne "")
  {
    print "  AuthType: $authtype - Credentials: $authen\n" if ($verbose);
    print "  Mail delivery is authenticated.  Skipping checks.\n" if ($verbose);
    reverse_track($dbh, $mail_from, $rcpt_to) if ($reverse_mail_tracking and $rcpt_mailer !~ /\Alocal\Z/i);
    goto PASS_MAIL;
  }


  # Check for local IP relay whitelisting from the sendmail access file
  # FIXME - needs to be implemented
  #

  # Check wildcard black or whitelisting based on ip address or subnet
  #   Do the check in such a way that more exact matches are returned first
  if ($check_wildcard_relay_ip) {
    my $tstr = $relay_ip;
    my $subquery;
    for (my $loop = 0; $loop < 4; $loop++) {
      $subquery .= " OR " if (defined($subquery));
      $subquery .= "relay_ip = " . $dbh->quote($tstr);
      $tstr =~ s/\A(.*)\.\d+\Z/$1/;  # strip off the last octet
    }
    my $query = "SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom "
      .         "  WHERE record_expires > NOW() "
      .         "    AND mail_from IS NULL "
      .         "    AND rcpt_to   IS NULL "
      .         "    AND ($subquery) "
      .         "  ORDER BY length(relay_ip) DESC";

    my $sth = $dbh->prepare($query) or goto DB_FAILURE;
    $sth->execute() or goto DB_FAILURE;
    ($rowid, my $blacklisted, my $whitelisted) = $sth->fetchrow_array();
    goto DB_FAILURE if ($sth->err);
    $sth->finish();

    if (defined $rowid) {
      if ($blacklisted) {
        print "  Blacklisted Relay.  Skipping checks and rejecting the mail.\n" if ($verbose);
        goto DELAY_MAIL;
      }
      if ($whitelisted) {
        print "  Whitelisted Relay.  Skipping checks and passing the mail.\n" if ($verbose);
        reverse_track($dbh, $mail_from, $rcpt_to) if ($reverse_mail_tracking and $rcpt_mailer !~ /\Alocal\Z/i);
        goto PASS_MAIL;
      }
    }
  }

  # Pull out the domain of the recipient for whitelisting checks
  my $tstr = $rcpt_to;
  if ($tstr =~ /\A<(.*)>\Z/) {  # Remove outer angle brackets if present
    $tstr = $1;
  }
  $tstr =~ /@([^@]*)\Z/;  # strip off everything before and including the last @
  my $rcpt_domain = $1;

  # See if this recipient (or domain/subdomain) is wildcard white/blacklisted
  #   Do the check in such a way that more exact matches are returned first
  if ($check_wildcard_rcpt_to) {
    my $subquery = "rcpt_to = " . $dbh->quote($rcpt_to);
    my $tstr = $rcpt_domain;
    while(index($tstr, ".") > 0) {
      $subquery .= " OR rcpt_to = " . $dbh->quote($tstr);
      $tstr =~ s/\A[^.]*\.(.*)\Z/$1/;  # strip off the leftmost domain part
    }
    my $query = "SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom "
      .         "  WHERE record_expires > NOW() "
      .         "    AND relay_ip  IS NULL "
      .         "    AND mail_from IS NULL "
      .         "    AND ($subquery) "
      .         "  ORDER BY length(rcpt_to) DESC";

    my $sth = $dbh->prepare($query) or goto DB_FAILURE;
    $sth->execute() or goto DB_FAILURE;
    ($rowid, my $blacklisted, my $whitelisted) = $sth->fetchrow_array();
    goto DB_FAILURE if ($sth->err);
    $sth->finish();

    if (defined $rowid) {
      if ($blacklisted) {
        print "  Blacklisted Recipient.  Skipping checks and rejecting the mail.\n" if ($verbose);
        goto DELAY_MAIL;
      }
      if ($whitelisted) {
        print "  Whitelisted Recipient.  Skipping checks and passing the mail.\n" if ($verbose);
        goto PASS_MAIL;
      }
    }
  }

  # Store and maintain the dns_name of the relay if we have one
  #   Not strictly necessary, but useful for reporting/troubleshooting
  if ($enable_relay_name_updates and length($relay_name_reversed) > 0) {
    my $rows = $dbh->do("INSERT IGNORE INTO dns_name (relay_ip,relay_name) VALUES ('$relay_ip'," 
      . $dbh->quote($relay_name_reversed) . ")");
    goto DB_FAILURE if (!defined($rows));
    if ($rows != 1) {
      # Row already exists, so make sure the name is updated
      my $rows = $dbh->do("UPDATE dns_name SET relay_name = " . $dbh->quote($relay_name_reversed)
        . " WHERE relay_ip = '$relay_ip'");
      goto DB_FAILURE if (!defined($rows));
    }
  }

  # Check to see if we already know this triplet set, and if the initial block is expired
  my $query = "SELECT id, NOW() > block_expires, origin_type, relay_ip FROM relaytofrom "
    .         "  WHERE record_expires > NOW() "
    .         "    AND mail_from = " . $dbh->quote($mail_from)
    .         "    AND rcpt_to   = " . $dbh->quote($rcpt_to);
  if ($do_relay_lookup_by_subnet) {
    # Remove the last octet for a /24 subnet, and add the .% for use in a like clause
    my $tstr = $relay_ip;
    $tstr =~ s/\A(.*)\.\d+\Z/$1.%/;
    $query .= "    AND (relay_ip LIKE " . $dbh->quote($tstr);
  }
  else {
    # Otherwise, use the relay_ip as an exact match
    $query .= "    AND (relay_ip = " . $dbh->quote($relay_ip);
  }
  # Changed to order by relay_ip being null, as this will return more specific records (matching IP) before ones with 
  #   relay_ip being null.
  # Changed to suborder by id, as this will make the query deterministic as far as which row is returned when there are 
  #   dupes.  We try to avoid dupes, but they are still theoretically possible.
  $query .= " OR relay_ip IS NULL) ORDER BY relay_ip IS NULL, id";

  my $sth = $dbh->prepare($query) or goto DB_FAILURE;
  $sth->execute() or goto DB_FAILURE;
  ($rowid, my $block_expired, my $origin_type, my $recorded_relay_ip) = $sth->fetchrow_array();
  goto DB_FAILURE if ($sth->err);
  $sth->finish();

  if (defined $rowid) {
    if ($block_expired) {
      print "  Email is known and block has expired.  Passing the mail.  rowid: $rowid\n" if ($verbose);
      # If this record is a reverse tracking record with unknown IP, then 
      #   update it to include the now-known IP (if tracking is enabled)
      if ($reverse_mail_tracking and !defined($recorded_relay_ip) and $origin_type eq "AUTO") {
        print "  Updating reverse tracking row with the source IP address.\n" if ($verbose);
        $dbh->do("UPDATE relaytofrom SET relay_ip = " . $dbh->quote($relay_ip) 
          . " WHERE id = $rowid AND relay_ip IS NULL");
        # This is a non-critical update, so don't bother checking if updated any rows
      }
      goto PASS_MAIL;
    }
    else {
      # the email is known, but the block has not expired.  So return a tempfail.
      print "  Email is known but block has not expired.  Issuing a tempfail.  rowid: $rowid\n" if ($verbose);
      goto DELAY_MAIL;
    }
  }

  # If got here, then this is a new and unknown triplet, so create a tracking record
  # There is a tiny race condition here that may allow two exactly concurrent mail deliveries with the exact
  #   same triplet info to two seperate MX hosts to create duplicate rows.  The real chances this will happen 
  #   are EXTREMELY small, but we still account for the possibility by doing row ordering on the query above.

  $sth = $dbh->prepare("INSERT INTO relaytofrom "
    . "        (relay_ip,mail_from,rcpt_to,block_expires,record_expires,origin_type,create_time) "
    . " VALUES (?,?,?,NOW() + INTERVAL $delay_mail_secs SECOND,NOW() + INTERVAL $auto_record_life_secs SECOND, "
    . "   'AUTO', NOW())") or goto DB_FAILURE;
  $sth->execute($relay_ip, $mail_from, $rcpt_to) or goto DB_FAILURE;
  $sth->finish;

  # Get the rowid of the row we just inserted (used later for updating)
  $rowid = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    
  if ($delay_mail_secs == 0) {
    print "  New mail row successfully inserted.  Passing mail.  rowid: $rowid\n" if ($verbose);
    # and now jump to normal blocking actions
    goto PASS_MAIL;
  }

  print "  New mail row successfully inserted.  Issuing a tempfail.  rowid: $rowid\n" if ($verbose);
  # and now jump to normal blocking actions
  goto DELAY_MAIL;


  ###########################################################################
  #
  # Here we have the goto tags for finishing the mail processing
  #
  ###########################################################################

  # Predeclare privdata, since many of these gotos use it
  my $privdata;

  DELAY_MAIL:
  # Increment the blocked count (if rowid is defined)
  if (defined $rowid) {
    $dbh->do("UPDATE relaytofrom SET blocked_count = blocked_count + 1 WHERE id = $rowid") or goto DB_FAILURE;
  }

  # FIXME - Should do mail logging?
  
  # Special handling for the null sender.  Spammers use the null sender a ton, but so do things like Exim's callback 
  #   sender verification spam checks.  If the sender is likely to be an SMTP callback, we don't want to block the 
  #   mail attempt now, but will instead block it at the eom phase.
  # UPDATE: Postfix appears to use <postmaster@some.domain> instead of the null sender for it's SMTP callbacks, 
  #   so added that as another workaround check.
  if ($mail_from eq "<>" or $mail_from =~ /\A<postmaster@/i or $tempfail_messages_after_data_phase) {
    print "  Delaying tempfail reject until eom phase.\n" if ($verbose);
  
    # save that this message needs to be blocked later in the transaction (after eom)
    $privdata = "00\x00$mail_from\x00$rcpt_to";
    # Save the changes to our privdata for the next callback
    $ctx->setpriv(\$privdata);
    
    # and let the message continue processing, since will be blocked at eom if it isn't aborted before that
    return SMFIS_CONTINUE;
  }
  
  # Save our privdata for the next callback (don't add this rowid, since have already handled it)
  $ctx->setpriv($privdata_ref);

  # Set the reply code to a unique message (for debugging) - this dsn is what is normally the default
  $ctx->setreply("451", "4.7.1", "Please try again later (TEMPFAIL)");
  # Instead, we use a better code, 450 and 4.3.2 per RFC 821 and 1893, saying the system 
  #   isn't currently accepting network messages
  # Disabled again.  For some reason, this causes aol to retry deliveries over and over with no delay.
  #   So much for giving a more informative x.x.x code.
  #$ctx->setreply("450", "4.3.2", "Please try again later (TEMPFAIL)");
 
  # Issue a temporary failure for this message.  Connection may or may not continue.
  return SMFIS_TEMPFAIL;


  BOUNCE_MAIL:
  # We don't use this anywhere yet, but may in future...
  # set privdata so later callbacks won't have problems
  $privdata = "0";
  $ctx->setpriv(\$privdata);
  # Indicate the message should be aborted (want a custom error code?)
  return SMFIS_REJECT;


  PASS_MAIL:
  # Do database bookkeeping (if rowid is defined)
  if (defined $rowid) {
    # We don't increment the passed count here because the mail may still be rejected
    #   for some reason at the sendmail level.  So we do it in the eom callback instead.

    # Here we do a special update to end the life of this record, if the sender is the null sender
    #   (Spammers send from this a lot, and it should only be used for bounces.  This
    #   Makes sure that only one (or a couple, small race) of these gets by per delay.
    if ($mail_from eq "<>") {
      # Only update the lifetime of records if they are AUTO, wouldn't want to do wildcard records
      my $rows = $dbh->do("UPDATE relaytofrom SET record_expires = NOW() "
        . " WHERE id = $rowid AND origin_type = 'AUTO'") or goto DB_FAILURE;
      print "  Mail is from null-sender.  Updated it to end its life.\n" if ($verbose and $rows > 0);
    }

    # Since we have a rowid, then set the context data to indicate we successfully 
    #   handled this message as a pass, and that we don't expect an abort without 
    #   needing further processing.  We have to keep the rcpt_to on there, since this 
    #   callback may be called several times for a specific message if it has multiple 
    #   recipients, and we need it for logging.
    # The format of the privdata is one or more rowids seperated by commas, followed by 
    #   a null, and the envelope from.
    if ($rowids > 0) {
       $rowids .= ",$rowid";
    } else {
      $rowids = $rowid;  
    }
  }
  # Save our privdata for the next callback
  $privdata = "$rowids\x00$mail_from\x00$rcpt_to";
  $ctx->setpriv(\$privdata);

  # FIXME - Should do mail logging?
 
  # And indicate the message should continue processing.
  return SMFIS_CONTINUE;


  DB_FAILURE:
  # Had a DB error.  Handle as configured.
  print "ERROR: Database Call Failed!\n  $DBI::errstr\n";
  db_disconnect();  # Disconnect, so will get a new connect next mail attempt
  # set privdata so later callbacks won't have problems (or if db comes back while still in this mail session)
  $privdata = "0\x00$mail_from\x00";
  $ctx->setpriv(\$privdata);
  return SMFIS_CONTINUE if ($pass_mail_when_db_unavail);
  return SMFIS_TEMPFAIL;
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
	'eom' =>	\&eom_callback,
	'abort' =>	\&abort_callback,
#	'close' =>	\&close_callback,
);

BEGIN:
{
  if (scalar(@ARGV) > 1) {
    print "Usage: perl $0 [config_file]\n\n"
      . "Please refer to documentation regarding changes to the configuration file\n"
      . "  where options that used to be specified on the command line are now\n"
      . "  set in the configuration file.\n"
      . "As an option, the path to the config file may be specified on the command line\n"
      . "  (to avoid modifying the filter script).\n";
    exit;
  }

  # If the config file was specified on the command line, use it
  if (defined($ARGV[0])) {
    $config_file = $ARGV[0];
  }

  # Make sure there are no errors in the config file before we start, and load the socket info
  load_config();

  # Record pid to file
  if (defined $relaydelay_pid_file) {
    open(PIDF, ">$relaydelay_pid_file") ||
      die "Unable to record PID to '$relaydelay_pid_file': $!\n";
    print PIDF "$$\n";
    close PIDF;
  }

  print "Using connection '$milter_socket_connection' for filter $milter_filter_name\n";

  if ($milter_socket_connection =~ /^local:(.+)$/i) {
    my $unix_socket = $1;

    if (-e $unix_socket) {
      print "Attempting to unlink local UNIX socket '$unix_socket' ... ";

      if (unlink($unix_socket) == 0) {
        print "failed.\n";
        exit;
      }
      print "successful.\n";
    }
  }

  if (not Sendmail::Milter::setconn("$milter_socket_connection")) {
    print "Failed to set up connection: $?\n";
    exit;
  }

  # Make sure we can connect to the database 
  my $dbh = db_connect(1);
  die "$DBI::errstr\n" unless($dbh);
  # and disconnect again, since the callbacks won't have access to the handle
  db_disconnect();

  #
  #  The flags parameter is optional. SMFI_CURR_ACTS sets all of the
  #  current version's filtering capabilities.
  #

  if (not Sendmail::Milter::register("$milter_filter_name", \%my_callbacks, SMFI_CURR_ACTS)) {
    print "Failed to register callbacks for $milter_filter_name.\n";
    exit;
  }

  print "Starting Sendmail::Milter $Sendmail::Milter::VERSION engine.\n";

  # Parameters to main are max num of interpreters, num requests to service before recycling threads
  # We don't set it to recycle children, as that seems to cause coredumps.
  if (Sendmail::Milter::main($maximum_milter_threads, 0)) {
    print "Successful exit from the Sendmail::Milter engine.\n";
  }
  else {
    print "Unsuccessful exit from the Sendmail::Milter engine.\n";
  }
}


# Make sure when threads are recycled that we release the global db connection
END {
  print "Closing DB connection.\n";
  db_disconnect();
}


