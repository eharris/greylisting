/* -#- Mode: C; c-basic-indent: 4; indent-tabs-mode: nil; -#- */
/* vim: set expandtab shiftwidth=4 softabstop=4 tabstop=8 */

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
#include <regex.h>
#include <pthread.h>
#include <stdarg.h>
#include <db.h>   /* berkeley db package */
#include "mysql.h"
#include <time.h>

int   verbose          = 1;
char *database_type    = "mysql";
char *database_name    = "relaydelay";
char *database_host    = "localhost";
int   database_port    = 3306;
char *database_user    = "milter";
char *database_pass    = "password";
char *config_file_name = "/etc/mail/relaydelay.conf";

#define BUFSIZE          4096
#define SAFESIZ          4095
#define MAX_QUERY_TRIES  1

/*
# This determines how many seconds of life are given to a record that is
#   created from a new mail [ip,from,to] triplet.  Note that the window
#   created by this setting for passing mails is reduced by the amount
#   set for $delay_mail_secs.
# NOTE: See Also: update_record_life and update_record_life_secs.
*/

int  auto_record_life_secs = 4 * 3600;  /* # 4 hours */

/*
# True if we should update the life of a record when passing a mail
#   This should generally be enabled, unless the normal lifetime
#   defined by $auto_record_life_secs is already a large value.
*/
int update_record_life = 1;

/*
# How much life (in secs) to give to a record we are updating from an
#   allowed (passed) email.  Only useful if update_record_life is
#   enabled.
# The default is 36 days, which should be enough to handle messages that
#   may only be sent once a month, or on things like the first Monday
#   of the month (which sometimes means 5 weeks).  Plus, we add a day
#   for a delivery buffer. */

int update_record_life_secs = 36 * 24 * 3600;

/*
# If you have very large amounts of traffic and want to reduce the number of
#   queries the db has to handle (and don't need these features), then these
#   wildcard checks can be disabled.  Just set them to 0 if so.
# If both are enabled, relay_ip is considered to take precedence, and is
#   checked first.  A match there will ignore the rcpt checks.
*/
int  check_wildcard_relay_ip = 1;
int  check_wildcard_rcpt_to  = 1;
int  check_wildcard_mail_from = 1;
/*
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
*/
int  tempfail_messages_after_data_phase = 0;

/*
# Set this to a nonzero value if you wish to do triplet lookups disregarding
#   the last octet of the relay ip.  This helps workaround the case of
#   more than one delivering MTA being used to deliver a particular email.
#   Practically all setups that are that way have the pool of delivering
#   MTA's on the same /24 subnet, so that's what we use.
*/
int do_relay_lookup_by_subnet = 0;

/*
# Set this to 0 if you wish to disable the automatic maintenance of the
#   relay_ip -> relay_name reference table.  Could save an insert
#   and an update, depending on circumstances.
*/
int enable_relay_name_updates = 1;

/*
# Enable this to do some rudimentary syntax checking on the passed mail_from
#   address.  This may exclude some valid addresses, so we leave it as an
#   option that can be disabled.
*/
int check_envelope_address_format = 1;

/*
# Set this to true if you wish to disable checking and just pass
#   mail when the db connection fails.  Otherwise, we will reject
#   all the mail with a tempfail if we are unable to check the
#   status for it in the db.
# If you are pretty good about keeping your system well maintained, then it is
#   recommended to leave this disabled.  But if it's possible that the db may go
#   down without anyone noticing for a significant amount of time, then this
#   should probably be enabled.
*/
int pass_mail_when_db_unavail = 0;

/* NEW---------------
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
   # for IP connections: 	"inet:9876@localhost" may work nicely!!!
*/

char *milter_socket_connection = "local:/var/run/relaydelay.sock";

/*
  # This config option specifies where sendmail's access.db file is located.  
  #   If you don't want the milter to check the access.db, just set this equal 
  #   to undef.
  # If enabled, the access db will be checked to see if there are matching
  #   ip or address entries that should make us bypass the greylist checks.
  # NOTE: These checks assume that the sendmail FEATURE(`relay_hosts_only') 
  #   is not enabled.  If you do have that enabled, the checks in the milter
  #   will be more permissive than you want.
  #   In addition, the milter will heed entries in the access db even if
  #   your sendmail configuration doesn't check certain types, so make sure
  #   you don't have any entries that sendmail will ignore unless you want 
  #   to suffer the consequences.
  #   For more information on access db options, see:
  #     http://www.sendmail.org/~ca/email/doc8.12/cf/m4/anti_spam.html
  #   For additional information, please also see the README file.
  #
  #char *sendmail_accessdb_file = 0;
*/
char *sendmail_accessdb_file = "/etc/mail/access.db";

/* # Where the pid file should be stored for relaydelay */
char *relaydelay_pid_file = "/var/run/relaydelay.pid";

/* # Set this to something nonzero to limit the number of children that the 
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
*/
int maximum_milter_threads = 40;

/*# This determines how many seconds we will block inbound mail that is
  #   from a previously unknown [ip,from,to] triplet.  If it is set to
  #   zero, incoming mail associations will be learned, but no deliveries
  #   will be tempfailed.  Use a setting of zero with caution, as it
  #   will learn spammers as well as legitimate senders.
  #   If it is set to a negative number (like -1), then the mail will
  #   be tempfailed the first time it is seen, but accepted thereafter.
*/

int delay_mail_secs = 58 * 60;  /* # 58 Minutes */

/*
  # Set this to true if you want to try to track locally originated mail
  #   so that replies are not delayed.  This adds a couple queries to the
  #   db overhead for each local mail processed, so use with caution.
  #   Also considers mail sent from whitelisted IPs and authenticated
  #   senders as local in case we are acting as a smarthost for them. 
*/
int reverse_mail_tracking = 1;

/*
  # This controls the lifetime of the automatic reverse whitelisting of
  #   senders that we have seen locally originated mail sent to.  Only 
  #   used if $reverse_mail_tracking is enabled.
*/
int reverse_mail_life_secs = 4 * 24 * 3600;  /*  4 Days */


/* ========================================================================== */
void writelog(int level, char *msg, ...) /* Brad provided this */
{
    va_list ap;
	
	if( verbose >= level )
	{
		/* print the TIME. This is getting more desirable! */
		struct tm *timestrp;
		time_t now = time(0);
		timestrp = localtime(&now);
		printf("%02d/%02d/%02d %02d:%02d:%02d ", 
			   timestrp->tm_year-100 /* good until 2100...*/, 
			   timestrp->tm_mon+1, timestrp->tm_mday,  /* months are in range 0 to 11 */
			   timestrp->tm_hour, timestrp->tm_min, timestrp->tm_sec);
		
        va_start(ap, msg);
        vprintf(msg, ap);
        va_end(ap);

		fflush(stdout);
	}
}

/* ========================== FOR THE ACCESS DB QUERIES ================ */

#ifdef DB_VERSION_MAJOR
DB *dbp; 
DBT key, data;

int access_query(char *lookforkey, char *hopingforvalue)
{
	char valbuf[200];
	int ret;
	
	key.data = lookforkey;
	key.size = strlen(key.data);
	key.ulen = key.size+1;
	valbuf[0]= 0;
	data.ulen=200;
	data.data = valbuf;
	data.size = 0;
	data.flags = DB_DBT_USERMEM;
	key.flags = DB_DBT_USERMEM;
	
	writelog(2,"About to check ACCESS DB for %s --", key.data);
	if ((ret = dbp->get(dbp, NULL, &key, &data, 0)) == 0)
	{
		valbuf[data.size] = 0;
		writelog(2,"FOUND: %s\n", data.data);
		if( strncmp(data.data,hopingforvalue,data.size) == 0 )
		{
			return 1;
		}
	} 
	else 
		writelog(2,"NOPE. ret= %d\n",ret);
	return 0;
}

void print_access_contents(void)
{
	DBC *cursor;
	int ret;
	char valbuf[200];
	char keybuf[200];
	
	key.data = keybuf;
	key.size = 0;
	key.ulen = 200;
	valbuf[0]= 0;
	keybuf[0]= 0;
	data.ulen=200;
	data.size = 0;
	data.data = valbuf;
	data.flags = DB_DBT_USERMEM;
	key.flags = DB_DBT_USERMEM;
	
	ret = dbp->cursor(dbp, NULL, &cursor, 0);
	if( ret != 0 )
		writelog(2,"CURSOR func failed with %d\n", ret);
	while( (ret=cursor->c_get(cursor,&key,&data,DB_NEXT)) == 0 )
	{
		keybuf[key.size] = 0;
		valbuf[data.size] = 0;
		writelog(2,"  accessdb  key=%s      val= %s\n", key.data, data.data);
	}
	writelog(2,"Cursor get loop broken with return value %d\n", ret);
	cursor->c_close(cursor);
}


#endif



/* ############################################################# */
MYSQL global_dbh;
int mysql_connected = 0;

int load_config(void)
{
	extern FILE *relaydelay_in;

	writelog(1,"Parsing %s...\n", config_file_name);
	
	relaydelay_in = fopen( config_file_name, "r");
	if( relaydelay_in == NULL)
	{
		printf("Error opening config file: %s\n", config_file_name);
		return 1;
	}

	relaydelay_parse();
	fclose(relaydelay_in);

	if( verbose )
	{
		printf("Finished Loading Config File\n");
		printf("After config file read:\n");
		printf("  database_port = %d\n", database_port);
		printf("  verbose = %d\n", verbose);
		printf("  delay_mail_secs = %d\n", delay_mail_secs);
		printf("  auto_record_life_secs = %d\n", auto_record_life_secs);
		printf("  update_record_life = %d\n", update_record_life);
		printf("  update_record_life_secs = %d\n", update_record_life_secs);
		printf("  check_wildcard_relay_ip = %d\n", check_wildcard_relay_ip);
		printf("  check_wildcard_rcpt_to = %d\n", check_wildcard_rcpt_to);
		printf("  check_wildcard_mail_from = %d\n", check_wildcard_mail_from);
		printf("  tempfail_messages_after_data_phase = %d\n", tempfail_messages_after_data_phase);
		printf("  do_relay_lookup_by_subnet = %d\n", do_relay_lookup_by_subnet);
		printf("  enable_relay_name_updates = %d\n", do_relay_lookup_by_subnet);
		printf("  check_envelope_address_format = %d\n", enable_relay_name_updates);
		printf("  pass_mail_when_db_unavail = %d\n", pass_mail_when_db_unavail);
		printf("  database_type = %s\n", database_type);
		printf("  database_name = %s\n", database_name);
		printf("  database_host = %s\n", database_host);
		printf("  database_user = %s\n", database_user);
		printf("  database_pass = %s\n", database_pass);
		printf("  milter_socket_connection = %s\n", milter_socket_connection);
		printf("  sendmail_accessdb_file = %s\n", sendmail_accessdb_file);
		printf("  relaydelay_pid_file = %s\n", relaydelay_pid_file);
		printf("  maximum_milter_threads = %d\n", maximum_milter_threads);
		printf("  reverse_mail_tracking = %d\n", reverse_mail_tracking);
		printf("  reverse_mail_life_secs = %d (%g hrs)\n\n", reverse_mail_life_secs, (double)(reverse_mail_life_secs)/3600.0);
		fflush(stdout);
	}
	return 0;
}


/*
#######################################################################
# Database functions
#######################################################################
*/

void db_connect(void)
{
	if( !mysql_connected )
    {
		mysql_init(&global_dbh);
		if( mysql_real_connect(
			&global_dbh,
			database_host,
			database_user,
			database_pass,
			database_name,
			database_port,
			0, 0))
		{
			mysql_connected = 1;
		}
		else
		{
			writelog(1,"Failed to connect to database: Error: %s\n",
				mysql_error(&global_dbh));

			/* the init will have allocated memory */
			mysql_close(&global_dbh);
		}
	}
}

void db_disconnect(void)
{
	mysql_close(&global_dbh);
	mysql_connected = 0;
}

int db_query(char *commandbuf, MYSQL_RES **result)
{
	static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
	int res;
	int try_count = 0;

	writelog(2,"   About to issue query: %s\n", commandbuf);
	

	writelog(2,"   Mutex Locking...\n");

	pthread_mutex_lock(&mut);
	
	writelog(2,"   Mutex Locked...\n");

	*result = NULL;
	do
	{
		db_connect();
		if( (res = mysql_query(&global_dbh, commandbuf)) == 0 )
		{
			writelog(2,"   Control returns from query:\n");

			if( mysql_field_count(&global_dbh) )
				*result = mysql_store_result(&global_dbh);

			writelog(2,"   Control returns from store_result:\n");
		}
		else
		{
			writelog(1,"ERROR: Database Call Failed: %s\n", mysql_error(&global_dbh));
			writelog(1,"=====  query was: %s\n", commandbuf);
			db_disconnect();
			++try_count;
		}
	}
	while (try_count < MAX_QUERY_TRIES && res );

	if (try_count >= MAX_QUERY_TRIES)
		writelog(1,"ERROR: Gave up trying to communicate with mysql.\n");

	writelog(2,"   Mutex UnLocking...\n");
	pthread_mutex_unlock(&mut);
	writelog(2,"   Mutex UnLocked...\n");

	return res;
}


/*

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

*/
int do_regex(char *pattern,
	     char *string,
	     regex_t *preg,
	     regmatch_t pmatch[10],
	     int match_message)
{
	int errcode;
	errcode = regcomp(preg, pattern, REG_EXTENDED);
	if( errcode )
	{
		if( verbose )
		{
			char errbuf[1024];
			regerror(errcode, preg, errbuf, 1024);
			writelog(1,"Had trouble compiling regex %s (%s)!\n",
			       pattern, errbuf);
		}
		return 1;
	}

	errcode = regexec(preg, string, 10, pmatch, 0);
	if( errcode )
	{
		if( verbose && (errcode == REG_NOMATCH || !match_message) )
		{
			char errbuf[1024];
			regerror(errcode, preg, errbuf, 1024);
			writelog(1,"Had trouble execing regex %s on string %s (%s)!\n",
			       pattern, string, errbuf);
		}
		return 1;
	}

	return 0;
}

/*
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
*/

void reverse_track(char *mail_from, char *rcpt_to)
{
	char query[BUFSIZE];
	char rcpt_to_copy[BUFSIZE];
	MYSQL_RES *result;
	MYSQL_ROW row1,row2;
	char row_id[32];
	
	if( rcpt_to[0] == '<' && rcpt_to[strlen(rcpt_to)-1] == '>' ) /* wasn't thinking clearly. Should have removed the <> from rcpt_to long ago! */
	{
		strcpy(rcpt_to_copy, rcpt_to+1);
		rcpt_to_copy[strlen(rcpt_to_copy)-1] = 0;
	}
	else
		strcpy(rcpt_to_copy, rcpt_to);
	
	sprintf(query,"SELECT id FROM relaytofrom WHERE record_expires > NOW() AND mail_from = '%s' AND rcpt_to = '<%s>'",
			rcpt_to_copy, mail_from);
	/* note the reversed from and to fields */
	
	if( db_query(query, &result) )
		return;
	
	if( !result )
	{
		writelog(1,"  reverse_track store_result(1) returned NULL\n");
		return;
	}

	row1 = mysql_fetch_row(result);
	writelog(2,"   fetch_row returns %x\n", row1);
	
	if( row1 && row1[0] && strlen(row1[0]) > 0 )
	{
		row2 = mysql_fetch_row(result);
		writelog(2,"   fetch_row returns %x\n", row2);
		if( !row2 || !row2[0] )
		{
			strncpy(row_id, row1[0], sizeof(row_id));
			
			/* # There's only one matching row, so if it's auto, and not already unblocked, unblock it. */
			sprintf(query, "UPDATE relaytofrom SET block_expires = NOW() \
                             WHERE block_expires > NOW() AND origin_type = 'AUTO' AND id = %s", row_id);
			
			writelog(1,"  Reverse tracking row updated to unblock.  rowid: %s\n",row_id);
		}
		return;
	}
	/* # If got here, then need to create a reverse record */
	sprintf(query,"INSERT INTO relaytofrom \
                   (relay_ip,mail_from,rcpt_to,block_expires,record_expires,origin_type,create_time) \
                    VALUES (NULL,'%s','<%s>',NOW(),NOW() + INTERVAL %d SECOND,'AUTO',NOW())",
			rcpt_to_copy, mail_from, reverse_mail_life_secs);
	/* Note again, the reversed from and to fields!  */
	if( db_query(query, &result) )
		return;
	
	if (verbose)
	{
		/* # Get the rowid for the debugging message */
		if( db_query("SELECT LAST_INSERT_ID()", &result) )
			return;
		if( !result )
		{
			writelog(1,"  reverse_track store_result(3) returned NULL\n");
			return;
		}
		row1 = mysql_fetch_row(result);
		writelog(2,"   fetch_row returns %x\n", row1);
		
		if( row1 && row1[0] && strlen(row1[0]) > 0 )
		{
			strncpy(row_id, row1[0], sizeof(row_id));
			writelog(1,"  Reverse tracking row successfully inserted for the recipient (%s) of this mail.  rowid: %s\n", rcpt_to_copy,row_id);
		}
	}
}

sfsistat envfrom_callback(SMFICTX *ctx, char **argv)
{
	char *mail_from = argv[0];
	char mail_from_buf[BUFSIZE];
	char *privdata, buf[BUFSIZE];

	writelog(2,"envfrom Callback:\n");

	if( check_envelope_address_format )
	{
		char *mail_mailer = smfi_getsymval(ctx, "{mail_mailer}");

		writelog(2,"   mail_mailer: %s\n", mail_mailer);

		if( strlen(mail_from) > 254 )
		{
			smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: Way, way, way too long. Buffer Overflow Exploit Attempt?");
			return SMFIS_REJECT;
		}
		
		strncpy(mail_from_buf, mail_from, SAFESIZ);
		mail_from_buf[SAFESIZ] = 0;

		if( !strstr(mail_mailer, "smtp") )
		{
			/* we aren't using an smtp-like mailer, so bypass checks
			 * SMM: I see stuff like "local" from MS Outlook, etc
			 * AND: I see some spammers using "local" also...
			 */
		}
		else
		{
			/*
			 * Check the envelope sender address, and make sure is
			 * well-formed. If is invalid, then issue a permanent
			 * failure telling why.
			 *
			 * NOTE: Some of these tests may exclude valid
			 *   addresses, but I've only seen spammers use the
			 *   ones specifically disallowed here, and they sure
			 *   don't look valid.  But, since the SMTP specs do
			 *   not strictly define what is allowed in an address,
			 *   I had to guess by what "looked" normal, or
			 *   possible.
			 */
			regex_t preg;
			regmatch_t pmatch[10];
			char mail_from_buf2[BUFSIZE], *at, *p1;
			int errcode;
			
			writelog(2,"   mail_from: %s\n", mail_from);
			if( do_regex("^<(.*)>$", mail_from, &preg, pmatch, 0) == 0 )
			{
				if( pmatch[1].rm_so != -1 && pmatch[1].rm_eo != -1 )
				{
					strncpy(mail_from_buf, mail_from+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
					mail_from_buf[pmatch[1].rm_eo-pmatch[1].rm_so] = 0;
					mail_from = mail_from_buf;
				}
				regfree(&preg);
			}
			if( strpbrk(mail_from, " \t\n\r\f") )
			{
				smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: contains whitespace");
				return SMFIS_REJECT;
			}
			/* Check for embedded brackets, parens, quotes,
			 * slashes, pipes (doublequotes are used at yahoo) */
			if( strpbrk(mail_from, "<>[]{}()'\"`/\\|") )
			{
				smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: invalid punctuation characters");
				return SMFIS_REJECT;
			}
			p1 = mail_from;
			while( *p1 )
			{
				if( *p1 < 33 || *p1 > 126 )
				{
					smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: contains invalid characters");
					return SMFIS_REJECT;
				}
				p1++;
			}
			/* FIXME there may be others, but can't find docs on what characters are permitted in an address */
			if( strlen(mail_from) > 0 )
			{
				char *from_acct, *from_domain;
				strncpy(mail_from_buf2, mail_from, SAFESIZ);
				mail_from_buf2[SAFESIZ] = 0;

				at = strchr(mail_from_buf2,'@');
				if( at )
				{
					*at = 0;
					from_acct = mail_from_buf2;
					from_domain = at+1;
					if( strlen(from_acct)==0 )
					{
						smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: user part empty");
						return SMFIS_REJECT;
					}
					if( strlen(from_domain)==0 )
					{
						smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: domain part empty");
						return SMFIS_REJECT;
					}
					if( strchr(from_domain,'@') )
					{
						smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: too many at signs");
						return SMFIS_REJECT;
					}
					if( do_regex("^([-a-zA-Z_0-9]+\\.)*[-a-zA-Z_0-9]+$", from_domain, &preg, pmatch,0) == 0 )
					{
						if( pmatch[0].rm_so == -1 || pmatch[0].rm_eo == -1 )
						{
							smfi_setreply(ctx, "501", "5.1.7", "Malformed envelope from address: domain part invalid");
							return SMFIS_REJECT;
						}
					}
				}
			}
		}
	}
	/*
	  # Save our private data (since it isn't available in the same form later)
	  #   The format is a comma seperated list of rowids (or zero if none),
	  #     followed by the envelope sender followed by the current envelope
	  #     recipient (or empty string if none) seperated by nulls
	  #   I would have really rather used a hash or other data structure,
	  #     but when I tried it, Sendmail::Milter seemed to choke on it
	  #     and would eventually segfault.  So went back to using a scalar.
	*/
	privdata = (char*)malloc(strlen(mail_from)+5);
	sprintf(privdata,"0\t%s\t", mail_from);
  	smfi_setpriv(ctx, privdata);

  	return SMFIS_CONTINUE;
}


/*
# The eom callback is called after a message has been successfully passed.
# It is also the only callback where we can change the headers or body.
# NOTE: It is only called once for a message, even if that message
#   had multiple recipients.  We have to handle updating the row for each
#   recipient here, and it takes a bit of trickery.
# NOTE: We will always get either an abort or an eom callback for any
#   particular message, but never both.
*/

int split(char sep, char *str, char ***array)
{
	int cnt;
	char *p, *p1;
	char *buf;

	if( !str )
		return 0;
	
	buf = strdup(str);

	/* sigh, first count up the number of entries */
	p = buf;
	cnt = 0;
	while( (p1=strchr(p,sep)) )
	{
		p = ++p1;
		cnt++;
	}
	cnt++;
	*array = (char**)malloc(sizeof(char *)*cnt);

	/* re-parse the string to build the actual array */
	cnt = 0;
	(*array)[cnt++] = buf;
	p = buf;
	while( (p1=strchr(p,sep)) )
	{
		*p1 = 0;           /* null terminate the previous string */
		p = ++p1;          /* move to the next string */
		(*array)[cnt++] = p; /* save the start of the string */
	}
	return cnt;
}

void free_split(char **arr)
{
	int i;

	free(arr[0]);
	free(arr);
}


sfsistat eom_callback(SMFICTX *ctx)
{
	/* Get our status and check to see if we need to do anything else */
	char *privdata_ref = smfi_getpriv(ctx);
	char *rowids, *mail_from, *rcpt_to;
	char *t1, *t2, buf1[99000];
	MYSQL_RES *result;
	/* Clear our private data on this context */
	smfi_setpriv(ctx,0);

	writelog(2,"IN EOM CALLBACK - PrivData: %s \n", privdata_ref?privdata_ref:"(nil)");

	buf1[0] = 0;
	if( privdata_ref )
	{
		strcpy(buf1, privdata_ref);
		free(privdata_ref);
		privdata_ref = 0;
	}

	t1 = strchr(buf1,'\t');
	if( t1 )
	{
		t2 = strchr(t1+1,'\t');
		if( t2 )
		{
			*t1 = 0;
			*t2 = 0;
			rowids = buf1;
			mail_from = t1+1;
			rcpt_to = t2+1;
		}
	}
	if( t1 && t2 )
	{
		/*
 		 * If and only if this message is from the null sender, check
		 * to see if we should tempfail it since we can't delay it
		 * after rcpt_to since that breaks SMTP callbacks.  We use a
		 * special rowid value of 00 to indicate a needed block.
		*/
		if( !strcmp(rowids,"00") && (!strcmp(mail_from,"<>") || tempfail_messages_after_data_phase))
		{
			/*
			 * Set the reply code to the normal default, but with
			 * a modified text part. I added the (TEMPFAIL) so it
			 * is easy to tell in the syslogs if the failure was
			 * due to the processing of the milter, or if it was
			 * due to other causes within sendmail or from the
			 * milter being inaccessible/timing out.
			 */
			writelog(1,"EOM: Rowids=%s mail_from=%s\n", rowids, mail_from);
			smfi_setreply(ctx, "451", "4.7.1", "Please try again later (TEMPFAIL)") ;
			return SMFIS_TEMPFAIL;

		}
		writelog(2,"About to check rowids (%s) and split...\n", rowids);
		
		
		if( strlen(rowids) > 0 )
		{
			char **arr;
			int i, cnt = split(',', rowids, &arr);

			writelog(2,"Split returns count (%d)...\n", cnt);

			for( i=0; i<cnt; i++ )
			{
				char commandbuf[8000];

				if( arr[i] == 0 ) /* SMM: 0 is not a valid rowid */
					continue;

				sprintf(commandbuf, "UPDATE relaytofrom SET passed_count = passed_count + 1 WHERE id = %s", arr[i] );
				if( db_query(commandbuf, &result) )
				{
					if( pass_mail_when_db_unavail )
						return SMFIS_CONTINUE;
					return SMFIS_TEMPFAIL;
				}

				writelog(1,"  * Mail successfully processed.  Incremented passed count on rowid %s.\n", arr[i]);


				/*  If configured to do so, then update the lifetime (only on AUTO records) */
				if (update_record_life)
				{
				        /* # This is done here rather than the rcpt callback since we don't know until now that
				        #   the delivery is completely successful (not spam blocked or nonexistant user, or
				        #   other failure out of our control) */
					sprintf(commandbuf,"UPDATE relaytofrom SET record_expires = NOW() + INTERVAL %d SECOND \
WHERE id = %s AND origin_type = 'AUTO'", 
							update_record_life_secs, arr[i]);
					if( db_query(commandbuf, &result) )
					{
						if( pass_mail_when_db_unavail )
							return SMFIS_CONTINUE;
						return SMFIS_TEMPFAIL;
					}
				}
			}
			free_split(arr);
		}
		/* here would be a good place to add the ol' header */

	}
	return SMFIS_CONTINUE;
}


/*
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
*/

sfsistat abort_callback(SMFICTX *ctx)
{
	/* Get our status and check to see if we need to do anything else */
	char *privdata_ref = smfi_getpriv(ctx);
	char *rowids, *mail_from, *rcpt_to;
	char *t1, *t2, buf1[99000];
	char **arr;
	int i, cnt;


	/* Clear our private data on this context */
	smfi_setpriv(ctx,0);

	writelog(2,"IN abort CALLBACK - PrivData: %s \n", privdata_ref);
	buf1[0] = 0;
	if( privdata_ref )
	{
		strcpy(buf1,privdata_ref);
		free(privdata_ref);
		privdata_ref = 0;
	}
	t1 = strchr(buf1,'\t');
	if( !t1 )
		return SMFIS_CONTINUE;

	t2 = strchr(t1+1,'\t');
	if( !t2 )
		return SMFIS_CONTINUE;

	*t1 = 0;
	*t2 = 0;
	rowids = buf1;
	mail_from = t1+1;
	rcpt_to = t2+1;

	if( !strlen(rcpt_to) )
		return SMFIS_CONTINUE;

	if( !strlen(rowids) )
		return SMFIS_CONTINUE;

	cnt = split(',', rowids, &arr);
	
	for( i=0; i<cnt; i++ )
	{
		char commandbuf[8000];
		MYSQL_RES *result;

		if( !strcmp(arr[i],"0") ) /* SMM == skip a zero row id! */
			continue;

		sprintf(commandbuf, "UPDATE relaytofrom SET aborted_count = aborted_count + 1 WHERE id = %s", arr[i] );
		if( db_query(commandbuf, &result) )
		{
			if( pass_mail_when_db_unavail )
				return SMFIS_CONTINUE;
			return SMFIS_TEMPFAIL;
		}
		writelog(1,"  * Mail was aborted.  Incremented aborted count on rowid %s.\n", arr[i]);

		/* # Check for the special case of no passed messages, means this is probably a
#   spammer, and we should expire the record so they have to go through the
#   whitelisting process again the next time they try.  BUT ONLY IF THIS
#   IS AN AUTO RECORD.
# If we find that it is such a record, update the expire time to now */
		sprintf(commandbuf, "UPDATE relaytofrom SET record_expires = NOW() \
WHERE id = %s AND origin_type = 'AUTO' AND passed_count = 0", arr[i] );
		if( db_query(commandbuf, &result) )
		{
			if( pass_mail_when_db_unavail )
				return SMFIS_CONTINUE;
			return SMFIS_TEMPFAIL;
		}

		if( mysql_affected_rows(&global_dbh)  )
			writelog(1,"  * Mail  record had no successful deliveries.  Expired record on rowid %s.\n", arr[i]);

	}

	return SMFIS_CONTINUE;
}

/*
# Here we perform the bulk of the work, since here we have individual recipient
#   information, and can act on it.
*/

sfsistat envrcpt_callback(SMFICTX *ctx, char **argv)
{
	/* Get our status and check to see if we need to do anything else */
	char *privdata_ref = smfi_getpriv(ctx);
	char privdata_copy[BUFSIZE];
	char *privdata1;
	char *rowids, *mail_from, *rcpt_to;
	char *t1, *t2, buf1[BUFSIZE*3],*p7;
	char relay_name_reversed[BUFSIZE];
	char row_id[32],rowids_buf[BUFSIZE];
	int res;
	MYSQL_RES *result;
	MYSQL_ROW row;
	char buf2[BUFSIZE], *p2, buf3[BUFSIZE];
	char *tmp, relay_ip[1000], relay_name[1000], relay_ident[1000], relay_maybe_forged[1000];
	char relay_ip_parts[4][20];
	char relay_name_parts[40][100], rcpt_domain_parts[40][100];
	char *mail_mailer, *sender, *rcpt_mailer, *recipient, *queue_id, *if_addr, *authen, *authtype;
	char *rcpt_to2[BUFSIZE], *tstr;
	char rcpt_domain[BUFSIZE], rcpt_acct[BUFSIZE],*r2;
	char from_domain[BUFSIZE], from_acct[BUFSIZE];
	char query2[BUFSIZE];
	int block_expired = 0,i;
	regex_t preg;
	regmatch_t pmatch[10];
	/* Clear our private data on this context */

	row_id[0] = 0;
	rcpt_to = argv[0];

	if( privdata_ref )
	{
		writelog(2,"Envrcpt callback:   privdata=%s\n", privdata_ref);
		strcpy(buf1, privdata_ref);
		strncpy(privdata_copy, privdata_ref, SAFESIZ);
	}
	else
	{
		writelog(2,"Envrcpt callback:   privdata=NULL\n");
		buf1[0] = 0;
		privdata_copy[0] = 0;
	}
	
	privdata_copy[SAFESIZ] = 0;

	if( privdata_ref )
	{
		free(privdata_ref);
		privdata_ref = 0;
	}

	t1 = strchr(buf1, '\t');
	if( !t1 )
	{
		writelog(1,"Error: Unexpected: No tab in the privdata (%s)!\n",buf1 );
		t2 = 0;
	}
	else
	{
		t2 = strchr(t1+1, '\t');
		if( !t2 )
		{
			writelog(1,"Error: Unexpected: No 2nd tab in the privdata (%s)!\n",buf1 );
		}
	}
	
	if( t1 && t2 )
	{
		*t1 = 0;
		*t2 = 0;
        strcpy(rowids_buf, buf1);
		rowids = rowids_buf;
		mail_from = t1+1;
	}
	else
	{
		rowids_buf[0] = 0;
		rowids = rowids_buf;
		buf1[0] = 0;
		mail_from = buf1;
	}
	

	writelog(2,"Stored Sender: %s\nPassed Recipient: %s\n", mail_from, rcpt_to);

	tmp = smfi_getsymval(ctx,"{_}");
	relay_ip[0] = 0;
	relay_name[0] = 0;
	relay_ident[0] = 0;
	relay_maybe_forged[0] = 0;
	for(i=0;i<4;i++)
		relay_ip_parts[i][0] = 0;
	for(i=0;i<40;i++)
		relay_name_parts[i][0] = 0;
	

	writelog(2,"relay info: %s\n", tmp);

	if( do_regex("^([^ \t\r]*@)?([^ \t\r]*) ?\\[(.*)\\]( \\(may be forged\\))?$", tmp, &preg, pmatch,1) == 0 )
	{
		if( pmatch[0].rm_so == -1 || pmatch[0].rm_eo == -1 )
		{
				writelog(2,"Relay info could not be parsed: %s\n",
						tmp);
		}
		else
		{
			if( pmatch[1].rm_so != -1 )
			{
				strncpy(relay_ident,tmp+pmatch[1].rm_so,pmatch[1].rm_eo-pmatch[1].rm_so);
				relay_ident[pmatch[1].rm_eo-pmatch[1].rm_so] = 0;
				writelog(2,"  Relay Ident: %s\n", relay_ident);
			}
			if( pmatch[2].rm_so != -1 )
			{
				strncpy(relay_name,tmp+pmatch[2].rm_so,pmatch[2].rm_eo-pmatch[2].rm_so);
				relay_name[pmatch[2].rm_eo-pmatch[2].rm_so] = 0;
				writelog(2,"  Relay name: %s\n", relay_name);
			}
			if( pmatch[3].rm_so != -1 )
			{
				strncpy(relay_ip,tmp+pmatch[3].rm_so,pmatch[3].rm_eo-pmatch[3].rm_so);
				relay_ip[pmatch[3].rm_eo-pmatch[3].rm_so] = 0;
				writelog(2,"  Relay IP: %s\n", relay_ip);
			}
			if( pmatch[4].rm_so != -1 )
			{
				strncpy(relay_maybe_forged,tmp+pmatch[4].rm_so,pmatch[4].rm_eo-pmatch[4].rm_so);
				relay_maybe_forged[pmatch[4].rm_eo-pmatch[4].rm_so] = 0;
				writelog(2,"  Relay Forged: %s\n", relay_maybe_forged);
			}
		}
	}
	else
	{
		writelog(1,"do_regex returns non-0: string to match: %s\n", tmp);
	}
	
	mail_mailer = smfi_getsymval(ctx,"{mail_mailer}");
	sender = smfi_getsymval(ctx,"{mail_addr}");
	rcpt_mailer = smfi_getsymval(ctx,"{rcpt_mailer}");
	recipient = smfi_getsymval(ctx,"{rcpt_addr}");
	queue_id = smfi_getsymval(ctx,"{i}");
	authen = smfi_getsymval(ctx,"{auth_authen}");
	authtype = smfi_getsymval(ctx,"{auth_type}");
	if_addr = smfi_getsymval(ctx,"{if_addr}");
	
	strcpy(relay_ip_parts[0], relay_ip);
	strcpy(relay_ip_parts[1], relay_ip);
	
	if( (p7=strrchr(relay_ip_parts[1],'.')) )
	{
		*p7 = 0;
		strcpy(relay_ip_parts[2], relay_ip_parts[1]);
		if( (p7=strrchr(relay_ip_parts[2],'.')) )
		{
			*p7 = 0;
			strcpy(relay_ip_parts[3], relay_ip_parts[2]);
			if( (p7=strrchr(relay_ip_parts[3],'.')) )
			{
				*p7 = 0;
			}
		}
	}
	
	if( relay_name && strlen(relay_name ) && !relay_maybe_forged[0] )
	{
		char *tstr;
		int j=0;
		tstr = relay_name;
		while( (p7 = strchr(tstr,'.')) )
		{
			strcpy(relay_name_parts[j++], tstr);
			tstr = p7+1;
		}
		strcpy(relay_name_parts[j++], tstr);
	}
	/* Pull out the domain of the recipient for whitelisting checks */
	strcpy(buf2,rcpt_to);
	if( buf2[0] == '<' && buf2[strlen(buf2)-1] == '>' )
	{
		strncpy(buf2,rcpt_to+1,strlen(rcpt_to)-2);
		buf2[strlen(rcpt_to)-2] = 0;
	}
	rcpt_acct[0] = 0;
	p2 = strrchr(buf2,'@');
	if( p2 )
	{
		*p2 = 0;
		strcpy(rcpt_acct,buf2);
		strcpy(buf3,p2+1);
		strcpy(buf2,buf3);
		
	}
	strcpy(rcpt_domain,buf2);
	if( strlen(rcpt_domain ) )
	{
		char *tstr;
		int j=0;
		tstr = rcpt_domain;
		while( (p7 = strchr(tstr,'.')) )
		{
			strcpy(rcpt_domain_parts[j++], tstr);
			tstr = p7+1;
		}
		strcpy(rcpt_domain_parts[j++], tstr);
	}
	
	writelog(2,"  From: %s  -  To: %s\n", sender, recipient);
	writelog(2,"  InMailer: %s  -  OutMailer: %s   -  QueueID: %s\n", mail_mailer, rcpt_mailer, queue_id);

	/* Only do our processing if the inbound mailer is an smtp variant.
	   A lot of spam is sent with the null sender address <>.  Sendmail reports
	   that as being from the local mailer, so we have a special case that needs
	   handling (but only if not also from localhost). */
	if( strstr(mail_mailer,"smtp") == NULL && strcmp(mail_mailer,"local") != 0 )
	{
		/* we aren't using an smtp-like mailer, so bypass checks */
		writelog(1,"  Mail delivery is not using an smtp-like mailer (%s). (from=%s)  Skipping checks.\n",
				 mail_mailer, mail_from);
		if( reverse_mail_tracking && strcasecmp(rcpt_mailer,"local") != 0 )
			reverse_track(mail_from, rcpt_to);
		
		goto PASS_MAIL;
	}

        /* Check to see if the mail is looped back on a local interface and skip checks if so */
	if( (if_addr && strcmp(if_addr,relay_ip) == 0) || ( !strcmp(relay_ip,"127.0.0.1") ) )
	{
		/* we are using an smtp-like mailer, and we are a local connection, so bypass checks */
		if( if_addr )
			writelog(1,"  Mail delivery is sent from a local interface (%s=%s)[mailer=%s].  Skipping checks.\n",
					 relay_ip, if_addr, mail_mailer );
		else
			writelog(1,"  Mail delivery is sent from a local interface (%s) (ip=%s).  Skipping checks.\n",
					 mail_mailer, relay_ip);
		goto PASS_MAIL;
	}
	if( authen && authen[0] )
	{
		writelog(1,"  AuthType: %s - Credentials: %s\n", authtype, authen);
		writelog(1,"  Mail delivery is authenticated.  Skipping checks.\n");
		if( reverse_mail_tracking && strcasecmp(rcpt_mailer,"local") != 0 )
			reverse_track(mail_from, rcpt_to);
		goto PASS_MAIL;
	}
	

	/*
	  # Check for local IP relay whitelisting from the sendmail access file
	  #
	  # We bypass the checks if we are acting as a smart host for this client, or if sendmail will not
	  #   accept the mail anyway and we want to let sendmail give the sender an immediate failure.
	  # As strange as it seems, we do not want to bypass the checks if the value is OK or SKIP.
	  # Only do the access.db checks if the var holding the file name has been defined

	  # SMM--- ALSO, NOTE: using 2.7.7 Sleepycat Berk DB, I notice that the key values stored in the db
	  # are all lowercase, no matter what was put in the access file. So, searching for Spam:whatever
	  # will never work. So, I changed the Spam:whatever to spam:whatever, and now I see some success.
	  # Uh, Connect: vs connect, also. If this is bogus for later versions, well, there'll
	  # have to be another revision.... sigh.
	*/
#if defined(DB_VERSION_MAJOR)
	if (sendmail_accessdb_file && strlen(sendmail_accessdb_file)) 
	{
		int bypass_checks = 0;
		char *lhs, *rhs, connectbuf[1000];
		int ret;
		
		/* # First check if this client is a host we should relay for (and therefore also not greylist)
		   #   We check against both Connect: entries and generic entries without a LHS tag.
		*/
		/* lookup relay_ip_parts */
		for(i=0;i<4;i++)
		{
			sprintf(connectbuf,"connect:%s", relay_ip_parts[i]);
			if( access_query(connectbuf, "RELAY") )
			{
				bypass_checks = 1;
				break;
			}
			if( !bypass_checks )
			{
				if( access_query(relay_ip_parts[i], "RELAY") )
				{
					bypass_checks = 1;
					break;
				}
			}
		}
		for(i=0;!bypass_checks && i<40;i++)
		{
			if( relay_name_parts[i][0] == 0 )
				break;
			
			sprintf(connectbuf,"connect:%s", relay_name_parts[i]);
			if( access_query(connectbuf, "RELAY") )
			{
				bypass_checks = 1;
				break;
			}
			if( !bypass_checks )
			{
				
				if( access_query(relay_name_parts[i], "RELAY") )
				{
					bypass_checks = 1;
					break;
				}
			}
		}
		if( bypass_checks )
		{
			writelog(1,"  Whitelisted Relay match (%s/%s) found in ACCESS DB.  Skipping checks and passing the mail.\n",
					 relay_ip,relay_name?relay_name:"(nil)");
		}
		else
		{
			/* # check to see if there is a Spam: FRIEND/HATER entry */
			if( !bypass_checks )
			{
				sprintf(connectbuf,"spam:%s@%s", rcpt_acct,rcpt_domain);
				if( access_query(connectbuf, "FRIEND") )
				{
					bypass_checks = 1;
				}
			}
			if( !bypass_checks )
			{
				sprintf(connectbuf,"spam:%s@", rcpt_acct);
				if( access_query(connectbuf, "FRIEND") )
				{
					bypass_checks = 1;
				}
			}
			for(i=0;!bypass_checks && i<40;i++)
			{
				if( rcpt_domain_parts[i][0] == 0 )
					break;
				
				sprintf(connectbuf,"spam:%s", rcpt_domain_parts[i]);
				if( access_query(connectbuf, "FRIEND") )
				{
					bypass_checks = 1;
					break;
				}
			}
			if( bypass_checks )
			{
				writelog(1,"  Whitelisted Recipient match (%s) found in ACCESS DB.  Skipping checks and passing the mail.\n",
						 rcpt_to);
			}
		}
		/* 
		   # We do not bypass the checks based on from addresses, because if they are blocked, they are handled by 
		   #   sendmail, and if they are RELAY or OK, we would still want to protect the recipients from spam.
		*/ 
		if (bypass_checks) 
		{
			if( reverse_mail_tracking && strcasecmp(rcpt_mailer,"local"))
				reverse_track(mail_from, rcpt_to);
			goto PASS_MAIL;
		}
	}
	
#endif

	/* 
	   # Check wildcard black or whitelisting based on ip address or subnet
	   #   Do the check in such a way that more exact matches are returned first 
	*/
	if( check_wildcard_relay_ip )
	{
		char subquery[BUFSIZE];
		char query[BUFSIZE];
		MYSQL_ROW row;
		int i;

		subquery[0] = 0;
		for(i=0; i<check_wildcard_relay_ip; i++)
		{
			if( subquery[0] )
				strcat(subquery," OR ");
			strcat(subquery,"relay_ip = '");
			strcat(subquery,relay_ip_parts[i]);
			strcat(subquery,"'");
		}
		sprintf(query,"SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom \
WHERE record_expires > NOW()   AND mail_from IS NULL AND rcpt_to   IS NULL AND (%s) ORDER BY length(relay_ip) DESC", 
				subquery);
		if( db_query(query, &result) )
			goto DB_FAILURE;

		if( !result )
		{
			writelog(1,"  store_result returned NULL\n");
			goto DB_FAILURE;
		}

		if( mysql_num_fields(result) != 3 )
		{
			writelog(1,"   Num Fields = %d; hoped for 3\n", mysql_num_fields(result));
			goto DB_FAILURE;
		}

		row = mysql_fetch_row(result);
		writelog(2,"   fetch_row returns %x\n", row);

		if( row && row[0] && strlen(row[0]) > 0 )
		{
			strncpy(row_id, row[0], sizeof(row_id));
			if( atoi(row[1]) )
			{
				writelog(1,"  Blacklisted Relay (%s[%s],%s,%s). Skipping checks and rejecting the mail.\n",relay_name, relay_ip, mail_from, rcpt_to);
				goto BOUNCE_MAIL;
			}
			if( atoi(row[2]) )
			{
				writelog(1,"  Whitelisted Relay (%s[%s],%s,%s). Skipping checks and passing the mail.\n",relay_name, relay_ip, mail_from, rcpt_to);
				if( reverse_mail_tracking && strcasecmp(rcpt_mailer,"local"))
					reverse_track(mail_from, rcpt_to);
				goto PASS_MAIL;
			}
		}
	}

	/* See if this recipient (or domain/subdomain) is wildcard white/blacklisted
	   Do the check in such a way that more exact matches are returned first */
	if( check_wildcard_rcpt_to )
	{
		char *p2,buf3[BUFSIZE];
		char subquery[BUFSIZE];
		char query[BUFSIZE];
		MYSQL_ROW row;
		int i=0;

		writelog(2,"   rcpt_acct=%s, rcpt_domain=%s, rcpt_to=%s \n", rcpt_acct, rcpt_domain, rcpt_to);
		subquery[0] = 0;
		while( i++ < check_wildcard_rcpt_to)
		{
			if( rcpt_domain_parts[i-1][0] == 0 )
				break;
			
			if( subquery[0] )
				strcat(subquery," OR )");
			strcat(subquery,"rcpt_to = '<");

			if( rcpt_acct[0] )
			{
				strcat(subquery,rcpt_acct);
				strcat(subquery,"@");
			}
			strcat(subquery,rcpt_domain_parts[i-1]);
			strcat(subquery,">'");
		}
		sprintf(query,"SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom \
WHERE record_expires > NOW()   AND relay_ip IS NULL AND mail_from   IS NULL AND (%s) ORDER BY length(rcpt_to) DESC", 
				subquery);
		if( db_query(query, &result) )
			goto DB_FAILURE;

		if( !result )
		{
			writelog(1,"   store_result call returned null results!\n");
			goto DB_FAILURE;
		}

		if( mysql_num_fields(result) != 3 )
		{
			writelog(1,"  Num Fields = %d; hoped for 3\n", mysql_num_fields(result));
			goto DB_FAILURE;
		}

		row = mysql_fetch_row(result);
		if( row && row[0] && strlen(row[0]) > 0 )
		{
			strncpy(row_id, row[0], sizeof(row_id));
			if( atoi(row[1]) )
			{
				writelog(1,"  Blacklisted Recpt (%s,%s,%s). Skipping checks and rejecting the mail.\n",relay_ip, mail_from, rcpt_to);
				goto BOUNCE_MAIL;
			}
			if( atoi(row[2]) )
			{
				writelog(1,"  Whitelisted Recpt (%s,%s,%s@%s). Skipping checks and passing the mail.\n", relay_ip, mail_from, rcpt_acct, rcpt_domain);
				goto PASS_MAIL;
			}
		}
	}

	/* Pull out the domain of the sender for whitelisting checks */
	strcpy(buf2,mail_from);
	if( buf2[0] == '<' && buf2[strlen(buf2)-1] == '>' )
	{
		strncpy(buf2,mail_from+1,strlen(mail_from)-2);
		buf2[strlen(mail_from)-2] = 0;
	}
	from_acct[0] = 0;
	p2 = strrchr(buf2,'@');
	if( p2 )
	{
		*p2 = 0;
		strcpy(from_acct,buf2);
		strcpy(buf3,p2+1);
		strcpy(buf2,buf3);
		
	}
	strcpy(from_domain,buf2);
	/* See if this sender (or domain/subdomain) is wildcard white/blacklisted
	   Do the check in such a way that more exact matches are returned first */
	if( check_wildcard_mail_from )
	{
		char *p2,buf3[BUFSIZE];
		char subquery[BUFSIZE];
		char query[BUFSIZE];
		MYSQL_ROW row;
		int i=0;

		writelog(2,"   from_acct=%s, from_domain=%s, mail_from=%s \n", from_acct, from_domain, mail_from);
		subquery[0] = 0;
		while( i++ < check_wildcard_mail_from)
		{
			if( subquery[0] )
				strcat(subquery," OR ");
			strcat(subquery,"mail_from = '");
			if( rcpt_acct[0] && i == 1)
			{
				strcat(subquery,from_acct);
				strcat(subquery,"@");
			}
			strcat(subquery,buf2);
			strcat(subquery,"'");
			if( i > 1 )
			{
				p2 = strchr(buf2,'.');
				if(p2)
				{
					strcpy(buf3,p2+1);
					strcpy(buf2,buf3);
				}
				else
					break;
			}
		}
		sprintf(query,"SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom \
WHERE record_expires > NOW() AND relay_ip IS NULL AND rcpt_to IS NULL AND (%s) ORDER BY length(mail_from) DESC", 
				subquery);
		if( db_query(query, &result) )
			goto DB_FAILURE;

		if( !result )
		{
			writelog(1,"   store_result call returned null results!\n");
			goto DB_FAILURE;
		}

		if( mysql_num_fields(result) != 3 )
		{
			writelog(1,"  Num Fields = %d; hoped for 3\n", mysql_num_fields(result));
			goto DB_FAILURE;
		}

		row = mysql_fetch_row(result);
		if( row && row[0] && strlen(row[0]) > 0 )
		{
			strncpy(row_id, row[0], sizeof(row_id));
			if( atoi(row[1]) )
			{
				writelog(1,"  Blacklisted Sender (%s,%s,%s). Skipping checks and rejecting the mail.\n",relay_ip,mail_from,rcpt_to);
				goto BOUNCE_MAIL;
			}
			if( atoi(row[2]) )
			{
				writelog(1,"  Whitelisted Sender (%s,%s,%s). Skipping checks and passing the mail.\n", relay_ip, mail_from,rcpt_to);
				goto PASS_MAIL;
			}
		}
		sprintf(query,"SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom \
WHERE record_expires > NOW() AND relay_ip IS NULL AND rcpt_to = '%s' AND (%s) ORDER BY length(mail_from) DESC", 
				rcpt_to, subquery);
		if( db_query(query, &result) )
			goto DB_FAILURE;

		if( !result )
		{
			writelog(1,"   store_result call returned null results!\n");
			goto DB_FAILURE;
		}

		if( mysql_num_fields(result) != 3 )
		{
			writelog(1,"  Num Fields = %d; hoped for 3\n", mysql_num_fields(result));
			goto DB_FAILURE;
		}

		row = mysql_fetch_row(result);
		if( row && row[0] && strlen(row[0]) > 0 )
		{
			strncpy(row_id, row[0], sizeof(row_id));
			if( atoi(row[1]) )
			{
				writelog(1,"  Blacklisted Sender->Recipient pair %s->%s. (ip=%s) Skipping checks and rejecting the mail.\n",mail_from,rcpt_to,relay_ip);
				goto BOUNCE_MAIL;
			}
			if( atoi(row[2]) )
			{
				writelog(1,"  Whitelisted Sender->Recipient pair %s->%s. (ip=%s) Skipping checks and passing the mail.\n", mail_from, rcpt_to, relay_ip);
				goto PASS_MAIL;
			}
		}
	}

	/* Store and maintain the dns_name of the relay if we have one
	   Not strictly necessary, but useful for reporting/troubleshooting */
	if( enable_relay_name_updates && strlen(relay_name) )
	{
		/* SMM-- don't understand quite the reversed relayname....
		   if this isn't strictly necc., then I'll skip it for now! */
		char rev[BUFSIZE];
		char forw[BUFSIZE],*p3;
		char query[BUFSIZE];
		strcpy(forw,relay_name);
		rev[0] = 0;
		while ((p3 = strrchr(forw,'.')))
		{
			*p3 = 0;
			if( rev[0] )
				strcat(rev,".");
			strcat(rev,p3+1);
		}
		if( rev[0] )
			strcat(rev,".");
		strcat(rev,forw);
		writelog(2,"   Reversed IP: %s\n", rev);
		sprintf(query,"INSERT IGNORE INTO dns_name (relay_ip,relay_name) VALUES ('%s','%s')",
				relay_ip, rev);
		if( db_query(query, &result) )
			goto DB_FAILURE;

		/* XXX: is it legal to not have a result here? */
		if( result )
		{
			if( mysql_num_rows(result) != 1 )
			{
				/* Row already exists, so make sure the name is updated */
				sprintf(query,"UPDATE dns_name SET relay_name = '%s' WHERE relay_ip = '%s'",
						rev, relay_ip);
				writelog(2,"   About to make Query: %s\n", query);
				if( db_query(query,&result) )
					goto DB_FAILURE;
			}
		}
	}

	/* Check to see if we already know this triplet set, and if the initial block is expired */

	sprintf(query2,"SELECT id, NOW() > block_expires FROM relaytofrom \
WHERE record_expires > NOW()   AND mail_from = '%s' AND rcpt_to   = '%s'", 
			mail_from, rcpt_to);
	if( do_relay_lookup_by_subnet )
	{
		char buf3[BUFSIZE],*p3;
		strcpy(buf3,relay_ip);
		p3 = strrchr(buf3,'.');
		if( p3 )
		{
			*(p3+1) = '%';
			*(p3+2) = 0;
		}

		strcat(query2," AND relay_ip LIKE '");
		strcat(query2,buf3);
		strcat(query2,"'");
	}
	else
	{
		strcat(query2," AND relay_ip = '");
		strcat(query2,relay_ip);
		strcat(query2,"'");

	}
	if( db_query(query2, &result) )
		goto DB_FAILURE;

	if( !result )
		goto DB_FAILURE;

	row = mysql_fetch_row(result);

	if( !mysql_num_rows(result) )
	{
		row_id[0] = 0;
		block_expired = 0;
	}
	else  /* SMM-- set up row_id from the successful fetch */
	{
		strncpy(row_id,row[0],sizeof(row_id));
		block_expired = atoi(row[1]);
	}

	if(row_id[0] && atoi(row_id) > 0 )
	{
		if( block_expired )
		{
			writelog(1,"  Email is known and block has expired. Passing the mail.(%s,%s,%s) Rowid: %s\n", relay_ip, mail_from, rcpt_to, row_id);
			goto PASS_MAIL;
		}
		else
		{
			/* the email is known, but the blick has not expired. So return a tempfail. */
			writelog(1,"  Email is known, but the block has not expired. Issueing a tempfail.(%s,%s,%s) Rowid: %s\n",
					 relay_ip, mail_from, rcpt_to, row_id);
			goto DELAY_MAIL;
		}
	}
	else
	{
		/* This is a new and unknown triplet, so create a tracking record, but make sure we don't create duplicates
		   FIXME - We use table locking to ensure non-duplicate rows.  Since we can't do it with a unique multi-field key
		   on the triplet fields (the key would be too large), it's either this or normalizing the data to have seperate
		   tables for each triplet field.  While that would be a good optimization, it would make this too complex for
		   an example implementation. */
		if( db_query("LOCK TABLE relaytofrom WRITE", &result) )
			goto DB_FAILURE;

		/* I am skipping the Re-read and unlock table, and DELAY_MAIL return,
		   because it's rare that this kind of thing would happen... I may need to
		   put this stuff back in sometime */


		sprintf(query2,"INSERT INTO relaytofrom (relay_ip,mail_from,rcpt_to,block_expires,record_expires,origin_type,create_time)\
 VALUES ('%s','%s','%s',NOW() + INTERVAL %d SECOND,NOW() + INTERVAL %d SECOND,  'AUTO', NOW())",
				relay_ip, mail_from, rcpt_to, delay_mail_secs, auto_record_life_secs);
		if( db_query(query2, &result) )
			goto DB_FAILURE;

		if( db_query("SELECT LAST_INSERT_ID()", &result) )
			goto DB_FAILURE;

		if( result )
		{
			if( mysql_num_rows(result) )
			{
				MYSQL_ROW row = mysql_fetch_row(result);
				strncpy(row_id, row[0], sizeof(row_id));
			}
			else
			{
				row_id[0] = 0;
			}
		}
		if( db_query("UNLOCK TABLE", &result) )
			goto DB_FAILURE;

		writelog(1,"  New mail row (%s,%s,%s) successfully inserted.  Issuing a tempfail.  rowid: %s\n", 
				 relay_ip, mail_from, rcpt_to, row_id);

		goto DELAY_MAIL;
	}


	DELAY_MAIL:
	if( row_id[0] && atoi(row_id) )
	{
		char query[BUFSIZE];
		sprintf(query,"UPDATE relaytofrom SET blocked_count = blocked_count + 1 WHERE id = %s",row_id);
		if (db_query(query, &result) )
			goto DB_FAILURE;
	}
	/* FIXME - Should do mail logging?

	 Special handling for null sender.  Spammers use it a ton, but so do things like exim's callback sender
	   verification spam checks.  If the sender is the null sender, we don't want to block it now, but will
	   instead block it at the eom phase. */

	if( !strcmp(mail_from,"<>") || tempfail_messages_after_data_phase )
	{
		char *privdata2;

		writelog(2,"  Delaying tempfail reject until eom phase.\n");
		/* save that this message needs to be blocked later in the transaction (after eom) */
		privdata2 = (char *)malloc(strlen(mail_from)+strlen(rcpt_to)+6);
		sprintf(privdata2,"00\t%s\t%s", mail_from, rcpt_to);
		smfi_setpriv(ctx,privdata2);
		/* and let the message continue processing, since will be blocked at eom if it isn't aborted before that */
		return SMFIS_CONTINUE;
	}
	/* Save our privdata1 for the next callback (don't add this rowid, since have already handled it) */
	privdata_ref = (char*)malloc(strlen(privdata_copy)+1);
	strcpy(privdata_ref,privdata_copy);
	smfi_setpriv(ctx,privdata_ref);
	privdata_copy[0] = 0;
	privdata_ref = 0;

	/* Set the reply code to a unique message (for debugging) - this dsn is what is normally the default */
	smfi_setreply(ctx, "450", "4.3.2", "Please try again later (TEMPFAIL)");

	/* Issue a temporary failure for this message.  Connection may or may not continue. */
	return SMFIS_TEMPFAIL;

	BOUNCE_MAIL:
	/* set privdata so later callbacks won't have problems */
	privdata_ref = (char*)malloc(3);
	strcpy(privdata_ref,"0");

	smfi_setpriv(ctx,privdata_ref);
	privdata_ref = 0;

	/* Indicate the message should be aborted (want a custom error code?) */
	smfi_setreply(ctx, "553", "5.3.0", "You really got someone quite upset at this site: you won't be able to deliver mail here any more. Go Away!");
	return SMFIS_REJECT;

	PASS_MAIL:
	/* Do database bookkeeping (if rowid is defined) */
	if( row_id[0] && atoi(row_id) )
	{
		/*     # We don't increment the passed count here because the mail may still be rejected
		   for some reason at the sendmail level.  So we do it in the eom callback instead.

		 Here we do a special update to end the life of this record, if the sender is the null sender
		   (Spammers send from this a lot, and it should only be used for bounces.  This
		   Makes sure that only one (or a couple, small race) of these gets by per delay. */
		if( !strcmp(mail_from,"<>" ) )
		{
			/* Only update the lifetime of records if they are AUTO, wouldn't want to do wildcard records  */
			char querystr[BUFSIZE];
			sprintf(querystr,"UPDATE relaytofrom SET record_expires = NOW() WHERE id = %s AND origin_type = 'AUTO'", row_id);
			if(db_query(querystr,&result)) 
			{
				goto DB_FAILURE;
			}
		}
		/*Since we have a rowid, then set the context data to indicate we successfully
		   handled this message as a pass, and that we don't expect an abort without
		   needing further processing.  We have to keep the rcpt_to on there, since this
		   callback may be called several times for a specific message if it has multiple
		   recipients, and we need it for logging.
		 The format of the privdata1 is one or more rowids seperated by commas, followed by
		   a null, and the envelope from. */
		if( strlen(rowids) > 0 && atoi(rowids) > 0)
		{
			strcat(rowids,",");
			strcat(rowids,row_id);
		}
		else
		{
			strcpy(rowids,row_id);
		}
	}

	/* Save our privdata1 for the next callback */
	privdata1 = (char*)malloc(strlen(rowids)+strlen(mail_from)+strlen(rcpt_to)+4);
	sprintf(privdata1,"%s\t%s\t%s", rowids, mail_from, rcpt_to);

	smfi_setpriv(ctx,privdata1);

	privdata1 = 0;

	/* FIXME - Should do mail logging? */

	/* And indicate the message should continue processing. */
	return SMFIS_CONTINUE;

	DB_FAILURE:
	/* Had a DB error.  Handle as configured. */

	privdata1 = (char *)malloc(strlen(mail_from)+5);
	sprintf(privdata1,"0\t%s\t", mail_from);

	smfi_setpriv(ctx,privdata1);
	privdata1 = 0;

	if( pass_mail_when_db_unavail )
		return SMFIS_CONTINUE;
	return SMFIS_TEMPFAIL;
}



struct smfiDesc my_callbacks =
{
	"relaydelay",  /* filter name */
	SMFI_VERSION, /* version code; don't change? */
	0,             /* flags */
	0,  /* connect */
	0,  /* helo */
	envfrom_callback,  /* envfrom */
	envrcpt_callback,  /* envrcpt */
	0,  /* header */
	0,  /* eoh */
	0,  /* body */
	eom_callback, /* eom */
	abort_callback, /* abort */
	0
};

int main(int argc, char **argv)
{
	char conn_str[500];
	extern FILE relaydelay_in;
	int ret;
	
	if( load_config() )
		return 1;

	if( relaydelay_pid_file)
	{
		FILE *PIDF;
		PIDF = fopen(relaydelay_pid_file,"w");
		if( !PIDF )
		{
			fprintf(stderr,"Unable to open pid file %s\n", relaydelay_pid_file);
			exit(10);
		}
		fprintf(PIDF,"%d\n", getpid());
		fclose(PIDF);
	}
	

	writelog(1,"relaydelay milter version %s\n", VERSION);
	db_connect();
	
	if( sendmail_accessdb_file && strlen(sendmail_accessdb_file) )
	{
#ifdef DB_VERSION_MAJOR
#if DB_VERSION_MAJOR >= 3
		if ((ret = db_create(&dbp, NULL, 0)) != 0) 
		{ 
			fprintf(stderr, "db_create: %s\n", db_strerror(ret)); 
			exit (1); 
		} 
#endif
        /* the open call below has this many args in 3.3; for later db's it looks like you should insert NULL to be the second arg! */
#if DB_VERSION_MAJOR == 2
		if ((ret = db_open(sendmail_accessdb_file, DB_HASH, DB_THREAD|DB_RDONLY, 0444, NULL, NULL, &dbp)) != 0) 
#endif
#if DB_VERSION_MAJOR == 3
		if ((ret = dbp->open(dbp, sendmail_accessdb_file, NULL, DB_HASH, DB_THREAD|DB_RDONLY, 0444)) != 0) 
#endif
#if DB_VERSION_MAJOR == 4
		if ((ret = dbp->open(dbp, NULL, sendmail_accessdb_file, NULL, DB_HASH, DB_THREAD|DB_RDONLY, 0444)) != 0) 
#endif
		{ 
#if DB_VERSION_MAJOR >= 3

			dbp->err(dbp, ret, "%s", sendmail_accessdb_file);
#endif			
			exit( 10);
		}
		memset(&key, 0, sizeof(key)); 
		memset(&data, 0, sizeof(data));

		print_access_contents();

#endif
	}
	
	if( smfi_setconn(milter_socket_connection) == MI_FAILURE )
	{
		fprintf(stderr,"Setting connection to %s was a total failure!\n\n", milter_socket_connection);
		exit(10);
	}
	if( smfi_register(my_callbacks) == MI_FAILURE )
	{
		fprintf(stderr,"Registration of Callbacks was a total failure!\n\n");
		exit(10);
	}

	if( smfi_main() == MI_FAILURE )
	{
		fprintf(stderr,"Main Returns FAILURE. Filter is not running!\n");
		exit(10);
	}
#ifdef DB_VERSION_MAJOR
	if( dbp )
	{
		dbp->close(dbp, 0);
	}
#endif
	db_disconnect();
}


