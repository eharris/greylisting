#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
#include <regex.h>


#include "mysql.h"

int verbose = 1;
char *database_type = "mysql";
char *database_name = "relaydelay";
char *database_host = "localhost";
int  database_port = 3306;
char *database_user = "milter";
char *database_pass = "password";

/*
# This determines how many seconds we will block inbound mail that is
#   from a previously unknown [ip,from,to] triplet.
*/
int delay_mail_secs = 3600;

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
int  check_wildcard_rcpt_to = 1;

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

/* ############################################################# */
MYSQL global_dbh;
int mysql_connected = 0;
int config_loaded = 0;

void load_config(void)
{
	extern FILE *relaydelay_in;

	if( config_loaded )
		return;
	if( verbose )
		printf("Parsing /etc/mail/relaydelay.conf...\n");

	relaydelay_in = fopen( "/etc/mail/relaydelay.conf", "r");
	if( relaydelay_in )
		relaydelay_parse();
	if( relaydelay_in )
		fclose(relaydelay_in);
	if( verbose ) printf("Finished Loading Config File\n");
	config_loaded = 1;
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
		MYSQL *conn;
		mysql_init(&global_dbh);
		conn = mysql_real_connect(&global_dbh, database_host, database_user, database_pass, database_name , database_port, 0, 0);
		if( ! conn && verbose )
			printf("real_connect returns NULL!!!\n");
		mysql_connected = 1;
	}
}

void db_disconnect(void)
{
	mysql_close(&global_dbh);	
	mysql_connected = 0;
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
int do_regex(char *pattern, char *string, regex_t *preg, regmatch_t pmatch[10],int match_message)
{
	int errcode;
	errcode = regcomp(preg, pattern, REG_EXTENDED);
	if( errcode )
	{
		char errbuf[1024];
		regerror(errcode,preg,errbuf,1024);
		if(verbose) printf("Had trouble compiling regex %s (%s)!\n", pattern, errbuf);
	}
	else
	{
		errcode = regexec(preg, string, 10, pmatch, 0);
		if( errcode )
		{
			char errbuf[1024];
			regerror(errcode,preg,errbuf,1024);
			if( verbose && (errcode == REG_NOMATCH && match_message || errcode != REG_NOMATCH) )
				printf("Had trouble execing regex %s on string %s (%s)!\n", pattern, string, errbuf);
		}
		else
		{
			return 0;
		}
	}
	return 1;
}

sfsistat envfrom_callback(SMFICTX *ctx, char **argv)
{
	char *mail_from = argv[0];
	char mail_from_buf[4096];
	char *privdata,buf[4096];
	
	if(verbose>1) printf("envfrom Callback:\n");

	db_connect();

	if( !config_loaded )
		load_config();
	if( check_envelope_address_format )
	{
		char *mail_mailer = smfi_getsymval(ctx,"{mail_mailer}");
		if(verbose > 1) printf("   mail_mailer: %s\n", mail_mailer);
		strcpy(mail_from_buf, mail_from);
		if( !strstr(mail_mailer,"smtp") )
		{
		      /* # we aren't using an smtp-like mailer, so bypass checks */

		}
		else
		{    /*
		      # Check the envelope sender address, and make sure is well-formed.
		      #   If is invalid, then issue a permanent failure telling why.
		      # NOTE: Some of these tests may exclude valid addresses, but I've only seen spammers
		      #   use the ones specifically disallowed here, and they sure don't look valid.  But,
		      #   since the SMTP specs do not strictly define what is allowed in an address, I
		      #   had to guess by what "looked" normal, or possible. */
			regex_t preg;
			regmatch_t pmatch[10];
			char mail_from_buf2[4096],*at,*p1;
			int errcode;
			if(verbose>1) printf("   mail_from: %s\n", mail_from);
			if( do_regex(  "^<(.*)>$", mail_from, &preg, pmatch, 0 ) == 0 )
			{
				if( pmatch[1].rm_so != -1 && pmatch[1].rm_eo != -1 )
				{
					strncpy(mail_from_buf,mail_from+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
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
			/*  # Check for embedded brackets, parens, quotes, slashes, pipes (doublequotes are used at yahoo) */
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
				strcpy(mail_from_buf2,mail_from);
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
	sprintf(privdata,"0%c%s%c", '\t', mail_from,'\t');
  	smfi_setpriv(ctx,privdata);

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
	int cnt=0,cnt2=1;
	char **arr;
	char *p=str,*p1=str,*buf2;
	buf2 = (char *)malloc(strlen(str)+1);
	strcpy(buf2,str);
	while( (p1=strchr(p,sep)) )
	{
		p = p1+1;
		cnt++;
	}
	cnt++;
	arr = (char**)malloc(sizeof(char *)*cnt);
	arr[0] = buf2;
	p = buf2;
	while( (p1=strchr(p,sep)) )
	{
		p = p1+1;
		arr[cnt2++] = p1+1;
	}
	*array = arr;
	return cnt;
}


sfsistat eom_callback(SMFICTX *ctx)
{
	/* Get our status and check to see if we need to do anything else */
	char *privdata_ref = smfi_getpriv(ctx);
	char *rowids,*mail_from,*rcpt_to;
	char *t1,*t2,buf1[99000];
	MYSQL_RES *result;
	/* Clear our private data on this context */
	smfi_setpriv(ctx,0);
	
	if( verbose>1 )
		printf("IN EOM CALLBACK - PrivData: %s \n", privdata_ref);

	if( !config_loaded )
		load_config();

	if( !mysql_connected)
		db_connect();

	strcpy(buf1,privdata_ref);
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
 		  # If and only if this message is from the null sender, check to see if we should tempfail it
		  #   (since we can't delay it after rcpt_to since that breaks SMTP callbacks)
		  #   (We use a special rowid value of 00 to indicate a needed block)
		*/
		if( !strcmp(rowids,"00") && (!strcmp(mail_from,"<>") || tempfail_messages_after_data_phase))
		{   /*
		    # Set the reply code to the normal default, but with a modified text part.
		    #   I added the (TEMPFAIL) so it is easy to tell in the syslogs if the failure was due to
		    #     the processing of the milter, or if it was due to other causes within sendmail
		    #     or from the milter being inaccessible/timing out. */
			smfi_setreply(ctx, "451", "4.7.1", "Please try again later (TEMPFAIL)") ;
			return SMFIS_TEMPFAIL;

		}
		if( strlen(rowids) > 0 )
		{
			char **arr;
			int i,cnt = split(',',rowids,&arr);	
			
			for(i=0; i<cnt; i++ )
			{
				char commandbuf[8000];
				int res;

				if( arr[i] == 0 ) /* SMM: 0 is not a valid rowid */
					continue;

				sprintf(commandbuf,"UPDATE relaytofrom SET passed_count = passed_count + 1 WHERE id = %s", arr[i] );
				if( verbose > 1 ) printf("About to issue query: %s\n", commandbuf);
				if( (res = mysql_query(&global_dbh, commandbuf)) == 0 )
				{
					result = mysql_store_result(&global_dbh);
					if( verbose )
					printf("  * Mail successfully processed.  Incremented passed count on rowid %s.\n", arr[i]);
				}
				else
				{
					if( verbose )printf("ERROR: Database Call Failed: %s", mysql_error(&global_dbh));
					db_disconnect();
					if( pass_mail_when_db_unavail )
						return SMFIS_CONTINUE;
					return SMFIS_TEMPFAIL;
				}
				/*  If configured to do so, then update the lifetime (only on AUTO records) */
				if (update_record_life) 
				{
				        /* # This is done here rather than the rcpt callback since we don't know until now that
				        #   the delivery is completely successful (not spam blocked or nonexistant user, or 
				        #   other failure out of our control) */
					sprintf(commandbuf,"UPDATE relaytofrom SET record_expires = NOW() + INTERVAL %d SECOND  WHERE id = %s AND origin_type = 'AUTO'", update_record_life_secs, arr[i]);
					if( verbose > 1 ) printf("  About to issue query: %s\n", commandbuf);
					if( mysql_query(&global_dbh, commandbuf) != 0 )
					{
						if(verbose) printf("ERROR: Database Call Failed: %s", mysql_error(&global_dbh));
						fflush(stdout);
						db_disconnect();
						if( pass_mail_when_db_unavail )
							return SMFIS_CONTINUE;
						return SMFIS_TEMPFAIL;
					}
					else
					{
						result = mysql_store_result(&global_dbh);
					}
				}
			}
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
	char *rowids,*mail_from,*rcpt_to;
	char *t1,*t2,buf1[99000];
	/* Clear our private data on this context */
	smfi_setpriv(ctx,0);
	
	if( verbose > 1 )
		printf("IN abort CALLBACK - PrivData: %s \n", privdata_ref);

	if( !config_loaded )
		load_config();

	if( !mysql_connected )
		db_connect();

	strcpy(buf1,privdata_ref);
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
	if( t1 && t2 && strlen(rcpt_to))
	{
		if( strlen(rowids) > 0 )
		{
			char **arr;
			int i,cnt = split(',',rowids,&arr);	
			db_connect();
			for(i=0; i<cnt; i++ )
			{
				char commandbuf[8000];
				int res;
				if( !strcmp(arr[i],"0") ) /* SMM == skip a zero row id! */
					continue;
				sprintf(commandbuf,"UPDATE relaytofrom SET aborted_count = aborted_count + 1 WHERE id = %s", arr[i] );
				if( (res = mysql_query(&global_dbh, commandbuf)) == 0 )
				{
					if( verbose )
					printf("  * Mail was aborted.  Incremented aborted count on rowid %s.\n", arr[i]);
				}
				else
				{
					if(verbose)printf("ERROR: Database Call Failed: %s", mysql_error(&global_dbh));
					db_disconnect();
					if( pass_mail_when_db_unavail )
						return SMFIS_CONTINUE;
					return SMFIS_TEMPFAIL;
				}
				/* # Check for the special case of no passed messages, means this is probably a 
				   #   spammer, and we should expire the record so they have to go through the
				   #   whitelisting process again the next time they try.  BUT ONLY IF THIS
				   #   IS AN AUTO RECORD.
				   # If we find that it is such a record, update the expire time to now */
				sprintf(commandbuf,"UPDATE relaytofrom SET record_expires = NOW() WHERE id = %s AND origin_type = 'AUTO' AND passed_count = 0", arr[i] );
				if( (res = mysql_query(&global_dbh, commandbuf)) == 0 )
				{
					if( mysql_affected_rows(&global_dbh) && verbose )
					printf("  * Mail  record had no successful deliveries.  Expired record on rowid %s.\n", arr[i]);
				}
				else
				{
					if( verbose )
					printf("ERROR: Database Call Failed: %s", mysql_error(&global_dbh));
					db_disconnect();
					if( pass_mail_when_db_unavail )
						return SMFIS_CONTINUE;
					return SMFIS_TEMPFAIL;
				}

			}
		}
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
	char privdata1[4096];
	char *rowids,*mail_from,*rcpt_to;
	char *t1,*t2,buf1[99000];
	char relay_name_reversed[4096];
	char row_id[32];
	int res;
	MYSQL_RES *result;
	/* Clear our private data on this context */
	
	if( verbose>1 )
		printf("Envrcpt callback:\n");
	row_id[0] = 0;	
	rcpt_to = argv[0];
	strcpy(buf1,privdata_ref);
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
		}
	}
	if( t1 && t2 )
	{
		char buf2[4096],*p2,buf3[4096];
		char *tmp,relay_ip[1000],relay_name[1000],relay_ident[1000],relay_maybe_forged[1000];
		char *mail_mailer, *sender, *rcpt_mailer, *recipient, *queue_id;
		char *rcpt_to2[4096],*tstr;
		char rcpt_domain[4096],*r2;
		char query2[4096];
		int block_expired = 0;
		regex_t preg;
		regmatch_t pmatch[10];
		if( verbose >1)
		{
			printf("Stored Sender: %s\nPassed Recipient: %s\n", mail_from, rcpt_to);
		}
		db_connect();
		tmp = smfi_getsymval(ctx,"{_}");
		relay_ip[0] = 0;
		relay_name[0] = 0;
		relay_ident[0] = 0;
		relay_maybe_forged[0] = 0;
	
		if( do_regex("^([^ \t\r]*@)?([^ \t\r]*) ?\\[(.*)\\]( \\(may be forged\\))?$", tmp, &preg, pmatch,1) == 0 )
		{
			if( pmatch[0].rm_so == -1 || pmatch[0].rm_eo == -1 )
			{
				if( verbose > 1)
				printf("Relay info could not be parsed: %s\n",
					tmp);
			}
			else
			{
				if( pmatch[1].rm_so != -1 )
				{
					strncpy(relay_ident,tmp+pmatch[1].rm_so,pmatch[1].rm_eo-pmatch[1].rm_so);
					relay_ident[pmatch[1].rm_eo-pmatch[1].rm_so] = 0;
					if( verbose>1 )printf("  Relay Ident: %s\n", relay_ident);
				}
				if( pmatch[2].rm_so != -1 )
				{
					strncpy(relay_name,tmp+pmatch[2].rm_so,pmatch[2].rm_eo-pmatch[2].rm_so);
					relay_name[pmatch[2].rm_eo-pmatch[2].rm_so] = 0;
					if( verbose>1 )printf("  Relay name: %s\n", relay_name);
				}
				if( pmatch[3].rm_so != -1 )
				{
					strncpy(relay_ip,tmp+pmatch[3].rm_so,pmatch[3].rm_eo-pmatch[3].rm_so);
					relay_ip[pmatch[3].rm_eo-pmatch[3].rm_so] = 0;
					if( verbose>1 )printf("  Relay IP: %s\n", relay_ip);
				}
				if( pmatch[4].rm_so != -1 )
				{
					strncpy(relay_maybe_forged,tmp+pmatch[4].rm_so,pmatch[4].rm_eo-pmatch[4].rm_so);
					relay_maybe_forged[pmatch[4].rm_eo-pmatch[4].rm_so] = 0;
					if( verbose>1 )printf("  Relay Forged: %s\n", relay_maybe_forged);
				}
			}
		}
		mail_mailer = smfi_getsymval(ctx,"{mail_mailer}");
		sender = smfi_getsymval(ctx,"{mail_addr}");
		rcpt_mailer = smfi_getsymval(ctx,"{rcpt_mailer}");
		recipient = smfi_getsymval(ctx,"{rcpt_addr}");
		queue_id = smfi_getsymval(ctx,"{i}");
		
		if( verbose > 1)
		{
			printf("  From: %s  -  To: %s\n", sender, recipient);
			printf("  InMailer: %s  -  OutMailer: %s   -  QueueID: %s\n", mail_mailer, rcpt_mailer, queue_id);
		}
		/* Only do our processing if the inbound mailer is an smtp variant.
		   A lot of spam is sent with the null sender address <>.  Sendmail reports 
		   that as being from the local mailer, so we have a special case that needs
		   handling (but only if not also from localhost). */
		if( !strstr(mail_mailer,"smtp") && ( strcmp(mail_from,"<>") || !strcmp(relay_ip,"127.0.0.1")))
		{
			/* we aren't using an smtp-like mailer, so bypass checks */
			if( verbose )
				printf("  Mail delivery is not using an smtp-like mailer (%s). (from=%s)  Skipping checks.\n",
					mail_mailer, mail_from);
			goto PASS_MAIL;
		}
		
		/*
		  # Check for local IP relay whitelisting from the sendmail access file
		  # FIXME - needs to be implemented
		  #

		  # Check wildcard black or whitelisting based on ip address or subnet
		  #   Do the check in such a way that more exact matches are returned first */
		if( check_wildcard_relay_ip )
		{
			char subquery[4096];
			char query[4096];
			int blacklisted, whitelisted;
			int i,res;
			MYSQL_RES *result;
			int num_rows, num_fields;

			strcpy(buf2,relay_ip);
			subquery[0] = 0;
			for(i=0; i<4; i++)
			{
				if( subquery[0] )
					strcat(subquery," OR ");
				strcat(subquery,"relay_ip = '");
				strcat(subquery,buf2);
				strcat(subquery,"'");
				p2 = strrchr(buf2,'.');
				if(p2)
					*p2 = 0;
			}
			sprintf(query,"SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom WHERE record_expires > NOW()   AND mail_from IS NULL AND rcpt_to   IS NULL AND (%s) ORDER BY length(relay_ip) DESC", subquery);
			if( verbose>1 ) printf("   About to make Query: %s\n", query);
			if( (res = mysql_query(&global_dbh, query)) == 0 )
			{
			if( verbose >1) printf("   About to store result\n");
				result = mysql_store_result(&global_dbh);
				if( result )
				{
					MYSQL_ROW row;
					int num_fields = mysql_num_fields(result);
			if( verbose>1 ) printf("   store_result succeeded == num_fields is %d\n", num_fields);
					row = mysql_fetch_row(result);
			if( verbose>1 ) printf("   fetch_row returns %x\n", row);
				
					if( row )
					{
						if( num_fields < 3 )
						{
							if( verbose > 1 )
							printf("   Num Fields = %d; hoped for 3\n", num_fields);
						}
						else
						{
							strncpy(row_id, row[0], sizeof(row_id));
							blacklisted = atoi(row[1]);
							whitelisted = atoi(row[2]);
							if( row_id && strlen(row_id) > 0 )
							{
								if( blacklisted )
								{
									if( verbose )
									printf("  Blacklisted Relay %s[%s]. Skipping checks and rejecting the mail.\n",relay_name, relay_ip);
									goto DELAY_MAIL;
								}
								if( whitelisted)
								{
									if( verbose )
									printf("  Whitelisted Relay %s[%s]. Skipping checks and passing the mail.\n",relay_name, relay_ip);
									goto PASS_MAIL;
								}
							}
						}
					}
				}
				else
				{
					if( verbose )
					printf("  store_result returned NULL\n");
					goto DB_FAILURE;
				}
			}
			else
			{
				if( verbose )
				printf("   SELECT call returned null results!\n");
				goto DB_FAILURE;
			}
		}
		
		/* Pull out the domain of the recipient for whitelisting checks */
		strcpy(buf2,mail_from);
		if( buf2[0] == '<' && buf2[strlen(buf2)-1] == '>' )
		{
			strncpy(buf2,rcpt_to+1,strlen(rcpt_to)-2);
			buf2[strlen(rcpt_to)-2] = 0;
		}
		p2 = strrchr(buf2,'@');
		if( p2 )
		strcpy(buf3,p2+1);
		strcpy(buf2,buf3);
		strcpy(rcpt_domain,buf2);
		/* See if this recipient (or domain/subdomain) is wildcard white/blacklisted
		   Do the check in such a way that more exact matches are returned first */
		if( check_wildcard_rcpt_to )
		{
			char buf2[4096],*p2,buf3[4096];
			char subquery[4096];
			char query[4096];
			int i,res,blacklisted,whitelisted;
			int num_rows, num_fields;
			if( verbose>1 ) printf("   rcpt_domain=%s, rcpt_to=%s \n", rcpt_domain, rcpt_to);
			strcpy(buf2,rcpt_domain);
			subquery[0] = 0;
			while(p2 = strchr(buf2,'.'))
			{
				if( subquery[0] )
					strcat(subquery," OR ");
				strcat(subquery,"rcpt_to = '");
				strcat(subquery,buf2);
				strcat(subquery,"'");
				p2 = strchr(buf2,'.');
				if(p2)
				{
					strcpy(buf3,p2+1);
					strcpy(buf2,buf3);
				}
			}
			sprintf(query,"SELECT id, block_expires > NOW(), block_expires < NOW() FROM relaytofrom WHERE record_expires > NOW()   AND relay_ip IS NULL AND mail_from   IS NULL AND (%s) ORDER BY length(rcpt_to) DESC", subquery);
			if( verbose>1 ) printf("   About to make Query: %s\n", query);
			if( (res = mysql_query(&global_dbh, query)) == 0 )
			{
				result = mysql_store_result(&global_dbh);
				if( result )
				{
					MYSQL_ROW row;
					int num_fields = mysql_num_fields(result);
					row = mysql_fetch_row(result);
					if( row )
					{
						if( num_fields < 3 )
						{
							if( verbose > 1 )
							printf("  Num Fields = %d; hoped for 3\n", num_fields);
						}
						else
						{
							strncpy(row_id, row[0], sizeof(row_id));
							blacklisted = atoi(row[1]);
							whitelisted = atoi(row[2]);
							if( row_id && strlen(row_id) > 0 )
							{
								if( blacklisted )
								{
									if( verbose )
									printf("  Blacklisted Recpt %s. Skipping checks and rejecting the mail.\n",rcpt_domain);
									goto DELAY_MAIL;
								}
								if( whitelisted)
								{
									if( verbose )
									printf("  Whitelisted Relay %s. Skipping checks and passing the mail.\n", rcpt_domain);
									goto PASS_MAIL;
								}
							}
						}
					}
				}
				else
				{
					if(verbose)
					printf("   store_result call returned null results!\n");
					goto DB_FAILURE;
				}
			}
			else
			{
				if( verbose )
				printf("SELECT call returned null results!\n");
				goto DB_FAILURE;
			}
		}
		
		/* Store and maintain the dns_name of the relay if we have one
		  Not strictly necessary, but useful for reporting/troubleshooting */
		if( enable_relay_name_updates && strlen(relay_name) )
		{
			/* SMM-- don't understand quite the reversed relayname....
			   if this isn't strictly necc., then I'll skip it for now! */
			char rev[4096];
			char forw[4096],*p3;
			char query[4096];
			MYSQL_RES *result;
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
			if( verbose>1 ) printf("   Reversed IP: %s\n", rev);
			sprintf(query,"INSERT IGNORE INTO dns_name (relay_ip,relay_name) VALUES ('%s','%s')",
				relay_ip, rev);
			if( verbose>1 ) printf("   About to make Query: %s\n", query);
			if( (res = mysql_query(&global_dbh, query)) == 0 )
			{
				result = mysql_store_result(&global_dbh);
				if( result )
				{
					int num_rows = mysql_num_rows(result);
					if( num_rows != 1 )
					{
						/* Row already exists, so make sure the name is updated */
						sprintf(query,"UPDATE dns_name SET relay_name = '%s' WHERE relay_ip = '%s'",
							rev, relay_ip);
						if( verbose>1 ) printf("   About to make Query: %s\n", query);
						if( (res=mysql_query(&global_dbh, query)) != 0 )
						{
							goto DB_FAILURE;
						}
					}
				}

			}
			else
				goto DB_FAILURE;
		}

		/* Check to see if we already know this triplet set, and if the initial block is expired */
		
		sprintf(query2,"SELECT id, NOW() > block_expires FROM relaytofrom WHERE record_expires > NOW()   AND mail_from = '%s' AND rcpt_to   = '%s'", mail_from, rcpt_to);
		if( do_relay_lookup_by_subnet )
		{
			char buf3[4096],*p3;
			strcpy(buf3,relay_ip);
			p3 = strrchr(buf3,'.');
			if( p3 )
			{ *(p3+1) = '%'; *(p3+2) = 0; }
			
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
		if( verbose>1 ) printf("   About to make Query: %s\n", query2);
		if( (res = mysql_query(&global_dbh, query2)) == 0 )
		{
			result = mysql_store_result(&global_dbh);
			if( result )
			{
				MYSQL_ROW row;
				int num_fields = mysql_num_fields(result);
				int num_rows = mysql_num_rows(result);
				row = mysql_fetch_row(result);

				if( !num_rows )
				{
					row_id[0] = 0;
					block_expired = 0;
				}
				else  /* SMM-- set up row_id from the successful fetch */
				{
					strncpy(row_id,row[0],sizeof(row_id));
					block_expired = atoi(row[1]);
				}
			}
			else
			{
				goto DB_FAILURE;

			}
		}
		else
		{
			goto DB_FAILURE;
		}
		if(row_id[0] && atoi(row_id) > 0 )
		{
			if( block_expired )
			{
				if( verbose )printf("  Email is known and block has expired. Passing the mail. Rowid: %s\n", row_id);
				goto PASS_MAIL;
			}
			else
			{
				/* the email is known, but the blick has not expired. So return a tempfail. */
				if( verbose )printf("  Email is known, but the block has not expired. Issueing a tempfail. Rowid: %s\n",
					row_id);
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
			if( verbose>1 ) printf("   About to make Query: %s\n", "LOCK TABLE relaytofrom WRITE");
			res= mysql_query(&global_dbh, "LOCK TABLE relaytofrom WRITE");
			if( res )
				goto DB_FAILURE;
			/* I am skipping the Re-read and unlock table, and DELAY_MAIL return, 
			because it's rare that this kind of thing would happen... I may need to 
			put this stuff back in sometime */
			
		
			sprintf(query2,"INSERT INTO relaytofrom (relay_ip,mail_from,rcpt_to,block_expires,record_expires,origin_type,create_time) VALUES ('%s','%s','%s',NOW() + INTERVAL %d SECOND,NOW() + INTERVAL %d SECOND,  'AUTO', NOW())", relay_ip, mail_from, rcpt_to, delay_mail_secs, auto_record_life_secs);
			if( verbose>1 ) printf("   About to make Query: %s\n", query2);
			res= mysql_query(&global_dbh, query2);
			if( res )
				goto DB_FAILURE;
		
			if( verbose>1 ) printf("   About to make Query: %s\n", "SELECT LAST_INSERT_ID()");
			res = mysql_query(&global_dbh, "SELECT LAST_INSERT_ID()");
			if( res )
				goto DB_FAILURE;
			result = mysql_store_result(&global_dbh);
			if( result )
			{
				MYSQL_ROW row;
				int num_fields = mysql_num_fields(result);
				int num_rows = mysql_num_rows(result);
				if( num_rows )
				{
				row = mysql_fetch_row(result);
				strncpy(row_id,row[0],sizeof(row_id));
				}
				else
				{
				row_id[0] = 0;
				}
			}
			if( verbose>1 ) printf("   About to make Query: %s\n", "UNLOCK TABLE");
			res = mysql_query(&global_dbh, "UNLOCK TABLE");
			if( res )
				goto DB_FAILURE;
		
			if( verbose)
				printf("  New mail row (%s,%s,%s) successfully inserted.  Issuing a tempfail.  rowid: %s\n", relay_ip, mail_from, rcpt_to, row_id); 
						
			goto DELAY_MAIL;
		}
	}


	DELAY_MAIL:
	if( row_id[0] && atoi(row_id) )
	{
		char query[4096];
		sprintf(query,"UPDATE relaytofrom SET blocked_count = blocked_count + 1 WHERE id = %s",row_id);
		if(verbose>1)
			printf("  About to query: %s\n", query);
		res= mysql_query(&global_dbh, query);
		if( res )
			goto DB_FAILURE;
	}
	/* FIXME - Should do mail logging?
  
	 Special handling for null sender.  Spammers use it a ton, but so do things like exim's callback sender
	   verification spam checks.  If the sender is the null sender, we don't want to block it now, but will
	   instead block it at the eom phase. */

	if( !strcmp(mail_from,"<>") || tempfail_messages_after_data_phase )
	{
		char privdata1[4096];
		if( verbose > 1)
			printf("  Delaying tempfail reject until eom phase.\n");
		/* save that this message needs to be blocked later in the transaction (after eom) */
		sprintf(privdata1,"00\t%s\t%s", mail_from, rcpt_to);
		smfi_setpriv(ctx,privdata1);
		/* and let the message continue processing, since will be blocked at eom if it isn't aborted before that */
		return SMFIS_CONTINUE;
	}
	/* Save our privdata1 for the next callback (don't add this rowid, since have already handled it) */
	smfi_setpriv(ctx,privdata_ref);
	/* Set the reply code to a unique message (for debugging) - this dsn is what is normally the default */
	smfi_setreply(ctx, "450", "4.3.2", "Please try again later (TEMPFAIL)");

	/* Issue a temporary failure for this message.  Connection may or may not continue. */
	return SMFIS_TEMPFAIL;

	BOUNCE_MAIL:
	/* set privdata1 so later callbacks won't have problems */
	smfi_setpriv(ctx,"0");
	/* Indicate the message should be aborted (want a custom error code?) */
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
			char querystr[4096];
			sprintf(querystr,"UPDATE relaytofrom SET record_expires = NOW() WHERE id = %s AND origin_type = 'AUTO'", row_id);
			if(mysql_query(&global_dbh, querystr))
			{
				goto DB_FAILURE;
			}
			result = mysql_store_result(&global_dbh);
		}
		/*Since we have a rowid, then set the context data to indicate we successfully 
		   handled this message as a pass, and that we don't expect an abort without 
		   needing further processing.  We have to keep the rcpt_to on there, since this 
		   callback may be called several times for a specific message if it has multiple 
		   recipients, and we need it for logging.
		 The format of the privdata1 is one or more rowids seperated by commas, followed by 
		   a null, and the envelope from. */
		if( strlen(rowids) > 0 )
			strcat(rowids,row_id);
		else
			strcpy(rowids,row_id);
	}
	
	/* Save our privdata1 for the next callback */
	sprintf(privdata1,"%s\t%s\t%s", rowids, mail_from, rcpt_to);
	smfi_setpriv(ctx,privdata1);

	/* FIXME - Should do mail logging? */
	
	/* And indicate the message should continue processing. */
	return SMFIS_CONTINUE;

	DB_FAILURE:
	/* Had a DB error.  Handle as configured. */

	printf("ERROR: Database Call Failed: %s", mysql_error(&global_dbh));
	db_disconnect();
	sprintf(privdata1,"0	%s	", mail_from);
	smfi_setpriv(ctx,privdata1);
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

	
	load_config();
	if( verbose > 1 )
	{
		printf("After config file read:\n");
        	printf("  database_port = %d\n", database_port);
       	 	printf("  verbose = %d\n", verbose);
       	 	printf("  delay_mail_secs = %d\n", delay_mail_secs);
       		printf("  auto_record_life_secs = %d\n", auto_record_life_secs);
       		printf("  update_record_life = %d\n", update_record_life);
       		printf("  update_record_life_secs = %d\n", update_record_life_secs);
       		printf("  check_wildcard_relay_ip = %d\n", check_wildcard_relay_ip);
       		printf("  check_wildcard_rcpt_to = %d\n", check_wildcard_rcpt_to);
       		printf("  tempfail_messages_after_data_phase = %d\n", tempfail_messages_after_data_phase);
       		printf("  do_relay_lookup_by_subnet = %d\n", do_relay_lookup_by_subnet);
       		printf("  enable_relay_name_updates = %d\n", do_relay_lookup_by_subnet);
       		printf("  check_envelope_address_format = %d\n", enable_relay_name_updates);
       		printf("  pass_mail_when_db_unavail = %d\n", pass_mail_when_db_unavail);
		
		printf("  database_type = %s\n", database_type);
       		printf("  database_name = %s\n", database_name);
       		printf("  database_host = %s\n", database_host);
       		printf("  database_user = %s\n", database_user);
       		printf("  database_pass = %s\n\n", database_pass);
	
	}
	printf("relaydelay milter version %s\n", VERSION);
	db_connect();
	sprintf(conn_str,"inet:%d@%s", 9876, "localhost" );

	if( smfi_setconn(conn_str) == MI_FAILURE )
	{
		fprintf(stderr,"Setting connection to %s was a total failure!\n\n", conn_str);
		exit(10);
	}
	if( smfi_register(my_callbacks) == MI_FAILURE )
	{
		fprintf(stderr,"Registration of Callbacks was a total failure!\n\n");
		exit(10);
	}

	smfi_main();

	db_disconnect();
}

