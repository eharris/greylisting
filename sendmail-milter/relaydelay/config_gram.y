%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
extern int
	database_port,
	verbose,
	delay_mail_secs,
	auto_record_life_secs,
	update_record_life,
	update_record_life_secs,
	check_wildcard_relay_ip,
	check_wildcard_rcpt_to,
	check_wildcard_mail_from,
	tempfail_messages_after_data_phase,
	do_relay_lookup_by_subnet,
	enable_relay_name_updates,
	check_envelope_address_format,
	pass_mail_when_db_unavail,
	maximum_milter_threads,
	reverse_mail_tracking,
	reverse_mail_life_secs,
	lineno;

extern char *database_type,
	*database_name,
	*database_host,
	*database_user,
	*database_pass,
	*milter_socket_connection,
	*sendmail_accessdb_file,
	*relaydelay_pid_file;

static char database_type_buf[100],
	database_name_buf[100],
	database_host_buf[100],
	database_user_buf[200],
	database_pass_buf[200],
	milter_socket_connection_buf[200],
	sendmail_accessdb_file_buf[200],
	relaydelay_pid_file_buf[200];
%}


%union
{
	char * str;
	int    num;
}



%token KW_DATABASE_TYPE KW_VERBOSE KW_DATABASE_NAME KW_DATABASE_HOST KW_DATABASE_PORT KW_DATABASE_USER KW_DATABASE_PASS
%token KW_AUTO_RECORD_LIFE_SECS KW_UPDATE_RECORD_LIFE  KW_UPDATE_RECORD_LIFE_SECS KW_CHECK_WILDCARD_RELAY_IP  KW_CHECK_WILDCARD_RCPT_TO
%token KW_TEMPFAIL_MESSAGES_AFTER_DATA_PHASE KW_DO_RELAY_LOOKUP_BY_SUBNET KW_ENABLE_RELAY_NAME_UPDATES KW_CHECK_ENVELOPE_ADDRESS_FORMAT
%token KW_DELAY_MAIL_SECS KW_PASS_MAIL_WHEN_DB_UNAVAIL  SEMI EQ USE STRICT MY KW_CHECK_WILDCARD_MAIL_FROM KW_MILTER_SOCKET_CONNECTION
%token KW_SENDMAIL_ACCESSDB_FILE KW_RELAYDELAY_PID_FILE KW_REVERSE_MAIL_TRACKING KW_REVERSE_MAIL_LIFE_SECS KW_MAXIMUM_MILTER_THREADS


%token <str> STR NAME
%token <num> NUM

%%


file : statement_list ;

statement_list : statement
		| statement_list statement
		;

statement : USE STRICT SEMI {}
	| KW_DATABASE_TYPE EQ STR SEMI {strncpy(database_type_buf,$3,200); database_type = database_type_buf; }
	| KW_VERBOSE EQ NUM SEMI { verbose = $3; }
	| KW_DELAY_MAIL_SECS EQ NUM SEMI {delay_mail_secs = $3; }
	| KW_DATABASE_NAME EQ STR SEMI {strncpy(database_name_buf,$3,200); database_name = database_name_buf; }
	| KW_DATABASE_HOST EQ STR SEMI {strncpy(database_host_buf,$3,200); database_host = database_host_buf; }
	| KW_DATABASE_PORT EQ NUM SEMI {database_port = $3; }
	| KW_DATABASE_USER EQ STR SEMI {strncpy(database_user_buf,$3,200); database_user = database_user_buf; }
	| KW_DATABASE_PASS EQ STR SEMI {strncpy(database_pass_buf,$3,200); database_pass = database_pass_buf; }
	| KW_MILTER_SOCKET_CONNECTION EQ STR SEMI {strncpy(milter_socket_connection_buf,$3,200); milter_socket_connection = milter_socket_connection_buf; }
	| KW_SENDMAIL_ACCESSDB_FILE EQ STR SEMI {strncpy(sendmail_accessdb_file_buf,$3,200); sendmail_accessdb_file = sendmail_accessdb_file_buf; }
	| KW_RELAYDELAY_PID_FILE EQ STR SEMI {strncpy(relaydelay_pid_file_buf,$3,200); relaydelay_pid_file = relaydelay_pid_file_buf; }
	| KW_AUTO_RECORD_LIFE_SECS EQ NUM SEMI {auto_record_life_secs = $3; }
	| KW_UPDATE_RECORD_LIFE EQ NUM SEMI {update_record_life = $3; }
	| KW_MAXIMUM_MILTER_THREADS EQ NUM SEMI {maximum_milter_threads = $3; }
	| KW_UPDATE_RECORD_LIFE_SECS EQ NUM SEMI {update_record_life_secs = $3; }
	| KW_CHECK_WILDCARD_RELAY_IP EQ NUM SEMI { check_wildcard_relay_ip = $3; }
	| KW_REVERSE_MAIL_TRACKING EQ NUM SEMI { reverse_mail_tracking = $3; }
	| KW_REVERSE_MAIL_LIFE_SECS EQ NUM SEMI { reverse_mail_life_secs = $3; }
    	| KW_CHECK_WILDCARD_RCPT_TO EQ NUM SEMI { check_wildcard_rcpt_to = $3; }
    	| KW_CHECK_WILDCARD_MAIL_FROM EQ NUM SEMI { check_wildcard_mail_from = $3; }
    	| KW_TEMPFAIL_MESSAGES_AFTER_DATA_PHASE EQ NUM SEMI { tempfail_messages_after_data_phase = $3; }
    	| KW_DO_RELAY_LOOKUP_BY_SUBNET EQ NUM SEMI { do_relay_lookup_by_subnet = $3; }
    	| KW_ENABLE_RELAY_NAME_UPDATES EQ NUM SEMI { enable_relay_name_updates = $3; }
    	| KW_CHECK_ENVELOPE_ADDRESS_FORMAT EQ NUM SEMI { check_envelope_address_format = $3; }
    	| KW_PASS_MAIL_WHEN_DB_UNAVAIL EQ NUM SEMI { pass_mail_when_db_unavail = $3; }
	| NAME EQ NUM SEMI {printf("Warning::::: %s variable not understood-- ignoring\n", $1);}
	| NAME EQ STR SEMI {printf("Warning::::: %s variable not understood-- ignoring\n", $1);}
	| MY {}
	;


%%

relaydelay_error(char *s)
{
	printf("Syntax error in Config file near line %d\n\n", lineno);
}


