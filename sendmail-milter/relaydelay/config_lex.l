%{
#include "config_gram.tab.h"
int lineno = 1;
%}


%%

\$database_type		{ return KW_DATABASE_TYPE;}
\$verbose		{ return KW_VERBOSE;}
\$delay_mail_secs	{ return KW_DELAY_MAIL_SECS;}
\$database_name		{ return KW_DATABASE_NAME;}
\$database_host		{ return KW_DATABASE_HOST;}
\$database_port		{ return KW_DATABASE_PORT;}
\$database_user		{ return KW_DATABASE_USER;}
\$database_pass		{ return KW_DATABASE_PASS;}
\$auto_record_life_secs	{ return KW_AUTO_RECORD_LIFE_SECS;}
\$update_record_life	{ return KW_UPDATE_RECORD_LIFE;}
\$update_record_life_secs	{ return KW_UPDATE_RECORD_LIFE_SECS;}
\$check_wildcard_relay_ip	{ return KW_CHECK_WILDCARD_RELAY_IP;}
\$check_wildcard_rcpt_to	{ return KW_CHECK_WILDCARD_RCPT_TO;}
\$check_wildcard_mail_from	{ return KW_CHECK_WILDCARD_MAIL_FROM;}
\$tempfail_messages_after_data_phase	{ return KW_TEMPFAIL_MESSAGES_AFTER_DATA_PHASE;}
\$do_relay_lookup_by_subnet	{ return KW_DO_RELAY_LOOKUP_BY_SUBNET;}
\$enable_relay_name_updates	{ return KW_ENABLE_RELAY_NAME_UPDATES;}
\$check_envelope_address_format	{ return KW_CHECK_ENVELOPE_ADDRESS_FORMAT;}
\$pass_mail_when_db_unavail	{ return KW_PASS_MAIL_WHEN_DB_UNAVAIL;}

;	{return SEMI;}
=	{return EQ;}
use	{return USE;}
strict  {return STRICT;}
my	{return MY;}
#.*$	{/* comment to end of line */ }
[0-9]+	{relaydelay_lval.num = atoi(yytext); return NUM;}
\"[^"]*\"	{relaydelay_lval.str = yytext+1; yytext[strlen(yytext)-1]=0;  return STR;}
\'[^']*\'	{relaydelay_lval.str = yytext+1; yytext[strlen(yytext)-1]=0;  return STR;}
[	 \r]*	{}
\n		{lineno++;}
[$0-9A-Za-z_]+	{relaydelay_lval.str = yytext; return NAME; }
%%

yywrap(){return 1;}

