
#######################################################################
# Database definitions
#######################################################################

# Using Mysql 3.23.2 or later (required for NULLs allowed in indexed fields

## Note: Feed this into mysql, while logged in as mysql root user. You can
##       use the source command. Please Edit this file first!

## NOTE: DO NOT just feed this data into mysql unedited! The white/black list stuff at the
## needs to removed or edited! Change the password for milter below or suffer the security
## consequences!

CREATE DATABASE relaydelay;
grant select,insert,update,delete,lock tables on relaydelay.* to milter@"localhost" identified by 'milter';

USE relaydelay;

# NOTE: We allow nulls in the 3 "triplet" fields for manual white/black listing.  A null indicates that that field 
#   should not be considered when looking for a match.  Automatic entries will always have all three populated.
# Note: Since we index the triplet fields, and allow them to be null, this requires at least Mysql 3.23.2 and MYISAM
#   tables.
create table relaytofrom     # Stores settings for each [relay, to, from] triplet
(
        id              bigint          NOT NULL        auto_increment, # unique triplet id
        relay_ip        char(16),                                       # sending relay in IPV4 ascii dotted quad notation
        mail_from       varchar(255),                                   # ascii address of sender
        rcpt_to         varchar(255),                                   # the recipient address.
        block_expires   datetime        NOT NULL,                       # the time that an initial block will/did expire
        record_expires  datetime        NOT NULL,                       # the date after which this record is ignored
        
        blocked_count   bigint          default 0 NOT NULL,             # num of blocked attempts to deliver
        passed_count    bigint          default 0 NOT NULL,             # num of passed attempts we have allowed
        aborted_count   bigint          default 0 NOT NULL,             # num of attempts we have passed, but were later aborted
        origin_type     enum("MANUAL","AUTO") NOT NULL,                 # indicates the origin of this record (auto, or manual)
        create_time     datetime        NOT NULL,                       # timestamp of creation time of this record
        last_update     timestamp       NOT NULL,                       # timestamp of last change to this record (automatic)

        primary key(id),
        key(relay_ip),
        key(mail_from(20)),                                             # To keep the index size down, only index first 20 chars
        key(rcpt_to(20))
);

create table dns_name        # Stores the reverse dns name lookup for records
(
       relay_ip      varchar(18)       NOT NULL,
       relay_name    varchar(255)      NOT NULL,                       # dns name, stored in reversed character order (for index)
       last_update   timestamp         NOT NULL,                       # timestamp of last change to this record (automatic)
       primary key(relay_ip),
       key(relay_name(20))
);

# This table is not used yet, possibly never will be
create table mail_log        # Stores a record for every mail delivery attempt
(
        id              bigint          NOT NULL        auto_increment, # unique log entry id
        relay_ip        varchar(16)     NOT NULL,                       # sending relay in IPV4 ascii dotted quad notation
        relay_name      varchar(255),                                   # sending relay dns name
        dns_mismatch    bool            NOT NULL,                       # true if does not match, false if matches or no dns
        mail_from       varchar(255)    NOT NULL,                       # the mail from: address
        rcpt_to         varchar(255)    NOT NULL,                       # the rcpt to: address
        rcpt_host       varchar(80)     NOT NULL,                       # the id (hostname) of the host that generated this row
        create_time     datetime        NOT NULL,                       # timestamp of inserted time, since no updates

        primary key(id),
        key(relay_ip),
        key(mail_from(20)),
        key(rcpt_to(20))
);


## NOTE: any addresses or IP's in this file are fictional. Any correspond to real IP's or addresses are unintentional and accidental!


# Example wildcard whitelists for subnets
insert into relaytofrom values (0,"127.0.0.1"   ,NULL,NULL,"0000-00-00 00:00:00","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());
insert into relaytofrom values (0,"192.168"     ,NULL,NULL,"0000-00-00 00:00:00","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());

# Example whitelist entry for a recipient  -- don't delay stuff headed to nosense...
insert into relaytofrom values (0,NULL,NULL,"nosense@ourfacility.com","0000-00-00 00:00:00","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());

# Example whitelist entry for a sender -- anything from these addresses will never be delayed
insert into relaytofrom values (0,NULL,"taxrefund@irs.gov",NULL,"0000-00-00 00:00:00","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());


# Example Blacklist entry for subnets  -- delay things forever from these ip's
insert into relaytofrom values (0,"65.61.136"   ,NULL,NULL,"9999-12-31 23:59:59","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());


# Example Blacklist entry for a recipient (delay everything forever going to this person)
insert into relaytofrom values (0,NULL,NULL,"nosense@ourfacility.com","9999-12-31 23:59:59","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());

# Example Blacklist entry for a sender (nobody want to hear from so-and-so!)
insert into relaytofrom values (0,NULL,"evilspammer@slimeballs.com",NULL,"9999-12-31 23:59:59","9999-12-31 23:59:59",0,0,0,"MANUAL",NOW(),NOW());


