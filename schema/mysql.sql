
#######################################################################
# Database definitions
#######################################################################

# Using Mysql 3.23.2 or later (required for NULLs allowed in indexed fields)

CREATE DATABASE relaydelay;

# Use something like this to create a user that can use the relaydelay database (change for your login info)
grant select,insert,update,delete on relaydelay.* to db_user@'localhost' identified by 'db_pass';

# Use something like this to remove a user from the db
#revoke all on relaydelay.* from db_user@'localhost';

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
        origin_type     enum('MANUAL','AUTO') NOT NULL,                 # indicates the origin of this record (auto, or manual)
        create_time     datetime        NOT NULL,                       # timestamp of creation time of this record
        last_update     timestamp       NOT NULL,                       # timestamp of last change to this record (automatic)

        primary key(id),
        key(relay_ip),
        key(mail_from(20)),                                             # To keep the index size down, only index first 20 chars
        key(rcpt_to(20))
);

# This is just an exact duplicate of the relaytofrom table with a different name for reporting purposes
create table relayreport     # Stores settings for each [relay, to, from] triplet
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
        origin_type     enum('MANUAL','AUTO') NOT NULL,                 # indicates the origin of this record (auto, or manual)
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
#create table mail_log        # Stores a record for every mail delivery attempt
#(
#        id              bigint          NOT NULL        auto_increment, # unique log entry id
#        relay_ip        varchar(16)     NOT NULL,                       # sending relay in IPV4 ascii dotted quad notation
#        relay_name      varchar(255),                                   # sending relay dns name
#        dns_mismatch    bool            NOT NULL,                       # true if does not match, false if matches or no dns
#        mail_from       varchar(255)    NOT NULL,                       # the mail from: address
#        rcpt_to         varchar(255)    NOT NULL,                       # the rcpt to: address
#        rcpt_host       varchar(80)     NOT NULL,                       # the id (hostname) of the host that generated this row
#        create_time     datetime        NOT NULL,                       # timestamp of inserted time, since no updates
#
#        primary key(id),
#        key(relay_ip),
#        key(mail_from(20)),
#        key(rcpt_to(20))
#);

############################################################################
#
# EVERYTHING AFTER HERE IS JUST EXAMPLE QUERIES TO DO SIMPLE REPORTING
# OR MAINTENANCE QUERIES AGAINST THE DATABASE.  THESE ARE NOT REQUIRED
# FOR SETTING UP THE DATABASE STRUCTURE.
#
############################################################################

# Example wildcard whitelists for subnets
#INSERT INTO relaytofrom (relay_ip, record_expires, create_time) VALUES ('192.168', '9999-12-31 23:59:59', NOW());

# Example wildcard whitelist entry for a received domain or subdomain
#INSERT INTO relaytofrom (rcpt_to, record_expires, create_time) VALUES ('example.domain.com', '9999-12-31 23:59:59', NOW());

# interesting queries for reporting on db contents
# get the delay time of the most persistant non-passed mails, in 5 minute buckets
#select convert((UNIX_TIMESTAMP( last_update ) - UNIX_TIMESTAMP( create_time )) / 300, unsigned) as foo, count(*) from relaytofrom where record_expires < NOW() and blocked_count > 0 and passed_count = 0 and aborted_count = 0 and last_update > 0 group by foo order by foo;

# look at most prolific passed email counts of mail by delivering ip address (subnet)
#select sum(passed_count) as num, substring_index(relay_ip, '.', 3) as net, mail_from, rcpt_to from relaytofrom where passed_count > 0 group by substring_index(relay_ip, '.', 3) order by num desc limit 100;

# look at most prolific blocked email counts by subnet
#select sum(blocked_count) as num, substring_index(relay_ip, '.', 3) as net, mail_from, rcpt_to from relaytofrom where passed_count = 0 group by substring_index(relay_ip, '.', 3) order by num desc limit 100;

# Look at number of unique triplets as relates to number of passed and blocked emails grouped by ip.
#select count(*) as mails,relay_ip,sum(blocked_count) as blocked,sum(passed_count) as passed from relaytofrom group by relay_ip order by blocked;

# Interesting to identify likely recurrent spammers that get through (may be legit tho) 
# (only useful after a decent amount of runtime)
#select count(*) as num,relay_ip,mail_from,rcpt_to,create_time,sum(blocked_count),sum(passed_count),sum(aborted_count) from relaytofrom where passed_count = 1 group by left(reverse(mail_from),10) order by num;

# Useful to find relays that should be manually whitelisted (if trusted) because of VERP with email tracking
#   but this can also be useful to find semi-legit spammers that don't change ip's.
#select count(*) as num, relay_ip from relaytofrom where passed_count = 1 group by substring_index(relay_ip, '.', 3) order by num;

# WARNING - the following queries that use a. and b. prefixes are very
# long-running, since they are basically cross products.  Be prepared for it
# to run several minutes, and slow down significantly as the db grows.
# Also, they are pretty complicated, and I probably am missing something
# that could make them better, but oh well.

# Look at emails with same from and to addrs, but different ips (usually spammers using distributed zombies)
#select a.id, a.relay_ip, b.relay_ip, sum(a.blocked_count) / count(*) as blkd, sum(a.passed_count) / count(*) as pass, a.mail_from, a.rcpt_to from relaytofrom a, relaytofrom b where a.mail_from = b.mail_from and a.rcpt_to = b.rcpt_to and a.id < b.id and a.relay_ip!= b.relay_ip and a.origin_type = 'AUTO' and b.origin_type = 'AUTO' group by a.id order by a.mail_from;

# Look at emails with same from and to, but create times that differ by at least 5 min
#select a.id, a.relay_ip, b.relay_ip, sum(a.blocked_count) / count(*) as blkd, sum(a.passed_count) / count(*) as pass, abs(time_to_sec(a.create_time) - time_to_sec(b.create_time)) as diffcreate, a.mail_from, a.rcpt_to from relaytofrom a, relaytofrom b where a.mail_from = b.mail_from and a.rcpt_to = b.rcpt_to and a.id < b.id and a.relay_ip != b.relay_ip and a.origin_type = 'AUTO' and b.origin_type = 'AUTO' and abs(time_to_sec(a.create_time) - time_to_sec(b.create_time)) > 300 and a.aborted_count = 0 and b.aborted_count = 0 group by a.id order by a.mail_from; 


