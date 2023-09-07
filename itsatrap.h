#include <stdint.h>
#include <stdio.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/agent_trap.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#define MAX_TRAPS 1024
#define MAX_TRPM1 1023

unsigned char securestr[]="7a`y%w6evZ_30fPlkXpTBDKp]?TFvoQ[AG}mt7|;U5e32lShqAPE8.B$%7{lyD]";

typedef struct _result_record {
 unsigned char result_string[256];
 unsigned char result_value[32];
} result_record;

typedef struct _cmdtrap {
 oid objectid[16];
 unsigned char oidnr;
 unsigned char oidstr[256];
 unsigned char vault[256];
 unsigned char vaultfile[256];
 unsigned char keystring[256];
 unsigned char community[32];
 unsigned char commands[8127];
 unsigned char snmpon;
 result_record results[256];
 unsigned char resultsnum;
 uint32_t seconds;
 pthread_t thread;
} cmdtrap;

typedef struct _cfgtrap {
 oid fail_oid[16];
 unsigned char foidnr;
 unsigned char foidstr[256];
 unsigned char ipstr1[48];
 unsigned char ipstr2[48];
 int restport;
} cfgtrap;

