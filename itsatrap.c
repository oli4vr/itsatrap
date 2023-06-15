#include "itsatrap.h"
#include "entropy.h"
#include "inifind.h"

unsigned char basepath[256]={0};

cmdtrap *traps[MAX_TRAPS]={NULL};
int trapc=0;

cfgtrap cfg;

unsigned char stopsrc=0;

int str2oid(unsigned char * in, oid * out) {
 int len=strnlen(in,32);
 int n=0;
 int nr=0;
 unsigned char *p=in;
 unsigned char ns[16];
 unsigned char *t=ns;
 unsigned char prev=0;
 for(;n<=len;n++) {
  if (*p!='.' && *p!=0 && (*p<'0' || *p>'9'))
  { return -1;}
  if (*p!='.' && *p!=0) {
   *t=*p;
   t++;
  } else if (prev!='.') {
   *t=0;
   *out=atoi(ns);
   nr++;
   out++;
   t=ns;
  }
  prev=*p;
  p++;
 }
 return nr;
}

int oid2str(oid * in, unsigned char len, unsigned char * out) {
 int n=1;
 unsigned char tmp1[256]={0};
 unsigned char tmp2[256]={0};
 if (len<2) return -1;
 snprintf(tmp1,256,"%ld",*in);
 for(;n<len;n++) {
    snprintf(tmp2,256,"%s.%ld",tmp1,in[n]);
    memcpy(tmp1,tmp2,256);
 }
 strncpy(out,tmp1,256);
 return n;
}


cmdtrap * manifest_nexttrap(unsigned char ** inbuff, unsigned char * tpath, unsigned char mode) {
    unsigned char tmp[256]={0};
    unsigned char vault[256]={0};
    unsigned char vaultfile[256]={0};
    unsigned char keystring[256]={0};
    unsigned char community[32]={0};
    unsigned char commands[8127]={0};
    uint32_t seconds;
    unsigned char * buffer=*inbuff;
    unsigned char * c=buffer, * p=buffer;
    long int offset;
    int rc;
    cmdtrap * rctrap;
    FILE* fp;

    while (*c=='\n') {c++;} ; p=c;
    while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(vault,p,256);
    snprintf(vaultfile,256,"%s/.trap.%s.entropy",tpath,vault);
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(keystring,p,256);
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(community,p,32);
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(tmp,p,256);
    tmp[255]=0;
    seconds=atoi(tmp);
    if (seconds < 1) return NULL;
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    if (mode==0) {
        strncpy(tmp,p,256);
        tmp[255]=0;
        fp=fopen(tmp,"r+b");
        if (fp==NULL) return NULL;
        rc=fread(commands,1,8126,fp);
        if (rc<1) return NULL;
        fclose(fp);
    } else {
        offset=entropy_search(commands,keystring,securestr,vaultfile,2);
        if (offset<0) return NULL;
    }
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(tmp,p,256);

    c++;*inbuff=c;

    rctrap=malloc(sizeof(cmdtrap));
    memcpy(rctrap->oidstr,tmp,256);
    rctrap->oidstr[255]=0;
    rctrap->oidnr=str2oid(tmp,rctrap->objectid);
    memcpy(rctrap->vaultfile,vaultfile,256);
    memcpy(rctrap->vault,vault,256);
    memcpy(rctrap->keystring,keystring,256);
    memcpy(rctrap->community,community,32);
    memcpy(rctrap->commands,commands,8127);
    rctrap->seconds=seconds;
    return rctrap;
}

void cleanup_manifesto() {
    int n=0;
    cmdtrap ** cp=traps;
    for(;n<MAX_TRAPS;n++) {
        if (*cp!=NULL) {free(*cp); *cp=NULL;}
        cp++;
    }
    trapc=0;
}

int print_cmdtrap(cmdtrap * c) {
    unsigned char tmp[256];
    if (c==NULL) {fprintf(stderr,"NULL\n");return -1;}
    oid2str(c->objectid,c->oidnr,tmp);
    fprintf(stderr,"OID    = %s\n",tmp);
    fprintf(stderr,"Vault  = %s\n",c->vault);
    fprintf(stderr,"Vaultf = %s\n",c->vaultfile);
    fprintf(stderr,"Keystr = %s\n",c->keystring);
    fprintf(stderr,"Commun = %s\n",c->community);
    fprintf(stderr,"Seconds= %d\n",c->seconds);
    fprintf(stderr,"Cmd    = \n#####\n%s\n#####\n",c->commands);
    return 0;
}

int generate_manifesto(unsigned char * fname, unsigned char * tpath) {
    FILE * fp;
    int rc,n;
    unsigned char csvfile[MESSAGE_SIZE]={0};
    unsigned char buffer[MESSAGE_SIZE]={0};
    unsigned char *bp=buffer;
    unsigned char dvault[256];
    cmdtrap * cp;
    mkdir(tpath,S_IRWXU);

    cleanup_manifesto();

    fp=fopen(fname,"r+b");
    if (fp==NULL) return -1;

    rc=fread(buffer,1,MESSAGE_SIZE,fp);
    fclose(fp);

    //fprintf(stderr,"%s\n",buffer);
    if (rc<1) return -2;
    buffer[MESSAGE_SIZE-1]=0;
    
    memcpy(csvfile,buffer,MESSAGE_SIZE);

    traps[trapc]=manifest_nexttrap(&bp,tpath,0);
    cp=traps[trapc];
    trapc++;
    while (cp!=NULL) {
        cp=traps[trapc];
        traps[trapc]=manifest_nexttrap(&bp,tpath,0);
        cp=traps[trapc];
        trapc++;
    }
    trapc--;
    // Determine default vault file + remove existing + generate new one
    snprintf(dvault,256,"%s/.trap.default.entropy",tpath);
    remove(dvault);
    rc=entropy_append(csvfile,"manifest.csv",securestr,dvault,16);

    for(n=0;n<trapc;n++) {
        cp=traps[n];
        remove(cp->vaultfile);
        //fprintf(stderr,"%s\n",cp->vaultfile);
        if (cp!=NULL)
            rc=entropy_append(cp->commands,cp->keystring,securestr,cp->vaultfile,2); 
    }
    return trapc;
}

int load_manifesto(unsigned char * spath) {
    FILE * fp;
    int rc,n;
    long int offset;
    unsigned char buffer[MESSAGE_SIZE]={0};
    unsigned char *bp=buffer;
    unsigned char dvault[256];
    cmdtrap * cp;

    cleanup_manifesto();

    snprintf(dvault,256,"%s/.trap.default.entropy",spath);

    offset=entropy_search(buffer,"manifest.csv",securestr,dvault,16);
    if (offset<0) return -1;

    //fprintf(stderr,"%s\n",buffer);
    buffer[MESSAGE_SIZE-1]=0;
    
    traps[trapc]=manifest_nexttrap(&bp,spath,1);
    cp=traps[trapc];
    trapc++;
    while (cp!=NULL) {
        //print_cmdtrap(cp);
        cp=traps[trapc];
        traps[trapc]=manifest_nexttrap(&bp,spath,1);
        cp=traps[trapc];
        trapc++;
    }
    trapc--;

    for(n=0;n<trapc;n++) {
        cp=traps[n];
        //print_cmdtrap(cp);
        //fprintf(stderr,"%s\n",cp->vaultfile);
    }
    return trapc;
}

int send_trap(cmdtrap * c,unsigned char * rcstr, unsigned char * outstr, unsigned char * ip) {
    netsnmp_session session, *ss;
    netsnmp_pdu    *pdu, *response;
    oid trap_oid[] = {1,3,6,1,6,3,1,1,4,1,0};

    snmp_sess_init( &session );

    session.version = SNMP_VERSION_2c;
    session.community = c->community;
    session.community_len = strnlen(c->community,32);
    session.peername=ip;

    ss = snmp_open(&session);
    
    if (!ss) {
      snmp_sess_perror("ack", &session);
      return -2;
    }

    pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    pdu->community = c->community;
    pdu->community_len = strnlen(c->community,32);
    pdu->trap_type = SNMP_TRAP_ENTERPRISESPECIFIC;

    snmp_add_var(pdu, trap_oid, OID_LENGTH(trap_oid), 'o', c->oidstr);
    snmp_add_var(pdu, c->objectid, c->oidnr , 'i', rcstr);
    snmp_add_var(pdu, c->objectid, c->oidnr , 's', outstr);

    send_trap_to_sess (ss, pdu);
    snmp_close(ss);
    
    return (0);
}

int exec_trap(cmdtrap * c) {
    int rc;
    unsigned char sz=sizeof(oid);
    unsigned char buffer[MESSAGE_SIZE+1]={0};
    unsigned char *sp=buffer;
    unsigned char neof=1;
    unsigned char *rcstr, *outstr;

    FILE * pipe;

    pipe=popen(c->commands,"r");
    if (pipe==NULL) return -1;
    rc=fread(buffer,1,MESSAGE_SIZE,pipe);
    pclose(pipe);

    while (neof) {
        rcstr=sp;
        while (*sp!=' ') {if (*sp==0) return 0; sp++;}
        *sp=0; sp++;
        outstr=sp;
        while (*sp!=10 && *sp!=0) {sp++;}
        if (*sp==0) neof=0;
        *sp=0; sp++;
        if (cfg.ipstr1[0]!=0)
            rc=send_trap(c,rcstr,outstr,cfg.ipstr1);
        if (cfg.ipstr2[0]!=0)
            rc=send_trap(c,rcstr,outstr,cfg.ipstr2);
    }

    return (rc);
}

int ini_loadcfg(cfgtrap * c,unsigned char * inifile) {
    int rc;
    unsigned char tmp[256];
    rc=findini(inifile,"General","ServerIP1",c->ipstr1);
    if (rc<1) c->ipstr1[0]=0;
    rc=findini(inifile,"General","ServerIP2",c->ipstr2);
    if (rc<1) c->ipstr2[0]=0;

}

void * itsathread(void * data) {
    int rc=0;
    cmdtrap * c=data;
    sleep(rand()&7);
    while(!stopsrc) {
        rc=exec_trap(c);
        sleep(c->seconds);
    }
}


int main(int argc, char ** argv) {

    int rc;
    int n;
    pthread_t *thr;
    FILE * fp;
    unsigned char cfgpath[256]={0};

    unsigned char badsyntax=0;
    unsigned char * argp;
    unsigned char tmp[256];

    unsigned char runmode=0;
    // 0 normal daemon
    // 1 build manifest

    snprintf(basepath,256,"%s/.itsatrap", getpwuid(getuid())->pw_dir);
    mkdir(basepath,S_IRWXU);
    snprintf(cfgpath,256,"%s/itsatrap.cfg",basepath);


    if (fp=fopen(cfgpath,"r")) {
        fclose(fp);
    } else {
        fp=fopen(cfgpath,"w");
        fprintf(fp,"[General]\n");
        fprintf(fp,"ServerIP1 = 127.0.0.1:162\n");
        fclose(fp);
    }
    rc=ini_loadcfg(&cfg,cfgpath);

    argc--;argv++;  
    while(argc>0 && badsyntax==0) {
        argp=argv[0];
        if (*argp=='-') {
            switch (argp[1]) {
                case 'b':
                 runmode=1;
                 argc--;
                 argv++;
                 argp=argv[0];
                 if (argc<1) {badsyntax=1;}
                 else {
                    rc=generate_manifesto(argp, basepath);
                    if (rc<0) {
                        fprintf(stderr,"Error generating manifest\n");
                        return -1;
                    }
                    cleanup_manifesto();
                    fprintf(stderr,"Manifest file generated in %s\n",basepath);
                    return 0;
                 }
                 break;
                case 'h':
                 badsyntax=2;
                 break;
            }
        }
        argv++;
    }

    if (badsyntax>0) {
        fprintf(stderr,"itsatrap\n by Olivier Van Rompuy\n\nSyntax :\n");
        fprintf(stderr,"itsatrap [-b csv_file]\n");
        return 1;
    }

    rc=load_manifesto(basepath);
    if (rc<1) {
        fprintf(stderr,"Error loading manifesto\n");
        return -2;
    }
    //fprintf(stderr,"RC=%d\n",rc);

    // Generate a separate scheduling thread for each configured cmdtrap
    for(n=0;n<trapc;n++) {
        thr=&(traps[n]->thread);
        pthread_create(thr,NULL,itsathread,(void*) traps[n]);
        pthread_detach(*thr);
    }

    while (!stopsrc) {
        sleep(30);
    }

    pthread_exit(0);
    return 0;
}

