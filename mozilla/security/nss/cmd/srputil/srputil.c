/****************************************************************************
 *  SRP util manipulates the srp verifier database needed for client
 *  authentication
 ****************************************************************************/

/* Generic header files */

#include <stdio.h>
#include <string.h>
#include <memory.h>

/* NSPR header files */

#include "nspr.h"
#include "plgetopt.h"
#include "prerror.h"
/*#include "prnetdb.h"*/
#include "plbase64.h"
#include "plhash.h"
#include "prlong.h"

/* NSS header files */

/*#include "pk11func.h" */
#include "secitem.h"
#include "secutil.h"
/*#include "ssl.h" */
#include "nss.h"
/*#include "secder.h"*/
/*#include "key.h"*/
/*#include "sslproto.h" */
#include "blapi.h"
#include "secrng.h"
#include "sechash.h"

#include "srputil.h"

/* buffer of 2048 reads at least one full line of the file */
#define buflen 2048
/* default group size*/
#define defgroup 8192


typedef enum { c_add, c_del, c_cpw, c_nil} actionCmd;

typedef struct SRPParamStr{
    SECItem    u; /* username      */
    SECItem    p; /* password      */
    SECItem    N; /* modulus       */
    SECItem    g; /* generator     */
    SECItem    s; /* salt          */
    SECItem    v; /* verifier      */
    int    group; /* group size    */
} SRPParams;


static void
Usage(const char *progName)
{
	fprintf(stderr, 
"Usage: %s [-g size] [-p pwd] {-a|-d|-r|-f} <-u user> <-s vfile>\n"
""
"-a\tadd user to db\n"
"-d\tremove user from db\n"
"-c\treset user password\n"
"-g size\tset group size\n"
"       \tvalid sizes: 1024,1536,2048,3072,4096,6144,8192\n"
"-u user\tuser to operate on\n"
"-p pwd\tuser password\n"
"-s vfile\tverifier database to use\n"
"",
	progName);
	exit(1);
}


/* 
 * Search srpvfile for user, read in users auth parameters
 *
 * file format:
 * \nusername\tgroupsize\tBase64(verifier)\tBase64(salt)
 *
 * -1 error parsing file, exit
 *  0 username not found
 *  1 username found
 */

int
getUserData(SRPParams * srp,PRFileDesc * srpvfile) {

    char * uname    = NULL;
    char * tmp      = NULL;
    char * pos      = NULL;
    char * verifier = NULL; /* parameters to be read */
    char * salt     = NULL;
    char buffer[buflen];
    unsigned int i,bytes;
    unsigned int ulen=srp->u.len;
    
    uname = PORT_Alloc(3+ulen);

    uname[0] = '\n';
    PORT_Memcpy(uname+1,srp->u.data,ulen);
    uname[ulen+1] = '\t';
    uname[ulen+2] = '\0';

    while ( (bytes = PR_Read(srpvfile,buffer,buflen-1)) ) {
        buffer[bytes] = '\0';
        if ((pos = PL_strstr(buffer,uname))) {
            /* move to begin of user name, read at least one line to buffer */
            PR_Seek(srpvfile,(-1)*buflen+(pos-buffer)+1,SEEK_CUR);
            PR_Read(srpvfile,buffer,buflen);

            tmp = buffer; i = 0;
            while (tmp[i] != '\t') i++;
            tmp[i] = '\0';
            srp->group = PORT_Atoi(tmp);

            tmp+=i+1; i = 0;
            while (tmp[i] != '\t') i++;
            tmp[i] = '\0';
            verifier = PL_strdup(tmp);

            tmp+=i+1; i = 0;
            while (tmp[i] != '\n') i++;
            tmp[i] = '\0';
            salt = PL_strdup(tmp);
            
            break;
        } else {
             /* exit if at EOF */
            if (bytes <= ulen+3)
                return 0;
            /* else, wrap position and continue search.. */
            PR_Seek(srpvfile,(-1)*(ulen+3),SEEK_CUR);
        }
    }

    if (verifier) {
        SECITEM_AllocItem(NULL,&srp->v,PL_strlen(verifier)*3/4);
        SECITEM_AllocItem(NULL,&srp->s,PL_strlen(salt)*3/4);
    

        PL_Base64Decode(verifier,0,(char *)srp->v.data);
        PL_Base64Decode(salt,0,(char *)srp->s.data);
    
        verifier[20]='\0';

        return 1;
    } else
        return 0;
}

/* Delete an entry from the database
 *
 * removes chars until and including line end
 */
int
delUserParams(PRFileDesc * srpvfile)
{
    /*XXX missing delete-function */
    return -1;
    return 0;
}

/* Add a user to the database
 *
 * - get group parameters
 * - generate salt
 * - generate pw-hash
 * - generate verifier
 * - save verifier+salt
 */
void
addUserParams(SRPParams * srp, const PRFileDesc * srpvfile)
{
    SHA1Context *ctx    = NULL;
    SECItem     *pwhash = NULL;
    char        *buffer = NULL;
    char        *tmp    = NULL;
    int         bytes   = 0;
    unsigned int         len;
    SECStatus   rv;

    /* group parameters */
    SECITEM_AllocItem(NULL,&srp->N,srp->group/8);
    SECITEM_AllocItem(NULL,&srp->g,1);
    
    printf("add user, group sizze %d\n",srp->group);
    switch (srp->group) {
        case 1024:
            PL_Base64Decode(SRP_GROUPS_N[0],0,(char *)srp->N.data);
            srp->g.data[0] = 0x02;
            break;
        case 1536:
            PL_Base64Decode(SRP_GROUPS_N[1],0,(char *)srp->N.data);
            srp->g.data[0] = 0x02;
            break;
        case 2048:
            PL_Base64Decode(SRP_GROUPS_N[2],0,(char *)srp->N.data);
            srp->g.data[0] = 0x02;
            break;
        case 3072:
            PL_Base64Decode(SRP_GROUPS_N[3],0,(char *)srp->N.data);
            srp->g.data[0] = 0x05;
            break;
        case 4096:
            PL_Base64Decode(SRP_GROUPS_N[4],0,(char *)srp->N.data);
            srp->g.data[0] = 0x05;
            break;
        case 6144:
            PL_Base64Decode(SRP_GROUPS_N[5],0,(char *)srp->N.data);
            srp->g.data[0] = 0x05;
            break;
        case 8192:
            PL_Base64Decode(SRP_GROUPS_N[6],0,(char *)srp->N.data);
            srp->g.data[0] = 0x13;
            break;
        default:
            fprintf(stderr,"Invalid group size %d\n",srp->group);
            exit(1);
    }
    /* generate salt if we have to, 256 byte */
    if (!srp->s.data) {
        if (!SECITEM_AllocItem(NULL,&srp->s,SHA1_LENGTH))
            goto no_mem;

        rv = RNG_RNGInit();
        RNG_SystemInfoForRNG();
        rv += RNG_GenerateGlobalRandomBytes(srp->s.data,srp->s.len);
        if (rv != SECSuccess) {
            fprintf(stderr,"Error: Random generator initialization failed.\n");
            exit(1);
        }
    }
    
    /* create verifier if we have to */
   if (!srp->v.data) {

        /* pwhash = SHA1(s|SHA1(user|":"|pwd)) */

        if (!(pwhash = SECITEM_AllocItem(NULL,NULL,SHA1_LENGTH)))
            goto no_mem;

        ctx = SHA1_NewContext();
        SHA1_Begin(ctx);
        SHA1_Update(ctx, srp->u.data, srp->u.len);
        SHA1_Update(ctx,(unsigned char *)":",1);
        SHA1_Update(ctx, srp->p.data, srp->p.len);
        SHA1_End(ctx,pwhash->data,&len,SHA1_LENGTH);
        SHA1_Begin(ctx);
        SHA1_Update(ctx, srp->s.data, srp->s.len);
        SHA1_Update(ctx, pwhash->data, pwhash->len);
        SHA1_End(ctx, pwhash->data, &len, SHA1_LENGTH);
        SHA1_DestroyContext(ctx, PR_TRUE);

        /* compute verifier, DH_Derive allocates memory */
        rv = DH_Derive(&srp->g, &srp->N, pwhash, &srp->v, 0);
        
        
    }
    printf("group sizze %d\n",srp->group);

    /* write \nuser\tgroup\tBase64(verifier)\tBase64(salt)\n to file,
     * deleting the last \n. */

    buffer = PORT_ZAlloc(buflen);
    buffer[0] = '\n';
    PORT_Memcpy(buffer+1,srp->u.data,srp->u.len);
    tmp = buffer + 1 + srp->u.len;
    bytes = sprintf(tmp,"\t%d\t",srp->group);
    tmp+=bytes;
    PL_Base64Encode((char *)srp->v.data,srp->v.len,tmp);
    PORT_Strcat(tmp,"\t");
    tmp += PORT_Strlen(tmp);
    PL_Base64Encode((char *)srp->s.data,srp->s.len,tmp);
    tmp += PORT_Strlen(tmp);
    bytes = sprintf(tmp,"\n");
    tmp+=bytes;

    PR_Seek(srpvfile,0,SEEK_END);
    bytes = PR_Write(srpvfile, buffer, (unsigned int)tmp-(unsigned int)buffer);

    if (bytes != tmp-buffer) {
        fprintf(stderr,"Error writing to file. File corruption likely.\n");
        exit(1);
    }
    return;

no_mem:
    fprintf(stderr,"Error: No memory.\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    int                 group         = 0;
	char *              progName      = NULL;
	char *              username      = NULL;
    char *              srpvfilename  = NULL;
    char *              password      = NULL;
    PRFileDesc *        srpvfile      = NULL;
    SRPParams *         srp           = NULL;
    actionCmd           cmd           = c_nil;
    SECStatus           rv            = 0;
	PLOptStatus         status        = PL_OPT_BAD;
	PLOptState *        optstate      = NULL;

	progName     = PL_strdup(argv[0]);

    if (argc < 3 ) {
        Usage(progName);
    }
	
	optstate = PL_CreateOptState(argc, argv, "g:adrcs:u:p:");
	while ((status = PL_GetNextOpt(optstate)) == PL_OPT_OK) {
		switch(optstate->option) {
		case 'a': cmd = c_add;   break;
		case 'd': cmd = c_del;   break;
		case 'c': cmd = c_cpw;   break;
		case 'g': group = PORT_Atoi(optstate->value);        break;
		case 'u': username = PL_strdup(optstate->value);     break;
		case 's': srpvfilename = PL_strdup(optstate->value); break;
		case 'p': password = PL_strdup(optstate->value);     break;
		default:
		case '?': Usage(progName);
		}
	}

    printf("action: %d, user: %s, group size %d\n", cmd, username, group);

    srp = PORT_ZAlloc(sizeof(SRPParams));

    if (cmd == c_add)
        srpvfile = PR_Open(srpvfilename, PR_RDWR|PR_CREATE_FILE, PR_IRUSR | PR_IWUSR);
    else
        srpvfile = PR_Open(srpvfilename, PR_RDWR, 0);



    /* check of set of given parameters is consistent */
    if (!srpvfile) {
        fprintf(stderr,"srputil: Unable to open SRP verifier file %s\n",
                srpvfilename);
        return 1;
    }
    if (username) {
        srp->u.len = PORT_Strlen(username);
        srp->u.data = (unsigned char *)username;
        username = NULL;
    } else {
        fprintf(stderr,"Error: No username specified.\n");
        exit(1);
    }
    if ((cmd == c_add || cmd == c_cpw ) && password) {
        srp->p.len = PORT_Strlen(password);
        srp->p.data = (unsigned char *)password;
        password = NULL;
    } else {
        fprintf(stderr,"Error: No password specified.\n");
        exit(1);
    }
    if (srp->u.len > 255) {
        fprintf(stderr,"Error: SRP does not allow usernames longer than 255 byte.\n");
        exit(1);
    }
    if (-1 == (rv = getUserData(srp, srpvfile))) {
        fprintf(stderr,"Error: Unable to parse file.\n");
        exit(1);
    }
    if (rv == 1 && cmd != c_add) {
        fprintf(stderr,"Error: User does not exist.\n");
        exit(1);
    }
    if (rv == 1 && cmd == c_add) {
        fprintf(stderr,"Error: User already exists.\n");
        exit(1);
    }

    switch (cmd) {
        case c_add:
            if (group)
                srp->group = group;
            else
                srp->group = defgroup;
            addUserParams(srp, srpvfile);
            break;
        case c_del:
            delUserParams(srpvfile);
            break;
        case c_cpw:
            /* addUserParams will act based on these changes */
            if (group)
                srp->group = group;
            SECITEM_FreeItem(&srp->v,PR_FALSE);
            SECITEM_FreeItem(&srp->s,PR_FALSE);
            delUserParams(srpvfile);
            addUserParams(srp, srpvfile);
            break;
        default:
        case c_nil:
            fprintf(stderr,"\nError: None of {-a|-c|-r|-f} were specified.\n");
            break;
    }
	return 0;
}

