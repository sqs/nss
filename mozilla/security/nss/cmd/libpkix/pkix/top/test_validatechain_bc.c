/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the PKIX-C library.
 *
 * The Initial Developer of the Original Code is
 * Sun Microsystems, Inc.
 * Portions created by the Initial Developer are
 * Copyright 2004-2007 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Contributor(s):
 *   Sun Microsystems, Inc.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/*
 * validateChainBasicConstraints.c
 *
 * Tests Cert Chain Validation
 *
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "pkix_pl_generalname.h"
#include "pkix_pl_cert.h"
#include "pkix.h"
#include "testutil.h"
#include "prlong.h"
#include "plstr.h"
#include "prthread.h"
#include "nspr.h"
#include "prtypes.h"
#include "prtime.h"
#include "pk11func.h"
#include "secasn1.h"
#include "cert.h"
#include "cryptohi.h"
#include "secoid.h"
#include "certdb.h"
#include "secitem.h"
#include "keythi.h"
#include "nss.h"

static void *plContext = NULL;

static
void printUsage(void){
        printf("\nUSAGE: incorrect.\n");
}

static PKIX_PL_Cert *
createCert(char *inFileName)
{
        PKIX_PL_ByteArray *byteArray = NULL;
        void *buf = NULL;
        PRFileDesc *inFile = NULL;
        PKIX_UInt32 len;
        SECItem certDER;
        SECStatus rv;
        /* default: NULL cert (failure case) */
        PKIX_PL_Cert *cert = NULL;

        PKIX_TEST_STD_VARS();

        certDER.data = NULL;

        inFile = PR_Open(inFileName, PR_RDONLY, 0);

        if (!inFile){
                pkixTestErrorMsg = "Unable to open cert file";
                goto cleanup;
        } else {
                rv = SECU_ReadDERFromFile(&certDER, inFile, PR_FALSE);
                if (!rv){
                        buf = (void *)certDER.data;
                        len = certDER.len;

                        PKIX_TEST_EXPECT_NO_ERROR
                                (PKIX_PL_ByteArray_Create
                                (buf, len, &byteArray, plContext));

                        PKIX_TEST_EXPECT_NO_ERROR(PKIX_PL_Cert_Create
                                                (byteArray, &cert, plContext));

                        SECITEM_FreeItem(&certDER, PR_FALSE);
                } else {
                        pkixTestErrorMsg = "Unable to read DER from cert file";
                        goto cleanup;
                }
        }

cleanup:

        if (inFile){
                PR_Close(inFile);
        }

        if (PKIX_TEST_ERROR_RECEIVED){
                SECITEM_FreeItem(&certDER, PR_FALSE);
        }

        PKIX_TEST_DECREF_AC(byteArray);

        PKIX_TEST_RETURN();

        return (cert);
}

int test_validatechain_bc(int argc, char *argv[])
{

        PKIX_TrustAnchor *anchor = NULL;
        PKIX_List *anchors = NULL;
        PKIX_List *certs = NULL;
        PKIX_ProcessingParams *procParams = NULL;
        PKIX_ValidateParams *valParams = NULL;
        PKIX_ValidateResult *valResult = NULL;
        PKIX_PL_X500Name *subject = NULL;
        PKIX_ComCertSelParams *certSelParams = NULL;
        PKIX_CertSelector *certSelector = NULL;

        char *trustedCertFile = NULL;
        char *chainCertFile = NULL;
        PKIX_PL_Cert *trustedCert = NULL;
        PKIX_PL_Cert *chainCert = NULL;
        PKIX_UInt32 chainLength = 0;
        PKIX_UInt32 i = 0;
        PKIX_UInt32 j = 0;
        PKIX_UInt32 actualMinorVersion;
	PKIX_VerifyNode *verifyTree = NULL;
	PKIX_PL_String *verifyString = NULL;

        PKIX_TEST_STD_VARS();

        if (argc < 3){
                printUsage();
                return (0);
        }

        startTests("ValidateChainBasicConstraints");

        PKIX_TEST_EXPECT_NO_ERROR(
            PKIX_PL_NssContext_Create(0, PKIX_FALSE, NULL, &plContext));

        chainLength = (argc - j) - 2;

        /* create processing params with list of trust anchors */
        trustedCertFile = argv[1+j];
        trustedCert = createCert(trustedCertFile);

        PKIX_TEST_EXPECT_NO_ERROR
                (PKIX_PL_Cert_GetSubject(trustedCert, &subject, plContext));

        PKIX_TEST_EXPECT_NO_ERROR
                (PKIX_ComCertSelParams_Create(&certSelParams, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ComCertSelParams_SetBasicConstraints
                    (certSelParams, -1, plContext));

        PKIX_TEST_EXPECT_NO_ERROR
                (PKIX_CertSelector_Create
                (NULL, NULL, &certSelector, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_CertSelector_SetCommonCertSelectorParams
                                    (certSelector, certSelParams, plContext));

        PKIX_TEST_DECREF_BC(subject);

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_TrustAnchor_CreateWithCert
                                    (trustedCert, &anchor, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_List_Create(&anchors, plContext));
        PKIX_TEST_EXPECT_NO_ERROR
                (PKIX_List_AppendItem
                (anchors, (PKIX_PL_Object *)anchor, plContext));
        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ProcessingParams_Create
                                    (anchors, &procParams, plContext));

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ProcessingParams_SetRevocationEnabled
                                    (procParams, PKIX_FALSE, plContext));

        PKIX_TEST_EXPECT_NO_ERROR
                    (PKIX_ProcessingParams_SetTargetCertConstraints
                    (procParams, certSelector, plContext));

        PKIX_TEST_DECREF_BC(certSelector);

        /* create cert chain */
        PKIX_TEST_EXPECT_NO_ERROR(PKIX_List_Create(&certs, plContext));
        for (i = 0; i < chainLength; i++){
                chainCertFile = argv[i + (2+j)];
                chainCert = createCert(chainCertFile);

                PKIX_TEST_EXPECT_NO_ERROR(PKIX_List_AppendItem
                        (certs, (PKIX_PL_Object *)chainCert, plContext));

                PKIX_TEST_DECREF_BC(chainCert);
        }

        /* create validate params with processing params and cert chain */
        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ValidateParams_Create
                                    (procParams, certs, &valParams, plContext));


        /* validate cert chain using processing params and return valResult */

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ValidateChain
                (valParams, &valResult, &verifyTree, plContext));

        if (valResult != NULL){
                printf("SUCCESSFULLY VALIDATED with Basic Constraint ");
                printf("Cert Selector minimum path length to be -1\n");
                PKIX_TEST_DECREF_BC(valResult);
        }

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_PL_Object_ToString
                ((PKIX_PL_Object*)verifyTree, &verifyString, plContext));
        (void) printf("verifyTree is\n%s\n", verifyString->escAsciiString);
        PKIX_TEST_DECREF_BC(verifyString);
        PKIX_TEST_DECREF_BC(verifyTree);

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_ComCertSelParams_SetBasicConstraints
                    (certSelParams, 6, plContext));

        /* validate cert chain using processing params and return valResult */

        PKIX_TEST_EXPECT_ERROR(PKIX_ValidateChain
                (valParams, &valResult, &verifyTree, plContext));

        if (valResult != NULL){
                printf("SUCCESSFULLY VALIDATED with Basic Constraint ");
                printf("Cert Selector minimum path length to be 6\n");
        }

        PKIX_TEST_DECREF_BC(trustedCert);
        PKIX_TEST_DECREF_BC(anchor);
        PKIX_TEST_DECREF_BC(anchors);
        PKIX_TEST_DECREF_BC(certs);
        PKIX_TEST_DECREF_BC(procParams);

cleanup:

        if (PKIX_TEST_ERROR_RECEIVED){
                printf("FAILED TO VALIDATE\n");
        }

        PKIX_TEST_EXPECT_NO_ERROR(PKIX_PL_Object_ToString
                ((PKIX_PL_Object*)verifyTree, &verifyString, plContext));
        (void) printf("verifyTree is\n%s\n", verifyString->escAsciiString);
        PKIX_TEST_DECREF_AC(verifyString);
        PKIX_TEST_DECREF_AC(verifyTree);

        PKIX_TEST_DECREF_AC(certSelParams);
        PKIX_TEST_DECREF_AC(valResult);
        PKIX_TEST_DECREF_AC(valParams);

        PKIX_TEST_RETURN();

        PKIX_Shutdown(plContext);

        endTests("ValidateChainBasicConstraints");

        return (0);

}
