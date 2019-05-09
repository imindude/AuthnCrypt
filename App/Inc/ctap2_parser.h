/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#pragma once

/* ****************************************************************************************************************** */

#include <stddef.h>
#include "fidodef.h"

/* ****************************************************************************************************************** */

#define MakeCredentialParam_clientDataHash          (1 << 0)    // required
#define MakeCredentialParam_rp                      (1 << 1)    // required
#define MakeCredentialParam_user                    (1 << 2)    // required
#define MakeCredentialParam_pubKeyCredParams        (1 << 3)    // required
#define MakeCredentialParam_excludeList             (1 << 4)    // optional
#define MakeCredentialParam_extensions              (1 << 5)    // optional
#define MakeCredentialParam_options                 (1 << 6)    // optional
#define MakeCredentialParam_pinAuth                 (1 << 7)    // optional
#define MakeCredentialParam_pinProtocol             (1 << 8)    // optional
#define MakeCredentialParam_Required                (MakeCredentialParam_clientDataHash | MakeCredentialParam_rp | \
                                                     MakeCredentialParam_user | MakeCredentialParam_pubKeyCredParams)

#define GetAssertionParam_rpId                      (1 << 0)    // required
#define GetAssertionParam_clientDataHash            (1 << 1)    // required
#define GetAssertionParam_allowList                 (1 << 2)    // optional
#define GetAssertionParam_extensions                (1 << 3)    // optional
#define GetAssertionParam_options                   (1 << 4)    // optional
#define GetAssertionParam_pinAuth                   (1 << 5)    // optional
#define GetAssertionParam_pinProtocol               (1 << 6)    // optional
#define GetAssertionParam_Required                  (GetAssertionParam_rpId | GetAssertionParam_clientDataHash)

#define ClientPinParam_pinProtocol                  (1 << 0)    // required
#define ClientPinParam_subCommand                   (1 << 1)    // required
#define ClientPinParam_keyAgreement                 (1 << 2)    // optional
#define ClientPinParam_pinAuth                      (1 << 3)    // optional
#define ClientPinParam_newPinEnc                    (1 << 4)    // optional
#define ClientPinParam_pinHashEnc                   (1 << 5)    // optional
#define ClientPinParam_Required                     (ClientPinParam_pinProtocol | ClientPinParam_subCommand)

#define CREDENTIAL_TYPE_unknown             0
#define CREDENTIAL_TYPE_publicKey           1

/* ****************************************************************************************************************** */

/* ****************************************************************************************************************** */


/* end of file ****************************************************************************************************** */
