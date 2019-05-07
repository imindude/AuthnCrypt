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
#include "cbor.h"
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

/* ****************************************************************************************************************** */

struct CborCredentialList
{
    CborValue   value_;
    size_t      count_;
};
typedef struct CborCredentialList   CborCredentialList;

/* ****************************************************************************************************************** */


/* end of file ****************************************************************************************************** */
