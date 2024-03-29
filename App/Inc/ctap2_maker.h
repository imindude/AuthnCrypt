/**
 * *********************************************************************************************************************
 * @title       Authn & Crypt
 * @author      imindude@gmail.com
 * @note        Application Code
 * *********************************************************************************************************************
 */

#pragma once

/* ****************************************************************************************************************** */

#include <stdint.h>
#include "fidodef.h"

/* ****************************************************************************************************************** */

uint8_t ctap2_maker_make_credential(MakeCredential *make_credential, CredentialId *credential_id,
        uint8_t *buffer_header, uint16_t *buffer_size);
uint8_t ctap2_maker_get_assertion(GetAssertion *get_assertion, CredentialList *cred_list, int8_t credential_count,
        uint8_t *buffer_header, uint16_t *buffer_size);
uint8_t ctap2_maker_get_info(uint8_t *buffer_header, uint16_t *buffer_size);
uint8_t ctap2_maker_client_pin(ClientPin *client_pin, uint8_t *buffer_header, uint16_t *buffer_size);

/* end of file ****************************************************************************************************** */
