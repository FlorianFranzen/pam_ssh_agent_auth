/*
 * Copyright (c) 2008, Jamie Beverly. 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY Jamie Beverly ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Jamie Beverly OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of Jamie Beverly.
 */


#include <string.h>

#include "includes.h"
#include "config.h"

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include <stdio.h>
#include <openssl/evp.h>
#include "ssh2.h"
#include "misc.h"

#include "userauth_pubkey_from_id.h"
#include "identity.h"
#include "get_command_line.h"
extern char **environ;

static char *
log_action(char ** action, size_t count)
{
    size_t i;
    char *buf = NULL;

    if (count == 0)
        return NULL;
   
    buf = pamsshagentauth_xcalloc((count * MAX_LEN_PER_CMDLINE_ARG) + (count * 3), sizeof(*buf));
    for (i = 0; i < count; i++) {
        strcat(buf, (i > 0) ? " '" : "'");
        strncat(buf, action[i], MAX_LEN_PER_CMDLINE_ARG);
        strcat(buf, "'");
    }
    return buf;
}

void
agent_action(Buffer *buf, char ** action, size_t count)
{
    size_t i;
    pamsshagentauth_buffer_init(buf);

    pamsshagentauth_buffer_put_int(buf, count);

    for (i = 0; i < count; i++) {
        pamsshagentauth_buffer_put_cstring(buf, action[i]);
    }
}


void
pamsshagentauth_session_id2_random(Buffer * session_id2) 
{
    uint8_t i;

    // Generate 1024 random bits (32 * 4 * 8)
    for (i = 0; i < 32; i++) {    
        pamsshagentauth_buffer_put_int(session_id2, pamsshagentauth_arc4random());
    }

    return;
}

int
pamsshagentauth_find_authorized_keys(const char * user, const char * ruser, const char * servicename)
{
    Buffer session_id2 = { 0 };
    Identity *id;
    Key *key;
    AuthenticationConnection *ac;
    char *comment;
    uint8_t retval = 0;
    uid_t uid = getpwnam(ruser)->pw_uid;

    OpenSSL_add_all_digests();
    pamsshagentauth_session_id2_random(&session_id2);

    if ((ac = ssh_get_authentication_connection(uid))) {
        pamsshagentauth_verbose("Contacted ssh-agent of user %s (%u)", ruser, uid);
        for (key = ssh_get_first_identity(ac, &comment, 2); key != NULL; key = ssh_get_next_identity(ac, &comment, 2)) 
        {
            if(key != NULL) {
                id = pamsshagentauth_xcalloc(1, sizeof(*id));
                id->key = key;
                id->filename = comment;
                id->ac = ac;
                if(userauth_pubkey_from_id(ruser, id, &session_id2)) {
                    retval = 1;
                }
                pamsshagentauth_xfree(id->filename);
                pamsshagentauth_key_free(id->key);
                pamsshagentauth_xfree(id);
                if(retval == 1)
                    break;
            }
        }
        pamsshagentauth_buffer_free(&session_id2);
        ssh_close_authentication_connection(ac);
    }
    else {
        pamsshagentauth_verbose("No ssh-agent could be contacted");
    }
    /* pamsshagentauth_xfree(session_id2); */
    EVP_cleanup();
    return retval;
}
