/*
 *  Authentication password
 *
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Jooseong Lee <jooseong.lee@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 */

#ifndef AUTH_PASSWD_H
#define AUTH_PASSWD_H

#include <sys/types.h>
#include <auth-passwd-error.h>
#include <auth-passwd-policy-types.h>

/**
 * @file    auth-passwd.h
 * @version 1.0
 * @brief   This file contains APIs of the Authentication Server
*/

/**
 * @defgroup SecurityFW
 * @{
 *
 * @defgroup AUTH_PASSWD Authentication Server - password
 * @version  1.0
 * @brief    Authentication Server client library functions
 *
*/

/**
 * @addtogroup AUTH_PASSWD
 * @{
*/

/*
 * ====================================================================================================
 * <tt>
 *
 * Revision History:
 *
 *  -- Company Name -- | Modification Date | Description of Changes
 *  -----------------------------------------------------------------------
 *   --- Samsung ------ | --- 2010-07-25 -- | First created
 *
 *    </tt>
 */

#ifdef __cplusplus
extern "C" {
#endif

int auth_passwd_check_passwd(const password_type passwd_type,
                             const char *passwd, 
                             unsigned int *current_attempts,
                             unsigned int *max_attempts,
                             unsigned int *valid_secs);

int auth_passwd_check_passwd_state(const password_type passwd_type, 
                                   unsigned int *current_attempts, 
                                   unsigned int *max_attempts, 
                                   unsigned int *valid_secs);

int auth_passwd_check_passwd_reused(const password_type passwd_type, 
                                    const char *passwd, 
                                    int *is_reused);

int auth_passwd_set_passwd(const password_type passwd_type,
                           const char *cur_passwd,
                           const char *new_passwd);

int auth_passwd_set_passwd_recovery(const char *cur_recovery_passwd, 
                                    const char *new_normal_passwd);
 
#ifdef __cplusplus
}
#endif

/**
 * @}
*/

/**
 * @}
*/

#endif
