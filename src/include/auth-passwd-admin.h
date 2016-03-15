/*
 *  Authentication password
 *
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef AUTH_PASSWD_ADMIN_H
#define AUTH_PASSWD_ADMIN_H

#include <sys/types.h>
#include <auth-passwd-error.h>
#include <auth-passwd-policy-types.h>

/**
 * @file    auth-passwd-admin.h
 * @version 1.0
 * @brief   This file contains APIs of the Authentication framework admin
*/

/**
 * @defgroup SecurityFW
 * @{
 *
 * @defgroup AUTH_PASSWD Authentication framework - password
 * @version  1.0
 * @brief    Authentication framework client library functions
 *
*/

/**
 * @addtogroup AUTH_PASSWD
 * @{
*/

#ifdef __cplusplus
extern "C" {
#endif

int auth_passwd_reset_passwd(password_type passwd_type,
							 uid_t uid,
							 const char *new_passwd);

int auth_passwd_new_policy(policy_h **pp_policy);

int auth_passwd_set_user(policy_h *p_policy, uid_t uid);

int auth_passwd_set_max_attempts(policy_h *p_policy, unsigned int max_attempts);

int auth_passwd_set_validity(policy_h *p_policy, unsigned int valid_days);

int auth_passwd_set_history_size(policy_h *p_policy, unsigned int history_size);

int auth_passwd_set_min_length(policy_h *p_policy, unsigned int min_length);

int auth_passwd_set_min_complex_char_num(policy_h *p_policy, unsigned int val);

int auth_passwd_set_max_char_occurrences(policy_h *p_policy, unsigned int val);

int auth_passwd_set_max_num_seq_len(policy_h *p_policy, unsigned int val);

int auth_passwd_set_quality(policy_h *p_policy, password_quality_type quality_type);

int auth_passwd_set_pattern(policy_h *p_policy, const char *pattern);

int auth_passwd_set_forbidden_passwd(policy_h *p_policy, const char *forbidden_passwd);

int auth_passwd_set_policy(policy_h *p_policy);

void auth_passwd_free_policy(policy_h *p_policy);

int auth_passwd_disable_policy(uid_t uid);

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
