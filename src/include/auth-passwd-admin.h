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

/**
 * \par Description:
 * This API sets phone password without performing any checks connected with provided password. It
 * should be used only if user forgot the password.
 *
 * \par Purpose:
 * This API should be used by DPM(device policy manager) or enterprise manager when the user forgot his/her
 * phone password.
 *
 * \par Typical use case:
 * User forgets the password. He calls emergency manager(auto or manual), which means DPM or enterprise manager, for reset password. Emergency manager calls this API and reset phone password.
 *
 * \par Method of function operation:
 * Resetting phone password with input string without any matching current password. Function does
 * no checks before password replacement (expiration time check, currently set password checks,
 * history check and attempt count check are skipped).
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 *
 *
 * \param[in] passwd_type Password type, such as normal(lock) password, recovery password and so on.
 * \param[in] uid Target user.
 * \param[in] new_passwd Null terminated new password string or NULL.
 *            If you want to remove password you must set:
 *            new_pwd = NULL.
 *
 * \return AUTH_PASSWD_API_SUCCESS
 * \return AUTH_PASSWD_API_ERROR_ACCESS_DENIED
 * \return AUTH_PASSWD_API_ERROR_SOCKET
 * \return AUTH_PASSWD_API_ERROR_INPUT_PARAM
 *              passwd_type is not supported
 *              or password length is longer than MAX_PASSWORD_LEN.
 *
 * \par Prospective clients:
 * Platform's THE ONLY DPM and some dedicated privileged processes
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 *
 * \post None
 *
 * \see auth_passwd_check_passwd_state(), auth_passwd_check_passwd(), auth_passwd_set_passwd_recovery()
 *
 * \remarks Only DPM and enterprise manager can call this API. The password file will be access controlled and securely hashed. Auth-fw will remain previous password file to recover unexpected password file corruption.
 *
 * \par Sample code:
 * \code
 * #include <auth-passwd-admin.h>
 * ...
 * int ret;
 *
 * ret = auth_passwd_check_passwd_state(AUTH_PWD_NORMAL, owner_user, "This_is_current_passwd");
 * if(ret == AUTH_PASSWD_API_ERROR_INPUT_PARAM)
 * {
 *      printf("%s", "Password type is wrong or password is so long\n");
 * }
 * else if(ret == AUTH_PASSWD_API_SUCCESS)
 * {
 *      printf("%s", "Password is valid by now\n");
 * }
 * else
 * {
 *      printf("%s", "Something wrong\n");
 * }
 * ...
 *
 * \endcode
 */
int auth_passwd_reset_passwd(password_type passwd_type,
							 uid_t uid,
							 const char *new_passwd);

/*
 * This API is responsible for initialize policy_h data structure
 * It uses dynamic allocation inside and user responsibility is to call
 * auth_passwd_free_policy() for freeing allocated resources
 *
 * \param[in] pp_policy Address of pointer for handle policy_h structure.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_new_policy(policy_h **pp_policy);

/*
 * This API is used to add user to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] uid Target user.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_user(policy_h *p_policy, uid_t uid);

/*
 * This API is used to add max attempts to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] max_attempts Number of maximum attempts that the password locks. 0 means infinite.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_max_attempts(policy_h *p_policy, unsigned int max_attempts);

/*
 * This API is used to add valid days to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] valid_days Number of days that this password is valid. 0 means infinity.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_validity(policy_h *p_policy, unsigned int valid_days);

/*
 * This API is used to add history size to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] history_size Number of history to be checked when user tries to change password. Maximum is currently 50.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_history_size(policy_h *p_policy, unsigned int history_size);

/*
 * This API is used to add minimum password length to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] min_length Minimum number of characters of password.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_min_length(policy_h *p_policy, unsigned int min_length);

/*
 * This API is used to add a minimum numbum of complex characters(non-alphabetic) to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] val Minimum number of complex characters in password.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_min_complex_char_num(policy_h *p_policy, unsigned int val);

/*
 * This API is used to add maximum count of the same character to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] val Maximum count of the same character in the password.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_max_char_occurrences(policy_h *p_policy, unsigned int val);

/*
 * This API is used to add maximum numeric sequence length to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] val Maximum numeric sequence length in the password
 *            regardless descending order, ascending order or repetitiona.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_max_num_seq_len(policy_h *p_policy, unsigned int val);

/*
 * This API is used to add password quality type to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] quality_type password complexity type.
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_quality(policy_h *p_policy, password_quality_type quality_type);

/*
 * This API is used to add password pattern to policy_h structure.
 *
 * \param[in] p_policy Pointer handling p_policy structure.
 * \param[in] pattern Regular expression for password strings.
 *            If you want to remove pattern in auth-fw you must set:
 *            pattern = NULL
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_pattern(policy_h *p_policy, const char *pattern);

/*
 * This API is used to add forbidden password to policy_h structure.
 * It can be called multiple times.
 *
 * \param[in] p_policy Pointer handling p_policy structure
 * \param[in] forbidden_passwd forbidden password user cannot set.
 *            If you want to remove forbidden passwords in auth-fw you must set:
 *            forbidden_passwd = NULL
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
int auth_passwd_set_forbidden_passwd(policy_h *p_policy, const char *forbidden_passwd);

/**
 * \par Description:
 * This API is used to set password policies in auth-fw.
 *
 * \par Purpose:
 * This API should be used by DPM when DPM send new policies to auth-fw.
 *
 * \par Typical use case:
 * DPM calls this API to send new passowrd policies to auth-fw.
 *
 * \par Method of function operation:
 * Sends new password polices to auth-fw, auth-fw updates received password polices
 * if policies is valid. When there are new polices for max attempts and valid period,
 * these policies apply to current normal(lock) password immediately.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * New polices for max attempts and valid period apply to current normal password immediately.
 * It means current attempts and the rest of time for expiration are initialized.
 *
 * \param[in] p_policy Pointer handling p_policy structure
 *
 * \return AUTH_PASSWD_API_SUCCESS
 * \return AUTH_PASSWD_API_ERROR_ACCESS_DENIED
 * \return AUTH_PASSWD_API_ERROR_SOCKET
 * \return AUTH_PASSWD_API_ERROR_INPUT_PARAM
 *              p_policy is a NULL pointer
 *              or target user is not set
 *              or policies are invalid.
 *
 * \par Prospective clients:
 * DPM
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 *
 * \post None
 *
 * \par Sample code:
 * \code
 * #include <auth-passwd-admin.h>
 * ...
 * policy_h *p_policy;
 *
 * auth_passwd_new_policy(&p_policy);
 * auth_passwd_set_user(p_policy, owner);
 * auth_passwd_set_min_length(p_policy, 4);
 * auth_passwd_set_min_complex_char_num(p_policy, 1);
 * auth_passwd_set_max_char_occurrences(p_policy, 2);
 * auth_passwd_set_max_num_seq_len(p_policy, 4);
 * auth_passwd_set_forbidden_passwd(p_policy, "abcd1#");
 * auth_passwd_set_forbidden_passwd(p_policy, "qwer1#");
 *
 * auth_passwd_set_policy(p_policy);
 * ...
 * auth_passwd_free_policy(p_policy);
 *
 * \endcode
 *
 */
int auth_passwd_set_policy(policy_h *p_policy);

/*
 * This API is used to free resources allocated by calling auth_passwd_new_policy().
 *
 * \param[in] p_policy Pointer handling allocated policy_h structure
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 */
void auth_passwd_free_policy(policy_h *p_policy);

/*
 * This API is used to disable current password policies in auth-fw.
 *
 * \param[in] uid Taget user
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 *
 */
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
