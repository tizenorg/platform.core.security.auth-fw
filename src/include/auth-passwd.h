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

#ifndef AUTH_PASSWD_H
#define AUTH_PASSWD_H

#include <sys/types.h>
#include <auth-passwd-error.h>
#include <auth-passwd-policy-types.h>

/**
 * @file    auth-passwd.h
 * @version 1.0
 * @brief   This file contains APIs of the Authentication framework
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
 * This API compares stored phone password with input password.
 *
 * \par Purpose:
 * This API should be used by applications which has phone UI lock capability.
 *
 * \par Typical use case:
 * Lock screen calls this API after user typed phone password and pressed okay.
 * Setting application call this API before setting password.
 *
 * \par Method of function operation:
 * Sends input password to auth-fw, auth-fw compares hashed current password and hashed input password.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error if you called this API too often.\n
 *
 * \param[in] passwd_type Password type, such as normal(lock) password, recovery password and so on.
 * \param[in] passwd Null terminated inputted password string.
 * \param[out] current_attempts Number of password check missed attempts.
 * \param[out] max_attempts Number of maximum attempts that the password locks. 0 means infinite.
 * \param[out] valid_secs Remaining time in second which represents this password will be expired. 0xFFFFFFFF means infinite
 *
 * \return AUTH_PASSWD_API_SUCCESS
 * \return AUTH_PASSWD_API_ERROR_ACCESS_DENIED
 * \return AUTH_PASSWD_API_ERROR_SOCKET
 * \return AUTH_PASSWD_API_ERROR_NO_PASSWORD
 *              input password is set but it should be NULL because auth-fw
 *              password is not set.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH
 *              input password does not match with auth-fw password
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER
 *              To many access in short period of time. Wait at least 0.5 sec.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED
 *              You tried to many times. No other attempts are possible.
 * \return AUTH_PASSWD_API_ERROR_INPUT_PARAM
 *              passwd_type is not supported.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_EXPIRED
 *
 * \par Prospective clients:
 * Applications which has phone UI lock feature.
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 *
 * \post None
 *
 * \see auth_passwd_check_passwd_state(), auth_passwd_set_passwd(), auth_passwd_set_passwd_recovery()
 *
 * \remarks The password file will be acces controlled and securely hashed. auth-fw will remain previous password file to recover unexpected password file curruption.
 *
 * \par Sample code:
 * \code
 * #include <auth-passwd.h>
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * ret = auth_passwd_check_passwd(AUTH_PWD_NORMAL, "is_this_password", &attmpt, &max_attempt, &expire_sec);
 * if(ret == AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH)
 * {
 *      printf("%s", "Oh you typed wrong password\n");
 *      ...
 * }
 * else if(ret == AUTH_PASSWD_API_SUCCESS)
 * {
 *      printf("%s", "You remember your password.\n");
 *      ...
 * }
 * ...
 *
 * \endcode
 *
 */
int auth_passwd_check_passwd(password_type passwd_type,
							 const char *passwd,
							 unsigned int *current_attempts,
							 unsigned int *max_attempts,
							 unsigned int *valid_secs);

/**
 * \par Description:
 * This API checks phone validity of password, to check existance, expiration, remaining attempts.
 *
 * \par Purpose:
 * This API should be used by applications which needs phone password check. Caller application should behave properly after this API call.
 *
 * \par Typical use case:
 * Lock screen can call this API before it shows unlock screen, if there is password, lock screen can show password input UI, if not, lock screen can show just unlock screen
 *
 * \par Method of function operation:
 * Sends a validate request to auth-fw and auth-fw replies with password information.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Password file should be stored safely. The password file will be stored by auth-fw and only allowed itself to read/write, and data is will be securely hashed\n
 *
 * \param[in] passwd_type Password type, such as normal(lock) password, recovery password and so on.
 * \param[out] current_attempts Number of password check missed attempts.
 * \param[out] max_attempts Number of maximum attempts that the password locks. 0 means infinite
 * \param[out] valid_secs Remaining time in second which represents this password will be expired. 0xFFFFFFFF means infinite
 *
 * \return 0 if there is no password set, other negative integer error code on error.
 *
 * \par Prospective clients:
 * Applications which can unlock UI
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 *
 * \post None
 *
 * \see auth_passwd_check_passwd(), auth_passwd_set_passwd()
 *
 * \remarks If password file is corrupted or accidentally deleted, this API may not synchronized with auth-fw, but auth-fw will check file status on next request.
 *
 * \par Sample code:
 * \code
 * #include <auth-fw.h>
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * ret = auth_passwd_check_passwd_state(AUTH_PWD_NORMAL, &attempt, &max_attempt, &expire_sec);
 * if(ret == AUTH_PASSWD_API_ERROR_NO_PASSWORD)
 * {
 *      printf("%s", "There is no password exists\n");
 * }
 * else if(ret == AUTH_PASSWD_API_SUCCESS && expire_sec > 0 && attempt < max_attempts)
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
 *
 */
int auth_passwd_check_passwd_state(password_type passwd_type,
								   unsigned int *current_attempts,
								   unsigned int *max_attempts,
								   unsigned int *valid_secs);

/**
 * \par Description:
 * This API checks if password was used before.
 *
 * \par Purpose:
 * This API should be used by applications which need to check if password would be rejected as used before.
 *
 * \par Typical use case:
 * App to change password could check if newly created password was used before.
 *
 * \par Method of function operation:
 * Sends a check request to auth-fw and auth-fw replies with password reusability information.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * Security-aware clients should check current password before calling this function.
 *
 * \param[in] passwd_type Password type, such as normal(lock) password, recovery password and so on.
 * \param[in] passwd A password to be checked
 * \param[out] is_reused Indicates if password was used before (non-zero value means, the password
 *                       was used before)
 *
 * \return AUTH_PASSWD_API_SUCCESS if function call was successful. Error code otherwise.
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 *
 * \post None
 *
 */
int auth_passwd_check_passwd_reused(password_type passwd_type,
									const char *passwd,
									int *is_reused);

/**
 * \par Description:
 * This API sets phone password only if current password matches.
 *
 * \par Purpose:
 * This API should be used by setting application when the user changes his/her
 * phone password.
 *
 * \par Typical use case:
 * Setting application calls this API to change phone password. Caller needs
 * current password to grant the change.
 *
 * \par Method of function operation:
 * Sends current password with new password to auth-fw, auth-fw
 * checks current password and set new password to current only when current
 * password is correct and new password meet password policies.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error
 * if you called this API too often.\n
 *
 * \param[in] passwd_type Password type, such as normal(lock) password, recovery password and so on.
 * \param[in] cur_passwd Null terminated current password string or NULL
 *            pointer if there is no password set yet.
 * \param[in] new_passwd Null terminated new password string or NULL.
 *            If you want to remove password you must set:
 *            new_pwd = NULL.
 *
 * \return AUTH_PASSWD_API_SUCCESS
 * \return AUTH_PASSWD_API_ERROR_ACCESS_DENIED
 * \return AUTH_PASSWD_API_ERROR_SOCKET
 * \return AUTH_PASSWD_API_ERROR_NO_PASSWORD
 *              cur_passwd is set but it should be NULL
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_EXIST
 *              cur_passwd is NULL but password in auth-fw was set.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH
 *              cur_passwd does not match with auth-fw password
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_INVALID
 *              new_passwd dose not meet password policies in auth-fw.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER
 *              To many access in short period of time. Wait at least 0.5 sec.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED
 *              You tried to many times. No other attempts are possible.
 * \return AUTH_PASSWD_API_ERROR_INPUT_PARAM
 *              passwd_type is not supported
 *              or password length is longer than MAX_PASSWORD_LEN.
 *
 * \par Prospective clients:
 * Platform's THE ONLY setting application and some dedicated privileged processes
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
 * \remarks Only setting application can call this API. The password file will be access controlled and securely hashed. Auth-fw will remain previous password file to recover unexpected password file corruption.
 *
 * \par Sample code:
 * \code
 * #include <auth-passwd.h>
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * ret = auth_passwd_check_passwd_state(AUTH_PWD_NORMAL, &attempt, &max_attempt, &expire_sec);
 * if(ret == AUTH_PASSWD_API_ERROR_NO_PASSWORD)
 * {
 *      printf("%s", "There is no password exists\n");
 *      ret = auth_passwd_set_passwd(AUTH_PWD_NORMAL, NULL, "this_is_new_pwd");
 *      if(ret != AUTH_PASSWD_API_SUCCESS)
 *      {
 *              printf("%s", "we have error\n");
 *              ...
 *      }
 * }
 * else if(ret == AUTH_PASSWD_API_SUCCESS && expire_sec > 0 && attempt < max_attempts)
 * {
 *      printf("%s", "Password is valid by now\n");
 *      ret = auth_passwd_set_passwd(AUTH_PWD_NORMAL, "this_is_current_passwd", "this_is_new_passwd");
 *      if(ret != AUTH_PASSWD_API_SUCCESS)
 *      {
 *              printf("%s", "we have error\n");
 *              ...
 *      }
 * }
 * else
 * {
 *      printf("%s", "Something wrong\n");
 * }
 * ...
 *
 * \endcode
 *
 */
int auth_passwd_set_passwd(password_type passwd_type,
						   const char *cur_passwd,
						   const char *new_passwd);

/**
 * \par Description:
 * This API sets normal(lock) password only if inputted recovery password is correct.
 *
 * \par Purpose:
 * This API should be used by applications which has phone UI lock capability.
 *
 * \par Typical use case:
 * Lock screen calls this API if current attempts is a specific number of attempts or more.
 *
 * \par Method of function operation:
 * Sends current recovery password with new normal(lock) password to auth-fw, auth-fw
 * checks current recovery password and set new normal password only when current
 * recovery password is correct and new normal password meet password policies.
 *
 * \par Sync (or) Async:
 * This is a Synchronous API.
 *
 * \par Important notes:
 * There is retry timer on this API to limit replay attack. You will get error
 * if you called this API too often.\n
 *
 * \param[in] cur_recovery_passwd Null terminated current recovery password string. It must not a NULL pointer.
 * \param[in] new_normal_passwd Null terminated new password string. It must not a NULL pointer.
 *
 * \return AUTH_PASSWD_API_SUCCESS
 * \return AUTH_PASSWD_API_ERROR_ACCESS_DENIED
 * \return AUTH_PASSWD_API_ERROR_SOCKET
 * \return AUTH_PASSWD_API_ERROR_NO_PASSWORD
 *              Recovery password is not set
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH
 *              cur_recovery_passwd does not match with recovery password
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_INVALID
 *              new_normal_passwd dose not meet password policies in auth-fw.
 * \return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER
 *              To many access in short period of time. Wait at least 0.5 sec.
 * \return AUTH_PASSWD_API_ERROR_INPUT_PARAM
 *              cur_recovery_passwd or new_normal_passwd is a NULL pointer
 *              or new_normal_passwd length is longer than MAX_PASSWORD_LEN.
 * \return AUTH_PASSWD_API_ERROR_RECOVERY_PASSWORD_RESTRICTED
 *              Lock screen can call this API only if max attempts is not set.
 *
 * \par Prospective clients:
 * Applications which has phone UI lock feature.
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 *
 * \post None
 *
 * \see auth_passwd_check_passwd()
 *
 * \remarks A specific number of attempts to call this API is depends on lock screen.
 * \remarks Lock screen can call this API only if max attempts is not set.
 *
 * \par Sample code:
 * \code
 * #include <auth-passwd.h>
 * ...
 * #define RECOVERY_ATTEMPTS 10;
 * ...
 * int ret;
 * unsigned int attempt, max_attempt, expire_sec;
 *
 * ret = auth_passwd_check_passwd(AUTH_PWD_NORMAL, "is_this_password", &attmpt, &max_attempt, &expire_sec);
 * if(ret == AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH)
 * {
 *      printf("%s", "Oh you typed wrong password\n");
 *      if (max_attempt >= RECOVERY_ATTEMPTS)
 *      {
 *          ret = auth_passwd_set_passwd_recovery("is_this_recovery_passwd", "this_is_new_normal_passwd");
 *          if(ret != AUTH_PASSWD_API_SUCCESS)
 *          {
 *              printf("%s", "Something wrong\n");
 *              ...
 *          }
 *          ...
 *      }
 *      ...
 * }
 * else if(ret == AUTH_PASSWD_API_SUCCESS)
 * {
 *      printf("%s", "You remember your password.\n");
 *      ...
 * }
 * ...
 *
 * \endcode
 *
 */
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
