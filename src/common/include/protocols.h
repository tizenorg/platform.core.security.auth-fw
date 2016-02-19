/*
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
 */
/*
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by authentication password.
 */

#ifndef _AUTH_PASSWD_PROTOCOLS_
#define _AUTH_PASSWD_PROTOCOLS_

#include <cstddef>
#include <time.h>
#include <sys/types.h>

namespace AuthPasswd {

extern char const * const SERVICE_SOCKET_PASSWD_CHECK;
extern char const * const SERVICE_SOCKET_PASSWD_SET;
extern char const * const SERVICE_SOCKET_PASSWD_RESET;
extern char const * const SERVICE_SOCKET_PASSWD_POLICY;

enum class PasswordHdrs
{
    HDR_CHK_PASSWD,
    HDR_CHK_PASSWD_STATE,
    HDR_CHK_PASSWD_REUSED,
    HDR_SET_PASSWD,
    HDR_SET_PASSWD_RECOVERY,
    HDR_RST_PASSWD,
    HDR_SET_PASSWD_POLICY
};

extern const size_t MAX_PASSWORD_LEN;
extern const unsigned int MAX_PASSWORD_HISTORY;
extern const unsigned int PASSWORD_INFINITE_EXPIRATION_DAYS;
extern const unsigned int PASSWORD_INFINITE_ATTEMPT_COUNT;
extern const unsigned int PASSWORD_API_NO_EXPIRATION;

} // namespace AuthPasswd

#endif // _AUTH_PASSWD_PROTOCOLS_

