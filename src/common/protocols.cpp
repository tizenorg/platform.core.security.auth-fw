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
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by authentication password.
 */

#include <protocols.h>
#include <cstddef>

namespace AuthPasswd {

char const * const SERVICE_SOCKET_PASSWD_CHECK =
    "/run/.authentication-server-api-passwd-check.sock";
char const * const SERVICE_SOCKET_PASSWD_SET =
    "/run/.authentication-server-api-passwd-set.sock";
char const * const SERVICE_SOCKET_PASSWD_RESET =
    "/run/.authentication-server-api-passwd-reset.sock";
char const * const SERVICE_SOCKET_PASSWD_POLICY =
    "/run/.authentication-server-api-passwd-policy.sock";

const size_t MAX_PASSWORD_LEN = 32;
const unsigned int MAX_PASSWORD_HISTORY = 50;
const unsigned int PASSWORD_INFINITE_EXPIRATION_DAYS = 0;
const unsigned int PASSWORD_INFINITE_ATTEMPT_COUNT = 0;
const unsigned int PASSWORD_API_NO_EXPIRATION = 0xFFFFFFFF;

} // namespace AuthPasswd

