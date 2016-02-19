/*
 *  Copyright (c) 2016 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        policy.h
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementatin of MessageBuffer.
 */

#ifndef _AUTH_PASSWD_POLICY_H_
#define _AUTH_PASSWD_POLICY_H_

#include <auth-passwd-policy-types.h>

struct auth_password_policy {

    uid_t uid;
    unsigned int maxAttempts;
    unsigned int validPeriod;
    unsigned int historySize; 
    unsigned int minLength;
    password_quality_type qualityType;
};

#endif // _AUTH_PASSWD_POLICY_H_
