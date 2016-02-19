/*
 *  Authentication password
 *
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
 *
 */

#ifndef AUTH_PASSWD_POLICY_TYPES_H
#define AUTH_PASSWD_POLICY_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct auth_password_policy policy_h;

typedef enum {
    AUTH_PWD_NORMAL,
    AUTH_PWD_RECOVERY
} password_type;

typedef enum {
    AUTH_PWD_QUALITY_UNSPECIFIED,
    AUTH_PWD_QUALITY_SOMETHING,
    AUTH_PWD_QUALITY_NUMERIC,
    AUTH_PWD_QUALITY_ALPHABETIC,
    AUTH_PWD_QUALITY_ALPHANUMERIC
} password_quality_type;

#ifdef __cplusplus
}
#endif

#endif /* AUTH_PASSWD_POLICY_TYPES_H */
