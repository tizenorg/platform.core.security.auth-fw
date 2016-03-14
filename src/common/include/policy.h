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

#include <unistd.h>
#include <set>
#include <string>
#include <auth-passwd-policy-types.h>
#include <dpl/serialization.h>
#include <symbol-visibility.h>

namespace AuthPasswd {

COMMON_API
extern const size_t MAX_PASSWORD_LEN;

COMMON_API
extern const unsigned int MAX_PASSWORD_HISTORY;

COMMON_API
extern const unsigned int MAX_PASSWORD_ATTEMPTS;

COMMON_API
extern const unsigned int PASSWORD_INFINITE_EXPIRATION_DAYS;

COMMON_API
extern const unsigned int PASSWORD_INFINITE_ATTEMPT_COUNT;

COMMON_API
extern const unsigned int PASSWORD_API_NO_EXPIRATION;

COMMON_API
extern const char* NO_PASSWORD;

COMMON_API
extern const char* NO_PATTERN;

COMMON_API
extern const char* NO_FORBIDDEND_PASSWORD;


COMMON_API
extern const std::string REGEX_QUALITY_UNSPECIFIED;

COMMON_API
extern const std::string REGEX_QUALITY_SOMETHING;

COMMON_API
extern const std::string REGEX_QUALITY_NUMERIC;

COMMON_API
extern const std::string REGEX_QUALITY_ALPHABETIC;

COMMON_API
extern const std::string REGEX_QUALITY_ALPHANUMERIC;

struct COMMON_API Policy {
    Policy();
    ~Policy();

    std::string info(void) const;

    inline void setFlag(password_policy_type field)
    {
        flag |= (1 << field);
    }

    inline bool isFlagOn(password_policy_type field)
    {
        return (flag & (1 << field)) ? true : false;
    }

    // XOR-ed value of password_policy_type enum
    int flag;

    uid_t uid;

    // maximum number of attempts that user can try to check the password without success in serial
    unsigned int maxAttempts;
    // number of days that this password is valid
    unsigned int validPeriod;
    // recent number of passwords which user cannot reuse
    unsigned int historySize;
    // a min number of characters of password
    unsigned int minLength;
    // a min number of complex chars(non-alphabetic) in password
    unsigned int minComplexCharNumber;
    // Maximum count of the same character in the password
    unsigned int maxCharOccurrences;
    // Maximum numeric sequence length in the password
    // regardless descending order, ascending order or repetition
    unsigned int maxNumSeqLength;
    // password quality
    unsigned int qualityType;

    // password regular expression
    std::string pattern;

    // forbidden strings in password
    std::set<std::string> forbiddenPasswds;
};

struct COMMON_API PolicySerializable : public Policy, ISerializable {
    explicit PolicySerializable(const Policy &);
    explicit PolicySerializable(IStream &);
    void Serialize(IStream &) const;
};

}

#endif // _AUTH_PASSWD_POLICY_H_
