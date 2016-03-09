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
 * @file        protocols.cpp
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by authentication password.
 */

#include <policy.h>
#include <sstream>

namespace AuthPasswd {

const size_t MAX_PASSWORD_LEN = 32;
const unsigned int MAX_PASSWORD_HISTORY = 50;
const unsigned int PASSWORD_INFINITE_EXPIRATION_DAYS = 0;
const unsigned int PASSWORD_INFINITE_ATTEMPT_COUNT = 0;
const unsigned int PASSWORD_API_NO_EXPIRATION = 0xFFFFFFFF;

const char* NO_PASSWORD = "";
const char* NO_PATTERN = "";
const char* NO_FORBIDDEND_PASSWORD = "";

const std::string REGEX_QUALITY_UNSPECIFIED = "[.]*";
const std::string REGEX_QUALITY_SOMETHING = ".+";
const std::string REGEX_QUALITY_NUMERIC = "^[0-9]+$";
const std::string REGEX_QUALITY_ALPHABETIC = "^[A-Za-z]+$";
const std::string REGEX_QUALITY_ALPHANUMERIC = "^[A-Za-z0-9]+$";

Policy::Policy() :
    flag(0),
    uid(0),
    maxAttempts(0),
    validPeriod(0),
    historySize(0),
    minLength(0),
    minComplexCharNumber(0),
    maxCharOccurrences(0),
    maxNumSeqLength(0),
    qualityType(AUTH_PWD_QUALITY_UNSPECIFIED),
    pattern(NO_PATTERN)
{
}

Policy::~Policy()
{
}

std::string Policy::info() const
{
    std::stringstream ss;
    ss << "Uid: " << uid;
    ss << " flag: " << flag;
    ss << " maxAttempts: " << maxAttempts;
    ss << " validPeriod: " << validPeriod;
    ss << " historySize: " << historySize;
    ss << " minLength: " << minLength;
    ss << " minComplexCharNumber: " << minComplexCharNumber;
    ss << " maxCharOccurrences: " << maxCharOccurrences;
    ss << " maxNumSeqLength: " << maxNumSeqLength;
    ss << " qualityType: " << qualityType;
    ss << " pattern: " << pattern;
    ss << " forbiddenPasswd size: " << forbiddenPasswds.size();
    ss << " forbiddenPasswd items:";
    for (auto &item : forbiddenPasswds)
        ss << " " << item;

    return ss.str();
}

PolicySerializable::PolicySerializable(const Policy &policy) : Policy(policy)
{
}

PolicySerializable::PolicySerializable(IStream &stream)
{
    Deserialization::Deserialize(stream, flag);
    Deserialization::Deserialize(stream, uid);
    Deserialization::Deserialize(stream, maxAttempts);
    Deserialization::Deserialize(stream, validPeriod);
    Deserialization::Deserialize(stream, historySize);
    Deserialization::Deserialize(stream, minLength);
    Deserialization::Deserialize(stream, minComplexCharNumber);
    Deserialization::Deserialize(stream, maxCharOccurrences);
    Deserialization::Deserialize(stream, maxNumSeqLength);
    Deserialization::Deserialize(stream, qualityType);
    Deserialization::Deserialize(stream, pattern);
    Deserialization::Deserialize(stream, forbiddenPasswds);
}

void PolicySerializable::Serialize(IStream &stream) const
{
    Serialization::Serialize(stream, flag);
    Serialization::Serialize(stream, uid);
    Serialization::Serialize(stream, maxAttempts);
    Serialization::Serialize(stream, validPeriod);
    Serialization::Serialize(stream, historySize);
    Serialization::Serialize(stream, minLength);
    Serialization::Serialize(stream, minComplexCharNumber);
    Serialization::Serialize(stream, maxCharOccurrences);
    Serialization::Serialize(stream, maxNumSeqLength);
    Serialization::Serialize(stream, qualityType);
    Serialization::Serialize(stream, pattern);
    Serialization::Serialize(stream, forbiddenPasswds);
}

} // namespace AuthPasswd
