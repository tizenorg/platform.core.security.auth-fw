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
 * @file        client-password-admin.cpp
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of password functions.
 */

#include <cstring>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <policy.h>

#include <auth-passwd-admin.h>

namespace {

inline bool isPasswordIncorrect(const char* pwd)
{
    // NULL means that password must be cancelled.
    return (pwd && (strlen(pwd) == 0 || strlen(pwd) > AuthPasswd::MAX_PASSWORD_LEN));
}

} // namespace anonymous

AUTH_PASSWD_API
int auth_passwd_reset_passwd(password_type passwd_type,
                             uid_t uid,
                             const char *new_passwd)
{
    using namespace AuthPasswd;

    return try_catch([&] {
        if (isPasswordIncorrect(new_passwd)) {
            LogError("Wrong input param.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        if (!new_passwd)
            new_passwd = NO_PASSWORD;

        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_RST_PASSWD));
        Serialization::Serialize(send, passwd_type);
        Serialization::Serialize(send, uid);
        Serialization::Serialize(send, std::string(new_passwd));

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_RESET, send.Pop(), recv);
        if (AUTH_PASSWD_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    });
}

AUTH_PASSWD_API
int auth_passwd_new_policy(policy_h **pp_policy)
{
    if (!pp_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    try {
        *pp_policy = new policy_h;

    } catch (std::bad_alloc& ex) {
        return AUTH_PASSWD_API_ERROR_OUT_OF_MEMORY;
    }

    (*pp_policy)->policyFlag = 0;

    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_user(policy_h *p_policy, uid_t uid)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_USER);
    p_policy->uid = uid;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_max_attempts(policy_h *p_policy, unsigned int max_attempts)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_MAX_ATTEMPTS);
    p_policy->maxAttempts = max_attempts;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_validity(policy_h *p_policy, unsigned int valid_days)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_VALID_PERIOD);
    p_policy->validPeriod = valid_days;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_history_size(policy_h *p_policy, unsigned int history_size)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_HISTORY_SIZE);
    p_policy->historySize = history_size;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_min_length(policy_h *p_policy, unsigned int min_length)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_MIN_LENGTH);
    p_policy->minLength = min_length;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_minComplexCharNumber(policy_h *p_policy, unsigned int minComplexCharNumber)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_MIN_COMPLEX_CHAR_NUMBER);
    p_policy->minComplexCharNumber = minComplexCharNumber;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_maxCharOccurrences(policy_h *p_policy, unsigned int maxCharOccurrences)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_MAX_CHAR_OCCURRENCES);
    p_policy->maxCharOccurrences = maxCharOccurrences;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_maxNumSeqLength(policy_h *p_policy, unsigned int maxNumSeqLength)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_MAX_NUMERIC_SEQ_LENGTH);
    p_policy->maxNumSeqLength = maxNumSeqLength;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_quality(policy_h *p_policy, password_quality_type quality_type)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_QUALITY_TYPE);
    p_policy->qualityType = quality_type;
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_pattern(policy_h *p_policy, const char *pattern)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    if (!pattern)
        pattern = AuthPasswd::NO_PATTERN;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_PATTERN);
    p_policy->pattern = std::string(pattern);
    return AUTH_PASSWD_API_SUCCESS;

}

AUTH_PASSWD_API
int auth_passwd_set_forbiddenPasswd(policy_h *p_policy, const char *forbiddenPasswd)
{
    if (!p_policy)
        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

    if (!forbiddenPasswd)
        forbiddenPasswd = AuthPasswd::NO_FORBIDDEND_PASSWORD;

    p_policy->policyFlag = p_policy->policyFlag | (1 << POLICY_FORBIDDEN_PASSWDS);
    p_policy->forbiddenPasswds.push_back(forbiddenPasswd);
    return AUTH_PASSWD_API_SUCCESS;
}

AUTH_PASSWD_API
int auth_passwd_set_policy(policy_h *p_policy)
{
    using namespace AuthPasswd;

    return try_catch([&] {
        if (!p_policy) {
            LogError("Wrong input param.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        if (!(p_policy->policyFlag & (1 << POLICY_USER)))
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PASSWD_POLICY));
        Serialization::Serialize(send, p_policy->policyFlag);
        Serialization::Serialize(send, p_policy->uid);
        Serialization::Serialize(send, p_policy->maxAttempts);
        Serialization::Serialize(send, p_policy->validPeriod);
        Serialization::Serialize(send, p_policy->historySize);
        Serialization::Serialize(send, p_policy->minLength);
        Serialization::Serialize(send, p_policy->minComplexCharNumber);
        Serialization::Serialize(send, p_policy->maxCharOccurrences);
        Serialization::Serialize(send, p_policy->maxNumSeqLength);
        Serialization::Serialize(send, p_policy->qualityType);
        Serialization::Serialize(send, p_policy->pattern);
        Serialization::Serialize(send, p_policy->forbiddenPasswds);

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_POLICY, send.Pop(), recv);
        if (AUTH_PASSWD_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    });
}

AUTH_PASSWD_API
void auth_passwd_free_policy(policy_h *p_policy)
{
    delete p_policy;
}

AUTH_PASSWD_API
int auth_passwd_disable_policy(uid_t uid)
{
    using namespace AuthPasswd;

    return try_catch([&] {

        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_DIS_PASSWD_POLICY));
        Serialization::Serialize(send, uid);

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_POLICY, send.Pop(), recv);
        if (AUTH_PASSWD_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    });
}
