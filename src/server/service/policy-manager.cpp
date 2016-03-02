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
 * @file        policy-manager.cpp
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of password policy management functions
 */

#include <policy-manager.h>

#include <iostream>
#include <iterator>
#include <algorithm>

#include <limits.h>

#include <dpl/log/log.h>

#include <auth-passwd-policy-types.h>
#include <auth-passwd-error.h>

namespace AuthPasswd
{

    void PolicyManager::addPolicy(const unsigned int user)
    {
        m_policyFile.insert(PolicyFileMap::value_type(user, PolicyFile(user)));
    }

    void PolicyManager::removePolicy(const unsigned int user)
    {
        m_policyFile.erase(user);
    }

    void PolicyManager::existPolicy(const unsigned int user)
    {
        PolicyFileMap::iterator itPwd = m_policyFile.find(user);
        if (itPwd != m_policyFile.end())
            return;

        addPolicy(user);
        return;
    }

    int PolicyManager::checkPolicy(const unsigned int passwdType,
                                   const std::string &currentPassword,
                                   const std::string &newPassword,
                                   const unsigned int user)
    {
        LogSecureDebug("Inside checkPolicy function.");

        // check if passwords are correct
        if (currentPassword.size() > MAX_PASSWORD_LEN) {
            LogError("Current password length failed.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (newPassword.size() > MAX_PASSWORD_LEN) {
            LogError("New password length failed.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        existPolicy(user);
        PolicyFileMap::iterator itPolicy = m_policyFile.find(user);

        if (!itPolicy->second.isPolicyActive() || (passwdType != AUTH_PWD_NORMAL))
            return AUTH_PASSWD_API_SUCCESS;

        if (!itPolicy->second.checkMinLength(newPassword)) {
            LogError("new passwd's minLength is invalid");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (!itPolicy->second.checkMinComplexCharNumber(newPassword)) {
            LogError("new passwd's minComplexCharNumber is invalid");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (!itPolicy->second.checkMaxCharOccurrences(newPassword)) {
            LogError("new passwd's maxCharOccurrences is invalid");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (!itPolicy->second.checkMaxNumSeqLength(newPassword)) {
            LogError("new passwd's maxNumSeqLength is invalid");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (!itPolicy->second.checkQualityType(newPassword)) {
            LogError("new passwd's qualityType is invalid");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (!itPolicy->second.checkPattern(newPassword)) {
            LogError("new passwd's pattern is invalid");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (!itPolicy->second.checkForbiddenPasswds(newPassword)) {
            LogError("new passwd is forbiddenPasswd");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        return AUTH_PASSWD_API_SUCCESS;
    }

    int PolicyManager::setPolicy(const auth_password_policy policy)
    {
        LogSecureDebug("Inside setPolicy function.");

        existPolicy(policy.uid);
        PolicyFileMap::iterator itPolicy = m_policyFile.find(policy.uid);

        // check if policies are correct
        for (int i = POLICY_TYPE_FIRST ; i < POLICY_TYPE_LAST+1 ; i++) {
            if (policy.policyFlag & (1 << i)) {
                switch (i) {
                    case POLICY_MAX_ATTEMPTS:
                        break;

                    case POLICY_VALID_PERIOD: {
                        time_t curTime = time(NULL);
                        if (policy.validPeriod > ((UINT_MAX - curTime) / 86400)) {
                           LogError("Incorrect input param.");
                           return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;
                    }

                    case POLICY_HISTORY_SIZE:
                        if (policy.historySize > MAX_PASSWORD_HISTORY) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_MIN_LENGTH:
                        if (policy.minLength > MAX_PASSWORD_LEN) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_MIN_COMPLEX_CHAR_NUMBER:
                        if (policy.minComplexCharNumber > MAX_PASSWORD_LEN) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_MAX_CHAR_OCCURRENCES:
                        if (policy.maxCharOccurrences > MAX_PASSWORD_LEN) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_MAX_NUMERIC_SEQ_LENGTH:
                        if (policy.maxNumSeqLength > MAX_PASSWORD_LEN) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_QUALITY_TYPE:
                        if (policy.qualityType > AUTH_PWD_QUALITY_LAST) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_PATTERN:
                        if (!itPolicy->second.isValidPattern(policy.pattern)) {
                            LogError("Incorrect input param.");
                            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                        }
                        break;

                    case POLICY_FORBIDDEN_PASSWDS:
                        break;

                    default:
                        LogError("Not supported policy type.");
                        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                }
            }
        }

        // update policies
        for (int i = POLICY_TYPE_FIRST ; i < POLICY_TYPE_LAST+1 ; i++) {
            if (policy.policyFlag & (1 << i)) {
                switch (i) {
                    case POLICY_MAX_ATTEMPTS:
                        LogSecureDebug("maxAttempts: " << policy.maxAttempts);
                        break;

                    case POLICY_VALID_PERIOD:
                        LogSecureDebug("validPeriod: " << policy.validPeriod);
                        break;

                    case POLICY_HISTORY_SIZE:
                        LogSecureDebug("historySize: " << policy.historySize);
                        break;

                    case POLICY_MIN_LENGTH:
                        LogSecureDebug("minLength: " << policy.minLength);
                        itPolicy->second.setMinLength(policy.minLength);
                        break;

                    case POLICY_MIN_COMPLEX_CHAR_NUMBER:
                        LogSecureDebug("minComplexCharNumber: " << policy.minComplexCharNumber);
                        itPolicy->second.setMinComplexCharNumber(policy.minComplexCharNumber);
                        break;

                    case POLICY_MAX_CHAR_OCCURRENCES:
                        LogSecureDebug("maxCharOccurrences: " << policy.maxCharOccurrences);
                        itPolicy->second.setMaxCharOccurrences(policy.maxCharOccurrences);
                        break;

                    case POLICY_MAX_NUMERIC_SEQ_LENGTH:
                        LogSecureDebug("maxNumSeqLength: " << policy.maxNumSeqLength);
                        itPolicy->second.setMaxNumSeqLength(policy.maxNumSeqLength);
                        break;

                    case POLICY_QUALITY_TYPE:
                        LogSecureDebug("qualityType: " << policy.qualityType);
                        itPolicy->second.setQualityType(policy.qualityType);
                        break;

                    case POLICY_PATTERN:
                        LogSecureDebug("pattern: " << policy.pattern);
                        itPolicy->second.setPattern(policy.pattern);
                        break;

                    case POLICY_FORBIDDEN_PASSWDS:
                        LogSecureDebug("forbiddenPasswds number: " << policy.forbiddenPasswds.size());
                        itPolicy->second.setForbiddenPasswds(policy.forbiddenPasswds);
                        break;

                    default:
                        LogError("Not supported policy type.");
                        return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                }
            }
        }
        itPolicy->second.enable();
        itPolicy->second.writeMemoryToFile();

        return AUTH_PASSWD_API_SUCCESS;
    }
} //namespace AuthPasswd
