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
 * @file        password-manager.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of password management functions
 */

#include <password-manager.h>

#include <iostream>
#include <iterator>
#include <algorithm>

#include <limits.h>

#include <dpl/log/log.h>

#include <auth-passwd-policy-types.h>
#include <auth-passwd-error.h>

#include <policy.h>

namespace {
    void calculateExpiredTime(unsigned int receivedDays, time_t &validSecs)
    {
        validSecs = AuthPasswd::PASSWORD_INFINITE_EXPIRATION_TIME;

        //when receivedDays means infinite expiration, return default validSecs value.
        if(receivedDays == AuthPasswd::PASSWORD_INFINITE_EXPIRATION_DAYS)
            return;

        time_t curTime = time(NULL);
        validSecs = (curTime + (receivedDays * 86400));
        return;
    }
} //namespace

namespace AuthPasswd
{
    void PasswordManager::addPassword(unsigned int user)
    {
        m_pwdFile.insert(PasswordFileMap::value_type(user, PasswordFile(user)));
    }

    void PasswordManager::removePassword(unsigned int user)
    {
        m_pwdFile.erase(user);
    }

    void PasswordManager::existPassword(unsigned int user)
    {
        PasswordFileMap::iterator itPwd = m_pwdFile.find(user);
        if (itPwd != m_pwdFile.end())
            return;

        addPassword(user);
        return;
    }

    int PasswordManager::checkPassword(unsigned int passwdType,
                                       const std::string &challenge,
                                       unsigned int currentUser,
                                       unsigned int &currentAttempt,
                                       unsigned int &maxAttempt,
                                       unsigned int &expirationTime)
    {
        LogSecureDebug("Inside checkPassword function.");

        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occurred.");
            return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER;
        }
        if (!itPwd->second.isPasswordActive(passwdType) && !challenge.empty()) {
            LogError("Password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        switch(passwdType) {
            case AUTH_PWD_NORMAL:

                itPwd->second.incrementAttempt();
                itPwd->second.writeAttemptToFile();

                currentAttempt = itPwd->second.getAttempt();
                maxAttempt = itPwd->second.getMaxAttempt();
                expirationTime = itPwd->second.getExpireTimeLeft();

                if (itPwd->second.checkIfAttemptsExceeded()) {
                    LogError("Too many tries.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
                }
                if (!itPwd->second.checkPassword(AUTH_PWD_NORMAL, challenge)) {
                    LogError("Wrong password.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH;
                }

                // Password maches and attempt number is fine - time to reset counter.
                itPwd->second.resetAttempt();
                itPwd->second.writeAttemptToFile();

                // Password is too old. You must change it before login.
                if (itPwd->second.checkExpiration()) {
                    LogError("Password expired.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_EXPIRED;
                }
                break;
            
            case AUTH_PWD_RECOVERY: 
                if (!itPwd->second.checkPassword(AUTH_PWD_RECOVERY, challenge)) {
                    LogError("Wrong password.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH;
                }
                break;

            default:
                LogError("Not supported password type.");
                return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::isPwdValid(unsigned int passwdType, unsigned int currentUser,
                                    unsigned int &currentAttempt, unsigned int &maxAttempt,
                                    unsigned int &expirationTime)
    {
        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        if (!itPwd->second.isPasswordActive(passwdType)) {
            LogError("Current password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        switch(passwdType) {
            case AUTH_PWD_NORMAL:
                currentAttempt = itPwd->second.getAttempt();
                maxAttempt = itPwd->second.getMaxAttempt();
                expirationTime = itPwd->second.getExpireTimeLeft();
                break;

            case AUTH_PWD_RECOVERY:
                // there are no maxAttempt and expirationTime for recovery password
                currentAttempt = PASSWORD_INFINITE_ATTEMPT_COUNT;
                maxAttempt = PASSWORD_INFINITE_ATTEMPT_COUNT;
                expirationTime = PASSWORD_API_NO_EXPIRATION;
                break;

            default:
                LogError("Not supported password type.");
                return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::isPwdReused(unsigned int passwdType, const std::string &passwd,
                                     unsigned int currentUser, bool &isReused)
    {
        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        isReused = false;

        switch(passwdType) {
            case AUTH_PWD_NORMAL:
                // check history, however only if history is active and password is not empty
                if (itPwd->second.isHistoryActive() && !passwd.empty())
                    isReused = itPwd->second.isPasswordReused(passwd);
                break;

            case AUTH_PWD_RECOVERY:
                break;

            default:
                LogError("Not supported password type.");
                return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::setPassword(unsigned int passwdType,
                                     const std::string &currentPassword,
                                     const std::string &newPassword,
                                     unsigned int currentUser)
    {
        LogSecureDebug("curUser = " << currentUser << ", pwdType = " << passwdType <<
                       ", curPwd = " << currentPassword << ", newPwd = " << newPassword);

        unsigned int receivedDays = PASSWORD_INFINITE_EXPIRATION_DAYS;
        time_t valid_secs = 0;

        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occured.");
            return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        // check delivered currentPassword
        // when m_passwordActive flag is false, current password should be empty
        if (!currentPassword.empty() && !itPwd->second.isPasswordActive(passwdType)) {
            LogError("Password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        switch(passwdType) {
            case AUTH_PWD_NORMAL:

                //increment attempt count before checking it against max attempt count
                itPwd->second.incrementAttempt();
                itPwd->second.writeAttemptToFile();

                if (itPwd->second.checkIfAttemptsExceeded()) {
                    LogError("Too many tries.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
                }

                if (!itPwd->second.checkPassword(AUTH_PWD_NORMAL, currentPassword)) {
                    LogError("Wrong password.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH;
                }

                //here we are sure that user knows current password - we can reset attempt counter
                itPwd->second.resetAttempt();
                itPwd->second.writeAttemptToFile();

                // check history, however only if history is active and new password is not empty
                if (itPwd->second.isHistoryActive() && !newPassword.empty()) {
                    if (itPwd->second.isPasswordReused(newPassword)) {
                        LogError("Password reused.");
                        return AUTH_PASSWD_API_ERROR_PASSWORD_REUSED;
                    }
                }

                if (!newPassword.empty())
                    receivedDays = itPwd->second.getExpireTime();

                calculateExpiredTime(receivedDays, valid_secs);

                //setting password
                itPwd->second.setPassword(AUTH_PWD_NORMAL, newPassword);
                itPwd->second.setExpireTimeLeft(valid_secs);
                itPwd->second.writeMemoryToFile();
                break;

            case AUTH_PWD_RECOVERY:
                if (!itPwd->second.checkPassword(AUTH_PWD_RECOVERY, currentPassword)) {
                    LogError("Wrong password.");
                    return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH;
                }
                itPwd->second.setPassword(AUTH_PWD_RECOVERY, newPassword);
                itPwd->second.writeMemoryToFile();
                break;

            default:
                LogError("Not supported password type.");
                return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::setPasswordRecovery(const std::string &curRcvPassword,
                                             const std::string &newPassword,
                                             unsigned int currentUser)
    {
        LogSecureDebug("curUser = " << currentUser << ", curPwd = " << curRcvPassword <<
                       ", newPwd = " << newPassword);

        unsigned int receivedDays = PASSWORD_INFINITE_EXPIRATION_DAYS;
        time_t valid_secs = 0;

        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occured.");
            return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        //check if passwords are correct
        if (curRcvPassword.empty() || newPassword.empty()) {
            LogError("Incorrect input param.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        // current recovery password should be existed.
        if (!itPwd->second.isPasswordActive(AUTH_PWD_RECOVERY)) {
            LogError("Password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        receivedDays = itPwd->second.getExpireTime();

        // don't recovery password if MaxAttempt value is not infinite.
        if (receivedDays != PASSWORD_INFINITE_EXPIRATION_DAYS)
            return AUTH_PASSWD_API_ERROR_RECOVERY_PASSWORD_RESTRICTED;

        if (!itPwd->second.checkPassword(AUTH_PWD_RECOVERY, curRcvPassword)) {
            LogError("Wrong password.");
            return AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH;
        }

        // check history, however only if history is active and new password is not empty
        if (itPwd->second.isHistoryActive()) {
            if (itPwd->second.isPasswordReused(newPassword)) {
                LogError("Password reused.");
                return AUTH_PASSWD_API_ERROR_PASSWORD_REUSED;
            }
        }

        calculateExpiredTime(receivedDays, valid_secs);

        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        //setting password
        itPwd->second.setPassword(AUTH_PWD_NORMAL, newPassword);
        itPwd->second.setExpireTimeLeft(valid_secs);
        itPwd->second.writeMemoryToFile();

        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::resetPassword(unsigned int passwdType,
                                       const std::string &newPassword,
                                       unsigned int receivedUser)
    {
        unsigned int receivedDays = PASSWORD_INFINITE_EXPIRATION_DAYS;
        time_t valid_secs = 0;

        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        switch(passwdType) {
            case AUTH_PWD_NORMAL:

                if (!newPassword.empty())
                    receivedDays = itPwd->second.getExpireTime();

                calculateExpiredTime(receivedDays, valid_secs);

                itPwd->second.resetAttempt();
                itPwd->second.writeAttemptToFile();

                itPwd->second.setPassword(AUTH_PWD_NORMAL, newPassword);
                itPwd->second.setExpireTimeLeft(valid_secs);
                itPwd->second.writeMemoryToFile();
                break;

            case AUTH_PWD_RECOVERY:
                itPwd->second.setPassword(AUTH_PWD_RECOVERY, newPassword);
                itPwd->second.writeMemoryToFile();
                break;

            default:
                LogError("Not supported password type.");
                return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        return AUTH_PASSWD_API_SUCCESS;
    }

    void PasswordManager::setPasswordMaxAttempts(unsigned int receivedUser,
                                                unsigned int receivedAttempts)
    {
        LogSecureDebug("received_attempts: " << receivedAttempts);

        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        itPwd->second.setMaxAttempt(receivedAttempts);
        itPwd->second.writeMemoryToFile();

        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();
    }

    void PasswordManager::setPasswordValidity(unsigned int receivedUser,
                                             unsigned int receivedDays)
    {
        LogSecureDebug("received_days: " << receivedDays);

        time_t valid_secs = 0;

        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        calculateExpiredTime(receivedDays, valid_secs);

        if (itPwd->second.isPasswordActive(AUTH_PWD_NORMAL))
            itPwd->second.setExpireTimeLeft(valid_secs);

        itPwd->second.setExpireTime(receivedDays);
        itPwd->second.writeMemoryToFile();
    }

    void PasswordManager::setPasswordHistory(unsigned int receivedUser,
                                            unsigned int receivedHistory)
    {
        LogSecureDebug("received_historySize: " << receivedHistory);

        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        itPwd->second.setMaxHistorySize(receivedHistory);
        itPwd->second.writeMemoryToFile();
    }
} //namespace AuthPasswd
