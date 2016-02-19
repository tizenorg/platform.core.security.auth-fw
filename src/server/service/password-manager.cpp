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

#include <protocols.h>

namespace {
    bool calculateExpiredTime(unsigned int receivedDays, time_t &validSecs)
    {
        validSecs = AuthPasswd::PASSWORD_INFINITE_EXPIRATION_TIME;

        //when receivedDays means infinite expiration, return default validSecs value.
        if(receivedDays == AuthPasswd::PASSWORD_INFINITE_EXPIRATION_DAYS)
            return true;

        time_t curTime = time(NULL);

        if (receivedDays > ((UINT_MAX - curTime) / 86400)) {
            LogError("Incorrect input param.");
            return false;
        } else {
            validSecs = (curTime + (receivedDays * 86400));
            return true;
        }
    }
} //namespace

namespace AuthPasswd
{
    void PasswordManager::addPassword(const unsigned int user)
    {
        m_pwdFile.insert(PasswordFileMap::value_type(user, PasswordFile(user)));
    }

    void PasswordManager::removePassword(const unsigned int user)
    {
        m_pwdFile.erase(user);
    }

    void PasswordManager::existPassword(const unsigned int user)
    {
        PasswordFileMap::iterator itPwd = m_pwdFile.find(user);
        if (itPwd != m_pwdFile.end())
            return;

        addPassword(user);
        return;
    }

    int PasswordManager::checkPassword(const unsigned int passwdType,
                                       const std::string &challenge,
                                       const unsigned int currentUser,
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

    int PasswordManager::isPwdValid(const unsigned int passwdType, const unsigned int currentUser,
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

    int PasswordManager::isPwdReused(const unsigned int passwdType, const std::string &passwd,
                                     const unsigned int currentUser, bool &isReused)
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

    int PasswordManager::setPassword(const unsigned int passwdType, 
                                     const std::string &currentPassword,
                                     const std::string &newPassword,
                                     const unsigned int currentUser,
                                     const unsigned int receivedAttempts,
                                     const unsigned int receivedDays,
                                     const unsigned int receivedHistory)
    {
        LogSecureDebug("curUser = " << currentUser << ", pwdType = " << passwdType <<
                       ", curPwd = " << currentPassword << ", newPwd = " << newPassword <<
                       ", recAtt = " << receivedAttempts << ", recDays = " << receivedDays <<
                       ", recHistory = " << receivedHistory);

        time_t valid_secs = 0;

        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occured.");
            return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        //check if passwords are correct
        if (currentPassword.size() > MAX_PASSWORD_LEN) {
            LogError("Current password length failed.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (newPassword.size() > MAX_PASSWORD_LEN) {
            LogError("New password length failed.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        // check delivered currentPassword
        // when m_passwordActive flag is false, current password should be empty
        if (!currentPassword.empty() && !itPwd->second.isPasswordActive(passwdType)) {
            LogError("Password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        switch(passwdType) {
            case AUTH_PWD_NORMAL:
                // You remove password and set up recAttempts or recDays
                if (newPassword.empty() && (receivedAttempts != 0 || receivedDays != 0)) {
                    LogError("Attempts or receivedDays is not equal 0");
                    return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                }

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

                if (!calculateExpiredTime(receivedDays, valid_secs)) {
                    LogError("Received expiration time incorrect.");
                    return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                }

                //setting password
                itPwd->second.setPassword(AUTH_PWD_NORMAL, newPassword);
                itPwd->second.setMaxAttempt(receivedAttempts);
                itPwd->second.setExpireTime(valid_secs);
                itPwd->second.setMaxHistorySize(receivedHistory);
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
                                             const unsigned int currentUser,
                                             const unsigned int receivedAttempts,
                                             const unsigned int receivedDays,
                                             const unsigned int receivedHistory)
    {
        LogSecureDebug("curUser = " << currentUser << ", curPwd = " << curRcvPassword <<
                       ", newPwd = " << newPassword << ", recAtt = " << receivedAttempts <<
                       ", recDays = " << receivedDays << ", recHistory = " << receivedHistory);

        time_t valid_secs = 0;

        existPassword(currentUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(currentUser);

        if (itPwd->second.isIgnorePeriod()) {
            LogError("Retry timeout occured.");
            return AUTH_PASSWD_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        //check if passwords are correct
        if (curRcvPassword.size() > MAX_PASSWORD_LEN || curRcvPassword.empty()) {
            LogError("Current recovery password length failed.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }
        if (newPassword.size() > MAX_PASSWORD_LEN || newPassword.empty()) {
            LogError("New password length failed.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        // current recovery password should be existed.
        if (!itPwd->second.isPasswordActive(AUTH_PWD_RECOVERY)) {
            LogError("Password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

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

        if (!calculateExpiredTime(receivedDays, valid_secs)) {
            LogError("Received expiration time incorrect.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        //setting password
        itPwd->second.setPassword(AUTH_PWD_NORMAL, newPassword);
        itPwd->second.setMaxAttempt(receivedAttempts);
        itPwd->second.setExpireTime(valid_secs);
        itPwd->second.setMaxHistorySize(receivedHistory);
        itPwd->second.writeMemoryToFile();

        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::resetPassword(const unsigned int passwdType,
                                       const std::string &newPassword,
                                       const unsigned int receivedUser,
                                       const unsigned int receivedAttempts,
                                       const unsigned int receivedDays,
                                       const unsigned int receivedHistory)
    {
        time_t valid_secs = 0;

        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        switch(passwdType) {
            case AUTH_PWD_NORMAL:
                if (!calculateExpiredTime(receivedDays, valid_secs))
                    return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

                if (newPassword.empty() && (receivedAttempts != 0 || receivedDays != 0)) {
                    LogError("Attempts or receivedDays is not equal 0");
                    return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
                }
                itPwd->second.resetAttempt();
                itPwd->second.writeAttemptToFile();
                itPwd->second.setPassword(AUTH_PWD_NORMAL, newPassword);
                itPwd->second.setMaxAttempt(receivedAttempts);
                itPwd->second.setExpireTime(valid_secs);
                itPwd->second.setMaxHistorySize(receivedHistory);
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

    int PasswordManager::setPasswordMaxAttempts(const unsigned int receivedUser,
                                                const unsigned int receivedAttempts)
    {
        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        // check if there is password
        if (!itPwd->second.isPasswordActive(AUTH_PWD_NORMAL)) {
            LogError("Password not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        itPwd->second.setMaxAttempt(receivedAttempts);
        itPwd->second.writeMemoryToFile();

        itPwd->second.resetAttempt();
        itPwd->second.writeAttemptToFile();

        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::setPasswordValidity(const unsigned int receivedUser,
                                             const unsigned int receivedDays)
    {
        time_t valid_secs = 0;

        LogSecureDebug("received_days: " << receivedDays);

        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        if (!itPwd->second.isPasswordActive(AUTH_PWD_NORMAL)) {
            LogError("Current password is not active.");
            return AUTH_PASSWD_API_ERROR_NO_PASSWORD;
        }

        if (!calculateExpiredTime(receivedDays, valid_secs))
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;

        itPwd->second.setExpireTime(valid_secs);
        itPwd->second.writeMemoryToFile();

        return AUTH_PASSWD_API_SUCCESS;
    }

    int PasswordManager::setPasswordHistory(const unsigned int receivedUser,
                                            const unsigned int receivedHistory)
    {
        existPassword(receivedUser);
        PasswordFileMap::iterator itPwd = m_pwdFile.find(receivedUser);

        if (receivedHistory > MAX_PASSWORD_HISTORY) {
            LogError("Incorrect input param.");
            return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
        }

        itPwd->second.setMaxHistorySize(receivedHistory);
        itPwd->second.writeMemoryToFile();

        return AUTH_PASSWD_API_SUCCESS;
    }
} //namespace AuthPasswd
