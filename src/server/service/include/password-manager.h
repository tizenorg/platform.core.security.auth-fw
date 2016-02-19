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
 * @file        password-manager.h
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of password management functions
 */

#ifndef _PASSWORDMANAGER_H_
#define _PASSWORDMANAGER_H_

#include <string>
#include <map>

#include <password-file.h>

namespace AuthPasswd
{
    class PasswordManager
    {
    public:
        typedef std::map<unsigned int, PasswordFile> PasswordFileMap;

        //checking functions
        //no const in checkPassword, attempts are update
        int checkPassword(const unsigned int passwdType, const std::string& challenge,
                          const unsigned int currentUser, unsigned int &currentAttempt,
                          unsigned int &maxAttempt, unsigned int &expirationTime);
        int isPwdValid(const unsigned int passwdType, const unsigned int currentUser,
                       unsigned int &currentAttempt, unsigned int &maxAttempt,
                       unsigned int &expirationTime);
        int isPwdReused(const unsigned int passwdType, const std::string &passwd, 
                        const unsigned int currentUser, bool &isReused);

        //setting functions
        int setPassword(const unsigned int passwdType, const std::string &currentPassword,
                        const std::string &newPassword, const unsigned int currentUser,
                        const unsigned int receivedAttempts, const unsigned int receivedDays,
                        const unsigned int receivedHistory);
        int setPasswordRecovery(const std::string &curRcvPassword, const std::string &newPassword,
                        const unsigned int currentUser, const unsigned int receivedAttempts,
                        const unsigned int receivedDays, const unsigned int receivedHistory);

        //resetting functions
        int resetPassword(const unsigned int passwdType, const std::string &newPassword,
                          const unsigned int receivedUser, const unsigned int receivedAttempts,
                          const unsigned int receivedDays, const unsigned int receivedHistory);

        //setting policy on the current passwd
        int setPasswordMaxAttempts(const unsigned int receivedUser,
                                   const unsigned int receivedAttempts);
        int setPasswordValidity(const unsigned int receivedUser, const unsigned int receivedDays);
        int setPasswordHistory(const unsigned int receivedUser, const unsigned int receivedHistory);

    private:
        //managing functions
        void addPassword(const unsigned int user);
        void removePassword(const unsigned int user);
        void existPassword(const unsigned int user);

        PasswordFileMap m_pwdFile;
    };
} //namespace AuthPasswd

#endif
