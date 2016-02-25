/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        password-file.h
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Piotr Bartosiewicz (p.bartosiewi@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of PasswordFile, used to manage password files.
 */
#ifndef _PASSWORD_FILE_H_
#define _PASSWORD_FILE_H_

#include <string>
#include <vector>
#include <list>
#include <chrono>
#include <memory>

#include <time.h>

#include <dpl/serialization.h>

namespace AuthPasswd
{
    extern const time_t PASSWORD_INFINITE_EXPIRATION_TIME;

    struct IPassword: public ISerializable
    {
        typedef std::vector<unsigned char> RawHash;

        enum class PasswordType : unsigned int
        {
            NONE = 0,
            SHA256 = 1,
        };

        virtual bool match(const std::string &password) const = 0;
    };

    typedef std::shared_ptr<IPassword> IPasswordPtr;
    typedef std::list<IPasswordPtr> PasswordList;

    class PasswordFile
    {
    public:
        PasswordFile(unsigned int user);

        void writeMemoryToFile() const;
        void writeAttemptToFile() const;

        void setPassword(unsigned int passwdType, const std::string &password);
        bool checkPassword(unsigned int passwdType, const std::string &password) const;

        bool isPasswordActive(unsigned int passwdType) const;

        void setMaxHistorySize(unsigned int history);
        unsigned int getMaxHistorySize() const;

        unsigned int getExpireTime() const;
        void setExpireTime(unsigned int expireTime);

        unsigned int getExpireTimeLeft() const;
        void setExpireTimeLeft(time_t expireTimeLeft);

        //attempt manipulating functions
        unsigned int getAttempt() const;
        void resetAttempt();
        void incrementAttempt();
        int getMaxAttempt() const;
        void setMaxAttempt(unsigned int maxAttempt);

        bool isPasswordReused(const std::string &password) const;

        bool checkExpiration() const;
        bool checkIfAttemptsExceeded() const;
        bool isIgnorePeriod() const;

        bool isHistoryActive() const;

    private:
#if (__GNUC__ > 4) || (__GNUC__ == 4 && (__GNUC_MINOR__ >= 7))
        typedef std::chrono::steady_clock ClockType;
#else
        typedef std::chrono::monotonic_clock ClockType;
#endif
        typedef std::chrono::duration<double> TimeDiff;
        typedef std::chrono::time_point<ClockType, TimeDiff> TimePoint;

        void loadMemoryFromFile();
        bool tryLoadMemoryFromOldFormatFile();

        void resetTimer();
        void preparePwdFile();
        void prepareAttemptFile();
        void resetState();
        bool fileExists(const std::string &filename) const;
        bool dirExists(const std::string &dirpath) const;
        std::string createDir(const std::string &dir, unsigned int user) const;

        mutable TimePoint m_retryTimerStart;

        //user name
        const unsigned int m_user;

        //password file data
        IPasswordPtr m_passwordCurrent;
        IPasswordPtr m_passwordRecovery;
        PasswordList m_passwordHistory;
        unsigned int m_maxAttempt;
        unsigned int m_maxHistorySize;
        unsigned int m_expireTime;
        time_t       m_expireTimeLeft;
        bool         m_passwordActive;
        bool         m_passwordRcvActive;

        //attempt file data
        unsigned int m_attempt;
    };
}    //namespace AuthPasswd

#endif
