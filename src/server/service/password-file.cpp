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
 * @file        password-file.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Piotr Bartosiewicz (p.bartosiewi@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of PasswordFile, used to manage password files.
 */
#include <password-file.h>

#include <fstream>
#include <algorithm>
#include <limits>

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <dpl/log/log.h>
#include <dpl/fstream_accessors.h>

#include <auth-passwd-policy-types.h>
#include <auth-passwd-error.h>

#include <error-description.h>
#include <policy.h>
#include <password-exception.h>
#include <password-file-buffer.h>

namespace {
    const std::string PASSWORD_FILE = "/password";
    const std::string OLD_VERSION_PASSWORD_FILE = "/password.old";
    const std::string ATTEMPT_FILE = "/attempt";
    const double RETRY_TIMEOUT = 0.5;
    const mode_t FILE_MODE = S_IRUSR | S_IWUSR;
    const unsigned int CURRENT_FILE_VERSION = 1;
} // namespace anonymous

namespace AuthPasswd
{
    const time_t PASSWORD_INFINITE_EXPIRATION_TIME = std::numeric_limits<time_t>::max();

    class NoPassword: public IPassword
    {
        public:
            NoPassword(IStream&) {}
            NoPassword() {}

            void Serialize(IStream &stream) const
            {
                Serialization::Serialize(stream, static_cast<unsigned int>(PasswordType::NONE));
            }

            bool match(const std::string &pass) const
            {
                return pass.empty();
            }
    };

    class SHA256Password: public IPassword
    {
        public:
            SHA256Password(IStream& stream)
            {
                Deserialization::Deserialize(stream, m_hash);
            }

            SHA256Password(const std::string &password)
                : m_hash(hash(password)) {}

            SHA256Password(const RawHash& paramHash)
                : m_hash(paramHash) {}

            void Serialize(IStream &stream) const
            {
                Serialization::Serialize(stream, static_cast<unsigned int>(PasswordType::SHA256));
                Serialization::Serialize(stream, m_hash);
            }

            bool match(const std::string &password) const
            {
                return m_hash == hash(password);
            }
        private:
            RawHash m_hash;

            static RawHash hash(const std::string &password)
            {
                RawHash result(SHA256_DIGEST_LENGTH);

                SHA256_CTX context;
                SHA256_Init(&context);
                SHA256_Update(&context, reinterpret_cast<const unsigned char*>(password.c_str()),
                        password.size());
                SHA256_Final(result.data(), &context);

                return result;
            }
    };

    // deserialization of new password format
    template <>
    void Deserialization::Deserialize(IStream& stream, IPasswordPtr& ptr)
    {
        unsigned int algorithm;
        Deserialization::Deserialize(stream, algorithm);
        switch (algorithm) {
            case (unsigned int)IPassword::PasswordType::NONE:
                ptr.reset(new NoPassword());
                break;
            case (unsigned int)IPassword::PasswordType::SHA256:
                ptr.reset(new SHA256Password(stream));
                break;
            default:
                Throw(PasswordException::FStreamReadError);
        }
    }

    PasswordFile::PasswordFile(const unsigned int user): m_user(user),
                                  m_passwordCurrent(new NoPassword()),
                                  m_passwordRecovery(new NoPassword()),
                                  m_maxAttempt(PASSWORD_INFINITE_ATTEMPT_COUNT),
                                  m_maxHistorySize(0),
                                  m_expireTime(PASSWORD_INFINITE_EXPIRATION_DAYS),
                                  m_expireTimeLeft(PASSWORD_INFINITE_EXPIRATION_TIME),
                                  m_passwordActive(false),
                                  m_passwordRcvActive(false),
                                  m_attempt(0)
    {
        // check if data directory exists
        // if not create it
        std::string userDir = createDir(RW_DATA_DIR, m_user);

        if (!dirExists(RW_DATA_DIR)) {
            if(mkdir(RW_DATA_DIR, 0700)) {
                LogError("Failed to create directory for files. Error: " << strerror(errno));
                Throw(PasswordException::MakeDirError);
            }
        }

        if (!dirExists(userDir.c_str())) {
            if(mkdir(userDir.c_str(), 0700)) {
                LogError("Failed to create directory for files. Error: " << strerror(errno));
                Throw(PasswordException::MakeDirError);
            }
        }

        preparePwdFile();
        prepareAttemptFile();
        resetTimer();
    }

    void PasswordFile::resetState()
    {
        m_maxAttempt = PASSWORD_INFINITE_ATTEMPT_COUNT;
        m_maxHistorySize = 0;
        m_expireTime = PASSWORD_INFINITE_EXPIRATION_DAYS;
        m_expireTimeLeft = PASSWORD_INFINITE_EXPIRATION_TIME;
        m_passwordRcvActive = false;
        m_passwordRecovery.reset(new NoPassword());
        m_passwordActive = false;
        m_passwordCurrent.reset(new NoPassword());
    }

    void PasswordFile::resetTimer()
    {
        m_retryTimerStart = ClockType::now();
        m_retryTimerStart -= TimeDiff(RETRY_TIMEOUT);
    }

    void PasswordFile::preparePwdFile()
    {
        std::string pwdFile = createDir(RW_DATA_DIR, m_user) + PASSWORD_FILE;
        std::string oldVersionPwdFile = createDir(RW_DATA_DIR, m_user) + OLD_VERSION_PASSWORD_FILE;

        // check if password file exists
        if (!fileExists(pwdFile)) {
            // if old format file exist - load it
            if (tryLoadMemoryFromOldFormatFile()) {
                // save in new format
                writeMemoryToFile();
                // and remove old file
                if (remove(oldVersionPwdFile.c_str())) {
                    LogError("Failed to remove file" << oldVersionPwdFile <<
                             " Error: " << strerror(errno));
                    Throw(PasswordException::RemoveError);
                }
                return;
            }
            LogSecureDebug("PWD_DBG not found " << m_user << " password file. Creating.");

            //create file
            writeMemoryToFile();
        } else {     //if file exists, load data
            LogSecureDebug("PWD_DBG found " << m_user << " password file. Opening.");
            try {
                loadMemoryFromFile();
            } catch (...) {
                LogError("Invalid " << pwdFile << " file format");
                resetState();
                writeMemoryToFile();
            }
        }
    }

    void PasswordFile::prepareAttemptFile()
    {
        std::string attemptFile = createDir(RW_DATA_DIR, m_user) + ATTEMPT_FILE;

        // check if attempt file exists
        // if not create it
        if (!fileExists(attemptFile)) {
            LogSecureDebug("PWD_DBG not found " << m_user << " attempt file. Creating.");
            writeAttemptToFile();
        } else {
            LogSecureDebug("PWD_DBG found " << m_user << " attempt file. Opening.");
            std::ifstream AttemptFile(attemptFile);
            if(!AttemptFile) {
                LogError("Failed to open " << m_user << " attempt file.");
                // ignore error
                return;
            }

            AttemptFile.read(reinterpret_cast<char*>(&m_attempt), sizeof(unsigned int));
            if(!AttemptFile) {
                LogError("Failed to read " << m_user <<" attempt count.");
                // ignore error
                resetAttempt();
            }
        }
    }

    bool PasswordFile::fileExists(const std::string &filename) const
    {
        struct stat buf;

        return ((stat(filename.c_str(), &buf) == 0));
    }

    bool PasswordFile::dirExists(const std::string &dirpath) const
    {
        struct stat buf;

        return ((stat(dirpath.c_str(), &buf) == 0) && (((buf.st_mode) & S_IFMT) == S_IFDIR));
    }

    std::string PasswordFile::createDir(const std::string &dir, const unsigned int user) const
    {
        std::string User = std::to_string(user);
        return dir + "/" + User;
    }

    void PasswordFile::writeMemoryToFile() const
    {
        PasswordFileBuffer pwdBuffer;

        LogSecureDebug("User: " << m_user << ", saving max_att: " << m_maxAttempt <<
                       ", history_size: " << m_maxHistorySize << ", m_expireTime: " <<
                       m_expireTime << ", m_expireTimeLeft: " << m_expireTimeLeft <<
                       ", isActive: " << m_passwordActive << ", isRcvActive: " <<
                       m_passwordRcvActive);

        //serialize password attributes
        Serialization::Serialize(pwdBuffer, CURRENT_FILE_VERSION);
        Serialization::Serialize(pwdBuffer, m_maxAttempt);
        Serialization::Serialize(pwdBuffer, m_maxHistorySize);
        Serialization::Serialize(pwdBuffer, m_expireTime);
        Serialization::Serialize(pwdBuffer, m_expireTimeLeft);
        Serialization::Serialize(pwdBuffer, m_passwordRcvActive);
        Serialization::Serialize(pwdBuffer, m_passwordRecovery);
        Serialization::Serialize(pwdBuffer, m_passwordActive);
        Serialization::Serialize(pwdBuffer, m_passwordCurrent);
        Serialization::Serialize(pwdBuffer, m_passwordHistory);

        std::string pwdFile = createDir(RW_DATA_DIR, m_user) + PASSWORD_FILE;
        pwdBuffer.Save(pwdFile);

        if (chmod(pwdFile.c_str(), FILE_MODE)) {
            LogError("Failed to chmod for " << pwdFile << " Error: " << strerror(errno));
            Throw(PasswordException::ChmodError);
        }
    }

    void PasswordFile::loadMemoryFromFile()
    {
        PasswordFileBuffer pwdBuffer;
        std::string pwdFile = createDir(RW_DATA_DIR, m_user) + PASSWORD_FILE;

        pwdBuffer.Load(pwdFile);

        unsigned int fileVersion = 0;
        Deserialization::Deserialize(pwdBuffer, fileVersion);
        if (fileVersion != CURRENT_FILE_VERSION)
            Throw(PasswordException::FStreamReadError);

        m_passwordHistory.clear();

        Deserialization::Deserialize(pwdBuffer, m_maxAttempt);
        Deserialization::Deserialize(pwdBuffer, m_maxHistorySize);
        Deserialization::Deserialize(pwdBuffer, m_expireTime);
        Deserialization::Deserialize(pwdBuffer, m_expireTimeLeft);
        Deserialization::Deserialize(pwdBuffer, m_passwordRcvActive);
        Deserialization::Deserialize(pwdBuffer, m_passwordRecovery);
        Deserialization::Deserialize(pwdBuffer, m_passwordActive);
        Deserialization::Deserialize(pwdBuffer, m_passwordCurrent);
        Deserialization::Deserialize(pwdBuffer, m_passwordHistory);

        LogSecureDebug("User: " << m_user << ", loaded max_att: " << m_maxAttempt <<
                       ", history_size: " << m_maxHistorySize << ", m_expireTime: " <<
                       m_expireTime << ", m_expireTimeLeft: " << m_expireTimeLeft <<
                       ", isActive: " << m_passwordActive << ", isRcvActive: " <<
                       m_passwordRcvActive);
    }

    bool PasswordFile::tryLoadMemoryFromOldFormatFile()
    {
        struct stat oldFileStat;
        std::string oldVersionPwdFile = createDir(RW_DATA_DIR, m_user) + OLD_VERSION_PASSWORD_FILE;

        if (stat(oldVersionPwdFile.c_str(), &oldFileStat) != 0)
            return false;

        static const int ELEMENT_SIZE = sizeof(unsigned) + SHA256_DIGEST_LENGTH;
        static const int VERSION_1_REMAINING = sizeof(unsigned) * 4;
        static const int VERSION_2_REMAINING = VERSION_1_REMAINING + sizeof(bool);
        int remaining = oldFileStat.st_size % ELEMENT_SIZE;

        if (remaining != VERSION_1_REMAINING && remaining != VERSION_2_REMAINING)
            return false;

        try {
            PasswordFileBuffer pwdBuffer;
            pwdBuffer.Load(oldVersionPwdFile);

            Deserialization::Deserialize(pwdBuffer, m_maxAttempt);
            Deserialization::Deserialize(pwdBuffer, m_maxHistorySize);
            Deserialization::Deserialize(pwdBuffer, m_expireTimeLeft);
            if (m_expireTimeLeft == 0)
                m_expireTimeLeft = PASSWORD_INFINITE_EXPIRATION_TIME;

            if (remaining == VERSION_2_REMAINING)
                Deserialization::Deserialize(pwdBuffer, m_passwordActive);
            else
                m_passwordActive = true;

            // deserialize passwords in old format
            struct OldPassword {
                OldPassword() {}
                OldPassword(IStream &stream)
                {
                    Deserialization::Deserialize(stream, m_hash);
                }
                IPassword::RawHash m_hash;
            };
            std::list<OldPassword> oldFormatPasswords;
            Deserialization::Deserialize(pwdBuffer, oldFormatPasswords);

            // convert passwords to new format
            m_passwordHistory.clear();
            if (oldFormatPasswords.empty()) {
                m_passwordCurrent.reset(new NoPassword());
                m_passwordActive = false;
            } else {
                m_passwordCurrent.reset(new SHA256Password(oldFormatPasswords.front().m_hash));
                std::for_each(++oldFormatPasswords.begin(), oldFormatPasswords.end(),
                    [&] (const OldPassword& pwd)
                    {m_passwordHistory.push_back(IPasswordPtr(new SHA256Password(pwd.m_hash)));}
                    );
            }

            m_expireTime = PASSWORD_INFINITE_EXPIRATION_DAYS;
            m_passwordRcvActive = false;
            m_passwordRecovery.reset(new NoPassword());

        } catch (...) {
            LogWarning("Invalid " << oldVersionPwdFile << " file format");
            resetState();
            return false;
        }

        return true;
    }

    void PasswordFile::writeAttemptToFile() const
    {
        std::string attemptFile = createDir(RW_DATA_DIR, m_user) + ATTEMPT_FILE;

        std::ofstream AttemptFile(attemptFile, std::ofstream::trunc);

        if(!AttemptFile.good()) {
            LogError("Failed to open " << m_user << " attempt file.");
            Throw(PasswordException::FStreamOpenError);
        }

        AttemptFile.write(reinterpret_cast<const char*>(&m_attempt), sizeof(unsigned int));
        if(!AttemptFile) {
            LogError("Failed to write " << m_user << " attempt count.");
            Throw(PasswordException::FStreamWriteError);
        }

        AttemptFile.flush();
        fsync(DPL::FstreamAccessors<std::ofstream>::GetFd(AttemptFile)); // flush kernel space buffer
        AttemptFile.close();
    }

    bool PasswordFile::isPasswordActive(const unsigned int passwdType) const
    {
        bool ret = false;

        if (passwdType == AUTH_PWD_NORMAL)
            ret = m_passwordActive;
        else if (passwdType == AUTH_PWD_RECOVERY)
            ret = m_passwordRcvActive;
        return ret;
    }

    void PasswordFile::setMaxHistorySize(unsigned int history)
    {
        // put current password in history
        if (m_maxHistorySize == 0 && history > 0)
            m_passwordHistory.push_front(m_passwordCurrent);

        //setting history should be independent from password being set
        m_maxHistorySize = history;

        while(m_passwordHistory.size() > history)
            m_passwordHistory.pop_back();
    }

    unsigned int PasswordFile::getMaxHistorySize() const
    {
        return m_maxHistorySize;
    }

    unsigned int PasswordFile::getAttempt() const
    {
        return m_attempt;
    }

    void PasswordFile::resetAttempt()
    {
        m_attempt = 0;
    }

    void PasswordFile::incrementAttempt()
    {
        m_attempt++;
    }

    int PasswordFile::getMaxAttempt() const
    {
        return m_maxAttempt;
    }

    void PasswordFile::setMaxAttempt(unsigned int maxAttempt)
    {
        m_maxAttempt = maxAttempt;
    }

    bool PasswordFile::isPasswordReused(const std::string &password) const
    {
        LogSecureDebug("Checking if " << m_user << " pwd is reused. HistorySize: " <<
                       m_passwordHistory.size() << ", MaxHistorySize: " << getMaxHistorySize());

        //go through history and check if password existed earlier
        if(std::any_of(m_passwordHistory.begin(), m_passwordHistory.end(),
                      [&password](const IPasswordPtr& pwd) { return pwd->match(password); })) {
            LogSecureDebug(m_user << " passwords match!");
            return true;
        }

        LogSecureDebug("isPasswordReused: No passwords match, " << m_user <<
                       " password not reused.");
        return false;
    }

    void PasswordFile::setPassword(const unsigned int passwdType, const std::string &password)
    {
        if (passwdType == AUTH_PWD_NORMAL) {
            //replace current password with new one
            if (password.empty()) {
                m_passwordCurrent.reset(new NoPassword());
                m_passwordActive = false;
            } else {
                m_passwordCurrent.reset(new SHA256Password(password));

                //put current password to history
                m_passwordHistory.push_front(m_passwordCurrent);

                //erase last password if we exceed max history size
                if(m_passwordHistory.size() > getMaxHistorySize())
                    m_passwordHistory.pop_back();
                m_passwordActive = true;
            }
        } else if (passwdType == AUTH_PWD_RECOVERY) {
            //replace current password with new one
            if (password.empty()) {
                m_passwordRecovery.reset(new NoPassword());
                m_passwordRcvActive = false;
            } else {
                m_passwordRecovery.reset(new SHA256Password(password));
                m_passwordRcvActive = true;
            }
        }
    }

    bool PasswordFile::checkPassword(const unsigned int passwdType, const std::string &password) const
    {
        bool ret = false;
        if (passwdType == AUTH_PWD_NORMAL)
            ret = m_passwordCurrent->match(password);
        else if (passwdType == AUTH_PWD_RECOVERY)
            ret = m_passwordRecovery->match(password);
        return ret;
    }

    void PasswordFile::setExpireTime(unsigned int expireTime)
    {
        m_expireTime = expireTime;
    }

    unsigned int PasswordFile::getExpireTime() const
    {
        return m_expireTime;
    }

    void PasswordFile::setExpireTimeLeft(time_t expireTimeLeft)
    {
        m_expireTimeLeft = expireTimeLeft;
    }

    unsigned int PasswordFile::getExpireTimeLeft() const
    {
        if(m_expireTimeLeft != PASSWORD_INFINITE_EXPIRATION_TIME) {
            time_t timeLeft = m_expireTimeLeft - time(NULL);
            return (timeLeft < 0) ? 0 : static_cast<unsigned int>(timeLeft);
        } else
            return PASSWORD_API_NO_EXPIRATION;
    }

    bool PasswordFile::checkExpiration() const
    {
        //return true if expired, else false
        return ((m_expireTimeLeft != PASSWORD_INFINITE_EXPIRATION_TIME) && (time(NULL) > m_expireTimeLeft));
    }

    bool PasswordFile::checkIfAttemptsExceeded() const
    {
        return ((m_maxAttempt != PASSWORD_INFINITE_ATTEMPT_COUNT) && (m_attempt > m_maxAttempt));
    }

    bool PasswordFile::isIgnorePeriod() const
    {
        TimePoint retryTimerStop = ClockType::now();
        TimeDiff diff = retryTimerStop - m_retryTimerStart;

        m_retryTimerStart = retryTimerStop;

        return (diff.count() < RETRY_TIMEOUT);
    }

    bool PasswordFile::isHistoryActive() const
    {
        return (m_maxHistorySize != 0);
    }
} //namespace AuthPasswd

