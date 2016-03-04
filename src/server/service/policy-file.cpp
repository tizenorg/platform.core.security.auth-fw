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
 * @file        policy-file.cpp
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of PolicyFile, used to manage policy files.
 */
#include <policy-file.h>

#include <fstream>
#include <algorithm>
#include <regex.h>

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <tzplatform_config.h>

#include <dpl/log/log.h>
#include <dpl/fstream_accessors.h>

#include <auth-passwd-policy-types.h>
#include <auth-passwd-error.h>

#include <error-description.h>
#include <policy.h>
#include <password-exception.h>
#include <password-file-buffer.h>

namespace {
    const std::string DATA_DIR = tzplatform_mkpath(TZ_SYS_DATA, "authentication-server");
    const std::string POLICY_FILE = "/policy";
    const mode_t FILE_MODE = S_IRUSR | S_IWUSR;
    const unsigned int CURRENT_FILE_VERSION = 1;
} // namespace anonymous

namespace AuthPasswd
{
    PolicyFile::PolicyFile(const unsigned int user): m_user(user),
                                m_enable(false),
                                m_minLength(0),
                                m_minComplexCharNumber(0),
                                m_maxCharOccurrences(0),
                                m_maxNumSeqLength(0),
                                m_qualityType(AUTH_PWD_QUALITY_UNSPECIFIED),
                                m_pattern(NO_PATTERN)
    {
        // check if data directory exists
        // if not create it
        std::string userDir = createDir(DATA_DIR.c_str(), m_user);

        if (!dirExists(DATA_DIR.c_str())) {
            if(mkdir(DATA_DIR.c_str(), 0700)) {
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

        preparePolicyFile();
    }

    void PolicyFile::resetState()
    {
        m_enable = false;
        m_minLength = 0;
        m_minComplexCharNumber = 0;
        m_maxCharOccurrences = 0;
        m_maxNumSeqLength = 0;
        m_qualityType = AUTH_PWD_QUALITY_UNSPECIFIED;
        m_pattern = NO_PATTERN;
        m_forbiddenPasswds.clear();
    }

    void PolicyFile::preparePolicyFile()
    {
        std::string policyFile = createDir(DATA_DIR.c_str(), m_user) + POLICY_FILE;

        // check if policy file exists
        if (!fileExists(policyFile)) {
            LogSecureDebug("POLICY_DBG not found " << m_user << " policy file. Creating.");

            //create file
            writeMemoryToFile();
        } else {     //if file exists, load data
            LogSecureDebug("POLICY_DBG found " << m_user << " policy file. Opening.");
            try {
                loadMemoryFromFile();
            } catch (...) {
                LogError("Invalid " << policyFile << " file format");
                resetState();
                writeMemoryToFile();
            }
        }
    }

    bool PolicyFile::fileExists(const std::string &filename) const
    {
        struct stat buf;

        return ((stat(filename.c_str(), &buf) == 0));
    }

    bool PolicyFile::dirExists(const std::string &dirpath) const
    {
        struct stat buf;

        return ((stat(dirpath.c_str(), &buf) == 0) && (((buf.st_mode) & S_IFMT) == S_IFDIR));
    }

    std::string PolicyFile::createDir(const std::string &dir, const unsigned int user) const
    {
        std::string User = std::to_string(user);
        return dir + "/" + User;
    }

    void PolicyFile::writeMemoryToFile() const
    {
        PasswordFileBuffer policyBuffer;

        LogSecureDebug("User: " << m_user << ", m_minLength: " << m_minLength <<
                       ", m_minComplexCharNumber: " << m_minComplexCharNumber <<
                       ", m_maxCharOccurrences: " << m_maxCharOccurrences <<
                       ", m_maxNumSeqLength: " << m_maxNumSeqLength <<
                       ", m_qualityType: " << m_qualityType <<
                       ", m_pattern: " << m_pattern <<
                       ", m_forbiddenPasswds.size: " << m_forbiddenPasswds.size());

        // serialize policy attributes
        Serialization::Serialize(policyBuffer, CURRENT_FILE_VERSION);
        Serialization::Serialize(policyBuffer, m_enable);
        Serialization::Serialize(policyBuffer, m_minLength);
        Serialization::Serialize(policyBuffer, m_minComplexCharNumber);
        Serialization::Serialize(policyBuffer, m_maxCharOccurrences);
        Serialization::Serialize(policyBuffer, m_maxNumSeqLength);
        Serialization::Serialize(policyBuffer, m_qualityType);
        Serialization::Serialize(policyBuffer, m_pattern);
        Serialization::Serialize(policyBuffer, m_forbiddenPasswds);

        std::string policyFile = createDir(DATA_DIR.c_str(), m_user) + POLICY_FILE;
        policyBuffer.Save(policyFile);

        if (chmod(policyFile.c_str(), FILE_MODE)) {
            LogError("Failed to chmod for " << policyFile << " Error: " << strerror(errno));
            Throw(PasswordException::ChmodError);
        }
    }

    void PolicyFile::loadMemoryFromFile()
    {
        PasswordFileBuffer policyBuffer;
        std::string policyFile = createDir(DATA_DIR.c_str(), m_user) + POLICY_FILE;

        policyBuffer.Load(policyFile);

        // deserialize policy attributes
        unsigned int fileVersion = 0;
        Deserialization::Deserialize(policyBuffer, fileVersion);
        if (fileVersion != CURRENT_FILE_VERSION)
            Throw(PasswordException::FStreamReadError);

        Deserialization::Deserialize(policyBuffer, m_enable);
        Deserialization::Deserialize(policyBuffer, m_minLength);
        Deserialization::Deserialize(policyBuffer, m_minComplexCharNumber);
        Deserialization::Deserialize(policyBuffer, m_maxCharOccurrences);
        Deserialization::Deserialize(policyBuffer, m_maxNumSeqLength);
        Deserialization::Deserialize(policyBuffer, m_qualityType);
        Deserialization::Deserialize(policyBuffer, m_pattern);
        Deserialization::Deserialize(policyBuffer, m_forbiddenPasswds);

        LogSecureDebug("User: " << m_user << ", m_minLength: " << m_minLength <<
                       ", m_minComplexCharNumber: " << m_minComplexCharNumber <<
                       ", m_maxCharOccurrences: " << m_maxCharOccurrences <<
                       ", m_maxNumSeqLength: " << m_maxNumSeqLength <<
                       ", m_qualityType: " << m_qualityType <<
                       ", m_pattern: " << m_pattern <<
                       ", m_forbiddenPasswds.size: " << m_forbiddenPasswds.size());
    }

    void PolicyFile::enable()
    {
        m_enable = true;
    }

    void PolicyFile::disable()
    {
        m_enable = false;
        resetState();
    }

    bool PolicyFile::isPolicyActive() const
    {
        return m_enable;
    }

    // policy minLength
    bool PolicyFile::checkMinLength(const std::string &password) const
    {
        return (password.size() >= m_minLength);
    }

    void PolicyFile::setMinLength(unsigned int minLength)
    {
        m_minLength = minLength;
    }

    // policy minComplexCharNumber
    bool PolicyFile::checkMinComplexCharNumber(const std::string &password) const
    {
        unsigned int i = 0, cnt = 0;
        char ch;

        if (m_minComplexCharNumber == 0)
            return true;

        for (i = 0; i < password.size(); i++) {
            ch = password[i];
            if( ch < 'A' || ( 'Z' < ch && ch < 'a')  || 'z' < ch)
                cnt++;
        }
        return (cnt >= m_minComplexCharNumber);
    }

    void PolicyFile::setMinComplexCharNumber(unsigned int minComplexCharNumber)
    {
        m_minComplexCharNumber = minComplexCharNumber;
    }

    // policy maxCharOccurrences
    bool PolicyFile::checkMaxCharOccurrences(const std::string &password) const
    {
        unsigned int i = 0;
        unsigned char ch;
        char occurrence[256]= {0, };

        if (m_maxCharOccurrences == 0)
            return true;

        for (i = 0; i < password.size(); i++) {
            ch = (unsigned char)password[i];
            occurrence[ch]++;
        }

        for (i = 0; i<256; i++) {
            if(occurrence[i] > m_maxCharOccurrences)
                return false;
        }
        return true;
    }

    void PolicyFile::setMaxCharOccurrences(unsigned int maxCharOccurrences)
    {
        m_maxCharOccurrences = maxCharOccurrences;
    }

    // policy maxNumSeqLength
    bool PolicyFile::checkMaxNumSeqLength(const std::string &password) const
    {
        char curr_ch = 0, prev_num = 0;
        unsigned int i, num_cnt=0, max_num_seq_len = 0, curr_num_seq_len = 0;
        unsigned int len = password.size();
        int order = -2; // -2: not set, -1 : decreasing, 0 : same, +1: increasing

        if (m_maxNumSeqLength == 0)
            return true;

        for (i = 0; i < len; i++) {
            curr_ch = password[i];
            if ('0' <= curr_ch && curr_ch <= '9') {
                num_cnt++;
                if (order == -2) { // not set, fist or second char of a sequence
                    if (prev_num == 0) { // fist second char
                        curr_num_seq_len = 1;
                    } else if (curr_ch == prev_num - 1) { // decreasing order
                        order = -1;
                        curr_num_seq_len = 2;
                    } else if (curr_ch == prev_num + 0) { // same order
                        order = 0;
                        curr_num_seq_len = 2;
                    } else if (curr_ch == prev_num + 1) { // increasing order
                        order = 1;
                        curr_num_seq_len = 2;
                    } else { // order restarts again
                        if (max_num_seq_len < curr_num_seq_len)
                            max_num_seq_len = curr_num_seq_len;

                        order = -2;
                        curr_num_seq_len = 1;
                    }
                } else if (curr_ch == prev_num + order) { // order is still working
                    curr_num_seq_len++;
                } else { // order changed
                    if (max_num_seq_len < curr_num_seq_len)
                        max_num_seq_len = curr_num_seq_len;
                    order = -2;
                    curr_num_seq_len = 1;
                }
                prev_num = curr_ch;
            } else { // order reset
                if (max_num_seq_len < curr_num_seq_len)
                    max_num_seq_len = curr_num_seq_len;

                order = -2;
                curr_num_seq_len = 0;
                prev_num = 0;
            }
        }
        return max_num_seq_len <= m_maxNumSeqLength;
    }

    void PolicyFile::setMaxNumSeqLength(unsigned int maxNumSeqLength)
    {
        m_maxNumSeqLength = maxNumSeqLength;
    }

    // policy qalityType
    bool PolicyFile::checkQualityType(const std::string &password) const
    {
        std::string pattern;

        switch (m_qualityType) {
            case AUTH_PWD_QUALITY_UNSPECIFIED:
                pattern = REGEX_QUALITY_UNSPECIFIED;
                break;

            case AUTH_PWD_QUALITY_SOMETHING:
                pattern = REGEX_QUALITY_SOMETHING;
                break;

            case AUTH_PWD_QUALITY_NUMERIC:
                pattern = REGEX_QUALITY_NUMERIC;
                break;

            case AUTH_PWD_QUALITY_ALPHABETIC:
                pattern = REGEX_QUALITY_ALPHABETIC;
                break;

            case AUTH_PWD_QUALITY_ALPHANUMERIC:
                pattern = REGEX_QUALITY_ALPHANUMERIC;
                break;

            default:
                return false;
        }

        regex_t re;
        if (regcomp(&re, pattern.c_str(), REG_EXTENDED|REG_NEWLINE) != 0)
            return false;
        return (regexec(&re, password.c_str(), 0, NULL, 0) == 0);
    }

    void PolicyFile::setQualityType(unsigned int qualityType)
    {
        m_qualityType = qualityType;
    }

    // policy pattern
    bool PolicyFile::isValidPattern(const std::string &pattern) const
    {
        if (pattern.empty())
            return true;

        regex_t re;
        return (regcomp(&re, pattern.c_str(), REG_EXTENDED|REG_NEWLINE) == 0);
    }

    bool PolicyFile::checkPattern(const std::string &password) const
    {
        if (m_pattern.empty())
            return true;

        regex_t re;
        if (regcomp(&re, m_pattern.c_str(), REG_EXTENDED|REG_NEWLINE) != 0)
            return false;

        return (regexec(&re, password.c_str(), 0, NULL, 0) == 0);
    }

    void PolicyFile::setPattern(const std::string &pattern)
    {
        m_pattern = pattern;
    }

    // policy forbiddenPasswds
    bool PolicyFile::checkForbiddenPasswds(const std::string &password) const
    {
        if (password.empty())
            return true;

        return (std::find(m_forbiddenPasswds.begin(), m_forbiddenPasswds.end(), password)
            == m_forbiddenPasswds.end());
    }

    void PolicyFile::setForbiddenPasswds(std::vector<std::string> forbiddenPasswds)
    {
        for (std::vector<std::string>::iterator it = forbiddenPasswds.begin() ;
             it != forbiddenPasswds.end() ; ++it) {

             std::string forbiddenPasswd = *it;
             LogError("forbiddenPasswd : " << forbiddenPasswd);

             if (forbiddenPasswd.empty())
                 m_forbiddenPasswds.clear();
             else
                 if (std::find(m_forbiddenPasswds.begin(), m_forbiddenPasswds.end(), forbiddenPasswd)
                     == m_forbiddenPasswds.end())
                     m_forbiddenPasswds.push_back(forbiddenPasswd);
        }
    }
} //namespace AuthPasswd
