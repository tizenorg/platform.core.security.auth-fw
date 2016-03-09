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
 * @file        policy-file.h
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of PolicyFile, used to manage policy files.
 */
#ifndef _POLICY_FILE_H_
#define _PILICY_FILE_H_

#include <string>
#include <vector>
#include <list>
#include <memory>

#include <policy.h>

namespace AuthPasswd
{
    class PolicyFile
    {
    public:
        PolicyFile(unsigned int user);

        void enable();
        void disable();

        bool isPolicyActive() const;

        void writeMemoryToFile() const;

        bool checkMinLength(const std::string &password) const;
        void setMinLength(unsigned int minLength);

        bool checkMinComplexCharNumber(const std::string &password) const;
        void setMinComplexCharNumber(unsigned int minComplexCharNumber);

        bool checkMaxCharOccurrences(const std::string &password) const;
        void setMaxCharOccurrences(unsigned int maxCharOccurrences);

        bool checkMaxNumSeqLength(const std::string &password) const;
        void setMaxNumSeqLength(unsigned int maxNumSeqLength);

        bool checkQualityType(const std::string &password) const;
        void setQualityType(unsigned int qualityType);

        bool isValidPattern(const std::string &pattern) const;
        bool checkPattern(const std::string &password) const;
        void setPattern(const std::string &pattern);

        bool checkForbiddenPasswds(const std::string &password) const;
        void setForbiddenPasswds(std::vector<std::string> forbiddenPasswds);

    private:
        void loadMemoryFromFile();
        void preparePolicyFile();
        void resetState();
        bool fileExists(const std::string &filename) const;
        bool dirExists(const std::string &dirpath) const;
        std::string createDir(const std::string &dir, unsigned int user) const;

        //user name
        unsigned int m_user;

        bool m_enable;

        //policy file data
        Policy m_policy;
    };
}    //namespace AuthPasswd

#endif
