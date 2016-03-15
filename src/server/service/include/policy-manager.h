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
 * @file        policy-manager.h
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of password management functions
 */

#ifndef _POLICYMANAGER_H_
#define _POLICYMANAGER_H_

#include <string>
#include <map>

#include <policy.h>

#include <policy-file.h>

namespace AuthPasswd {
class PolicyManager {
public:
	typedef std::map<unsigned int, PolicyFile> PolicyFileMap;

	// policy checking functions
	int checkPolicy(unsigned int passwdType,
					const std::string &currentPassword,
					const std::string &newPassword,
					unsigned int user);

	// policy setting functions
	int setPolicy(Policy policy);

	// policy disabling functions
	int disablePolicy(unsigned int user);

private:
	// managing functions
	void addPolicy(unsigned int user);
	void removePolicy(unsigned int user);
	void existPolicy(unsigned int user);

	PolicyFileMap m_policyFile;
};
} //namespace AuthPasswd

#endif
