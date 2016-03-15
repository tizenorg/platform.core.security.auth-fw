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

namespace AuthPasswd {
class PasswordManager {
public:
	typedef std::map<unsigned int, PasswordFile> PasswordFileMap;

	//checking functions
	//no const in checkPassword, attempts are update
	int checkPassword(unsigned int passwdType, const std::string &challenge,
					  unsigned int currentUser, unsigned int &currentAttempt,
					  unsigned int &maxAttempt, unsigned int &expirationTime);
	int isPwdValid(unsigned int passwdType, unsigned int currentUser,
				   unsigned int &currentAttempt, unsigned int &maxAttempt,
				   unsigned int &expirationTime);
	int isPwdReused(unsigned int passwdType, const std::string &passwd,
					unsigned int currentUser, bool &isReused);

	//setting functions
	int setPassword(unsigned int passwdType, const std::string &currentPassword,
					const std::string &newPassword, unsigned int currentUser);
	int setPasswordRecovery(const std::string &curRcvPassword, const std::string &newPassword,
							unsigned int currentUser);

	//resetting functions
	int resetPassword(unsigned int passwdType, const std::string &newPassword,
					  unsigned int receivedUser);

	//setting policy on the current passwd
	void setPasswordMaxAttempts(unsigned int receivedUser,
								unsigned int receivedAttempts);
	void setPasswordValidity(unsigned int receivedUser, unsigned int receivedDays);
	void setPasswordHistory(unsigned int receivedUser, unsigned int receivedHistory);

private:
	//managing functions
	void addPassword(unsigned int user);
	void removePassword(unsigned int user);
	void existPassword(unsigned int user);

	PasswordFileMap m_pwdFile;
};
} //namespace AuthPasswd

#endif
