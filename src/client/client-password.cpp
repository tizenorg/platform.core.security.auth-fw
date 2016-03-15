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
 * @file        client-password.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of password functions.
 */

#include <cstring>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>

#include <protocols.h>
#include <policy.h>

#include <auth-passwd.h>

namespace {

inline bool isPasswordIncorrect(const char *passwd)
{
	// NULL means that password must be cancelled.
	return (passwd && (strlen(passwd) == 0 || strlen(passwd) > AuthPasswd::MAX_PASSWORD_LEN));
}

} // namespace anonymous

AUTH_PASSWD_API
int auth_passwd_check_passwd(password_type passwd_type,
							 const char *passwd,
							 unsigned int *current_attempts,
							 unsigned int *max_attempts,
							 unsigned int *valid_secs)
{
	using namespace AuthPasswd;
	return try_catch([&] {
		if (isPasswordIncorrect(passwd) ||
		current_attempts == NULL || max_attempts == NULL || valid_secs == NULL) {
			LogError("Wrong input param");
			return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
		}

		if (!passwd)
			passwd = NO_PASSWORD;

		MessageBuffer send, recv;

		*current_attempts = 0;
		*max_attempts = 0;
		*valid_secs = 0;

		Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_CHK_PASSWD));
		Serialization::Serialize(send, passwd_type);

		//Clear pwd memory
		std::string passwd_str(passwd);
		Serialization::Serialize(send, passwd_str);
		passwd_str.clear();

		int retCode = sendToServer(SERVICE_SOCKET_PASSWD_CHECK, send.Pop(), recv);

		if (AUTH_PASSWD_API_SUCCESS != retCode) {
			LogDebug("Error in sendToServer. Error code: " << retCode);
			return retCode;
		}

		Deserialization::Deserialize(recv, retCode);

		switch (retCode) {
		case AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH:
		case AUTH_PASSWD_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED:
		case AUTH_PASSWD_API_ERROR_PASSWORD_EXPIRED:
		case AUTH_PASSWD_API_SUCCESS:
			Deserialization::Deserialize(recv, *current_attempts);
			Deserialization::Deserialize(recv, *max_attempts);
			Deserialization::Deserialize(recv, *valid_secs);
			break;

		default:
			break;
		}

		return retCode;
	});
}

AUTH_PASSWD_API
int auth_passwd_check_passwd_state(password_type passwd_type,
								   unsigned int *current_attempts,
								   unsigned int *max_attempts,
								   unsigned int *valid_secs)
{
	using namespace AuthPasswd;
	return try_catch([&] {
		if (NULL == current_attempts || NULL == max_attempts ||
		NULL == valid_secs) {
			LogError("Wrong input param");
			return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
		}

		MessageBuffer send, recv;

		*current_attempts = 0;
		*max_attempts = 0;
		*valid_secs = 0;

		Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_CHK_PASSWD_STATE));
		Serialization::Serialize(send, passwd_type);

		int retCode = sendToServer(SERVICE_SOCKET_PASSWD_CHECK, send.Pop(), recv);

		if (AUTH_PASSWD_API_SUCCESS != retCode) {
			LogDebug("Error in sendToServer. Error code: " << retCode);
			return retCode;
		}

		Deserialization::Deserialize(recv, retCode);

		if (retCode == AUTH_PASSWD_API_SUCCESS) {
			Deserialization::Deserialize(recv, *current_attempts);
			Deserialization::Deserialize(recv, *max_attempts);
			Deserialization::Deserialize(recv, *valid_secs);
		}

		return retCode;
	});
}

AUTH_PASSWD_API
int auth_passwd_check_passwd_reused(password_type passwd_type,
									const char *passwd,
									int *is_reused)
{
	using namespace AuthPasswd;
	return try_catch([&] {
		if (NULL == passwd || NULL == is_reused) {
			LogError("Wrong input param");
			return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
		}

		MessageBuffer send, recv;

		Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_CHK_PASSWD_REUSED));
		Serialization::Serialize(send, passwd_type);
		Serialization::Serialize(send, std::string(passwd));

		int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);

		if (AUTH_PASSWD_API_SUCCESS != retCode) {
			LogDebug("Error in sendToServer. Error code: " << retCode);
			return retCode;
		}

		Deserialization::Deserialize(recv, retCode);

		if (AUTH_PASSWD_API_SUCCESS == retCode)
			Deserialization::Deserialize(recv, *is_reused);

		return retCode;
	});
}

AUTH_PASSWD_API
int auth_passwd_set_passwd(password_type passwd_type,
						   const char *cur_passwd,
						   const char *new_passwd)
{
	using namespace AuthPasswd;
	return try_catch([&] {
		if (!cur_passwd)
			cur_passwd = NO_PASSWORD;

		if (isPasswordIncorrect(new_passwd) || strlen(cur_passwd) > MAX_PASSWORD_LEN) {
			LogError("Wrong input param.");
			return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
		}

		if (!new_passwd)
			new_passwd = NO_PASSWORD;

		MessageBuffer send, recv;

		Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PASSWD));
		Serialization::Serialize(send, passwd_type);
		Serialization::Serialize(send, std::string(cur_passwd));
		Serialization::Serialize(send, std::string(new_passwd));

		int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);

		if (AUTH_PASSWD_API_SUCCESS != retCode) {
			LogError("Error in sendToServer. Error code: " << retCode);
			return retCode;
		}

		Deserialization::Deserialize(recv, retCode);

		return retCode;
	});
}

AUTH_PASSWD_API
int auth_passwd_set_passwd_recovery(const char *cur_recovery_passwd,
									const char *new_normal_passwd)
{
	using namespace AuthPasswd;
	return try_catch([&] {
		if (!new_normal_passwd || isPasswordIncorrect(new_normal_passwd) ||
		!cur_recovery_passwd || isPasswordIncorrect(cur_recovery_passwd)) {
			LogError("Wrong input param.");
			return AUTH_PASSWD_API_ERROR_INPUT_PARAM;
		}

		MessageBuffer send, recv;

		Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PASSWD_RECOVERY));
		Serialization::Serialize(send, std::string(cur_recovery_passwd));
		Serialization::Serialize(send, std::string(new_normal_passwd));

		int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);

		if (AUTH_PASSWD_API_SUCCESS != retCode) {
			LogError("Error in sendToServer. Error code: " << retCode);
			return retCode;
		}

		Deserialization::Deserialize(recv, retCode);

		return retCode;
	});
}
