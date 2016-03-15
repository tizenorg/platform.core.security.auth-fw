/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        user-check.cpp
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Get user id from socket file descriptor of client.
 */
#include "user-check.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <dpl/log/log.h>

namespace AuthPasswd {

int socket_get_user(int sockfd, unsigned int &user)
{
	struct ucred cr;
	socklen_t len = sizeof(struct ucred);

	if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &len)) {
		LogError("getsockopt() failed");
		return 1;
	}

	user = cr.uid;
	return 0;
}

} // namespace AuthPasswd
