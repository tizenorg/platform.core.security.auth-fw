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
 * @file        client-common.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file is implementation of client-common functions.
 */

#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <error-description.h>
#include <message-buffer.h>
#include <auth-passwd.h>
#include <auth-passwd-admin.h>
#include <client-common.h>

IMPLEMENT_SAFE_SINGLETON(AuthPasswd::Log::LogSystem);

namespace {

const int POLL_TIMEOUT = 300000;

void authPasswdClientEnableLogSystem(void)
{
	AuthPasswd::Singleton<AuthPasswd::Log::LogSystem>::Instance().SetTag("AUTH_PASSWD_CLIENT");
}

int waitForSocket(int sock, int event, int timeout)
{
	int retval;
	pollfd desc[1];
	desc[0].fd = sock;
	desc[0].events = event;

	while ((-1 == (retval = poll(desc, 1, timeout))) && (errno == EINTR)) {
		timeout >>= 1;
		errno = 0;
	}

	if (0 == retval)
		LogDebug("Poll timeout");
	else if (-1 == retval) {
		int err = errno;
		LogError("Error in poll: " << AuthPasswd::errnoToString(err));
	}

	return retval;
}

} // namespace anonymous

namespace AuthPasswd {


int SockRAII::Connect(char const *const interface)
{
	sockaddr_un clientAddr;
	int flags;

	if (m_sock != -1) // guard
		close(m_sock);

	m_sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (m_sock < 0) {
		int err = errno;
		LogError("Error creating socket: " << AuthPasswd::errnoToString(err));
		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	if ((flags = fcntl(m_sock, F_GETFL, 0)) < 0 ||
			fcntl(m_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
		int err = errno;
		LogError("Error in fcntl: " << AuthPasswd::errnoToString(err));
		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	memset(&clientAddr, 0, sizeof(clientAddr));
	clientAddr.sun_family = AF_UNIX;

	if (strlen(interface) >= sizeof(clientAddr.sun_path)) {
		LogError("Error: interface name " << interface << "is too long. Max len is:" << sizeof(
					 clientAddr.sun_path));
		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	strncpy(clientAddr.sun_path, interface, sizeof(clientAddr.sun_path) - 1);
	LogDebug("ClientAddr.sun_path = " << interface);
	int retval = TEMP_FAILURE_RETRY(connect(m_sock, (struct sockaddr *)&clientAddr,
											SUN_LEN(&clientAddr)));

	if ((retval == -1) && (errno == EINPROGRESS)) {
		if (0 >= waitForSocket(m_sock, POLLOUT, POLL_TIMEOUT)) {
			LogError("Error in waitForSocket.");
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		int error = 0;
		socklen_t len = sizeof(error);
		retval = getsockopt(m_sock, SOL_SOCKET, SO_ERROR, &error, &len);

		if (-1 == retval) {
			int err = errno;
			LogError("Error in getsockopt: " << AuthPasswd::errnoToString(err));
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		if (error == EACCES) {
			LogError("Access denied");
			return AUTH_PASSWD_API_ERROR_ACCESS_DENIED;
		}

		if (error != 0) {
			LogError("Error in connect: " << AuthPasswd::errnoToString(error));
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		return AUTH_PASSWD_API_SUCCESS;
	}

	if (-1 == retval) {
		int err = errno;
		LogError("Error connecting socket: " << AuthPasswd::errnoToString(err));

		if (err == EACCES)
			return AUTH_PASSWD_API_ERROR_ACCESS_DENIED;

		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	return AUTH_PASSWD_API_SUCCESS;
}

int sendToServerWithFd(int fd, const RawBuffer &send, MessageBuffer &recv)
{
	ssize_t done = 0;
	char buffer[2048];

	while ((send.size() - done) > 0) {
		if (0 >= waitForSocket(fd, POLLOUT, POLL_TIMEOUT)) {
			LogError("Error in poll(POLLOUT)");
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		ssize_t temp = TEMP_FAILURE_RETRY(::send(fd, &send[done], send.size() - done, MSG_NOSIGNAL));

		if (-1 == temp) {
			int err = errno;
			LogError("Error in send: " << errnoToString(err));
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		done += temp;
	}

	do {
		if (0 >= waitForSocket(fd, POLLIN, POLL_TIMEOUT)) {
			LogError("Error in poll(POLLIN)");
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		ssize_t temp = TEMP_FAILURE_RETRY(::recv(fd, buffer, 2048, 0));

		if (-1 == temp) {
			int err = errno;
			LogError("Error in recv: " << errnoToString(err));
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		if (0 == temp) {
			LogError("Read return 0/Connection closed by server(?)");
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		RawBuffer raw(buffer, buffer + temp);
		recv.Push(raw);
	} while (!recv.Ready());

	return AUTH_PASSWD_API_SUCCESS;
}

int sendToServer(char const *const interface, const RawBuffer &send, MessageBuffer &recv)
{
	int ret;
	SockRAII sock;

	if (AUTH_PASSWD_API_SUCCESS != (ret = sock.Connect(interface))) {
		LogError("Error in SockRAII");
		return ret;
	}

	return sendToServerWithFd(sock.Get(), send, recv);
}

int sendToServerAncData(char const *const interface, const RawBuffer &send, struct msghdr &hdr)
{
	int ret;
	SockRAII sock;
	ssize_t done = 0;

	if (AUTH_PASSWD_API_SUCCESS != (ret = sock.Connect(interface))) {
		LogError("Error in SockRAII");
		return ret;
	}

	while ((send.size() - done) > 0) {
		if (0 >= waitForSocket(sock.Get(), POLLOUT, POLL_TIMEOUT)) {
			LogError("Error in poll(POLLOUT)");
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		ssize_t temp = TEMP_FAILURE_RETRY(write(sock.Get(), &send[done], send.size() - done));

		if (-1 == temp) {
			int err = errno;
			LogError("Error in write: " << errnoToString(err));
			return AUTH_PASSWD_API_ERROR_SOCKET;
		}

		done += temp;
	}

	if (0 >= waitForSocket(sock.Get(), POLLIN, POLL_TIMEOUT)) {
		LogError("Error in poll(POLLIN)");
		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	ssize_t temp = TEMP_FAILURE_RETRY(recvmsg(sock.Get(), &hdr, MSG_CMSG_CLOEXEC));

	if (temp < 0) {
		int err = errno;
		LogError("Error in recvmsg(): " << errnoToString(err) << " errno: " << err);
		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	if (0 == temp) {
		LogError("Read return 0/Connection closed by server(?)");
		return AUTH_PASSWD_API_ERROR_SOCKET;
	}

	return AUTH_PASSWD_API_SUCCESS;
}

int try_catch(const std::function<int()> &func)
{
	try {
		return func();
	} catch (MessageBuffer::Exception::Base &e) {
		LogError("AuthPasswd::MessageBuffer::Exception " << e.DumpToString());
	} catch (std::bad_alloc &e) {
		LogError("Memory allocation failed " << e.what());
		return AUTH_PASSWD_API_ERROR_OUT_OF_MEMORY;
	} catch (std::exception &e) {
		LogError("STD exception " << e.what());
	} catch (...) {
		LogError("Unknown exception occured");
	}

	return AUTH_PASSWD_API_ERROR_UNKNOWN;
}

} // namespace AuthPasswd

static void init_lib(void) __attribute__((constructor));
static void init_lib(void)
{
	authPasswdClientEnableLogSystem();
}

static void fini_lib(void) __attribute__((destructor));
static void fini_lib(void)
{
}

