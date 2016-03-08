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
 * @file        password.h
 * @author      Zigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of password service
 */

#ifndef _PASSWORD_H_
#define _PASSWORD_H_

#include <map>

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <message-buffer.h>
#include <connection-info.h>
#include <protocols.h>

#include <password-manager.h>
#include <policy-manager.h>

namespace AuthPasswd
{
    class PasswordService
      : public AuthPasswd::GenericSocketService
      , public AuthPasswd::ServiceThread<PasswordService>
    {
    public:
        class Exception
        {
        public:
            DECLARE_EXCEPTION_TYPE(AuthPasswd::Exception, Base)
            DECLARE_EXCEPTION_TYPE(Base, IncorrectHeader)
        };

        //service functions
        ServiceDescriptionVector GetServiceDescription();

        void Start();
        void Stop();

        DECLARE_THREAD_EVENT(AcceptEvent, accept)
        DECLARE_THREAD_EVENT(WriteEvent, write)
        DECLARE_THREAD_EVENT(ReadEvent, process)
        DECLARE_THREAD_EVENT(CloseEvent, close)

        void accept(const AcceptEvent &event);
        void write(const WriteEvent &event);
        void process(const ReadEvent &event);
        void close(const CloseEvent &event);

    private:
        //internal service functions
        bool processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID);
        int processCheckFunctions(PasswordHdrs hdr, MessageBuffer& buffer,
                                  unsigned int cur_user, unsigned int &cur_att,
                                  unsigned int &max_att, unsigned int &exp_time);
        int processSetFunctions(PasswordHdrs hdr, MessageBuffer& buffer,
                                unsigned int cur_user, bool &isPwdReused);
        int processResetFunctions(PasswordHdrs hdr, MessageBuffer& buffer);
        int processPolicyFunctions(PasswordHdrs hdr, MessageBuffer& buffer);

        // service attributes
        PasswordManager m_pwdManager;
        PolicyManager m_policyManager;
        ConnectionInfoMap m_connectionInfoMap;
    };
} // namespace AuthPasswd

#endif // _PASSWORD_H_
