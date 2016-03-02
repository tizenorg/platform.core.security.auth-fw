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
 * @file        password.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of password service
 */

#include <iostream>
#include <string>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <user-check.h>

#include <password.h>

#include <auth-passwd-policy-types.h>
#include <auth-passwd-error.h>
#include <password-exception.h>

namespace AuthPasswd {

namespace {
// Service may open more than one socket.
// These ID's will be assigned to sockets
// and will be used only by service.
// When new connection arrives, AcceptEvent
// will be generated with proper ID to inform
// service about input socket.
//
// Please note: SocketManager does not use it and
// does not check it in any way.
//
// If your service requires only one socket
// (uses only one socket labeled with smack)
// you may ignore this ID (just pass 0)
const InterfaceID SOCKET_ID_CHECK   = 0;
const InterfaceID SOCKET_ID_SET     = 1;
const InterfaceID SOCKET_ID_RESET   = 2;
const InterfaceID SOCKET_ID_POLICY  = 3;

} // namespace anonymous

GenericSocketService::ServiceDescriptionVector PasswordService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_PASSWD_CHECK,  "*", SOCKET_ID_CHECK},
        {SERVICE_SOCKET_PASSWD_SET,    "*", SOCKET_ID_SET},
        {SERVICE_SOCKET_PASSWD_RESET,  "*", SOCKET_ID_RESET},
        {SERVICE_SOCKET_PASSWD_POLICY, "*", SOCKET_ID_POLICY}
    };
}

void PasswordService::Start() {
    Create();
}

void PasswordService::Stop() {
    Join();
}

void PasswordService::accept(const AcceptEvent &event)
{
    LogSecureDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);

    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void PasswordService::write(const WriteEvent &event)
{
    LogSecureDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void PasswordService::process(const ReadEvent &event)
{
    LogSecureDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.interfaceID));
}

void PasswordService::close(const CloseEvent &event)
{
    LogSecureDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

int PasswordService::processCheckFunctions(PasswordHdrs hdr, MessageBuffer& buffer,
                                           const unsigned int cur_user, unsigned int &cur_att,
                                           unsigned int &max_att, unsigned int &exp_time)
{
    int result = AUTH_PASSWD_API_ERROR_SERVER_ERROR;

    switch (hdr) {
        case PasswordHdrs::HDR_CHK_PASSWD: {
            unsigned int passwdType = 0;
            std::string challenge;
            Deserialization::Deserialize(buffer, passwdType);
            Deserialization::Deserialize(buffer, challenge);
            result = m_pwdManager.checkPassword(passwdType, challenge, cur_user, cur_att, max_att,
                                                exp_time);
            break;
        }

        case PasswordHdrs::HDR_CHK_PASSWD_STATE: {
            unsigned int passwdType = 0;
            Deserialization::Deserialize(buffer, passwdType);
            result = m_pwdManager.isPwdValid(passwdType, cur_user, cur_att, max_att, exp_time);
            break;
        }

        default:
            LogError("Unknown msg header.");
            Throw(Exception::IncorrectHeader);
    }
    return result;
}

int PasswordService::processSetFunctions(PasswordHdrs hdr, MessageBuffer& buffer,
                                         const unsigned int cur_user, bool &isPwdReused)
{
    int result = AUTH_PASSWD_API_ERROR_SERVER_ERROR;

    switch (hdr) {
        case PasswordHdrs::HDR_SET_PASSWD: {
            std::string curPasswd, newPasswd;
            unsigned int passwdType = 0;
            Deserialization::Deserialize(buffer, passwdType);
            Deserialization::Deserialize(buffer, curPasswd);
            Deserialization::Deserialize(buffer, newPasswd);
            result = m_policyManager.checkPolicy(passwdType, curPasswd, newPasswd, cur_user);
            if (result == AUTH_PASSWD_API_SUCCESS)
                result = m_pwdManager.setPassword(passwdType, curPasswd, newPasswd, cur_user);
            break;
        }

        case PasswordHdrs::HDR_SET_PASSWD_RECOVERY: {
            std::string curRcvPasswd, newPasswd;
            Deserialization::Deserialize(buffer, curRcvPasswd);
            Deserialization::Deserialize(buffer, newPasswd);
            result = m_policyManager.checkPolicy(AUTH_PWD_NORMAL, curRcvPasswd, newPasswd, cur_user);
            if (result == AUTH_PASSWD_API_SUCCESS)
                result = m_pwdManager.setPasswordRecovery(curRcvPasswd, newPasswd, cur_user);
            break;
        }

        case PasswordHdrs::HDR_CHK_PASSWD_REUSED: {
             unsigned int passwdType = 0;
             std::string passwd;
             Deserialization::Deserialize(buffer, passwdType);
             Deserialization::Deserialize(buffer, passwd);
             result = m_pwdManager.isPwdReused(passwdType, passwd, cur_user, isPwdReused);
             break;
        }

        default:
            LogError("Unknown msg header.");
            Throw(Exception::IncorrectHeader);
    }
    return result;
}

int PasswordService::processResetFunctions(PasswordHdrs hdr, MessageBuffer& buffer)
{
    int result = AUTH_PASSWD_API_ERROR_SERVER_ERROR;

    std::string newPasswd, emptyStr="";
    unsigned int passwdType = 0, rec_user = 0;

    switch (hdr) {
        case PasswordHdrs::HDR_RST_PASSWD:
            Deserialization::Deserialize(buffer, passwdType);
            Deserialization::Deserialize(buffer, newPasswd);
            Deserialization::Deserialize(buffer, rec_user);
            result = m_pwdManager.resetPassword(passwdType, newPasswd, rec_user);
            break;

        default:
            LogError("Unknown msg header.");
            Throw(Exception::IncorrectHeader);
    }
    return result;
}

int PasswordService::processPolicyFunctions(PasswordHdrs hdr, MessageBuffer& buffer)
{
    int result = AUTH_PASSWD_API_ERROR_SERVER_ERROR;

    auth_password_policy policy;

    switch (hdr) {
        case PasswordHdrs::HDR_SET_PASSWD_POLICY:
            Deserialization::Deserialize(buffer, policy.policyFlag);
            Deserialization::Deserialize(buffer, policy.uid);
            Deserialization::Deserialize(buffer, policy.maxAttempts);
            Deserialization::Deserialize(buffer, policy.validPeriod);
            Deserialization::Deserialize(buffer, policy.historySize);
            Deserialization::Deserialize(buffer, policy.minLength);
            Deserialization::Deserialize(buffer, policy.minComplexCharNumber);
            Deserialization::Deserialize(buffer, policy.maxCharOccurrences);
            Deserialization::Deserialize(buffer, policy.maxNumSeqLength);
            Deserialization::Deserialize(buffer, policy.qualityType);
            Deserialization::Deserialize(buffer, policy.pattern);
            Deserialization::Deserialize(buffer, policy.forbiddenPasswds);

            result = m_policyManager.setPolicy(policy);

            if (result == AUTH_PASSWD_API_SUCCESS) {
                if (policy.policyFlag & (1 << POLICY_MAX_ATTEMPTS))
                    m_pwdManager.setPasswordMaxAttempts(policy.uid, policy.maxAttempts);
                if (policy.policyFlag & (1 << POLICY_VALID_PERIOD))
                    m_pwdManager.setPasswordValidity(policy.uid, policy.validPeriod);
                if (policy.policyFlag & (1 << POLICY_HISTORY_SIZE))
                    m_pwdManager.setPasswordHistory(policy.uid, policy.historySize);
            }
            break;

        default:
            LogError("Unknown msg header.");
            Throw(Exception::IncorrectHeader);
    }

    return result;
}

bool PasswordService::processOne(const ConnectionID &conn, MessageBuffer &buffer,
                                 InterfaceID interfaceID)
{
    LogSecureDebug("Iteration begin");

    MessageBuffer sendBuffer;

    int retCode = AUTH_PASSWD_API_ERROR_SERVER_ERROR;
    unsigned int cur_user = 0, cur_att = 0, max_att = 0, exp_time = 0;
    bool isPwdReused;

    if (!buffer.Ready())
        return false;

    Try {       //try..catch for MessageBuffer errors, closes connection when exception is thrown
        int tempHdr;
        Deserialization::Deserialize(buffer, tempHdr);
        PasswordHdrs hdr = static_cast<PasswordHdrs>(tempHdr);

        try {   //try..catch for internal service errors, assigns error code for returning.
            switch (interfaceID) {
                case SOCKET_ID_CHECK:
                    if(socket_get_user(conn.sock, cur_user))
                        retCode = AUTH_PASSWD_API_ERROR_NO_USER;
                    else
                        retCode = processCheckFunctions(hdr, buffer, cur_user, cur_att, max_att, exp_time);
                    break;

                case SOCKET_ID_SET:
                    if(socket_get_user(conn.sock, cur_user))
                        retCode = AUTH_PASSWD_API_ERROR_NO_USER;
                    else
                        retCode = processSetFunctions(hdr, buffer, cur_user, isPwdReused);
                    break;

                case SOCKET_ID_RESET:
                    retCode = processResetFunctions(hdr, buffer);
                    break;

                case SOCKET_ID_POLICY:
                    retCode = processPolicyFunctions(hdr, buffer);
                    break;

                default:
                    LogError("Wrong interfaceID.");
                    Throw(Exception::IncorrectHeader);
            }
        } catch (PasswordException::Base &e) {
            LogError("Password error: " << e.DumpToString());
            retCode = AUTH_PASSWD_API_ERROR_SERVER_ERROR;
        } catch (std::exception &e) {
            LogError("STD error: " << e.what());
            retCode = AUTH_PASSWD_API_ERROR_SERVER_ERROR;
        }

        //everything is OK, send return code and extra data
        Serialization::Serialize(sendBuffer, retCode);

        //Returning additional information should occur only when checking functions
        //are called, and under certain return values
        if (interfaceID == SOCKET_ID_CHECK)
        {
            switch(retCode)
            {
                case AUTH_PASSWD_API_ERROR_PASSWORD_MISMATCH:
                case AUTH_PASSWD_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED:
                case AUTH_PASSWD_API_ERROR_PASSWORD_EXPIRED:
                case AUTH_PASSWD_API_SUCCESS:
                    Serialization::Serialize(sendBuffer, cur_att);
                    Serialization::Serialize(sendBuffer, max_att);
                    Serialization::Serialize(sendBuffer, exp_time);
                    break;
            default:
                break;
            }
        } else if (interfaceID == SOCKET_ID_SET) {
            if (hdr == PasswordHdrs::HDR_CHK_PASSWD_REUSED && retCode == AUTH_PASSWD_API_SUCCESS) {
                Serialization::Serialize(sendBuffer, (int)isPwdReused);
            }
        }

        m_serviceManager->Write(conn, sendBuffer.Pop());
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    } Catch (PasswordService::Exception::Base) {
        LogError("Incorrect message header. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    return true;
}

} // namespace AuthPasswd

