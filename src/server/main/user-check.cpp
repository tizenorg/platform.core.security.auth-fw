#include <user-check.h>
#include <dpl/log/log.h>

namespace AuthPasswd {

int socket_get_user(int sockfd, unsigned int &user)
{
    struct ucred cr;
    socklen_t len = sizeof(struct ucred);
    if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &len))
    {
        LogError("getsockopt() failed");
        return 1;
    }
    user = cr.uid;
    return 0;
}

} // namespace AuthPasswd
