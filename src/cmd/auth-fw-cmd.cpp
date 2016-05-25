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
 * @file        auth-fw-cmd.cpp
 * @author      Jooseong Lee (jooseong.lee@samsung.com)
 * @version     1.0
 * @brief       Implementation of auth-fw-cmd tool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <auth-passwd.h>
#include <auth-passwd-admin.h>

#define PASSWORD_MAX_LEN 32
#define PASSWORD_REGEX_LEN 100

int checkPassword(int argc, char **argv);
int setPassword(int argc, char **argv);
int resetPassword(int argc, char **argv);
int setPolicy(int argc, char **argv);
int disablePolicy(int argc, char **argv);
void usage(char *arg);

unsigned int user;

char type;
char cur_passwd[PASSWORD_MAX_LEN + 1];
char new_passwd[PASSWORD_MAX_LEN + 1];
char forbidden_passwd[PASSWORD_MAX_LEN + 1];
char regex[PASSWORD_REGEX_LEN + 1];

static const char help[] =
        "Usage: %s [OPTIONS]\n\n"

        "Password check options (with -a or --check)\n"
        " -t, --type                  password type:one of normal'0' and simple'1'\n"
        " -c, --cur-passwd            current password\n\n"

        "Password set options (with -s or --set)\n"
        " -t, --type                  password type:one of normal'0' and simple'1'\n"
        " -c, --cur-passwd            current password\n"
        " -n, --new-passwd            new password\n\n"

        "Password reset options (with -r or --reset)\n"
        " -u, --user                  uid to reset a password\n"
        " -t, --type                  password type:one of normal'0' and simple'1'\n"
        " -n, --new-passwd            new password\n\n"

        "Password policy set options (with -p or --set-policy)\n"
        " -u, --user                  uid to set password policies\n"
        " -m, --max-attempts          number of maximum attempts that the password locks\n"
        " -v, --validity              number of days that this password is valid\n"
        " -i, --history-size          number of history to be checked\n"
        " -l, --min-length            number of characters of password\n"
        " -x, --min-complex-char      minimum number of complex characters\n"
        " -o, --max-char-occurrences  maximum count of the same character\n"
        " -q, --max-num-seq-len       maximum numeric sequence length\n"
        " -y, --quality               password complexity type:one of unspecified'0', something'1',\n"
        "                             numeric'2', alphabetic'3' and alphanumeric'4'\n"
        " -e, --pattern               pattern Regular expression for password strings\n"
        " -f, --forbidden-passwd      forbidden password user cannot set\n\n"

        "Password policy disabling options (with -d or --disable-policy)\n"
        " -u, --user                  uid to disable password policies\n\n"

        "Help options (with -h or --help)\n"
        " -h, --help                  print help message\n\n"

        "Password value\n"
        " If there is no password, use -c, --cur-passwd option without value, except check case:\n"
        "  auth-fw-cmd --set -t 0 --cur-passwd --new-passwd=\"HelloTizen!\"\n"
        " You can use -n, --new password option without value to remove password:\n"
        "  auth-fw-cmd --set -t 0 -c HelloTizen! -n\n"
        "  auth-fw-cmd --reset -u 5001 -t 0 -n\n\n"

        "Password policy value\n"
        " You don't need to set all password policies except user value:\n"
        "  auth-fw-cmd --set-policy -u 5001 -m 10 -v 7\n"
        "  auth-fw-cmd --set-policy -u 5001 -i 3 -l 4\n"
        " If you want to initialize some policies, use policy option without value:\n"
        "  auth-fw-cmd --set-policy -u 5001 -m -v 3\n"
        "  auth-fw-cmd --set-policy -u 5001 -i 3 -l\n"
;

static const char short_options[] = "asrpdh";
static const char short_options_check[] = "at:c::";
static const char short_options_set[] = "st:c::n::";
static const char short_options_reset[] = "ru:t:n::";
static const char short_options_policy[] = "pu:m::v::i::l::x::o::q::y::e::f::";
static const char short_options_disable[] = "du:";

static struct option long_options[] = {
    {"check", no_argument, NULL, 'a'},
    {"set", no_argument, NULL, 's'},
    {"reset", no_argument, NULL, 'r'},
    {"set-policy", no_argument, NULL, 'p'},
    {"disable-policy", no_argument, NULL, 'd'},

    {"user", required_argument, NULL, 'u'},
    {"type", required_argument, NULL, 't'},
    {"cur-passwd", optional_argument, NULL, 'c'},
    {"new-passwd", optional_argument, NULL, 'n'},

    {"max-attempts", optional_argument, NULL, 'm'},
    {"validity", optional_argument, NULL, 'v'},
    {"history-size", optional_argument, NULL, 'i'},
    {"min-length", optional_argument, NULL, 'l'},
    {"min-complex-char", optional_argument, NULL, 'x'},
    {"max-char-occurrences", optional_argument, NULL, 'o'},
    {"max-num-seq-len", optional_argument, NULL, 'q'},
    {"quality", optional_argument, NULL, 'y'},
    {"pattern", optional_argument, NULL, 'e'},
    {"forbidden-passwd", optional_argument, NULL, 'f'},

    {"help", no_argument, NULL, 'h'},
    {NULL, 0, 0, 0}
};

int main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                return checkPassword(argc, argv);

            case 's':
                return setPassword(argc, argv);

            case 'r':
                return resetPassword(argc, argv);

            case 'p':
                return setPolicy(argc, argv);

            case 'd':
                return disablePolicy(argc, argv);

            case 'h':
                usage(argv[0]);
                return 0;

            default:
                usage(argv[0]);
                return 0;
        }
    }

    usage(argv[0]);

    return 0;
}

int checkPassword(int argc, char **argv) {

    int ret;
    int opt;
    int option_flag1 = 0;
    int option_flag2 = 0;

    unsigned int cur_attempts = 0;
    unsigned int max_attempts = 0;
    unsigned int valid_secs = 0;

    while ((opt = getopt_long(argc, argv, short_options_check, long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                break;

            case 't':
                option_flag1 = 1;
                type = optarg[0];
                break;

            case 'c':
                option_flag2 = 1;
                if (optarg) {
                    if (strlen(optarg) > PASSWORD_MAX_LEN) {
                        printf("error: too long current password '%s'\n", optarg);
                        return 0;
                    }
                    memcpy(cur_passwd, optarg, strlen(optarg));

                } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                    if (strlen(argv[optind]) > PASSWORD_MAX_LEN) {
                        printf("error: too long current password '%s'\n", argv[optind]);
                        return 0;
                    }
                    memcpy(cur_passwd, argv[optind], strlen(argv[optind]));

                } else {
                    usage(argv[0]);
                    return 0;
                }
                break;

            default:
                usage(argv[0]);
                return 0;
        }
    }

    if (option_flag1 && option_flag2) {
        ret = auth_passwd_check_passwd((password_type)(type - '0'),
                                       cur_passwd,
                                       &cur_attempts,
                                       &max_attempts,
                                       &valid_secs);
        printf("check password: ret=\"%d\", cur attempts=\"%d\", max attempts=\"%d\", valid secs=\"%d\"\n",
               ret, cur_attempts, max_attempts, valid_secs);
    }
    else
        usage(argv[0]);

    return 0;
}

int setPassword(int argc, char **argv) {

    int ret;
    int opt;
    int option_flag1 = 0;
    int option_flag2 = 0;
    int option_flag3 = 0;

    while ((opt = getopt_long(argc, argv, short_options_set, long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                break;

            case 't':
                option_flag1 = 1;
                type = optarg[0];
                break;

            case 'c':
                option_flag2 = 1;
                if (optarg) {
                    if (strlen(optarg) > PASSWORD_MAX_LEN) {
                        printf("error: too long current password '%s'\n", optarg);
                        return 0;
                    }
                    memcpy(cur_passwd, optarg, strlen(optarg));

                } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                    if (strlen(argv[optind]) > PASSWORD_MAX_LEN) {
                        printf("error: too long current password '%s'\n", argv[optind]);
                        return 0;
                    }
                    memcpy(cur_passwd, argv[optind], strlen(argv[optind]));
                }
                break;

            case 'n':
                option_flag3 = 1;
                if (optarg) {
                    if (strlen(optarg) > PASSWORD_MAX_LEN) {
                        printf("error: too long new password '%s'\n", optarg);
                        return 0;
                    }
                    memcpy(new_passwd, optarg, strlen(optarg));

                } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                    if (strlen(argv[optind]) > PASSWORD_MAX_LEN) {
                        printf("error: too long new password '%s'\n", argv[optind]);
                        return 0;
                    }
                    memcpy(new_passwd, argv[optind], strlen(argv[optind]));
                }
                break;

            default:
                usage(argv[0]);
                return 0;
        }
    }

    if (option_flag1 && option_flag2 && option_flag3) {
        ret = auth_passwd_set_passwd((password_type)(type - '0'),
                                     cur_passwd,
                                     new_passwd);
        printf("set password: ret=\"%d\"\n", ret);
    }
    else
        usage(argv[0]);

    return 0;
}

int resetPassword(int argc, char **argv) {

    int ret;
    int opt;
    int option_flag1 = 0;
    int option_flag2 = 0;
    int option_flag3 = 0;

    while ((opt = getopt_long(argc, argv, short_options_reset, long_options, NULL)) != -1) {
        switch (opt) {
            case 'r':
                break;

            case 'u':
                option_flag1 = 1;
                user = atoi(optarg);
                break;

            case 't':
                option_flag2 = 1;
                type = optarg[0];
                break;

            case 'n':
                option_flag3 = 1;
                if (optarg) {
                    if (strlen(optarg) > PASSWORD_MAX_LEN) {
                        printf("error: too long new password '%s'\n", optarg);
                        return 0;
                    }
                    memcpy(new_passwd, optarg, strlen(optarg));

                } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                    if (strlen(argv[optind]) > PASSWORD_MAX_LEN) {
                        printf("error: too long new password '%s'\n", argv[optind]);
                        return 0;
                    }
                    memcpy(new_passwd, argv[optind], strlen(argv[optind]));
                }
                break;

            default:
                usage(argv[0]);
                return 0;
        }
    }

    if (option_flag1 && option_flag2 && option_flag3) {
        ret = auth_passwd_reset_passwd((password_type)(type - '0'),
                                       user,
                                       new_passwd);
        printf("reset password: ret=\"%d\"\n", ret);
    }
    else
        usage(argv[0]);

    return 0;
}

int setPolicy(int argc, char **argv) {

    int ret;
    int opt;
    int option_flag = 0;

    unsigned int attempts = 0;
    unsigned int valid_days = 0;
    unsigned int history_size = 0;
    unsigned int min_length = 0;
    unsigned int min_complex_char = 0;
    unsigned int max_char_occurrences = 0;
    unsigned int max_num_seq = 0;

    char quality = '0';

    policy_h *p_policy;

    if (auth_passwd_new_policy(&p_policy) != AUTH_PASSWD_API_SUCCESS) {
        printf("error: failed to call auth_passwd_new_policy()\n");
        return 0;
    }

    while ((opt = getopt_long(argc, argv, short_options_policy, long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                break;

            case 'u':
                option_flag = 1;
                user = atoi(optarg);
                if (auth_passwd_set_user(p_policy, user)) {
                    printf("error: failed to call auth_passwd_set_user()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'v':
                if (optarg)
                    valid_days = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    valid_days = atoi(argv[optind]);

                if (auth_passwd_set_validity(p_policy, valid_days)) {
                    printf("error: failed to call auth_passwd_set_validity()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'm':
                if (optarg)
                    attempts = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    attempts = atoi(argv[optind]);

                if (auth_passwd_set_max_attempts(p_policy, attempts)) {
                    printf("error: failed to call auth_passwd_set_max_attempts()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'i':
                if (optarg)
                    history_size = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    history_size = atoi(argv[optind]);

                if (auth_passwd_set_history_size(p_policy, history_size)) {
                    printf("error: failed to call auth_passwd_set_history_size()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'l':
                if (optarg)
                    min_length = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    min_length = atoi(argv[optind]);

                if (auth_passwd_set_min_length(p_policy, min_length)) {
                    printf("error: failed to call auth_passwd_set_min_length()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'x':
                if (optarg)
                    min_complex_char = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    min_complex_char = atoi(argv[optind]);

                if (auth_passwd_set_min_complex_char_num(p_policy, min_complex_char)) {
                    printf("error: failed to call auth_passwd_set_min_complex_char_num()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'o':
                if (optarg)
                    max_char_occurrences = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    max_char_occurrences = atoi(argv[optind]);

                if (auth_passwd_set_max_char_occurrences(p_policy, max_char_occurrences)) {
                    printf("error: failed to call auth_passwd_set_max_char_occurrences()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'q':
                if (optarg)
                    max_num_seq = atoi(optarg);
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    max_num_seq = atoi(argv[optind]);

                if (auth_passwd_set_max_num_seq_len(p_policy, max_num_seq)) {
                    printf("error: failed to call auth_passwd_set_num_seq_len()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'y':
                if (optarg)
                    quality = optarg[0];
                else if (argv[optind] != NULL && argv[optind][0] != '-')
                    quality = argv[optind][0];

                if (auth_passwd_set_quality(p_policy, (password_quality_type)(quality - '0'))) {
                    printf("error: failed to call auth_passwd_set_quality()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'e':
                if (optarg) {
                    if (strlen(optarg) > PASSWORD_REGEX_LEN) {
                        printf("error: too long regular expression '%s'\n", optarg);
                        return 0;
                    }
                    memcpy(regex, optarg, strlen(optarg));

                } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                    if (strlen(argv[optind]) > PASSWORD_REGEX_LEN) {
                        printf("error: too long regular expression '%s'\n", argv[optind]);
                        return 0;
                    }
                    memcpy(regex, argv[optind], strlen(argv[optind]));
                }

                if (auth_passwd_set_pattern(p_policy, regex)) {
                    printf("error: failed to call auth_passwd_set_pattern()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            case 'f':
                if (optarg) {
                    if (strlen(optarg) > PASSWORD_MAX_LEN) {
                        printf("error: too long forbidden password '%s'\n", optarg);
                        return 0;
                    }
                    memcpy(forbidden_passwd, optarg, strlen(optarg));

                } else if (argv[optind] != NULL && argv[optind][0] != '-') {
                    if (strlen(argv[optind]) > PASSWORD_MAX_LEN) {
                        printf("error: too long forbidden password '%s'\n", argv[optind]);
                        return 0;
                    }
                    memcpy(forbidden_passwd, argv[optind], strlen(argv[optind]));
                }

                if (auth_passwd_set_forbidden_passwd(p_policy, forbidden_passwd)) {
                    printf("error: failed to call auth_passwd_set_forbidden_passwd()\n");
                    auth_passwd_free_policy(p_policy);
                    return 0;
                }
                break;

            default:
                auth_passwd_free_policy(p_policy);
                usage(argv[0]);
                return 0;
        }
    }

    if (option_flag) {
        ret = auth_passwd_set_policy(p_policy);
        printf("set policy: ret=\"%d\"\n", ret);
    }
    else
        usage(argv[0]);

    auth_passwd_free_policy(p_policy);
    return 0;
}

int disablePolicy(int argc, char **argv) {

    int ret;
    int opt;
    int option_flag = 0;

    while ((opt = getopt_long(argc, argv, short_options_disable, long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                break;

            case 'u':
                option_flag = 1;
                user = atoi(optarg);
                break;

            default:
                usage(argv[0]);
                return 0;
        }
    }

    if (option_flag) {
        ret = auth_passwd_disable_policy(user);
        printf("disable policy: ret=\"%d\"\n", ret);
    }
    else
        usage(argv[0]);

    return 0;
}

void usage(char *arg)
{
    printf(help, arg);
}
