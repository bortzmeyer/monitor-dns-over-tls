/* DNS-over-TLS monitoring plugin for Nagios-compatible programs. Goal: to be integrated one day in <https://www.monitoring-plugins.org/> 

Requires getdns <https://getdnsapi.net/> >= 1.1

Stéphane Bortzmeyer <bortzmeyer@nic.fr>

with help from Willem Toorop <willem@nlnetlabs.nl>, Francis Dupont, Sara Dickinson and the entire IETF
98 hackathon */

/* TODO experimental, use autoconf or some other method to see if GNUtls is available. Set to 0 manually, in the time mebing, if you have no GNUtls. */
#define USE_GNUTLS 1

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#if USE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

/* TODO use monitoring plugins common.h instead */
enum {
    STATE_OK,
    STATE_WARNING,
    STATE_CRITICAL,
    STATE_UNKNOWN,
    STATE_DEPENDENT
};
enum {
    FALSE,
    TRUE
};
/* End of copy from common.h */

const char     *progname = "check_dns_with_getdns";
const char     *copyright = "2017";
const char     *email = "bortzmeyer@nic.fr";    /* Later
                                                 * "devel@monitoring-plugins.org" */
#define PREFIX "GETDNS"

int             debug = FALSE;
int             specify_port = FALSE;
int             server_port = 853;
char            server_port_text[6] = "";
char           *lookup_name = NULL;
char           *server_name = NULL;
int             require_authentication = FALSE;
int             authenticate = FALSE;
int             accept_dns_errors = TRUE;
getdns_dict    *keys;
char           *raw_keys;
char           *auth_name;
#if USE_GNUTLS
int             check_cert = FALSE;
int             days_till_exp_warn, days_till_exp_crit;
#endif

/* TODO use monitoring plugins utils.c instead */
int
is_integer(char *number)
{
    long int        n;

    if (!number || (strspn(number, "-0123456789 ") != strlen(number)))
        return FALSE;

    n = strtol(number, NULL, 10);

    if (errno != ERANGE && n >= INT_MIN && n <= INT_MAX)
        return TRUE;
    else
        return FALSE;
}
int
is_intpos(char *number)
{
    if (is_integer(number) && atoi(number) > 0)
        return TRUE;
    else
        return FALSE;
}
int
is_intneg(char *number)
{
    if (is_integer(number) && atoi(number) < 0)
        return TRUE;
    else
        return FALSE;
}

int
is_intnonneg(char *number)
{
    if (is_integer(number) && atoi(number) >= 0)
        return TRUE;
    else
        return FALSE;
}
/* End of copy from utils.c */

void
usage(char *msg)
{
    /* We write to stdout because this is what Nagios expects */
    fprintf(stdout, "%s Usage: %s -H TLS-resolver-as-IP-address -n domain-name \n",
            msg, progname);
}

void
internal_error(char *msg)
{
    fprintf(stdout, "%s UNKNOWN - %s\n", PREFIX, msg);
    exit(STATE_UNKNOWN);
}

void
error(char *msg)
{
    fprintf(stdout, "%s CRITICAL - %s\n", PREFIX, msg);
    exit(STATE_CRITICAL);
}

void
warning(char *msg)
{
    fprintf(stdout, "%s WARNING - %s\n", PREFIX, msg);
    exit(STATE_WARNING);
}

void
success(char *msg)
{
    fprintf(stdout, "%s OK - %s\n", PREFIX, msg);
}

static char     msgbuf[4096], msgbuf2[1024];

int
main(int argc, char **argv)
{

    if (argc < 2) {
        usage("Not enough args.");
        exit(STATE_UNKNOWN);
    }

/* TODO add standard long options, which include critical, warning, verbose, etc */
    static struct option longopts[] = {
        {"debug", no_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},    /* TODO actually implement it */
        {"hostname", required_argument, 0, 'H'},
        {"name", required_argument, 0, 'n'},
        {"require_authentication", no_argument, 0, 'r'},
        {"authenticate", no_argument, 0, 'a'},
        {"accept_dns_errors", no_argument, 0, 'e'},
        {"keys", required_argument, 0, 'k'},
        {"authname", required_argument, 0, 'A'},
        {"certificate", required_argument, 0, 'C'},
        {0, 0, 0, 0}
    };

    int             c = 1;
    int             option = 0;
    char           *p, *tmp;
    while (1) {
        c = getopt_long(argc, argv, "Vvh?hdH:n:p:C:ark:A:e", longopts, &option);
        if (c == -1 || c == EOF)
            break;

        switch (c) {
        case '?':              /* usage */
            usage("");
            exit(STATE_UNKNOWN);        /* Because getopt returns ? if there is an
                                         * unknown option */
            break;
        case 'h':              /* help */
            usage("");          /* TODO more detailed help */
            exit(STATE_OK);
            break;
        case 'd':              /* debug */
            debug = TRUE;
            break;
        case 'r':              /* Require authentication of the TLS server */
            require_authentication = TRUE;
            break;
        case 'a':              /* Test there is authentication of the TLS server */
            authenticate = TRUE;
            break;
        case 'e':              /* Regard NXDOMAIN or SERVFAIL as critical errors */
            accept_dns_errors = FALSE;
            break;
        case 'V':              /* version */
            sprintf(msgbuf, "getdns %s, API %s.", getdns_get_version(),
                    getdns_get_api_version());
            usage(msgbuf);
            exit(STATE_OK);
            break;
        case 'n':              /* Name to lookup */
            lookup_name = strdup(optarg);
            break;
        case 'C':              /* Check PKIX cert validity */
#if USE_GNUTLS
            if ((tmp = strchr(optarg, ',')) != NULL) {
                *tmp = '\0';
                if (!is_intnonneg(optarg)) {
                    sprintf(msgbuf, "Invalid certificate expiration period %s",
                            optarg);
                    usage(msgbuf);
                    exit(STATE_UNKNOWN);
                }
                days_till_exp_warn = atoi(optarg);
                *tmp = ',';
                tmp++;
                if (!is_intnonneg(tmp)) {
                    sprintf(msgbuf, "Invalid certificate expiration period %s", tmp);
                    usage(msgbuf);
                    exit(STATE_UNKNOWN);
                }
                days_till_exp_crit = atoi(tmp);
            } else {
                days_till_exp_crit = 0;
                if (!is_intnonneg(optarg)) {
                    sprintf(msgbuf, "Invalid certificate expiration period %s",
                            optarg);
                    usage(msgbuf);
                    exit(STATE_UNKNOWN);
                }
                days_till_exp_warn = atoi(optarg);
            }
            if (days_till_exp_warn < days_till_exp_crit) {
                sprintf(msgbuf,
                        "Warning certificate expiration threshold must be superior to the critical one (%s)",
                        optarg);
                usage(msgbuf);
                exit(STATE_UNKNOWN);
            }
            check_cert = TRUE;
#else
            usage("No TLS support compiled :-(");
            exit(STATE_UNKNOWN);
#endif
            break;
        case 'H':              /* DNS Server to test. Must be an IP address. * *
                                 * check_dns uses it for the name to lookup */
            server_name = strdup(optarg);
            if (server_name[0] == '[') {
                if ((p = strstr(server_name, "]:")) != NULL)    /* [IPv6]:port */
                    server_port = atoi(p + 2);
            } else if ((p = strchr(server_name, ':')) != NULL && strchr(++p, ':') == NULL)      /* IPv4:port 
                                                                                                 * or 
                                                                                                 * host:port 
                                                                                                 */
                server_port = atoi(p);
            break;
        case 'k':
            raw_keys = strdup(optarg);
            break;
        case 'A':              /* TLS auth name */
            auth_name = strdup(optarg);
            break;
        case 'p':              /* Server port TODO not yet implemented */
            if (!is_intnonneg(optarg)) {
                sprintf(msgbuf, "Invalid port number %s.", optarg);
                usage(msgbuf);
                exit(STATE_UNKNOWN);
            } else {
                server_port = atoi(optarg);
                specify_port = TRUE;
            }
            break;
        default:
            usage("");
            exit(STATE_UNKNOWN);
        }
    }

    if (lookup_name == NULL || server_name == NULL) {
        usage("");
        exit(STATE_UNKNOWN);
    }

    /* Create the DNS context for this call */
    getdns_context *this_context = NULL;
    getdns_return_t context_create_return = getdns_context_create(&this_context, 1);
    if (context_create_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Trying to create the context failed: %s (%d)",
                getdns_get_errorstr_by_id(context_create_return),
                context_create_return);
        internal_error(msgbuf);
    }

    /* Set up the getdns call */
    getdns_dict    *this_response;
    getdns_dict    *this_resolver = getdns_dict_create();
    getdns_return_t process_return = getdns_str2dict(server_name, &this_resolver);      /* str2dict
                                                                                         * *
                                                                                         * requires
                                                                                         * * getdns
                                                                                         * >= * 1.1 */
    if (process_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf,
                "Unable to convert %s to bindata: %s (%d) (we accept only IP addresses, not names)",
                server_name, getdns_get_errorstr_by_id(process_return),
                process_return);
        internal_error(msgbuf);
    }

    /* Only DNS-over-TLS */
    getdns_transport_list_t this_transport[] = { GETDNS_TRANSPORT_TLS };
    getdns_return_t transport_return =
        getdns_context_set_dns_transport_list(this_context,
                                              1,        /* Just one transport */
                                              this_transport);
    if (transport_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Unable to set TLS transport: %s (%d).",
                getdns_get_errorstr_by_id(transport_return), transport_return);
        internal_error(msgbuf);
    }

    /* Authentication */
    if (require_authentication || authenticate) {
        if (raw_keys == NULL && auth_name == NULL) {
            sprintf(msgbuf, "To authenticate, I need keys (option -k) or auth name (option -A)");       /* TODO: 
                                                                                 * this 
                                                                                 * will 
                                                                                 * change 
                                                                                 * with 
                                                                                 * the 
                                                                                 * future 
                                                                                 * auth. 
                                                                                 * profils, 
                                                                                 * using 
                                                                                 * things 
                                                                                 * like 
                                                                                 * PKIX 
                                                                                 * validation 
                                                                                 */
            internal_error(msgbuf);
        }
    }
    if (raw_keys != NULL || auth_name != NULL) {
        getdns_return_t set_auth_return;
        
        if (raw_keys != NULL) {
            keys = getdns_pubkey_pin_create_from_string(this_context, raw_keys);
            if (keys == NULL) {
                sprintf(msgbuf, "Cannot parse keys \"%s\"", raw_keys);
                internal_error(msgbuf);
            }
            getdns_list    *keys_list = getdns_list_create();
            getdns_list_set_dict(keys_list, 0, keys);
#if 0
            getdns_list    *keys_errors = getdns_list_create();
            set_auth_return = getdns_pubkey_pinset_sanity_check(keys_list, keys_errors);
            if (set_auth_return != GETDNS_RETURN_GOOD) {
                sprintf(msgbuf, "Something is wrong in keys %s: %s (%d), %s", raw_keys,
                        getdns_get_errorstr_by_id(set_auth_return), set_auth_return,
                        getdns_pretty_print_list(keys_errors));
                internal_error(msgbuf);
            }
#endif
            set_auth_return =
                getdns_dict_set_list(this_resolver, "tls_pubkey_pinset", keys_list);
            if (set_auth_return != GETDNS_RETURN_GOOD) {
                sprintf(msgbuf, "Unable to set keys for %s: %s (%d)", server_name,
                        getdns_get_errorstr_by_id(set_auth_return), set_auth_return);
                internal_error(msgbuf);
            }
        } else {
            getdns_bindata authname_bindata;
            authname_bindata.size = strlen(auth_name);
            authname_bindata.data = auth_name;
            set_auth_return =
                getdns_dict_set_bindata(this_resolver, "tls_auth_name", &authname_bindata);
            if (set_auth_return != GETDNS_RETURN_GOOD) {
                sprintf(msgbuf, "Unable to set auth name for %s: %s (%d)", server_name,
                        getdns_get_errorstr_by_id(set_auth_return), set_auth_return);
                internal_error(msgbuf);
            }
        }
        if (require_authentication) {
            set_auth_return =
                getdns_context_set_tls_authentication(this_context,
                                                      GETDNS_AUTHENTICATION_REQUIRED);
            if (set_auth_return != GETDNS_RETURN_GOOD) {
                sprintf(msgbuf, "Unable to set authentication: %s (%d)",
                        getdns_get_errorstr_by_id(set_auth_return), set_auth_return);
                internal_error(msgbuf);
            }
        }
    }

    /* Set upstream resolver to the thing we want to test */
    getdns_list    *this_list = getdns_list_create();
    getdns_return_t list_set_return =
        getdns_list_set_dict(this_list, 0, this_resolver);
    if (list_set_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Unable to add \"%s\" to the list: %s (%d)",
                server_name, getdns_get_errorstr_by_id(list_set_return),
                list_set_return);
        internal_error(msgbuf);
    }
    getdns_return_t set_resolver_return =
        getdns_context_set_upstream_recursive_servers(this_context,
                                                      this_list);
    if (set_resolver_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Unable to set TLS upstream resolver %s: %s (%d)",
                server_name, getdns_get_errorstr_by_id(set_resolver_return),
                set_resolver_return);
        internal_error(msgbuf);
    }

    getdns_return_t set_stub_return =
        getdns_context_set_resolution_type(this_context,
                                           GETDNS_RESOLUTION_STUB);
    if (set_stub_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Unable to set to stub mode: %s (%d)",
                getdns_get_errorstr_by_id(set_stub_return), set_stub_return);
        internal_error(msgbuf);
    }

    /* Extensions */
    getdns_dict    *extensions = getdns_dict_create();
/* process_return = getdns_dict_set_int(extensions, "dnssec_return_status", GETDNS_EXTENSION_TRUE);  TODO too buggy, creates at leats two problems (frozen call to getdns_address_sync <https://github.com/getdnsapi/getdns/issues/272> and no answers in response */
    process_return =
        getdns_dict_set_int(extensions, "return_call_reporting",
                            GETDNS_EXTENSION_TRUE);
    /* TODO test process_return */
    if (debug) {
        printf("DEBUG: context is %s\n",
               getdns_pretty_print_dict(getdns_context_get_api_information
                                        (this_context)));
    }

    /* Make the call */
    getdns_return_t dns_request_return =
        getdns_address_sync(this_context, lookup_name,
                            extensions, &this_response);
    if (dns_request_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Error %s (%d) when resolving %s at %s",
                getdns_get_errorstr_by_id(dns_request_return), dns_request_return,
                lookup_name, server_name);
        /* TODO * Most of the time, we get 1 "generic error". Find something better */
        error(msgbuf);
    }

    if (debug) {
        printf("DEBUG: response is %s\n", getdns_pretty_print_dict(this_response));
    }

    getdns_return_t this_ret;
    /* Be sure the search returned something */
    uint32_t        this_error;
    this_ret = getdns_dict_get_int(this_response, "status", &this_error);
    if (this_error != GETDNS_RESPSTATUS_GOOD)   // If the search didn't return
        // "good"
    {
        uint32_t        rcode;
        this_ret =
            getdns_dict_get_int(this_response, "/replies_tree/0/header/rcode",
                                &rcode);
        if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME
            || this_ret == GETDNS_RETURN_NO_SUCH_LIST_ITEM) {
            /* Probably a timeout, so we got no reply at all */
            sprintf(msgbuf,
                    "The search had no results (timeout?), and a return value of \"%s\" (%d)",
                    getdns_get_errorstr_by_id(this_error), this_error);
            error(msgbuf);
        } else if (this_ret != GETDNS_RETURN_GOOD) {
            sprintf(msgbuf, "Cannot retrieve the DNS return code: %s (%d)",
                    getdns_get_errorstr_by_id(this_ret), this_ret);
            internal_error(msgbuf);
        }
        if (!accept_dns_errors) {
            char           *rcode_text;
            if (rcode != 0) {   /* https://www.iana.org/assignments/dns-parameters/dns-parameters.xml#dns-parameters-6 
                                 */
                switch (rcode) {
                case 1:
                    rcode_text = "FORMERR";
                    break;
                case 2:
                    rcode_text = "SERVFAIL";
                    break;
                case 3:
                    rcode_text = "NXDOMAIN";
                    break;
                case 4:
                    rcode_text = "NOTIMP";
                    break;
                case 5:
                    rcode_text = "REFUSED";
                    break;
                default:
                    rcode_text = "(unreferenced)";
                }
                sprintf(msgbuf,
                        "DNS return code in error \"%s\" (%d)", rcode_text, rcode);
                error(msgbuf);
            }
        } else {
            /* OK, we can continue */
        }
    }
    getdns_list    *report_list;
    this_ret = getdns_dict_get_list(this_response, "call_reporting", &report_list);
    if (this_ret != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Trying to get the report failed: %s (%d)\n",
                getdns_get_errorstr_by_id(this_ret), this_ret);
        internal_error(msgbuf);
    }
    getdns_dict    *report_dict;
    getdns_list_get_dict(report_list, 0, &report_dict); /* TODO test ret code */
    uint32_t        rtt;
    this_ret = getdns_dict_get_int(report_dict, "run_time/ms", &rtt);
    if (this_ret != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Trying to get the RTT failed: %s (%d)\n",
                getdns_get_errorstr_by_id(this_ret), this_ret);
        internal_error(msgbuf);
    }
    getdns_bindata *auth_status;
    this_ret = getdns_dict_get_bindata(report_dict, "tls_auth_status", &auth_status);
    if (this_ret != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf,
                "Trying to get the TLS authentication status certificate failed: %s (%d)\n",
                getdns_get_errorstr_by_id(this_ret), this_ret);
        internal_error(msgbuf);
    }
    auth_status->data[auth_status->size] = '\0';        /* Is it really necessary?
                                                         * getdns guarantees a nul
                                                         * at the end? */
#if USE_GNUTLS
    getdns_bindata *cert;
    /* Requires getdns >= 1.1, otherwise, we get back a "A helper function for dicts 
     * had a name argument that for a name that is not in the dict. (305)" */
    this_ret = getdns_dict_get_bindata(report_dict, "tls_peer_cert", &cert);
    if (this_ret != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Trying to get the PKIX certificate failed: %s (%d)\n",
                getdns_get_errorstr_by_id(this_ret), this_ret);
        internal_error(msgbuf);
    }
    gnutls_x509_crt_t parsed_cert;
    int             gnutls_return;
    gnutls_return = gnutls_x509_crt_init(&parsed_cert);
    if (gnutls_return != GNUTLS_E_SUCCESS) {
        sprintf(msgbuf, "Cannot initialize the PKIX certificate: %s",
                gnutls_strerror_name(gnutls_return));
        internal_error(msgbuf);
    }
    gnutls_datum_t  raw_cert;
    raw_cert.size = cert->size;
    raw_cert.data = malloc(cert->size);
    memcpy(raw_cert.data, cert->data, cert->size);
    gnutls_return =
        gnutls_x509_crt_import(parsed_cert, &raw_cert, GNUTLS_X509_FMT_DER);
    if (gnutls_return != GNUTLS_E_SUCCESS) {
        sprintf(msgbuf, "Cannot parse the PKIX certificate of %s: %s", server_name,
                gnutls_strerror_name(gnutls_return));
        error(msgbuf);
    }
    time_t          expiration_time;
    expiration_time = gnutls_x509_crt_get_expiration_time(parsed_cert);
    if (check_cert) {
        /* TODO do not exit immediately, keep the message and the state */
        struct timeval  tv;
        gettimeofday(&tv, NULL);
        if (expiration_time < tv.tv_sec) {
            sprintf(msgbuf, "Certificate expired %d days ago",
                    (int) (tv.tv_sec - expiration_time) / 86400);
            error(msgbuf);
        } else if (expiration_time < (tv.tv_sec + days_till_exp_crit * 86400)) {
            sprintf(msgbuf, "Certificate will expire in %d days",
                    (int) (expiration_time - tv.tv_sec) / 86400);
            error(msgbuf);
        } else if (expiration_time < (tv.tv_sec + days_till_exp_warn * 86400)) {
            sprintf(msgbuf, "Certificate will expire in %d days",
                    (int) (expiration_time - tv.tv_sec) / 86400);
            warning(msgbuf);
        }
    }
#endif
    getdns_list    *just_the_addresses_ptr;     /* TODO allow to specify other DNS
                                                 * types */
    this_ret =
        getdns_dict_get_list(this_response, "just_address_answers",
                             &just_the_addresses_ptr);
    if (this_ret != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Trying to get the answers failed: %s (%d)\n",
                getdns_get_errorstr_by_id(this_ret), this_ret);
        internal_error(msgbuf);
    }
    size_t          num_addresses;
    this_ret = getdns_list_get_length(just_the_addresses_ptr, &num_addresses);
    if (num_addresses <= 0) {
        sprintf(msgbuf, "Got zero IP addresses for %s", lookup_name);
        warning(msgbuf);
    }
    /* Go through each record */
#if USE_GNUTLS
    struct tm      *f_time = gmtime(&expiration_time);
    strftime(msgbuf2, 1000, "%Y-%m-%d", f_time);
    sprintf(msgbuf, "%d ms, expiration date %s, auth. %s: ", rtt, msgbuf2,
            (char *) auth_status->data);
#else
    sprintf(msgbuf, "%d ms: ", rtt);
#endif
    for (size_t rec_count = 0; rec_count < num_addresses; ++rec_count) {
        getdns_dict    *this_address;
        this_ret =
            getdns_list_get_dict(just_the_addresses_ptr, rec_count, &this_address);
        /* Just get the address */
        getdns_bindata *this_address_data;
        this_ret =
            getdns_dict_get_bindata(this_address, "address_data",
                                    &this_address_data);
        char           *this_address_str =
            getdns_display_ip_address(this_address_data);
        sprintf(msgbuf, "%s Address %s", msgbuf, this_address_str);
    }
    if (authenticate && (strcmp((char *) auth_status->data, "Success")) != 0) {
        error(msgbuf);
    }
    /* sprintf(msgbuf, "From %s got %s", server_name, msgbuf); TODO does not work */
    success(msgbuf);
    getdns_dict_destroy(this_response);

    /* Clean up */
    getdns_context_destroy(this_context);
    /* Assuming we get here, leave gracefully */
    exit(EXIT_SUCCESS);
}
