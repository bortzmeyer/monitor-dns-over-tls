/* DNS-over-TLS monitoring plugin for Nagios-compatible programs. Goal: to be integrated one day in <https://www.monitoring-plugins.org/> 

Requires getdns <https://getdnsapi.net/> >= 1.1

Stéphane Bortzmeyer <bortzmeyer@nic.fr>

with help from Willem Toorop <willem@nlnetlabs.nl> and the entire IETF
98 hackathon */

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

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

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

int             specify_port = FALSE;
int             server_port = 853;
char            server_port_text[6] = "";
char           *lookup_name = NULL;
char           *server_name = NULL;

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

static char     msgbuf[4096];

int
main(int argc, char **argv)
{

    if (argc < 2) {
        usage("Not enough args.");
        exit(STATE_UNKNOWN);
    }

/* TODO add standard long options */
    static struct option longopts[] = {
        {"port", required_argument, 0, 'p'},
        {"name", required_argument, 0, 'n'},
        {0, 0, 0, 0}
    };

    int             c = 1;
    int             option = 0;
    char           *p;
    while (1) {
        c = getopt_long(argc, argv, "Vvh?H:n:p:", longopts, &option);
        if (c == -1 || c == EOF)
            break;

        switch (c) {
        case '?':              /* usage */
            usage("");
            exit(STATE_OK);
            break;
        case 'h':              /* help */
            usage("");          /* TODO more detailed help */
            exit(STATE_OK);
            break;
        case 'V':              /* version */
            usage("TODO not yet implemented.");
            exit(STATE_OK);
            break;
        case 'n':              /* Name to lookup */
            lookup_name = strdup(optarg);
            break;
        case 'H':              /* DNS Server to test. Must be an IP address. *
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
        case 'p':              /* Server port */
            if (!is_intnonneg(optarg)) {
                sprintf(msgbuf, "Invalid port number %s.", optarg);
                usage(msgbuf);
                exit(STATE_UNKNOWN);
            } else {
                server_port = atoi(optarg);
                specify_port = TRUE;
            }
            break;
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
/* process_return = getdns_dict_set_int(extensions, "dnssec_return_status", GETDNS_EXTENSION_TRUE);  TODO too buggy, creates at leats two problems (frozen call to getdns_address_sync and no answers in response */
    process_return =
        getdns_dict_set_int(extensions, "return_call_reporting",
                            GETDNS_EXTENSION_TRUE);
    /* TODO test process_return */

    /* Make the call */
    getdns_return_t dns_request_return =
        getdns_address_sync(this_context, lookup_name,
                            extensions, &this_response);
    if (dns_request_return != GETDNS_RETURN_GOOD) {
        sprintf(msgbuf, "Error %s (%d) when resolving %s at %s", getdns_get_errorstr_by_id(dns_request_return), dns_request_return, lookup_name, server_name);  /* TODO 
                                                                                                                                                                 * Most 
                                                                                                                                                                 * of 
                                                                                                                                                                 * the 
                                                                                                                                                                 * time, 
                                                                                                                                                                 * we 
                                                                                                                                                                 * get 
                                                                                                                                                                 * 1 
                                                                                                                                                                 * "generic 
                                                                                                                                                                 * error". 
                                                                                                                                                                 * Find 
                                                                                                                                                                 * something 
                                                                                                                                                                 * better 
                                                                                                                                                                 */
        error(msgbuf);
    }

    getdns_return_t this_ret;
    /* Be sure the search returned something */
    uint32_t        this_error;
    this_ret = getdns_dict_get_int(this_response, "status", &this_error);
    if (this_error != GETDNS_RESPSTATUS_GOOD)   // If the search didn't return
        // "good"
    {
        sprintf(msgbuf,
                "The search had no results, and a return value of \"%s\" (%d)",
                getdns_get_errorstr_by_id(this_error), this_error);
        error(msgbuf);
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
    sprintf(msgbuf, "%d ms: ", rtt);
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
    /* sprintf(msgbuf, "From %s got %s", server_name, msgbuf); TODO does not work */
    success(msgbuf);            /* TODO display RTT */
    getdns_dict_destroy(this_response);

    /* Clean up */
    getdns_context_destroy(this_context);
    /* Assuming we get here, leave gracefully */
    exit(EXIT_SUCCESS);
}
