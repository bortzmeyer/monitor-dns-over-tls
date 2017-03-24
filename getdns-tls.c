#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

#define UNUSED_PARAM(x) ((void)(x))

void
process_results(getdns_context * this_context,
                getdns_dict * this_response, void *this_userarg)
{
    UNUSED_PARAM(this_userarg); /* Not looking at the userarg for this example */
    UNUSED_PARAM(this_context); /* Not looking at the context for this example */
    getdns_return_t this_ret;   /* Holder for all function returns */
    /* Be sure the search returned something */
    uint32_t        this_error;
    this_ret = getdns_dict_get_int(this_response, "status", &this_error);       // Ignore 
                                                                                // any 
                                                                                // error
    if (this_error != GETDNS_RESPSTATUS_GOOD)   // If the search didn't return
                                                // "good"
    {
        fprintf(stderr,
                "The search had no results, and a return value of %d. Exiting.\n",
                this_error);
        (void) getdns_dict_destroy(this_response);
        return;
    }
    getdns_list    *just_the_addresses_ptr;
    this_ret =
        getdns_dict_get_list(this_response, "just_address_answers",
                             &just_the_addresses_ptr);
    if (this_ret != GETDNS_RETURN_GOOD) // This check is really not needed, but
                                        // prevents a compiler error under
                                        // "pedantic"
    {
        fprintf(stderr, "Trying to get the answers failed: %d\n", this_ret);
        getdns_dict_destroy(this_response);
        return;
    }
    size_t          num_addresses;
    this_ret = getdns_list_get_length(just_the_addresses_ptr, &num_addresses);  // Ignore 
                                                                                // any 
                                                                                // error
    /* Go through each record */
    for (size_t rec_count = 0; rec_count < num_addresses; ++rec_count) {
        getdns_dict    *this_address;
        this_ret = getdns_list_get_dict(just_the_addresses_ptr, rec_count, &this_address);      // Ignore 
                                                                                                // any 
                                                                                                // error
        /* Just print the address */
        getdns_bindata *this_address_data;
        this_ret = getdns_dict_get_bindata(this_address, "address_data", &this_address_data);   // Ignore 
                                                                                                // any 
                                                                                                // error
        char           *this_address_str =
            getdns_display_ip_address(this_address_data);
        printf("The address is %s\n", this_address_str);
        free(this_address_str);
    }
    getdns_dict_destroy(this_response);
}

int
main(int argc, char **argv)
{

    if (argc != 3) {
        fprintf(stderr, "Usage: %s TLS-resolver domain-name\n", argv[0]);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }

    /* Create the DNS context for this call */
    getdns_context *this_context = NULL;
    getdns_return_t context_create_return = getdns_context_create(&this_context, 1);
    if (context_create_return != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "Trying to create the context failed: %d",
                context_create_return);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }

    /* Set up the getdns call */
    const char     *this_server = argv[1];
    const char     *this_name = argv[2];
    getdns_dict    *this_response;

    /* Resolve the argument (which may be a name or an address into bindata) */
     uint32_t        this_error;
     getdns_return_t dns_request_return = getdns_address_sync(this_context, this_server,
                                                             (getdns_dict *) NULL,
                                                             &this_response);
    if (dns_request_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Wrong argument %s as resolver: %d. Exiting.\n", this_server, dns_request_return);
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    getdns_return_t process_return = getdns_dict_get_int(this_response, "status", &this_error);      
    if (process_return != GETDNS_RETURN_GOOD)   
    {
        fprintf(stderr,
                "The search for the resolver's address had no results, and a return value of %d. Exiting.\n",
                process_return);
        (void) getdns_dict_destroy(this_response);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    getdns_list    *just_the_addresses_ptr;
   process_return =
        getdns_dict_get_list(this_response, "just_address_answers",
                             &just_the_addresses_ptr);
    if (process_return != GETDNS_RETURN_GOOD)
    {
        fprintf(stderr, "Trying to get the answers for the resolver's addrss failed: %d\n", process_return);
        getdns_dict_destroy(this_response);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    size_t          num_addresses;
    process_return = getdns_list_get_length(just_the_addresses_ptr, &num_addresses);
    /* Always zero if the argument is an IP address. So, we cheat 
     if (num_addresses <= 0) {
      fprintf(stderr, "No IP addresses for the resolver\n");
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
        getdns_dict    *this_address; 
	Test only the first one
        process_return = getdns_list_get_dict(just_the_addresses_ptr, 0, &this_address);   
        getdns_bindata this_resolver;
        process_return = getdns_dict_get_bindata(this_address, "address_data", &this_resolver);   
   */
    uint32_t localhost = htonl(0x7f000001);
            getdns_bindata 
	      this_resolver = { 4, (void *)&localhost};
	  
    /* Only DNS-over-TLS */
    getdns_transport_list_t this_transport[] = {GETDNS_TRANSPORT_TLS};
    getdns_return_t transport_return = getdns_context_set_dns_transport_list(
     this_context,
     1, /* Just one transport */
     this_transport);
    if (transport_return != GETDNS_RETURN_GOOD) {
        fprintf(stderr, "Unable to set TLS transport: %d. Exiting.\n", transport_return);
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }

    /* Set upstream resolver to the thing we want to test */
    getdns_bindata this_type = { 4, (void *)"IPv4" }; /* TODO allows to change it to IPv6 */
    getdns_list     *this_list = getdns_list_create();
    getdns_dict *this_dict = getdns_dict_create();
    getdns_return_t dict_set_return = getdns_dict_set_bindata(this_dict, "address_type", &this_type);
    if (dict_set_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Unable to add address type to the dict: %d. Exiting.\n", dict_set_return);
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    dict_set_return = getdns_dict_set_bindata(this_dict, "address_data", &this_resolver);
    if (dict_set_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Unable to add \"%s\" to the dict: %d. Exiting.\n", this_server, dict_set_return);
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    getdns_return_t list_set_return = getdns_list_set_dict(this_list, 0, this_dict);
    if (list_set_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Unable to add \"%s\" to the list: %d. Exiting.\n", this_server, list_set_return);
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    printf("DEBUG: dict %s\n", getdns_pretty_print_list(this_list));
    getdns_return_t set_resolver_return = getdns_context_set_upstream_recursive_servers(
     this_context,
     this_list);
    if (set_resolver_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Unable to set TLS upstream resolver: %s. Exiting.\n", getdns_get_errorstr_by_id(set_resolver_return));
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }

    getdns_return_t set_stub_return = getdns_context_set_resolution_type(
     this_context,
     GETDNS_RESOLUTION_STUB);
    if (set_stub_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Unable to set to stub mode: %s. Exiting.\n", getdns_get_errorstr_by_id(set_stub_return));
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }

    printf("DEBUG: context is %s\n", getdns_pretty_print_dict(getdns_context_get_api_information(this_context)));
    /* Make the call */
    dns_request_return = getdns_address_sync(this_context, this_name,
                                                             (getdns_dict *) NULL,
                                                             &this_response);
    if (dns_request_return != GETDNS_RETURN_GOOD) {
      fprintf(stderr, "Error %d when resolving %s. Exiting.\n", dns_request_return, this_name);
        getdns_context_destroy(this_context);
        return (GETDNS_RETURN_GENERIC_ERROR);
    }
    process_results(this_context, this_response, (void *) NULL);
    /* Clean up */
    getdns_context_destroy(this_context);
    /* Assuming we get here, leave gracefully */
    exit(EXIT_SUCCESS);
}
