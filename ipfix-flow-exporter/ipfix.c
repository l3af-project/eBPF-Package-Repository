/*
 *
 * Copyright (c) 2016-2018 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**********************************************************
 * @file ipfix.c
 *
 * @brief Source code to perform IPFIX protocol operations.
 **********************************************************/

#define _XOPEN_SOURCE
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>   /* for memcpy() */
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <linux/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <math.h>
#include "ipfix.h"
#include "p2f.h"
#include "log.h"


#define FILE_NAME "output.txt"

/*
 * Doubly linked list for collector template store (cts).
 */
#define MAX_IPFIX_TEMPLATES 100
#define INGRESS 0
#define EGRESS 1

#define XTS_RESEND_TIME (300) /* 5 minutes */
#define XTS_EXPIRE_TIME (1800) /* 30 minutes */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define ntoh64(x) x
# define hton64(x) x
#else 
#   define ntoh64(x) __builtin_bswap64(x)
#   define hton64(x) __builtin_bswap64(x)
# endif

/*
 * Doubly linked list for exporter template store (xts).
 */
static ipfix_exporter_template_t *export_template_store_head = NULL;
static ipfix_exporter_template_t *export_template_store_tail = NULL;
static uint16_t xts_count = 0;
static pthread_mutex_t export_lock = PTHREAD_MUTEX_INITIALIZER;
static ipfix_message_t *export_message = NULL;
static unsigned int number_of_records = 0;


/* Exporter object to send messages, alive until process termination */
static ipfix_exporter_t gateway_export = {
    {0,0,{0},{'0','0','0','0','0','0','0','0'}},
    {0,0,{0},{'0','0','0','0','0','0','0','0'}},
    0,0,0
};

char *ipfix_export_template = "simple";
int ipfix_export_port = 4755;
ipfix_template_type_e export_template_type;


/******************************************
 * \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
 *                                        |
 *          IPFIX EXPORTING               |
 *                                        |
 * ////////////////////////////////////////
 *****************************************/


/*
 * Exporting process observation domain id.
 * Will be generated upon creation of the first ipfix_exporter object.
 */
static uint32_t exporter_obs_dom_id = 0;

#define IPFIX_COLLECTOR_DEFAULT_PORT 4739
#define HOST_NAME_MAX_SIZE 50
#define TEMPLATE_NAME_MAX_SIZE 50

static uint16_t exporter_template_id ;
static uint16_t exporter_tcp_ingress_template_id = 256;
static uint16_t exporter_tcp_egress_template_id = 257;
static uint16_t exporter_icmp_ingress_template_id = 258;
static uint16_t exporter_icmp_egress_template_id = 259;

extern FILE *info;

#define ipfix_exp_template_field_macro(a, b) \
  ((ipfix_exporter_template_field_t) {a, b, 0})

/* TODO: 53500 is a Vendor's PEN number. Using an available PEN number here.
 * https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
#define ipfix_exp_template_ent_field_macro(a, b) \
  ((ipfix_exporter_template_field_t) {a, b, 53500})


/*
 * @brief allocate memory for an exporter template fields.
 *
 */
static void ipfix_exp_template_fields_malloc(ipfix_exporter_template_t *template,
                                             uint16_t field_count) {
    size_t field_list_size = field_count * sizeof(ipfix_exporter_template_field_t);

    template->fields = calloc(1, field_list_size);
}

/*
 * @brief delete memory for an exporter template fields.
 *
 */
static void ipfix_delete_exp_template_fields(ipfix_exporter_template_t *template) {
    uint16_t field_count = 0;

    if (template == NULL) {
        log_err("api-error: template is null");
        return;
    }

    field_count = template->hdr.field_count;

    size_t field_list_size = field_count * sizeof(ipfix_exporter_template_field_t);
    if (template->fields) {
        memset(template->fields, 0, field_list_size);
        free(template->fields);
        template->fields = NULL;
    } else {
        log_warn("warning: fields were already null");
    }
}

/*
 * @brief Allocate heap memory for an exporter template.
 *
 * @param num_fields Number of fields the template will be able to hold.
 *
 * @return A newly allocated ipfix_exporter_template
 */
static ipfix_exporter_template_t *ipfix_exp_template_malloc(uint16_t field_count) {
    log_debug("Allocating memory for an exporter template");
    /* Init a new exporter template on the heap */
    ipfix_exporter_template_t *template = calloc(1, sizeof(ipfix_exporter_template_t));

    if (template != NULL) {
        /* Allocate memory for the fields */
        ipfix_exp_template_fields_malloc(template, field_count);
        template->length = 4;
    }
    else {
        log_err("error: IPFIX template malloc failed");
    }

    return template;
}


/*
 * @brief Free an allocated exporter template structure.
 *
 * First free the attached fields memory. Then free the template memory.
 *
 * @param template IPFIX exporter template that will have it's heap memory freed.
 */
static inline void ipfix_delete_exp_template(ipfix_exporter_template_t *template) {
    log_debug("Deleting template");
    if (template == NULL) {
        log_err("api-error: template is null");
        return;
    }

    if (template->fields) {
        /* Free the attached fields memory */
        ipfix_delete_exp_template_fields(template);
    }

    /* Free the template */
    memset(template, 0, sizeof(ipfix_exporter_template_t));
    free(template);
    template = NULL;
}


/*
 * @brief Allocate heap memory for an exporter data record.
 *
 * @return A newly allocated ipfix_exporter_data
 */
static ipfix_exporter_data_t *ipfix_exp_data_record_malloc(void) {
    log_debug("Allocating memory for data record");
    ipfix_exporter_data_t *data_record = NULL;

    /* Init a new exporter data record on the heap */
    data_record = calloc(1, sizeof(ipfix_exporter_data_t));

    if (data_record == NULL) {
        log_err("error: malloc failed, data record is null");
    }

    return data_record;
}


/*
 * @brief Free an allocated exporter data record.
 *
 * @param template IPFIX exporter data record that will have it's heap memory freed.
 */
static inline void ipfix_delete_exp_data_record(ipfix_exporter_data_t *data_record) {
    log_debug("Deleting Data record");
    if (data_record == NULL) {
        log_err("api-error: data record is null");
        return;
    }
    /* Free the data record */
    memset(data_record, 0, sizeof(ipfix_exporter_data_t));
    free(data_record);
    data_record = NULL;
}


/*
 * @brief Append to the exporter template store (xts).
 *
 * Add a given template to the end of the exporter template store
 * linked list.
 *
 * @param template IPFIX exporter template that will be appended.
 *
 * @return 0 if templates was added, 1 if template was not added.
 */
static int ipfix_xts_append(ipfix_exporter_template_t *template) {
    log_debug("Appending template to exporter template store");
    if (xts_count >= (MAX_IPFIX_TEMPLATES - 1)) {
        log_warn("warning: ipfix template cannot be added to xts, already at maximum storage threshold");
        return 1;
    }

    /* Write the current time */
    //template->last_seen = time(NULL);

    pthread_mutex_lock(&export_lock);
    if (export_template_store_head == NULL) {
        /* This is the first template in store list */
        export_template_store_head = template;
    } else {
        /* Append to the end of store list */
        export_template_store_tail->next = template;
        template->prev = export_template_store_tail;
    }

    /* Update the tail */
    export_template_store_tail = template;

    /* Increment the store count */
    xts_count += 1;
    pthread_mutex_unlock(&export_lock);

    return 0;
}


/*
 * @brief Copy a template from the export store list into a new template.
 *
 * Using \p as the template from the store, copy it's contents
 * into a newly allocated template that is totally independent.
 * The user of the new template can modify it however they wish,
 * with no impact to the original export store template.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @return 0 for success, 1 for failure.
 */
static int ipfix_xts_copy(ipfix_exporter_template_t **dest_template,
                          ipfix_exporter_template_t *src_template) {
    log_debug("Copying template from the export store list into a new template");
    uint16_t field_count = 0;
    ipfix_exporter_template_field_t *new_fields = NULL;
    ipfix_exporter_template_t *new_template = NULL;
    int ct;
    if (dest_template == NULL || src_template == NULL) {
        log_err("api-error: dest or src template is null");
        return 1;
    }
    field_count = src_template->hdr.field_count;

    /* Allocate heap memory for new_template */
    new_template = ipfix_exp_template_malloc(field_count);

    if (new_template == NULL) {
        log_err("error: template is null");
        return 1;
    }

    /* Save pointer to new_template field memory */
    new_fields = new_template->fields;

    /* Replace memcpy with field assignment */
    new_template->hdr = src_template->hdr;
    new_template->fields = src_template->fields;
    new_template->type = src_template->type;
    new_template->last_sent = src_template->last_sent;
    new_template->length = src_template->length;
    new_template->next = src_template->next;
    new_template->prev = src_template->prev;

    /* Reattach new_fields */
    new_template->fields = new_fields;

    /* New template is a copy, so it isn't part of the store */
    new_template->next = NULL;
    new_template->prev = NULL;

    /* Copy the fields data */
    if (src_template->fields && new_template->fields) {
           for (ct=0; ct<field_count; ct++) {
              new_template->fields[ct].info_elem_id = src_template->fields[ct].info_elem_id;
              new_template->fields[ct].fixed_length = src_template->fields[ct].fixed_length;
              new_template->fields[ct].enterprise_num = src_template->fields[ct].enterprise_num;
          }
    }

    /* Assign dest_template handle to newly allocated template */
    *dest_template = new_template;

    return 0;
}


/*
 * @brief Search the IPFIX exporter template store (xts) for a match.
 *
 * Using the \p type of the template, search through the store list
 * to find whether an identical template exists in the store
 * already.
 *
 * @param type IPFIX exporter template type that will be searched for.
 * @param dest_template IPFIX exporter template that will have match contents
 *                      copied into.
 *
 * @return 1 for match, 0 for not match
 */
static ipfix_exporter_template_t *ipfix_xts_search(ipfix_template_type_e type,
                                    ipfix_exporter_template_t **dest_template) {
    log_debug("Searching template in exporter template store");
    ipfix_exporter_template_t *cur_template = NULL;

    if (export_template_store_head == NULL) {
        return NULL;
    }

    cur_template = export_template_store_head;

    while (cur_template) {
        if (cur_template->type == type) {
            /* Found match */
            if (dest_template != NULL) {
                ipfix_xts_copy(dest_template, cur_template);
            }
            return cur_template;
        }
        cur_template = cur_template->next;
    }

    return NULL;
}


/*
 * @brief Free all templates that exist in the exporter template store (xts).
 *
 * Any ipfix_exporter_template structures that currently remain within the XTS will
 * be zeroized and have their heap memory freed.
 */
void ipfix_xts_cleanup(void) {
    log_debug("Free all templates that exist in the exporter template store");
    ipfix_exporter_template_t *this_template;
    ipfix_exporter_template_t *next_template;

    if (export_template_store_head == NULL) {
        return;
    }

    pthread_mutex_lock(&export_lock);
    this_template = export_template_store_head;
    next_template = this_template->next;

    /* Free the first stored template */
    ipfix_delete_exp_template(this_template);

    while (next_template) {
        /* Free any remainders */
        this_template = next_template;
        next_template = this_template->next;

        ipfix_delete_exp_template(this_template);
    }
    pthread_mutex_unlock(&export_lock);
}


/////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Template Set
/////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX template set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the necessary set id and length.
 *
 * @param set Pointer to an ipfix_exporter_template_set_t in memory.
 */
static void ipfix_exp_template_set_init(ipfix_exporter_template_set_t *set) {
    log_debug("Initialize an IPFIX template set");
    if (set == NULL) {
        log_err("api-error: set is null");
        return;
    }

    memset(set, 0, sizeof(ipfix_exporter_template_set_t));
    set->set_hdr.set_id = IPFIX_TEMPLATE_SET;
    set->set_hdr.length = 4; /* size of the header */
}


/*
 * @brief Allocate heap memory for a template set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the necessary set id and length.
 *
 * @return An allocated IPFIX template set, or NULL
 */
static ipfix_exporter_template_set_t *ipfix_exp_template_set_malloc(void) {
    log_debug("Allocating heap memory for a template set");
    ipfix_exporter_template_set_t *template_set = NULL;

    template_set = calloc(1, sizeof(ipfix_exporter_template_set_t));

    if (template_set != NULL) {
    ipfix_exp_template_set_init(template_set);
    } else {
        log_err("error: template set malloc failed");
    }

    return template_set;
}


/*
 * @brief Append to the list of templates attached to the set.
 *
 * The \p set contains the head/tail of a list of related templates.
 * Here, \p template will be added to that list.
 *
 * @param set Pointer to an ipfix_exporter_template_set_t in memory.
 * @param template IPFIX exporter template that will be appended.
 */
static void ipfix_exp_template_set_add(ipfix_exporter_template_set_t *set,
                                       ipfix_exporter_template_t *template) {

    log_debug("Appending template to the list of templates attached to the set");
    /*
     * Add the template to the list attached to set.
     */
    if (set->records_head == NULL) {
        /* This is the first template in set list*/
        set->records_head = template;
    } else {
        /* Append to the end of set list */
        set->records_tail->next = template;
        template->prev = set->records_tail;
    }
    /* Update the tail */
    set->records_tail = template;

    /* Update the set length with total size of template */
    set->set_hdr.length += template->length;
    if (set->parent_message) {
        /*
         * The template set has already been attached to a message,
         * so update the length of that as well.
         */
        set->parent_message->hdr.length += template->length;
    }
}


/*
 * @brief Cleanup a template set by freeing any allocated memory that's been attached.
 *
 * A template \p set contains a list of templates that have been allocated on
 * the heap. This function takes care of freeing up that list.
 *
 * @param set Pointer to an ipfix_exporter_template_set_t in memory.
 */
static void ipfix_exp_template_set_cleanup(ipfix_exporter_template_set_t *set) {
    log_debug("Cleanup list of templates in a template set");
    ipfix_exporter_template_t *this_template;
    ipfix_exporter_template_t *next_template;

    if (set->records_head == NULL) {
        return;
    }

    this_template = set->records_head;
    next_template = this_template->next;

    /* Free the first stored template */
    ipfix_delete_exp_template(this_template);

    while (next_template) {
        this_template = next_template;
        next_template = this_template->next;

        ipfix_delete_exp_template(this_template);
    }
}


/*
 * @brief Free an allocated template set.
 *
 * First free the any attached memory to the template \p set.
 * Then free the template \p set itself.
 *
 * @param set Pointer to an ipfix_exporter_template_set_t in memory.
 */
static void ipfix_delete_exp_template_set(ipfix_exporter_template_set_t *set) {
    log_debug("Cleanup a template set");
    if (set == NULL) {
        return;
    }

    ipfix_exp_template_set_cleanup(set);

    memset(set, 0, sizeof(ipfix_exporter_template_set_t));
    free(set);
    set = NULL;
}


/////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Data Set
/////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX data set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the associated template and initial length.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 */
static void ipfix_exp_data_set_init(ipfix_exporter_data_set_t *set,
                                    uint16_t rel_template_id) {
    log_debug("Initialize an IPFIX data set");
    if (set == NULL) {
        log_err("api-error: set is null");
        return;
    }

    memset(set, 0, sizeof(ipfix_exporter_data_set_t));
    set->set_hdr.set_id = rel_template_id;
    set->set_hdr.length = 4; /* size of the header */
}


/*
 * @brief Allocate heap memory for a data set.
 *
 * Taking \p set as input, zeroize the set and then
 * add the necessary set id and length.
 *
 * @param rel_template_id The associated template id that collector
 *                        uses to interpret the data set.
 *
 * @return An allocated IPFIX data set, or NULL
 */
static ipfix_exporter_data_set_t *ipfix_exp_data_set_malloc(uint16_t rel_template_id) {
    log_debug("Allocating memory for a data set");
    ipfix_exporter_data_set_t *data_set = NULL;

    data_set = calloc(1, sizeof(ipfix_exporter_data_set_t));

    if (data_set != NULL) {
        ipfix_exp_data_set_init(data_set, rel_template_id);
    } else {
        log_err("error: data set malloc failed");
    }

    return data_set;
}


/*
 * @brief Append to the list of data records attached to the set.
 *
 * The \p set contains the head/tail of a list of related data_record.
 * Here, \p data_record will be added to that list.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 * @param data_record IPFIX exporter data record that will be appended.
 */
static void ipfix_exp_data_set_add(ipfix_exporter_data_set_t *set,
                                   ipfix_exporter_data_t *data_record) {

    log_debug("Appending data record to the list of data records attached to the set");
    /*
     * Add the template to the list attached to set.
     */
    if (set->records_head == NULL) {
        /* This is the first data record in set list*/
        set->records_head = data_record;
    } else {
        /* Append to the end of set list */
        set->records_tail->next = data_record;
        data_record->prev = set->records_tail;
    }

    /* Update the tail */
    set->records_tail = data_record;

    /* Update the set length with total size of data record */
    set->set_hdr.length += data_record->length;


    if (set->parent_message) {
        /*
         * The data set has already been attached to a message,
         * so update the length of that as well.
         */
        set->parent_message->hdr.length += data_record->length;
    }
}


/*
 * @brief Cleanup a data set by freeing any allocated memory that's been attached.
 *
 * A data \p set contains a list of data records that have been allocated on
 * the heap. This function takes care of freeing up that list.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 */
static void ipfix_exp_data_set_cleanup(ipfix_exporter_data_set_t *set) {
    log_debug("Cleanup list of data records in a dat set");
    ipfix_exporter_data_t *this_data_record;
    ipfix_exporter_data_t *next_data_record;

    if (set->records_head == NULL) {
        return;
    }

    this_data_record = set->records_head;
    next_data_record = this_data_record->next;

    /* Free the first data record */
    ipfix_delete_exp_data_record(this_data_record);

    while (next_data_record) {
        this_data_record = next_data_record;
        next_data_record = this_data_record->next;

        ipfix_delete_exp_data_record(this_data_record);
    }

}


/*
 * @brief Free an allocated data set.
 *
 * First free the any attached memory to the data \p set.
 * Then free the data \p set itself.
 *
 * @param set Pointer to an ipfix_exporter_data_set in memory.
 */
static void ipfix_delete_exp_data_set(ipfix_exporter_data_set_t *set) {
    log_debug("Cleanup a dat set");
    if (set == NULL) {
        return;
    }
    ipfix_exp_data_set_cleanup(set);

    memset(set, 0, sizeof(ipfix_exporter_data_set_t));
    free(set);
    set = NULL;
}


////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Set Node
////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX set node.
 *
 * The set \p node will have it's memory zeroized, and then a set
 * will be allocated and attached to the \p node.
 *
 * WARNING: The \p node must be cleaned up before process exit
 * because of the downstream allocated memory.
 *
 * @param node Pointer to an ipfix_exporter_set_node in memory.
 * @param set_id set_id 2 for template set, 3 for option set, >= 256 for data set,
 *        otherwise invalid
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_set_node_init(ipfix_exporter_set_node_t *node,
                                   uint16_t set_id) {
    log_debug("Initialize an IPFIX set node");
    ipfix_exporter_template_set_t *template_set = NULL;
    ipfix_exporter_option_set_t *option_set = NULL;
    ipfix_exporter_data_set_t *data_set = NULL;

    if (node == NULL) {
        log_err("api-error: set is null");
        return 1;
    }

    memset(node, 0, sizeof(ipfix_exporter_set_node_t));

    if (set_id == IPFIX_TEMPLATE_SET) {
        /* Create and attach a template set */
        template_set = ipfix_exp_template_set_malloc();
        node->set.template_set = template_set;
    } else if (set_id == IPFIX_OPTION_SET) {
        /* Create and attached an option set */
        option_set = calloc(1, sizeof(ipfix_exporter_option_set_t));
        node->set.option_set = option_set;
    } else if (set_id >= 256) {
        /* Create and attach a data set */
        data_set = ipfix_exp_data_set_malloc(set_id);
        node->set.data_set = data_set;
    } else {
        log_err("api-error: invalid set_id");
        return 1;
    }

    node->set_type = set_id;

    return 0;
}


/*
 * @brief Allocate heap memory for a set node.
 *
 * The set node is used as a container to encapsulate any 1 of the valid IPFIX set
 * types, i.e. template set, option set, or data set. Use \p set_id as an indicator
 * for which type of IPFIX set should be allocated and attached to the new set node
 * container.
 *
 * @param set_id 2 for template set, 3 for option set, >= 256 for data set,
 *        otherwise invalid
 *
 * @return An allocated set node container
 */
static ipfix_exporter_set_node_t *ipfix_exp_set_node_malloc(uint16_t set_id) {
    ipfix_exporter_set_node_t *node = NULL;

    node = calloc(1, sizeof(ipfix_exporter_set_node_t));

    if (node != NULL) {
        if (ipfix_exp_set_node_init(node, set_id)) {
            log_err("error: could not init the set_node");
        }
    } else {
        log_err("error: set_node malloc failed");
    }

    return node;
}


/*
 * @brief Cleanup a set node by freeing any allocated memory that's been attached.
 *
 * A set \p node contains an attached IPFIX set that exists on the heap.
 * This function takes care of freeing up that set and any other necessary cleanup
 * steps.
 *
 * @param set Pointer to an ipfix_exporter_set_node in memory.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_set_node_cleanup(ipfix_exporter_set_node_t *node) {
    log_debug("Cleanup a set node");
    uint16_t set_type = 0;

    if (node == NULL) {
        log_err("api-error: node is null");
        return 1;
    }
    set_type = node->set_type;

    if (set_type == IPFIX_TEMPLATE_SET) {
        /* Cleanup and delete the template set */
        ipfix_delete_exp_template_set(node->set.template_set);
    } else if (set_type == IPFIX_OPTION_SET) {
        /* Cleanup and delete the option set */
        free(node->set.option_set);
        node->set.option_set = NULL;
    } else if (set_type >= 256) {
        /* Cleanup and delete the data set */
        ipfix_delete_exp_data_set(node->set.data_set);
    } else {
        log_err("error: invalid set type");
        return 1;
    }

    return 0;
}


/*
 * @brief Free an allocated set node.
 *
 * First free the any attached memory to the set \p node.
 * Then free the set \p node itself.
 *
 * @param set Pointer to an ipfix_exporter_set_node in memory.
 */
static void ipfix_delete_exp_set_node(ipfix_exporter_set_node_t *node) {
    if (node == NULL) {
        log_warn("warning: node parameter is null");
        return;
    }

    ipfix_exp_set_node_cleanup(node);

    memset(node, 0, sizeof(ipfix_exporter_set_node_t));
    free(node);
    node = NULL;
}


////////////////////////////////////////////////////////////////////
// MEMORY MODEL: Exporter Message
////////////////////////////////////////////////////////////////////

/*
 * @brief Initialize an IPFIX message.
 *
 * @param set Pointer to an ipfix_exporter_template_set_t in memory.
 * @param template IPFIX exporter template that will be appended.
 */
static void ipfix_exp_message_init(ipfix_message_t *message) {
    log_debug("Initializing an IPFIX message");
    memset(message, 0, sizeof(ipfix_message_t));

    /* IPFIX version = 10 */
    message->hdr.version_number = htons(10);
    /* Must be converted to network-byte order before message send */
    message->hdr.length = 16;
    /* Set the observation domain id */
    message->hdr.observe_dom_id = htonl(exporter_obs_dom_id);
}


/*
 * @brief Allocate heap memory for an IPFIX message.
 *
 * @return An allocated IPFIX message, or NULL
 */
static ipfix_message_t *ipfix_exp_message_malloc(void) {
    log_debug("Initializing an IPFIX message");
    export_message = NULL;

    export_message = calloc(1, sizeof(ipfix_message_t));

    if (export_message != NULL) {
        ipfix_exp_message_init(export_message);
    } else {
        log_err("error: data set malloc failed");
    }
    return export_message;
}


/*
 * @brief Find the an IPFIX template set in a message.
 *
 * Look for a valid template set which is attached to the \p message.
 * It is not necessary to provide a set id, because templates sets
 * will always have a set id equal to 2.
 *
 * @param message Pointer to an ipfix_message in memory.
 *
 * @return The desired data set, or NULL
 */
static ipfix_exporter_template_set_t *ipfix_exp_message_find_template_set(ipfix_message_t *message)
{
    log_debug("Finding an IPFIX template set in a message");
    ipfix_exporter_set_node_t *set_node = NULL;
    ipfix_exporter_template_set_t *template_set = NULL;
    uint16_t set_id = 2;

    if (message->sets_head == NULL) {
        return NULL;
    }

    set_node = message->sets_head;
    if (set_node->set_type == set_id) {
        template_set = set_node->set.template_set;
        /* Found match */
        if (template_set != NULL) {
            return template_set;
        }
    }

    while (set_node->next) {
        set_node = set_node->next;
        if (set_node->set_type == set_id) {
            template_set = set_node->set.template_set;
            /* Found match */
            if (template_set != NULL) {
                return template_set;
            }
        }
    }

    return NULL;
}


/*
 * @brief Find the requested IPFIX data set in a message.
 *
 * Look for a data set which matches the \p set_id and which
 * is attached to the \p message.
 *
 * @param message Pointer to an ipfix_message in memory.
 * @param set_id The set id of the data set, used to identify it.
 *
 * @return The desired data set, or NULL
 */
static ipfix_exporter_data_set_t *ipfix_exp_message_find_data_set(ipfix_message_t *message,
                                                                  uint16_t set_id) {
    log_debug("Finding an IPFIX data set in a message");
    ipfix_exporter_set_node_t *set_node = NULL;
    ipfix_exporter_data_set_t *data_set = NULL;

    if (message->sets_head == NULL) {
        return NULL;
    }
    set_node = message->sets_head;
    if (set_node->set_type == set_id) {
        data_set = set_node->set.data_set;
        /* Found match */
        if (data_set != NULL) {
            return data_set;
        }
    }

    while (set_node->next) {
        set_node = set_node->next;
        if (set_node->set_type == set_id) {
            data_set = set_node->set.data_set;
            /* Found match */
            if (data_set != NULL) {
                return data_set;
            }
        }
    }
    return NULL;
}


/*
 * @brief Add to the list of set nodes attached to the IPFIX message.
 *
 * The \p message contains the head/tail of a list of related set_nodes.
 * Here \p node will be added to that list.
 *
 * @param message Pointer to an ipfix_message in memory.
 * @param node IPFIX exporter set node that will be appended.
 *
 * return 0 for success, 1 for failure, 2 if message full
 */
static int ipfix_exp_message_add(ipfix_message_t *message,
                                 ipfix_exporter_set_node_t *node) {
    log_debug("Adding node to the list of set nodes attached to the IPFIX message");
    uint16_t set_type = 0;

    if (message == NULL) {
        log_err("api-error: message is null");
        return 1;
    }

    if (node == NULL) {
        log_err("api-error: node is null");
        return 1;
    }

    /*
     * Get the set type
     */
    set_type = node->set_type;

    if (set_type == IPFIX_TEMPLATE_SET) {
        /* Add the template set length */
        if (message->hdr.length + node->set.template_set->set_hdr.length > IPFIX_MTU) {
            log_debug("info: message is full in IPFIX_TEMPLATE_SET , please attach to another message ");
            return 2;
        }
        node->set.template_set->parent_message = message;
        message->hdr.length += node->set.template_set->set_hdr.length;
    } else if (set_type == IPFIX_OPTION_SET) {
        /* Add the option set length */
        if (message->hdr.length + node->set.template_set->set_hdr.length > IPFIX_MTU) {
            log_debug("info: message is full in IPFIX_OPTION_SET, please attach to another message ");
            return 2;
        }
        // TODO add parent message here for option set
        message->hdr.length += node->set.option_set->set_hdr.length;
    } else if (set_type >= 256) {
        /* Add the data set length */
        if (message->hdr.length + node->set.template_set->set_hdr.length > IPFIX_MTU) {
            log_debug("info: message is full in set_type >= 256 , please attach to another message ");
            return 2;
        }
        node->set.data_set->parent_message = message;
        message->hdr.length += node->set.data_set->set_hdr.length;
    } else {
        log_err("error: invalid set type");
        return 1;
    }

    /*
     * Add the template to the list attached to set.
     */
    if (message->sets_head == NULL) {
        /* This is the first template in set list*/
        message->sets_head = node;
    } else {
        /* Append to the end of set list */
        message->sets_tail->next = node;
        node->prev = message->sets_tail;
    }

    /* Update the tail */
    message->sets_tail = node;

    return 0;
}


/*
 * @brief Cleanup an IPFIX message by freeing any allocated memory that's been attached.
 *
 * A \p message contains a list of set nodes that have been allocated on
 * the heap. This function takes care of freeing up that list.
 *
 * @param set Pointer to an ipfix_message in memory.
 */
static void ipfix_exp_message_cleanup(ipfix_message_t *message) {
    log_debug("Adding node to the list of set nodes attached to the IPFIX message");
    ipfix_exporter_set_node_t *this_set_node;
    ipfix_exporter_set_node_t *next_set_node;

    if (message->sets_head == NULL) {
        return;
    }

    this_set_node = message->sets_head;
    next_set_node = this_set_node->next;

    /* Free the first set node */
    ipfix_delete_exp_set_node(this_set_node);

    while (next_set_node) {
        this_set_node = next_set_node;
        next_set_node = this_set_node->next;

        ipfix_delete_exp_set_node(this_set_node);
    }
}


/*
 * @brief Free an allocated IPFIX message.
 *
 * First free the any attached memory to the \p message.
 * Then free the \p message itself.
 *
 * @param set Pointer to an ipfix_message in memory.
 */
static void ipfix_delete_exp_message(void) {
    log_debug("Deleting memory for an IPFIX message");

    if (export_message == NULL) {
        return;
    }

    ipfix_exp_message_cleanup(export_message);

    memset(export_message, 0, sizeof(ipfix_message_t));
    free(export_message);
    export_message = NULL;
}

void generate_obs_domainid() {
    log_debug("Generating Observation domain id");
    char *ip_addr;
    char host[256];
    int i;
    struct hostent *host_entry;
    gethostname(host, sizeof(host)); //find the host name
    host_entry = gethostbyname(host); //find host information

    /* Host address list will never be empty for a valid IPFIX exporter */
    for(i=0; host_entry->h_addr_list[i]; i++) {
        ip_addr = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[i]));
        exporter_obs_dom_id = inet_addr(ip_addr);
        /* Check for eleminate loopback */
	if(strcmp(ip_addr , "127.0.0.01") != 0) {
	    exporter_obs_dom_id = inet_addr(ip_addr);
	    return;
	}
   }
}

/*
 * @brief Initialize an IPFIX exporter object.
 *
 * Startup an exporter object that keeps track of the number
 * of messages sent, and configures it with a transport socket
 * for sending messages. If \p host_name is NULL, the localhost
 * is used as the server (collector) target.
 *
 * @param host_name Host name of the server, a.k.a collector.
 */
int ipfix_exporter_init(const char *host_name, int remote_port, int local_port) {
    log_debug("Initializing an IPFIX exporter object");
    char host_desc[HOST_NAME_MAX_SIZE];
    unsigned long localhost = 0;
    //int remote_port = 0;
    ipfix_exporter_t *e = &gateway_export;

    memset(e, 0, sizeof(ipfix_exporter_t));

    if (host_name != NULL) {
        strncpy(host_desc, host_name, sizeof(host_desc));
        host_desc[HOST_NAME_MAX_SIZE-1] = '\0' ;
    }
    e->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (e->socket < 0) {
        log_err("error: cannot create socket");
        return 1;
    }

    /* Set local (exporter) address */
    e->exprt_addr.sin_family = AF_INET;
    e->exprt_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    e->exprt_addr.sin_port = htons(local_port);
    if (bind(e->socket, (struct sockaddr *)&e->exprt_addr,
             sizeof(e->exprt_addr)) < 0) {
        log_err("error: bind address failed");
        return 1;
    }

    /* Set remote (collector) address */
    e->clctr_addr.sin_family = AF_INET;
    if (remote_port != 0) {
        e->clctr_addr.sin_port = htons(remote_port);
    } else {
        remote_port = IPFIX_COLLECTOR_DEFAULT_PORT;
        e->clctr_addr.sin_port = htons(remote_port);
    }

    localhost = inet_addr(host_desc);
    e->clctr_addr.sin_addr.s_addr = localhost;

    /* Generate the global observation domain id if not done already */
    if (!exporter_obs_dom_id) {
	generate_obs_domainid();
    }

    log_info("IPFIX exporter configured... ");
    log_info("Observation Domain ID: %u ", exporter_obs_dom_id);
    log_info("Host Port: %u ", ipfix_export_port);
    log_info("Remote IP Address: %s ", host_desc);
    log_info("Remote Port: %u ", remote_port);
    log_info("Ready!");

    return 0;
}

static unsigned int convert_to_millisecs(const unsigned long time_value)
{
    unsigned long time_in_mills = (time_value/MICROSEC) ;
    if (time_value % MICROSEC > 500000)
       time_in_mills++;
    return time_in_mills;
}
/*
 * @brief Create a simple data record.
 *
 * Make a basic data record that holds the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 * The new data record will use the \p flow_record to encode the appropriate
 * information according to the IPFIX specification.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @param fr_record flow record created during the metric observation
 *                  phase of the process, i.e. process_flow_record_map(). It contains
 *                  information that will be encoded into the new data record.
 *
 * @return The desired data record, otherwise NULL for failure.
 */
static ipfix_exporter_data_t *ipfix_exp_create_simple_data_record (const flow_record_t *fr_record)
{
    log_debug("Creating a TCP data record");
    ipfix_exporter_data_t *data_record = NULL;
    uint8_t protocol = 0;
    uint8_t direction = 0;
    uint8_t type_of_service = 0;
    uint8_t dscp = 0;
    data_record = ipfix_exp_data_record_malloc();
    uint8_t min_ttl = 0;
    uint8_t max_ttl = 0;
    //unsigned char *app_name = NULL;

    if (data_record != NULL) {
        /*
         * Assign the data fields
         */
        /* IPFIX_SOURCE_IPV4_ADDRESS */
        data_record->record.simple.source_ipv4_address = fr_record->key.sa;

        /* IPFIX_DESTINATION_IPV4_ADDRESS */
        data_record->record.simple.destination_ipv4_address = fr_record->key.da;

        /* IPFIX_SOURCE_TRANSPORT_PORT */
        data_record->record.simple.source_transport_port = fr_record->key.sp;

        /* IPFIX_DESTINATION_TRANSPORT_PORT */
        data_record->record.simple.destination_transport_port = fr_record->key.dp;

        /* IPFIX_DELTA_PACKET_COUNT */
        data_record->record.simple.no_of_packets = fr_record->np;

        /* IPFIX_OCTET_COUNT */
        data_record->record.simple.no_of_bytes = fr_record->nb;

        /* IPFIX_PROTOCOL_IDENTIFIER */
        protocol = (uint8_t)(fr_record->key.prot & 0xff);
        data_record->record.simple.protocol_identifier = protocol;

        /* IPFIX_FLOW_DIRECTION */
        direction = (uint8_t)(fr_record->dir & 0xff);
        data_record->record.simple.dir = direction;

        /* IPFIX_TCP_FLAGS */
        data_record->record.simple.control_bit = (uint16_t)(fr_record->tcp_control_bits);

        /* IPFIX_TYPE_OF_SERVICE */
        type_of_service = (uint8_t)(fr_record->tos & 0xff);
        data_record->record.simple.tos = type_of_service;

        /* IPFIX_INGRESS_IFINDEX and IPFIX_EGRESS_IFINDEX*/
	if(data_record->record.simple.dir == INGRESS){
           data_record->record.simple.ifindex = fr_record->ingress_ifindex;;
        }
	else if (data_record->record.simple.dir == EGRESS){
           data_record->record.simple.ifindex = 0;
        }

        /* IPFIX_MINIMUM_TTL */
        min_ttl = (uint8_t)(fr_record->min_ttl & 0xff);
        data_record->record.simple.min_ttl = min_ttl;

        /* IPFIX_MAXIMUM_TTL */
        max_ttl = (uint8_t)(fr_record->max_ttl & 0xff);
        data_record->record.simple.max_ttl = max_ttl;

        /* IPFIX_FLOW_START_SYS_UP_TIME */
        data_record->record.simple.flow_start_sys_up_time = convert_to_millisecs(fr_record->flow_start);

        /* IPFIX_FLOW_END_SYS_UP_TIME */
        data_record->record.simple.flow_end_sys_up_time = convert_to_millisecs(fr_record->flow_end);

        /* IPFIX_FLOW_ID */
        data_record->record.simple.flow_id = fr_record->flow_id;

        /* IPFIX_DSCP*/
        dscp = (uint8_t)((fr_record->tos >> 2) & 0xff);
        data_record->record.simple.dscp = dscp;
        /* Set the type of template for identification */
        if(fr_record->dir == INGRESS) {
     	    data_record->type = IPFIX_SIMPLE_INGRESS_TEMPLATE;
	} else if(fr_record->dir == EGRESS) {
     	    data_record->type = IPFIX_SIMPLE_EGRESS_TEMPLATE;
        }
        /* Set the length (number of bytes) of the data record */
        data_record->length = SIZE_IPFIX_DATA_SIMPLE ;
    } else {
        log_info("error: unable to malloc data record");
    }

    return data_record;
}

/*
 * @brief Create a simple icmp data record.
 *
 * Make a basic data record that holds the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 * The new data record will use the \p flow_record to encode the appropriate
 * information according to the IPFIX specification.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @param fr_record flow record created during the metric observation
 *                  phase of the process. It contains
 *                  information that will be encoded into the new data record.
 *
 * @return The desired data record, otherwise NULL for failure.
 */
static ipfix_exporter_data_t *ipfix_exp_create_icmp_data_record (const flow_record_t *fr_record)
{
    log_debug("Creating an ICMP data record");
    ipfix_exporter_data_t *data_record = NULL;
    uint8_t protocol = 0;
    uint8_t direction = 0;
    uint8_t type_of_service = 0;
    uint8_t icmp_type = 0;
    uint8_t min_ttl = 0;
    uint8_t max_ttl = 0;
    uint8_t dscp = 0;

    data_record = ipfix_exp_data_record_malloc();

    if (data_record != NULL) {
        /*
         * Assign the data fields
         */
        /* IPFIX_SOURCE_IPV4_ADDRESS */
        data_record->record.icmp.source_ipv4_address = fr_record->key.sa;

        /* IPFIX_DESTINATION_IPV4_ADDRESS */
        data_record->record.icmp.destination_ipv4_address = fr_record->key.da;

        /* IPFIX_SOURCE_TRANSPORT_PORT */
        data_record->record.icmp.source_transport_port = fr_record->key.sp;

        /* IPFIX_DESTINATION_TRANSPORT_PORT */
        data_record->record.icmp.destination_transport_port = fr_record->key.dp;

        /* IPFIX_DELTA_PACKET_COUNT */
        data_record->record.icmp.no_of_packets = fr_record->np;

        /* IPFIX_OCTET_COUNT */
        data_record->record.icmp.no_of_bytes = fr_record->nb;

        /* IPFIX_PROTOCOL_IDENTIFIER */
        protocol = (uint8_t)(fr_record->key.prot & 0xff);
        data_record->record.icmp.protocol_identifier = protocol;

        /* IPFIX_FLOW_DIRECTION */
        direction = (uint8_t)(fr_record->dir & 0xff);
        data_record->record.icmp.dir = direction;

        /* IPFIX_TYPE_OF_SERVICE */
        type_of_service = (uint8_t)(fr_record->tos & 0xff);
        data_record->record.icmp.tos = type_of_service;

        /* IPFIX_TYPE_OF_SERVICE */
        icmp_type = (uint16_t)(fr_record->icmp_type & 0xfff);
        data_record->record.icmp.icmp_type = icmp_type;

        /* IPFIX_INGRESS_IFACE OR IPFIX_EGRESS_IFACE */
	if(data_record->record.icmp.dir == INGRESS){
            data_record->record.icmp.ifindex = fr_record->ingress_ifindex;;
        } else if (data_record->record.icmp.dir == EGRESS){
            data_record->record.icmp.ifindex = 0;
	}

        /* IPFIX_MINIMUM_TTL */
        min_ttl = (uint8_t)(fr_record->min_ttl & 0xff);
        data_record->record.icmp.min_ttl = min_ttl;

        /* IPFIX_MAXIMUM_TTL */
        max_ttl = (uint8_t)(fr_record->max_ttl & 0xff);
        data_record->record.icmp.max_ttl = max_ttl;

        /* IPFIX_FLOW_START_SYS_UP_TIME */
        data_record->record.icmp.flow_start_sys_up_time = convert_to_millisecs(fr_record->flow_start);

        /* IPFIX_FLOW_END_SYS_UP_TIME */
        data_record->record.icmp.flow_end_sys_up_time = convert_to_millisecs(fr_record->flow_end);

        /* IPFIX_FLOW_ID */
        data_record->record.icmp.flow_id = fr_record->flow_id;

        /* IPFIX_DSCP*/
        dscp = (uint8_t)((fr_record->tos >> 2) & 0xff);
        data_record->record.icmp.dscp = dscp;

        /* Set the type of template for identification */
	if(fr_record->dir == INGRESS) {
            data_record->type = IPFIX_ICMP_INGRESS_TEMPLATE;
        } else if (fr_record->dir == EGRESS) {
            data_record->type = IPFIX_ICMP_EGRESS_TEMPLATE;
	}
	/* Set the length (number of bytes) of the data record */
        data_record->length = SIZE_IPFIX_DATA_ICMP;
    } else {
        log_err("error: unable to malloc data record");
    }

    return data_record;
}

/*
 * @brief Create a data record, given a valid type.
 *
 * Create a new data record on the heap according to the
 * \p template_type. If the template type is not supported then
 * an error is logged and no data record is made because
 * all data records must have a related template in order to
 * be successfully interpreted.
 *
 * WARNING: The end user of the newly allocated data record is
 * responsible for freeing that memory.
 *
 * @param template_type A valid entry from the enum ipfix_template_type list.
 * @param fr_record  flow record created during the metric observation
 *                  phase of the process. It contains
 *                  information that will be encoded into the new data record.
 *
 * @return The desired data record, otherwise NULL for failure.
 */
static ipfix_exporter_data_t *ipfix_exp_create_data_record (ipfix_template_type_e template_type,
                                                            const flow_record_t *fr_record) {

    log_debug("Creating data record of tyes %d", template_type);
    ipfix_exporter_data_t *data_record = NULL;

    switch (template_type) {
    case IPFIX_SIMPLE_INGRESS_TEMPLATE:
    case IPFIX_SIMPLE_EGRESS_TEMPLATE:
        data_record = ipfix_exp_create_simple_data_record(fr_record);
        break;

    case IPFIX_ICMP_INGRESS_TEMPLATE:
    case IPFIX_ICMP_EGRESS_TEMPLATE:
        data_record = ipfix_exp_create_icmp_data_record(fr_record);
        break;
    default:
        log_err("api-error: template type is not supported");
        break;
    }

    if (data_record == NULL) {
        log_err("error: unable to create data record");
    }
    return data_record;
}


static void ipfix_exp_template_add_field(ipfix_exporter_template_t *t,
                                         ipfix_exporter_template_field_t f) {
    t->fields[t->hdr.field_count] = f;
    t->hdr.field_count++;
    t->length += 4;
}


/*
 * @brief Create a simple 5-tuple template.
 *
 * Make a basic template that represents the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @return The desired template, otherwise NULL for failure.
 */
static ipfix_exporter_template_t *ipfix_exp_create_simple_template(int dir) {
    log_debug("Creating TCP template");
    ipfix_exporter_template_t *template = NULL;
    uint16_t num_fields = 17;

    template = ipfix_exp_template_malloc(num_fields);

    if (template != NULL) {
        /* Add the fields */
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_OCTET_DELTA_COUNT, 8));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_PACKET_DELTA_COUNT, 8));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_PROTOCOL_IDENTIFIER, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_SOURCE_IPV4_ADDRESS, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_DESTINATION_IPV4_ADDRESS, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_SOURCE_TRANSPORT_PORT, 2));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_DESTINATION_TRANSPORT_PORT, 2));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_FLOW_DIRECTION, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_TCP_CONTROL_BITS, 2));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_IP_CLASS_OF_SERVICE, 1));
	if(dir == INGRESS)
             ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_INGRESS_INTERFACE, 4));
	else
             ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_EGRESS_INTERFACE, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_MINIMUM_TTL, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_MAXIMUM_TTL, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_START_SYS_UP_TIME, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_END_SYS_UP_TIME, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_ID, 8));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_IP_DSCP, 1));
        /* Set the type of template for identification */
	if(dir == INGRESS){
            template->type = IPFIX_SIMPLE_INGRESS_TEMPLATE;
	} else if(dir == EGRESS) {
            template->type = IPFIX_SIMPLE_EGRESS_TEMPLATE;
        }
    } else {
        log_err("error: template is null");
    }

    return template;
}


/*
 * @brief Create a simple 5-tuple template.
 *
 * Make a basic template that represents the traditional 5-tuple
 * unique id. This consists of the source/destination ipv4 address,
 * source/destination transport port, and the transport protocol identifier.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @return The desired template, otherwise NULL for failure.
 */
static ipfix_exporter_template_t *ipfix_exp_create_icmp_template(int dir) {
    log_debug("Creating ICMP template");
    ipfix_exporter_template_t *template = NULL;
    uint16_t num_fields = 17;

    template = ipfix_exp_template_malloc(num_fields);

    if (template != NULL) {
        /* Add the fields */
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_OCTET_DELTA_COUNT, 8));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_PACKET_DELTA_COUNT, 8));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_PROTOCOL_IDENTIFIER, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_SOURCE_IPV4_ADDRESS, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_DESTINATION_IPV4_ADDRESS, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_SOURCE_TRANSPORT_PORT, 2));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_DESTINATION_TRANSPORT_PORT, 2));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_FLOW_DIRECTION, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_IP_CLASS_OF_SERVICE, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_ICMP_TYPE, 2));
	if(dir == INGRESS)
            ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_INGRESS_INTERFACE, 4));
        else if(dir == EGRESS)
            ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_EGRESS_INTERFACE, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_MINIMUM_TTL, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_MAXIMUM_TTL, 1));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_START_SYS_UP_TIME, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_END_SYS_UP_TIME, 4));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_FLOW_ID, 8));
        ipfix_exp_template_add_field(template,
                                     ipfix_exp_template_field_macro(IPFIX_IP_DSCP, 1));

	if(dir == INGRESS)
            template->type = IPFIX_ICMP_INGRESS_TEMPLATE;
	else
            template->type = IPFIX_ICMP_EGRESS_TEMPLATE;
    } else {
        log_err("error: template is null");
    }

    return template;
}


/*
 * @brief Create a template, given a valid type.
 *
 * Create a new template on the heap according to the
 * \p template_type. If the template type is not supported then
 * an error is logged and no template is made.
 *
 * WARNING: The end user of the newly allocated template is
 * responsible for freeing that memory.
 *
 * @param template_type A valid entry from the enum ipfix_template_type list.
 *
 * @return The desired template, otherwise NULL for failure.
 */
static ipfix_exporter_template_t *ipfix_exp_create_template
(ipfix_template_type_e template_type) {
    log_debug("Creating template of type %d", template_type);

    ipfix_exporter_template_t *template = NULL;
    switch (template_type) {
    case IPFIX_SIMPLE_INGRESS_TEMPLATE:
        template = ipfix_exp_create_simple_template(0);
        exporter_template_id = exporter_tcp_ingress_template_id;
        break;
    case IPFIX_SIMPLE_EGRESS_TEMPLATE:
        template = ipfix_exp_create_simple_template(1);
        exporter_template_id = exporter_tcp_egress_template_id;
        break;
    case IPFIX_ICMP_INGRESS_TEMPLATE:
        template = ipfix_exp_create_icmp_template(0);
        exporter_template_id = exporter_icmp_ingress_template_id;
        break;
    case IPFIX_ICMP_EGRESS_TEMPLATE:
        template = ipfix_exp_create_icmp_template(1);
        exporter_template_id = exporter_icmp_egress_template_id;
        break;

    default:
        log_err("api-error: template type is not supported");
        break;
    }

    if (template != NULL) {
        template->hdr.template_id = exporter_template_id;
        ipfix_xts_append(template);
    } else {
        log_err("error: unable to create template");
    }

    return template;
}


/*
 * @brief Encode a template set into an IPFIX message.
 *
 * Take a \p set of Ipfix templates, and encode the whole
 * \p set into a \p message_buf according RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 * A handle to \p msg_length is used, where the value represents
 * the total running length of the \p message. This is used by
 * calling functions to keep track of how much data has been
 * written into the \p message and for the \p message_buf write offset.
 *
 * @param set Single set of multiple Ipfix templates.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_template_set(ipfix_exporter_template_set_t *set,
                                         unsigned char *message_buf,
                                         uint16_t *msg_length) {
    log_debug("Encoding template set");

    ipfix_exporter_template_t *current = NULL;
    unsigned char *data_ptr = NULL;
    uint16_t bigend_set_id = 0;
    uint16_t bigend_set_len = 0;


    if (message_buf == NULL) {
        log_err("api-error: message_buf is null");
        return 1;
    }

    if (set == NULL) {
        log_err("api-error: set is null");
        return 1;
    }

    if (set->set_hdr.length > (IPFIX_MAX_SET_LEN - *msg_length)) {
        log_err("error: set is larger than remaining message buffer");
        return 1;
    }

    data_ptr = message_buf + *msg_length;

    bigend_set_id = htons(set->set_hdr.set_id);
    bigend_set_len = htons(set->set_hdr.length);

    /* Encode the set header into message */
    memcpy(data_ptr, (const void *)&bigend_set_id, 2);
    data_ptr += 2;
    *msg_length += 2;

    memcpy(data_ptr, (const void *)&bigend_set_len, 2);
    data_ptr += 2;
    *msg_length += 2;

    current = set->records_head;

    /* Encode the set templates into message */
    while (current != NULL) {
        int i = 0;
        uint16_t bigend_template_id = htons(current->hdr.template_id);
        uint16_t bigend_template_field_count = htons(current->hdr.field_count);

        /* Encode the template header into message */
        memcpy(data_ptr, (const void *)&bigend_template_id, 2);
        data_ptr += 2;
        *msg_length += 2;

        memcpy(data_ptr, (const void *)&bigend_template_field_count, 2);
        data_ptr += 2;
        *msg_length += 2;

        for (i = 0; i < current->hdr.field_count; i++) {
            uint16_t bigend_field_id = htons(current->fields[i].info_elem_id);
            uint16_t bigend_field_len = htons(current->fields[i].fixed_length);
            uint32_t bigend_ent_num = htonl(current->fields[i].enterprise_num);

            /* Encode the field element into message */
            memcpy(data_ptr, (const void *)&bigend_field_id, 2);
            data_ptr += 2;
            *msg_length += 2;

            memcpy(data_ptr, (const void *)&bigend_field_len, 2);
            data_ptr += 2;
            *msg_length += 2;

            /* Enterprise number */
            if (bigend_ent_num) {
                memcpy(data_ptr, (const void *)&bigend_ent_num, sizeof(uint32_t));
                data_ptr += sizeof(uint32_t);
                *msg_length += sizeof(uint32_t);
            }
        }

        current = current->next;
    }

    return 0;
}

/*
 * @brief Encode a simple 5-tuple data record into an IPFIX message.
 *
 * Using the \p data_record container, encode the attached fields
 * into the \p message buf according to the RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 *
 * @param data_record Single Ipfix data record.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_data_record_simple(ipfix_exporter_data_t *data_record,
                                               unsigned char *message_buf) {
    log_debug("Encoding TCP data record");
    unsigned char *ptr = NULL;

    uint16_t flags = 0;
    uint16_t bigend_src_port = 0, bigend_dest_port = 0;
    uint64_t flow_id = 0;
    uint32_t bigend_sys_end_time = 0, bigend_sys_start_time = 0;
    uint64_t number_of_pkts = 0, number_of_bytes = 0;
    uint32_t if_idx = 0;
    uint8_t min_ttl=0, max_ttl = 0;

    if (data_record == NULL) {
        log_err("api-error: data_record is null");
        return 1;
    }

    if (data_record->type == IPFIX_SIMPLE_INGRESS_TEMPLATE || data_record->type == IPFIX_SIMPLE_EGRESS_TEMPLATE) {
        log_debug("info: data record type simple");
    }
    else {
        log_err("api-error: wrong data record type");
        return 1;
    }
    /* Get starting position in target message buffer */
    ptr = message_buf;

    /* IPFIX_OCTET_COUNT */
    number_of_bytes =  ntoh64(data_record->record.simple.no_of_bytes);
    memcpy(ptr, &number_of_bytes, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    /* IPFIX_PACKET_COUNT */
    number_of_pkts =  ntoh64(data_record->record.simple.no_of_packets);
    memcpy(ptr, &number_of_pkts, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    /* IPFIX_PROTOCOL_IDENTIFIER */
    memcpy(ptr, &data_record->record.simple.protocol_identifier, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_SOURCE_IPV4_ADDRESS */
    memcpy(ptr, &data_record->record.simple.source_ipv4_address, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_DESTINATION_IPV4_ADDRESS */
    memcpy(ptr, &data_record->record.simple.destination_ipv4_address, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_SOURCE_TRANSPORT_PORT */
    bigend_src_port = htons(data_record->record.simple.source_transport_port);
    memcpy(ptr, &bigend_src_port, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* IPFIX_DESTINATION_TRANSPORT_PORT */
    bigend_dest_port = htons(data_record->record.simple.destination_transport_port);
    memcpy(ptr, &bigend_dest_port, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* IPFIX_FLOW_DIRECTION */
    memcpy(ptr, &data_record->record.simple.dir, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_TCP_CONTROL_BIT */
    flags = htons(data_record->record.simple.control_bit);
    memcpy(ptr, &flags, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* IPFIX_TYPE_OF_SERVICE */
    memcpy(ptr, &data_record->record.simple.tos, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_INGRESS_IFACE OR IPFIX_EGRESS_IFACE */
    if(data_record->record.simple.dir == INGRESS) {
        if_idx = htonl(data_record->record.simple.ifindex);
        memcpy(ptr, &if_idx, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
    } else if(data_record->record.simple.dir == EGRESS) {
        /* Ask from infosec as this way things slightly more easy to decipher on the Stealthwatch system.(Infosec) */
	if_idx = htonl(0);
        memcpy(ptr, &if_idx, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
    }

    /* IPFIX_MINIMUM_TTL */
    min_ttl = data_record->record.simple.min_ttl;
    memcpy(ptr, &min_ttl, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_MAXIMUM_TTL */
    max_ttl = data_record->record.simple.max_ttl;
    memcpy(ptr, &max_ttl, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_FLOW_START_MILLISECONDS */
    bigend_sys_start_time = htonl(data_record->record.simple.flow_start_sys_up_time);
    memcpy(ptr, &bigend_sys_start_time, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_FLOW_END_MILLISECONDS */
    bigend_sys_end_time = htonl(data_record->record.simple.flow_end_sys_up_time);
    memcpy(ptr, &bigend_sys_end_time, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_FLOW_ID */
    flow_id = hton64(data_record->record.simple.flow_id);
    memcpy(ptr, &flow_id, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    /* IPFIX_TYPE_OF_SERVICE */
    memcpy(ptr, &data_record->record.simple.dscp, sizeof(uint8_t));
    return 0;
}


/*
 * @brief Encode a simple 5-tuple data record into an IPFIX message.
 *
 * Using the \p data_record container, encode the attached fields
 * into the \p message buf according to the RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 *
 * @param data_record Single Ipfix data record.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_data_record_icmp(ipfix_exporter_data_t *data_record,
                                               unsigned char *message_buf) {

    log_debug("Encoding ICMP data record");
    unsigned char *ptr = NULL;

    uint16_t bigend_src_port = 0, bigend_dest_port = 0;
    uint64_t flow_id = 0;
    uint64_t number_of_pkts = 0, number_of_bytes = 0;
    uint32_t if_idx = 0;
    uint8_t min_ttl = 0, max_ttl = 0;
    uint32_t bigend_sys_start_time = 0, bigend_sys_end_time = 0;

    if (data_record == NULL) {
        log_err("api-error: data_record is null");
        return 1;
    }

    if (data_record->type == IPFIX_ICMP_INGRESS_TEMPLATE || data_record->type == IPFIX_ICMP_EGRESS_TEMPLATE) {
        log_debug("data record type is icmp");
    }
    else {
        log_err("api-error: wrong data record type");
        return 1;
    }
    /* Get starting position in target message buffer */
    ptr = message_buf;

    /* IPFIX_OCTET_count */
    number_of_bytes =  ntoh64(data_record->record.icmp.no_of_bytes);
    memcpy(ptr, &number_of_bytes, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    /* IPFIX_packet_count */
    number_of_pkts =  ntoh64(data_record->record.icmp.no_of_packets);
    memcpy(ptr, &number_of_pkts, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    /* IPFIX_PROTOCOL_IDENTIFIER */
    memcpy(ptr, &data_record->record.icmp.protocol_identifier, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_SOURCE_IPV4_ADDRESS */
    memcpy(ptr, &data_record->record.icmp.source_ipv4_address, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_DESTINATION_IPV4_ADDRESS */
    memcpy(ptr, &data_record->record.icmp.destination_ipv4_address, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_SOURCE_TRANSPORT_PORT */
    bigend_src_port = htons(data_record->record.icmp.source_transport_port);
    memcpy(ptr, &bigend_src_port, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* IPFIX_DESTINATION_TRANSPORT_PORT */
    bigend_dest_port = htons(data_record->record.icmp.destination_transport_port);
    memcpy(ptr, &bigend_dest_port, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* IPFIX_FLOW_DIRECTION */
    memcpy(ptr, &data_record->record.icmp.dir, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_TYPE_OF_SERVICE */
    memcpy(ptr, &data_record->record.icmp.tos, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_ICMP_TYPE */
    memcpy(ptr, &data_record->record.icmp.icmp_type, sizeof(uint16_t));
    ptr += sizeof(uint16_t);

    /* IPFIX_INGRESS_IFACE OR IPFIX_EGRESS_IFACE */
    if(data_record->record.icmp.dir == INGRESS) {
        if_idx = htonl(data_record->record.icmp.ifindex);
        memcpy(ptr, &if_idx, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
    } else if (data_record->record.icmp.dir == EGRESS) {
        /* Ask from infosec as this way things slightly more easy to decipher on the Stealthwatch system.(Infosec) */
        if_idx = htonl(0);
        memcpy(ptr, &if_idx, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
    }

    /* IPFIX_MINIMUM_TTL */
    min_ttl = data_record->record.icmp.min_ttl;
    memcpy(ptr, &min_ttl, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_MAXIMUM_TTL */
    max_ttl = data_record->record.icmp.max_ttl;
    memcpy(ptr, &max_ttl, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    /* IPFIX_FLOW_START_MILLISECONDS */
    bigend_sys_start_time = htonl(data_record->record.icmp.flow_start_sys_up_time);
    memcpy(ptr, &bigend_sys_start_time, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_FLOW_END_MILLISECONDS */
    bigend_sys_end_time = htonl(data_record->record.icmp.flow_end_sys_up_time);
    memcpy(ptr, &bigend_sys_end_time, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    /* IPFIX_FLOW_ID */
    flow_id = hton64(data_record->record.icmp.flow_id);
    memcpy(ptr, &flow_id, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    /* IPFIX_DSCP */
    memcpy(ptr, &data_record->record.icmp.dscp, sizeof(uint8_t));

    return 0;
}

/*
 * @brief Encode a data set into an IPFIX message.
 *
 * Take a \p set of Ipfix data records, and encode the whole
 * \p set into a \p message_buf according RFC7011 spec.
 * The \p message_buf may contain other other data, so this
 * functions appends to the message, opposed to overwriting.
 * A handle to \p msg_length is used, where the value represents
 * the total running length of the \p message. This is used by
 * calling functions to keep track of how much data has been
 * written into the \p message.
 *
 * @param set Single set of multiple Ipfix data records.
 * @param message_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_data_set(ipfix_exporter_data_set_t *set,
                                     unsigned char *message_buf,
                                     uint16_t *msg_length) {
    log_debug("Encoding data set");
    ipfix_exporter_data_t *this_data_record = NULL;
    unsigned char *data_ptr = NULL;
    uint16_t bigend_set_id = 0, bigend_set_len = 0;

    if (message_buf == NULL) {
        log_err("api-error: message_buf is null");
        return 1;
    }

    if (set == NULL) {
        log_err("api-error: set is null");
        return 1;
    }

    if (set->set_hdr.length > (IPFIX_MAX_SET_LEN - *msg_length)) {
        log_err("error: set is larger than remaining message buffer");
        return 1;
    }

    data_ptr = message_buf + *msg_length;

    bigend_set_id = htons(set->set_hdr.set_id);
    bigend_set_len = htons(set->set_hdr.length);

    /* Encode the set header into message */
    memcpy(data_ptr, &bigend_set_id, 2);
    data_ptr += 2;
    *msg_length += 2;

    memcpy(data_ptr, &bigend_set_len, 2);
    data_ptr += 2;
    *msg_length += 2;

    this_data_record = set->records_head;

    /* Encode the set data records into message */
    while (this_data_record != NULL) {
        switch (this_data_record->type) {
        case IPFIX_SIMPLE_INGRESS_TEMPLATE:
        case IPFIX_SIMPLE_EGRESS_TEMPLATE:
            if (ipfix_exp_encode_data_record_simple(this_data_record, data_ptr)) {
                log_err("error: could not encode the simple data record into message");
                return 1;
            }
            break;

        case IPFIX_ICMP_INGRESS_TEMPLATE:
        case IPFIX_ICMP_EGRESS_TEMPLATE:
            if (ipfix_exp_encode_data_record_icmp(this_data_record, data_ptr)) {
                log_err("error: could not encode the simple data record into message");
                return 1;
            }
            break;

        default:
            log_err("error: invalid data record type, cannot encode into message");
            return 1;
        }

        data_ptr += this_data_record->length;
        *msg_length += this_data_record->length;
        number_of_records++;
        this_data_record = this_data_record->next;
    }

    return 0;
}


/*
 * @brief Encode a set node into an IPFIX message.
 *
 * Take a \p set_node and inspect it see see whether
 * it contains a template set, option set, or data set.
 * After figuring out which set is contained, the appropriate
 * set encoding function will be called, passing down the
 * \p raw_msg_buf and \p buf_len to the sub-functions.
 *
 * @param set_node Single set node encapsulating a template/option/data set..
 * @param raw_msg_buf Buffer for message that the template \p set will be encoded and written into.
 * @param msg_length Total length of the \p message.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_set_node(ipfix_exporter_set_node_t *set_node,
                                     unsigned char *raw_msg_buf,
                                     uint16_t *buf_len) {

    uint16_t set_type = 0;

    if (set_node == NULL) {
        log_err("api-error: set_node is null");
        return 1;
    }
    set_type = set_node->set_type;
    if (set_type == IPFIX_TEMPLATE_SET) {
        /* Encode the template set into the message */
        ipfix_exp_encode_template_set(set_node->set.template_set,
                                      raw_msg_buf, buf_len);
    } else if (set_type == IPFIX_OPTION_SET) {
        /* Encode the option set into the message */
        // TODO call option set encoding function here
        log_warn("warning: option set encoding not supported yet");
    } else if (set_type >= 256) {
        ipfix_exp_encode_data_set(set_node->set.data_set,
                                  raw_msg_buf, buf_len);
    } else {
        log_err("error: invalid set type");
        return 1;
    }
    return 0;
}


/*
 * @brief Encode a message container into the buffer for sending over network.
 *
 * Take a \p message and iterate over it's attached sub-containers
 * which may include template/option/data sets. As each set is encountered
 * the data contained within will be encoded according to the IPFIX specification
 * and subsequently written into a buffer for sending over the network.
 *
 * @param message Message entity related to all sub-container entities.
 * @param raw_msg_buf Buffer for message that the template \p set will be encoded and written into.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_exp_encode_message(ipfix_message_t *message,
                                    unsigned char *raw_msg_buf) {

    log_debug("Encoding an IPFIX message");
    ipfix_exporter_set_node_t *this_set_node = NULL;
    uint16_t buf_len = 0;

    if (message == NULL) {
        log_err("api_error: message is null");
        return 1;
    }

    if (message->sets_head == NULL) {
        log_err("error: message does not contain any sets");
        return 1;
    }

    /* Get the head of set node list */
    this_set_node = message->sets_head;

    while (buf_len < IPFIX_MAX_SET_LEN) {
        /* FIXME need to make this length check actually robust */
        if (this_set_node == NULL) {
            /* Reached end of set node list */
            break;
        }
        /* Encode the node into the message */
        if (ipfix_exp_encode_set_node(this_set_node, raw_msg_buf, &buf_len)) {
               log_err("error: could not encode set node");
            return 1;
        }
        /* Go to next node in the list */
        this_set_node = this_set_node->next;
    }
    return 0;
}

/*
 * @brief print data record for debugging.
 *
 */
void print_ipfix_data_record(ipfix_exporter_data_t *data_record)
{
    struct in_addr addr;
    char *address;

    struct tm tm;
    char buf[255], result[50];

    addr.s_addr = data_record->record.simple.source_ipv4_address;
    address =  inet_ntoa(addr);
    log_info("source address  %s ", address);
    addr.s_addr = data_record->record.simple.destination_ipv4_address;
    address =  inet_ntoa(addr);
    log_info("destination address  %s ", address);
    log_info("source port %d ",data_record->record.simple.source_transport_port);
    log_info("destination port %d ",data_record->record.simple.destination_transport_port);
    sprintf(result, "%d", data_record->record.simple.flow_start_sys_up_time);
    memset(&tm, 0, sizeof(struct tm));
    strptime(result, "%s", &tm);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &tm);
    log_info("flowstart  %s ", buf);
    sprintf(result, "%d", data_record->record.simple.flow_end_sys_up_time);
    memset(&tm, 0, sizeof(struct tm));
    strptime(result, "%s", &tm);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &tm);
    log_info("flowend  %s ", buf);
    log_info("protocol identifier %d ",htons(data_record->record.simple.protocol_identifier));
    log_info("packet delta count %ld ",data_record->record.simple.no_of_packets);
}

/*
 * @brief Send an IPFIX message using a configured exporter.
 *
 * An IPFIX exporter, \p e, that has been properly configured
 * is used to send a \p msg to an IPFIX collector server.
 * It is important to stress that at this point, both the exporter \p e,
 * and the message \p msg, are both initialized, setup, and containing valid
 * data that adheres to the RFC7011 specification.
 *
 * @param e Single set of multiple Ipfix templates.
 * @param message IPFIX message that the \p set will be encoded and written into.
 *
 * @return 0 for success, 1 for failure
 */
int ipfix_export_send_message() {
    ssize_t bytes = 0;
    //ipfix_message_t *message = export_message ;
    size_t msg_len = export_message->hdr.length;
    ipfix_exporter_t *e = &gateway_export;
    ipfix_raw_message_t raw_message;

    memset(&raw_message, 0, sizeof(ipfix_raw_message_t));

    /*
     * Encode the message contents according to RFC7011,
     * and pack it into the raw_message for sending
     */
    ipfix_exp_encode_message(export_message, raw_message.payload);

    /* Convert the header length to network-byte order */
    export_message->hdr.length = htons(export_message->hdr.length);
    /* Write the time message is exported */
    export_message->hdr.export_time = htonl(time(NULL));

    /* Write message sequence number relative to current session */
    export_message->hdr.sequence_number = htonl(e->record_count);
    /*
     * Copy message header into raw_message header
     */
    memcpy(&raw_message.hdr, &export_message->hdr, sizeof(ipfix_hdr_t));
    /* Send the message */
    bytes = sendto(e->socket, (const char*)&raw_message, msg_len, 0,
                   (struct sockaddr *)&e->clctr_addr,
                   sizeof(e->clctr_addr));

    e->record_count = number_of_records;
    if (bytes < 0) {
        log_err("error: ipfix message could not be sent");
        return 1;
    } else {
        log_info("info: sequence # %d, sent %lu bytes ", e->record_count, bytes);
    }

    ipfix_delete_exp_message();
    return 0;
}


void ipfix_cleanup() {
    log_info("IPFIX cleanup ");
    ipfix_xts_cleanup();
    if (export_message != NULL) {
        ipfix_delete_exp_message();
    }
}

/*
 * @brief Encapsulate a data record within a data set and then
 *        attach it to an IPFIX \p message.
 *
 * @param fr_record  flow record created during the metric observation
 *                  phase of the process, i.e. process_flow_record_map().It contains
 *                  information that will be encoded into the new data record.
 * @param message IPFIX message that the data record/set will be encoded and written into.
 * @param template_type The template that will be adhered to for new data record creation.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_export_message_attach_data_set(const flow_record_t *fr_record,
                                                ipfix_message_t *message,
                                                ipfix_template_type_e template_type) {

    ipfix_exporter_set_node_t *set_node = NULL;
    ipfix_exporter_data_set_t *data_set = NULL;
    ipfix_exporter_data_t *data_record = NULL;
    ipfix_exporter_template_t *template = NULL;
    int signal = 0;
    int rc = 1;

    /*
     * Get a template corresponding to the requested type
     * and make a new data record that adheres to the template_type.
     */
    log_debug("Craeting data record for template type %d", template_type);
    switch (template_type) {
        case IPFIX_SIMPLE_INGRESS_TEMPLATE:
            template = ipfix_xts_search(IPFIX_SIMPLE_INGRESS_TEMPLATE, NULL);
            data_record = ipfix_exp_create_data_record(IPFIX_SIMPLE_INGRESS_TEMPLATE,
                                                       fr_record);
            break;
        case IPFIX_SIMPLE_EGRESS_TEMPLATE:
            template = ipfix_xts_search(IPFIX_SIMPLE_EGRESS_TEMPLATE, NULL);
            data_record = ipfix_exp_create_data_record(IPFIX_SIMPLE_EGRESS_TEMPLATE,
                                                       fr_record);
            break;
        case IPFIX_ICMP_INGRESS_TEMPLATE:
            template = ipfix_xts_search(IPFIX_ICMP_INGRESS_TEMPLATE, NULL);
            data_record = ipfix_exp_create_data_record(IPFIX_ICMP_INGRESS_TEMPLATE,
                                                       fr_record);
            break;
        case IPFIX_ICMP_EGRESS_TEMPLATE:
            template = ipfix_xts_search(IPFIX_ICMP_EGRESS_TEMPLATE, NULL);
            data_record = ipfix_exp_create_data_record(IPFIX_ICMP_EGRESS_TEMPLATE,
                                                       fr_record);
            break;
        default:
            log_err("error: template type not supported for exporting");
            goto end;
    }


    /* Try to get an existing data set in the message */
    data_set = ipfix_exp_message_find_data_set(message,
                                               template->hdr.template_id);

    if (data_set == NULL) {
        log_info("The message doesn't contain a data set related to the specified template type");
        /*
         * The message doesn't contain a data set related to
         * the specified template type. Create and init the
         * set node with a new data set. Finally, the set node
         * will be attached to the message.
         */
        set_node = ipfix_exp_set_node_malloc(template->hdr.template_id);
        if (set_node == NULL) {
            log_err("error: unable to create a data set_node");
            goto end;
        }

        /* Point local data_set to inside set_node for easy manipulation */
        data_set = set_node->set.data_set;

        /* TO FIX IPFIX service restart issue observed, Moving ipfix_exp_data_set_add
         * to after ipfix_exp_message_add */
        /* Add the data_record to the data_set */
        //ipfix_exp_data_set_add(data_set, data_record);

        /*
         * Try to attach the data set node to the message container.
         * If the message is full, return the code indicating that
         * a new message should be made with the current fr_record.
         * A.k.a. try again
         */
        signal = ipfix_exp_message_add(message, set_node);

        if (signal == 1) {
            log_err("error: unable to attach set_node to message");
            goto end;
        } else if (signal == 2) {
            /* Not enough space in message */
            rc = 2;
            goto end;
        }
        ipfix_exp_data_set_add(data_set, data_record);
    }
    else{
        /*
         * The valid Data Set already exists in message .
         * Simply make the data record and attach to the data_set.
         * If the message if full, return the code indicating that
         * a new message should be made with the current fr_record.
         * A.k.a. try again
         */
        if (data_record->length + message->hdr.length <= IPFIX_MAX_SET_LEN) {
            /* Add the data record to the existing data set */
            ipfix_exp_data_set_add(data_set, data_record);
        } else {
            /* Not enough space in message */
            rc = 2;
            goto end;
        }
    }
    /* Successfully attached */
    rc = 0;

end:
    log_debug("Attaching data set to message has failed.. Cleaning up %d", rc);
    if (rc) {
        /* Did not attach to message so cleanup here */
        if (set_node) {
            ipfix_delete_exp_set_node(set_node);
        }
        if (data_record) {
            ipfix_delete_exp_data_record(data_record);
        }
    }

    return rc;
}

/*
 * @brief Encapsulate a template record within a template set and then
 *        attach it to an IPFIX \p message.
 *
 * @param message IPFIX message that the template record/set will be encoded and written into.
 * @param template_type The template type to create.
 *
 * @return 0 for success, 1 for failure
 */
static int ipfix_export_message_attach_template_set(ipfix_message_t *message,
                                                    ipfix_template_type_e template_type) {

    ipfix_exporter_set_node_t *set_node = NULL;
    ipfix_exporter_template_set_t *template_set = NULL;
    ipfix_exporter_template_t *xts_tmp = NULL;
    ipfix_exporter_template_t *local_tmp = NULL;
    int flag_send_template = 0;
    int signal = 0;
    int flag_cleanup = 1;
    int rc = 1;

    /*
     * Search for the template in the xts. If it's already there,
     * simply let the search function take care of copying into the
     * local template. If it does not already exist in xts, create
     * an entry in the xts and copy locally to here. No need to
     * free the xts_tmp because exists within the store.
     */
    switch (template_type) {
        case IPFIX_SIMPLE_INGRESS_TEMPLATE:
            if (!ipfix_xts_search(IPFIX_SIMPLE_INGRESS_TEMPLATE, &local_tmp)) {
                xts_tmp = ipfix_exp_create_template(IPFIX_SIMPLE_INGRESS_TEMPLATE);
                if (ipfix_xts_copy(&local_tmp, xts_tmp)) {
                    log_err("error: copy from export template store failed");
                    goto end;
                }
            }
            break;
        case IPFIX_SIMPLE_EGRESS_TEMPLATE:
            if (!ipfix_xts_search(IPFIX_SIMPLE_EGRESS_TEMPLATE, &local_tmp)) {
                xts_tmp = ipfix_exp_create_template(IPFIX_SIMPLE_EGRESS_TEMPLATE);
                if (ipfix_xts_copy(&local_tmp, xts_tmp)) {
                    log_err("error: copy from export template store failed");
                    goto end;
                }
            }
            break;
        case IPFIX_ICMP_INGRESS_TEMPLATE:
            if (!ipfix_xts_search(IPFIX_ICMP_INGRESS_TEMPLATE, &local_tmp)) {
                xts_tmp = ipfix_exp_create_template(IPFIX_ICMP_INGRESS_TEMPLATE);
                if (ipfix_xts_copy(&local_tmp, xts_tmp)) {
                    log_err("error: copy from export template store failed");
                    goto end;
                }
            }
            break;
        case IPFIX_ICMP_EGRESS_TEMPLATE:
            if (!ipfix_xts_search(IPFIX_ICMP_EGRESS_TEMPLATE, &local_tmp)) {
                xts_tmp = ipfix_exp_create_template(IPFIX_ICMP_EGRESS_TEMPLATE);
                if (ipfix_xts_copy(&local_tmp, xts_tmp)) {
                    log_err("error: copy from export template store failed");
                    goto end;
                }
            }
            break;
        case IPFIX_RESERVED_TEMPLATE:
        default:
            log_err("error: template type not supported for exporting");
            goto end;
    }

    /*
     * Check if template needs to be sent
     */
    if (((XTS_RESEND_TIME <= (time(NULL) - local_tmp->last_sent)) &&
        ((time(NULL) - local_tmp->last_sent) < XTS_EXPIRE_TIME)) ||
        local_tmp->last_sent == 0) {
        log_debug("Template is within the resend period");
        /*
         * The template is within the resend period or has not been
         * previously sent before.
         */
        flag_send_template = 1;
    }

    if (flag_send_template) {
        ipfix_exporter_template_t *db_tmp = NULL;

        /* Get a valid template set to attach to, if possible */
        template_set = ipfix_exp_message_find_template_set(message);

        /*
         * Get a pointer to the XTS database template.
         * This is for updating the time and other attributes on
         * the template object.
         */
        if( template_type == IPFIX_SIMPLE_INGRESS_TEMPLATE) {
            db_tmp = ipfix_xts_search(IPFIX_SIMPLE_INGRESS_TEMPLATE, NULL);
        } else if (template_type == IPFIX_SIMPLE_EGRESS_TEMPLATE) {
            db_tmp = ipfix_xts_search(IPFIX_SIMPLE_EGRESS_TEMPLATE, NULL);
        } else if (template_type == IPFIX_ICMP_INGRESS_TEMPLATE) {
            db_tmp = ipfix_xts_search(IPFIX_ICMP_INGRESS_TEMPLATE, NULL);
        } else if (template_type == IPFIX_ICMP_EGRESS_TEMPLATE) {
            db_tmp = ipfix_xts_search(IPFIX_ICMP_EGRESS_TEMPLATE, NULL);
        } else {
            log_err("error: template type not supported for exporting");
        }
        if (template_set == NULL) {
            log_debug("Template set is NULL");
            /*
             * The message doesn't contain a template set yet.
             * Create and init the set node with a new template set.
             * Finally, the set node will be attached to the message.
             */

            /* Create and init the set node with a template set for use */
            set_node = ipfix_exp_set_node_malloc(IPFIX_TEMPLATE_SET);
            if (set_node == NULL) {
                log_err("error: unable to create a template set_node");
                goto end;
            }

            /* Point local template_set to inside set_node for easy manipulation */
            template_set = set_node->set.template_set;

            /* Add the new template to the template_set */
            //ipfix_exp_template_set_add(template_set, local_tmp);

            /*
             * Try to attach the template set node to the message container.
             * If the message is full, the set node will be deleted, and the function
             * will call itself with the current flow record to get a new message started.
             */
            signal = ipfix_exp_message_add(message, set_node);
            if (signal == 0) {
                /*
                 * Update the last_sent time on template
                 * in exporter template store (xts)
                 */
                if (db_tmp) {
                    db_tmp->last_sent = time(NULL);
                }
            } else if (signal == 1) {
                log_err("error: unable to attach set_node to message");
                goto end;
            } else if (signal == 2) {
                /* Not enough space in message */
                rc = 2;
                goto end;
            }
            ipfix_exp_template_set_add(template_set, local_tmp);
        }
        else{
            /*
             * A valid Template Set already exists in message.
             * Simply make the template and attach to the template_set.
             */
            if (local_tmp->length + message->hdr.length <= IPFIX_MAX_SET_LEN) {
                /* Add the new template to the template_set */
                ipfix_exp_template_set_add(template_set, local_tmp);

                /*
                 * Update the last_sent time on template
                 * in exporter template store (xts)
                 */
                if (db_tmp) {
                    db_tmp->last_sent = time(NULL);
                }
            }
            else {
                /* Not enough space in message */
                rc = 2;
                goto end;
            }
        }
        /*
         * Attached the set node and template to message
         * so don't cleanup those objects.
         */
        flag_cleanup = 0;
    }
    /* Successfully attached */
    rc = 0;
end:
    if (flag_cleanup) {
        log_debug("Attaching template set to message has failed.. Cleaning up %d", rc);
        /* Did not attach to message so cleanup here */
        if (set_node) {
            ipfix_delete_exp_set_node(set_node);
        }
        if (local_tmp) {
            ipfix_delete_exp_template(local_tmp);
        }
    }

    return rc;
}

/*
 * @brief The main IPFIX exporting control function for creating messages that
 *        that will be sent along the network.
 *
 * @param fr_record  flow record created during the metric observation
 *                  phase of the process, i.e. process_flow_record_map(). It contains
 *                  information that will be encoded into the message.
 *
 * @return 0 for success, 1 for failure
 */
int ipfix_create_template_data_set(flow_record_t *fr_record, ipfix_template_type_e export_template_type,
                                   char* remote_ip, int remote_port, int local_port) {
    int attach_code = 0;
    /* Init the exporter for use, if not done already */
    if (gateway_export.socket == 0) {
        ipfix_exporter_init(remote_ip, remote_port, local_port);
    }

    if(export_template_type == 1)
        exporter_template_id = exporter_tcp_ingress_template_id;
    else if (export_template_type == 2)
        exporter_template_id = exporter_tcp_egress_template_id;
    else if (export_template_type == 3)
        exporter_template_id = exporter_icmp_ingress_template_id;
    else if (export_template_type == 4)
        exporter_template_id = exporter_icmp_egress_template_id;

    if(export_message == NULL)
        export_message = ipfix_exp_message_malloc();
    /*
     * Attach a template if necessary.
     */
    attach_code = ipfix_export_message_attach_template_set(export_message,
                                                           export_template_type);
    if (attach_code == 2) {
        /*
         * Could not attach template to the message because
         * it was already full. Here we send off the packed message
         * and then make a new one to attach this template to.
         */
         //TODO

        if (export_message) {
            ipfix_export_send_message();

            /* Make new message */
            if (!(export_message = ipfix_exp_message_malloc())) {
                log_err("error: unable to create a message");
                return 1;
            }
        }


        if (ipfix_export_message_attach_template_set(export_message,
                                                     export_template_type)) {
            /*
             * We either had an error or could not attach again.
             * This is a problem...
             */
            return 1;
        }
    }

    /*
     * Attach data record.
     */
    attach_code = ipfix_export_message_attach_data_set(fr_record,
                                                       export_message,
                                                       export_template_type);
    if (attach_code == 2) {
        /*
         * Could not attach data record to the message because
         * it was already full. Here we send off the packed message
         * and then make a new one to attach this data record to.
         */

        if (export_message) {
            ipfix_export_send_message();

            /* Make new message */
            if (!(export_message = ipfix_exp_message_malloc())) {
                log_err("error: unable to create a message");
                return 1;
            }
        }

        if (ipfix_export_message_attach_data_set(fr_record,
                                                 export_message,
                                                 export_template_type)) {
            /*
             * We either had an error or could not attach again.
             * This is a problem...
             */
            return 1;
        }
    }
    return 0;
}

