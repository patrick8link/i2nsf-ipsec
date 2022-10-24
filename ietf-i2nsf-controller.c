/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>

#include "control_base/utils.h"
#include "control_base/log.h"
#include "control_base/sysrepo_utils.h"

#define VERSION "0.1"

int exit_application = 0;
sr_conn_ctx_t *conn = NULL;
sr_session_ctx_t *sess = NULL;


static void
sigint_handler(int signum)
{
    exit_application = 1;
}

int
main(int argc, char **argv)
{

    if ( geteuid() != 0 ) {
        fprintf ( stderr, "Must be root in order to execute cfgipsec2. You are UID=%u, EUID=%u\n", getuid(), geteuid() );
        return 1;
    }

    // Get options
    int foreground = false;
    feature_case_value = CASE2_IPSEC;

    int c;
    while ( ( c = getopt ( argc, argv, "f:c:v:h" ) ) != -1 ) {
        switch ( c ) {
            case 'f':
                foreground = true; // TBD
                break;
            case 'c':
                if (strcmp(optarg,"case1") != 0 && strcmp(optarg,"case2") != 0) {
                    printf("feature not valid: %s\n",optarg);
                    exit(EXIT_FAILURE);
                } else if (strcmp(optarg, "case1") == 0) {
                    feature_case_value = CASE1_IPSECIKE;
                } // else, take dafult values (case2)
                break;
            case 'v':
                if (strcmp(optarg,"0") != 0 && strcmp(optarg,"1") != 0 && strcmp(optarg,"2") != 0) {
                    printf("verbose not valid: %s\n",optarg);
                    exit(EXIT_FAILURE);
                } else if (strcmp(optarg,"0") == 0) {
                    set_verbose_level(CI_VERB_ERROR);
                } else if (strcmp(optarg,"2") == 0) {
                    set_verbose_level(CI_VERB_DEBUG);
                }
                break;
            case 'h': {
                fprintf(stderr, "cfgipsec2 version %s \n", VERSION);
                fprintf(stderr, "Usage:\n" );
                fprintf(stderr, "       %s [-c case] [-v verbose_level]\n",argv[0]);
                fprintf(stderr, "\n" );
                fprintf(stderr, "Where:\n" );
                fprintf(stderr, "       - case is `case1` (with IKE) or `case2` (without IKE, default)\n" );
                fprintf(stderr, "       - verbose_level is 0: ERROR, 1: INFORMATIONAL (default), 2: DEBUG\n" );
                fprintf(stderr, "" );
                return 0;
            }
            default: {
                fprintf(stderr, "Usage: %s [-c case] [-v verbose_level]\n", argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }

    //// connect to sysrepo
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL; 

    int rc = SR_ERR_OK;
    char *module_name = "ietf-i2nsf-ike";

    const char *xpath = "";	
    sr_schema_t *schemas = NULL;
    size_t schema_cnt = 0, i = 0;
    bool enabled = false;
    char command[MAX_PATH];
	
    DBG("Connect to sysrepo %i",rc);
    rc = sr_connect("sdn_ipsec_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        ERR("Error by sr_connect: %s", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        ERR( "Error by sr_session_start: %s", sr_strerror(rc));
        goto cleanup;
    }

    // check if module ietf-ipsec is already installed
    rc = sr_list_schemas(session, &schemas, &schema_cnt);
    for (i = 0; i < schema_cnt; i++) {
        if (0 == strcmp(schemas[i].module_name, module_name)) {    
            DBG("Module %s enabled.", module_name);
	        enabled = true;
	    }
    }
    sr_free_schemas(schemas, schema_cnt);
    if (!enabled) {
            ERR("Module %s not installed. Please, run make install.", module_name);
		    return EXIT_FAILURE;
    }

    /* read startup config */
    //apply_current_startup_config(session, module_name); TBD

    xpath = "/ietf-i2nsf-ike:ipsec-ike/conn-entry";
    rc = sr_subtree_change_subscribe(session,xpath, ike_entry_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        ERR( " sr_module_change_subscribe ike: %s", sr_strerror(rc));
        ERR( "Try to reinstall the ietf-ipsec module running make uninstall then make install.");
        goto cleanup;
    }

    xpath = "/ietf-i2nsf-ike:ipsec-ike/pad/pad-entry";
    rc = sr_subtree_change_subscribe(session,xpath, pad_entry_change_cb, NULL,
            1, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        ERR( " sr_module_change_subscribe pad: %s", sr_strerror(rc));
        goto cleanup;
    }

    xpath = "/ietf-i2nsf-ike:ipsec-ike/conn-entry/spd/spd-entry";
    rc = sr_subtree_change_subscribe(session,xpath, spd_entry_change_cb, NULL,
            2, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        ERR( " sr_module_change_subscribe spd: %s", sr_strerror(rc));
        goto cleanup;
    }  
    

 
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }

    INFO("Application exit requested, exiting.");

    rc = sr_commit(session);
    if (SR_ERR_OK != rc) {
        ERR( " sr_commit: %s", sr_strerror(rc));
        goto cleanup;
    }
    
cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(session, subscription);
    }
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
    return rc;
}

