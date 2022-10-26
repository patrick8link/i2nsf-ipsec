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

#include "utils.h"
#include "sysrepo_utils.h"

int feature_case_value = 0;

char *
ev_to_str(sr_notif_event_t ev) {

    switch (ev) {
    case SR_EV_VERIFY:
        return "verify";
    case SR_EV_APPLY:
        return "apply";
    case SR_EV_ABORT:
    default:
        return "abort";
    }
}


static void
print_current_config(sr_session_ctx_t *session, const char *module_name) {

    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char select_xpath[XPATH_MAX_LEN];
    snprintf(select_xpath, XPATH_MAX_LEN, "/%s:*//*", module_name);

    rc = sr_get_items(session, select_xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        ERR("sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        sr_print_val(&values[i]);
    }
    sr_free_values(values, count);
}


// callbackk for ike-conn-entry element
int ipsec_entry_change_cb(sr_session_ctx_t *session, const char *ike_entry_xpath, sr_notif_event_t event, void *private_ctx)
{

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char * name = NULL;
    char * token_ike = "/name";
    int l = strlen(token_ike);
    char xpath[MAX_PATH] = "";

    DBG(" ========== IKE Notification  %s ============================================", ev_to_str(event));
    if (SR_EV_VERIFY == event) {

        DBG("========= VERIFY: IKE-ENTRY HAS CHANGED, CURRENT RUNNING CONFIG: ==========");
        rc = sr_get_changes_iter(session, ike_entry_xpath, &it);
        if(SR_ERR_OK != rc){
            ERR("Get changes iter failed for xpath %s: %s", ike_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while(SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)){
            switch(oper){
                case SR_OP_CREATED:
                    DBG("<SR_OP_CREATED> ==> %s", new_value->xpath);
                    break;
                case SR_OP_DELETED:
                    DBG("<SR_OP_DELETED");
                    break;
                case SR_OP_MODIFIED:
                    DBG("<SR_OP_MODIFIED>");
                    break;
                case SR_OP_MOVED:
                    DBG("<SR_OP_MOVED>");
                    break;
            }
            sr_free_val(old_value);
            sr_free_val(new_value);
        }
        

        DBG(" ========== FIN READING running CONFIG: ==========");
    }
    else if (SR_EV_APPLY == event) {

        DBG(" ========== APPLY: IKE CHANGES: =============================================");
        rc = sr_get_changes_iter(session, ike_entry_xpath, &it);
        if(SR_ERR_OK != rc){
            ERR("Get changes iter failed for xpath %s: %s", ike_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while(SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)){
            switch(oper){
                case SR_OP_CREATED:
                    DBG("<SR_OP_CREATED> ==> %s");
                    name = strrchr(new_value->xpath, '/');
                    if(0 == strncmp(token_ike, name, l)){
                        INFO("Add entry %s", sr_val_to_str(new_value));
                    }
                    break;
                case SR_OP_DELETED:
                    DBG("<SR_OP_DELETED");
                    break;
                case SR_OP_MODIFIED:
                    DBG("<SR_OP_MODIFIED>");
                    break;
                case SR_OP_MOVED:
                    DBG("<SR_OP_MOVED>");
                    break;
            }
            sr_free_val(old_value);
            sr_free_val(new_value);
        }
        DBG(" ========== END OF CHANGES =======================================");
        system("python3.8 ./python/test/rpc2Gw1.py");
    }
cleanup:

    sr_free_change_iter(it);
    return rc;
}

