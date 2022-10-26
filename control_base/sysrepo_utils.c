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
//IKE
int feature_case_value = 0;
char conn_name1[50] = "";
char autostartup[20] = "";
char version[5] = "2";
int ike_sa_lifetime;
int ipsec_sa_lifetime;
int ike_reauth_lifetime;
char phase1_authby[50]="";
int dh_group;
char local_ts[30]="";
char local_identifier[50]="";
char remote_ts[30]="";
char remote_identifier[50]="";
char local_addrs[30]="";
char local[30] = "";
char remote_addrs[30]="";
char remote[30] = "";
int pfs_group;

//PAD
char *entry_id;
int key;
char ipv4_addr[30];
char auth_protocol[50];
char auth_method[40];
char ssecret[40];

char *entry_id_2;
int key_2;
char ipv4_addr_2[30];
char auth_protocol_2[50];
char auth_method_2[40];
char ssecret_2[40];


//SPD
char src[30], dst[30], src_remove[30], dst_remove[30],src_tunnel[30], dst_tunnel[30];
int satype, action_policy_type, policy_dir, policy_id, protocol_next_layer, srcport, dstport, mode, proto;
int spd_lft_byte_hard = 0;
int spd_lft_byte_soft = 0;
int spd_lft_byte_current = 0;
int spd_lft_packet_hard = 0;
int spd_lft_packet_soft = 0;
int spd_lft_packet_current = 0;
int spd_lft_hard_add_expires_seconds = 0;
int spd_lft_hard_use_expires_seconds = 0;
int spd_lft_soft_add_expires_seconds = 0;
int spd_lft_soft_use_expires_seconds = 0;
int spd_lft_current_add_expires_seconds = 0;
int spd_lft_current_use_expires_seconds = 0;



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

int readIPSEC_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath, char *ipsec_id){
    int rc = SR_ERR_OK;
    int ac = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *value = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char *name = NULL;
    char proposals[50] = "default";
    char peer[30];

    strcpy(conn_name1, ipsec_id);
    DBG("Reading IPSEC entry: %s", conn_name1);
    rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
    if(SR_ERR_OK != rc){
        DBG("sr_get_change_next returned error");
        return rc;
    }
    do {
        if(oper == SR_OP_CREATED) value = new_value;
        else value = old_value;
        
        name = strrchr(value->xpath, '/');
        DBG("name = %s", name);

        //IKE
        if(0 == strcmp("/autostartup", name)){
            if(0 == strcmp(value->data.enum_val, "start"))
                strcpy(autostartup, "true");
            else 
                strcpy(autostartup, "false");
            
            DBG("[IKE] autostartup: %s", autostartup);
        }

        else if(0 == strcmp("/version", name)){
            if(0 == strcmp(value->data.string_val, "ikev2")){
                strcpy(version, "2");
            }
            DBG("[IKE] version %s", version);
        }

        else if(0 == strcmp("/reauth-time", name)){
            ike_reauth_lifetime = value->data.int64_val;
            DBG("[IKE] ike_reauth_lifetime: %i", ike_reauth_lifetime);   
        }
        
        else if (0 == strcmp("/rekey-time", name)) {
            ike_sa_lifetime = value->data.int64_val;
            DBG ("[IKE] rekey-time: %i",ike_sa_lifetime);
        }
        
        else if (0 == strcmp("/over-time", name)) {
            ipsec_sa_lifetime = value->data.int64_val;
            DBG ("[IKE] over-time: %i",ipsec_sa_lifetime);
        }

        else if (0 == strcmp("/dh_group", name)) {
            dh_group = value->data.int32_val;
            DBG ("[IKE] dh_group %i",dh_group);
        }

        else if (0 == strcmp("/local-pad-entry-name",name)) {
            if (NULL != strstr(value->xpath,"local")) {
               strcpy(local,value->data.string_val);
               strcpy(local_identifier,value->data.string_val);
                DBG("[IKE] local identifier %s", local_identifier);
                char select_xpath[200];
                sr_val_t *values = NULL;
                size_t count = 0;
                snprintf(select_xpath, 200, "/ietf-i2nsf-ike:ipsec-ike/pad/pad-entry[name='%s']/ipv4-address",local);
                ac = sr_get_items(sess, select_xpath, &values, &count);
                sr_print_val(values);
                strcpy(local_addrs,values->data.string_val);
                DBG("[IKE] local ipv4 %s", local_addrs);
            }
        }

        else if (0 == strcmp("/remote-pad-entry-name",name)) {
            if (NULL != strstr(value->xpath,"remote")) {
                strcpy(remote,value->data.string_val);
                strcpy(remote_identifier,value->data.string_val);
                DBG("[IKE] remote identifier %s", remote_identifier);
                char select_xpath[200];
                sr_val_t *values = NULL;
                size_t count = 0;
                snprintf(select_xpath, 200, "/ietf-i2nsf-ike:ipsec-ike/pad/pad-entry[name='%s']/ipv4-address",remote);
                ac = sr_get_items(sess, select_xpath, &values, &count);
                sr_print_val(values);
                strcpy(remote_addrs,values->data.string_val);
                DBG("[IKE] remote ipv4 %s", remote_addrs);
            }
        }

        else if (0 == strcmp("/my-identifier",name)) {
            if (NULL != strstr(value->xpath,"local")) {
                strcpy(local_identifier,value->data.string_val);
                DBG("[IKE] local identifier %s", local_identifier);
            }
            if (NULL != strstr(value->xpath,"remote")) {
                strcpy(remote_identifier,value->data.string_val);
                DBG("[IKE] remote identifier %s", remote_identifier);
            }
        }


        //PAD
        else if(0 == strcmp("/name", name)){
            DBG("[PAD] found pad entry: %s", value->data.string_val);
        }
        else if(0 == strcmp("/id_key", name)) {
            key = value->data.int64_val;
        	DBG ("[PAD] id_keyt %i", key);
    	}

		else if (0 == strcmp("/ipv4-address",name)) {
            strcpy(ipv4_addr, value->data.string_val);
            DBG("[PAD] ipv4-address: %s", ipv4_addr);
        }

		else if (0 == strcmp("/auth-protocol",name)) {
            strcpy(auth_protocol, value->data.string_val);
            DBG("[PAD] auth_protocol: %s", auth_protocol);
        }

		else if (0 == strcmp("/auth-method",name)) {
			if (0 == strcmp(value->data.string_val,"pre-shared")) {		
                strcpy(auth_method, "psk");
                DBG("[PAD] auth_method: %s", auth_method);
			} else {
				ERR("Auth_method unsuppoted: %s",sr_strerror(SR_ERR_VALIDATION_FAILED));
				return SR_ERR_VALIDATION_FAILED;
			}

        }

		else if (0 == strcmp("/secret",name)) {
			char *data;
			int x; 
			data = value->data.string_val;
            strupp(data);
            remove_all_chars(data, ':');
            char res[500]="";
            int length = strlen(data);
            int i;
            char buf=0;
            for(i = 0; i < length; i++){
                if(i % 2 != 0){
                    x = hex_to_ascii(buf, data[i]);
                    DBG("%c",x);
                    char c = (char)x;
                    strncat(res,&c,1);
                }else{
                    buf = value->data.string_val[i];
                }
            }
            strcpy(ssecret,res);
            DBG("[PAD] ssecret: %s", res);
        }



        //SPD
        if (NULL != strstr(value->xpath,"/direction")) {
            if (!strcasecmp(value->data.string_val, "OUTBOUND"))
                policy_dir =  IPSEC_DIR_OUTBOUND;
            else if (!strcasecmp(value->data.string_val, "INBOUND"))
                policy_dir = IPSEC_DIR_INBOUND;
            else if (!strcasecmp(value->data.string_val, "FORWARD"))
                policy_dir = IPSEC_DIR_FORWARD;
            else {
                rc = SR_ERR_VALIDATION_FAILED;    
                ERR("spd-entry Bad direction: %s", sr_strerror(rc));
                return rc;
            }
            DBG("[SPD] direction: %i",policy_dir);
        }

        else if (NULL != strstr(value->xpath,"/traffic-selector")) {
            DBG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!new iterator - traffic selector!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            // if (getSelectorList_it(sess,it,xpath,oper,old_value,new_value)){
            //     rc = SR_ERR_VALIDATION_FAILED;
            //     break;
            // }
        }

        else if (NULL != strstr(value->xpath,"/processing-info")) {
            DBG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!new iterator - processing info!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            // if (getProcessing_it(sess,it,xpath,oper,old_value,new_value)) {
            //     rc = SR_ERR_VALIDATION_FAILED;
            //     break;
            // }
        }

        else if (0 == strcmp("/bytes", name)) {
            if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                spd_lft_byte_soft = value->data.int32_val;
                DBG("[SPD] lifetime byte-soft: %i",spd_lft_byte_soft);
            } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) { 
                spd_lft_byte_hard = value->data.int32_val;
                DBG("[SPD] lifetime byte-hard: %i",spd_lft_byte_hard);
            }
        }  

        else if (0 == strcmp("/packets", name)) {
            if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                spd_lft_packet_soft = value->data.int32_val;
                DBG("[SPD] lifetime packet-soft: %i",spd_lft_packet_soft);
            } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) {  
                spd_lft_packet_hard = value->data.int32_val;
                DBG("[SPD] lifetime packet-hard: %i",spd_lft_packet_hard);
            }  
        }  

        else if (0 == strcmp("/added", name)) {
            if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                spd_lft_soft_add_expires_seconds = value->data.int64_val;
                DBG("[SPD] lifetime time-soft: %i",spd_lft_soft_add_expires_seconds);
            } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) { 
                spd_lft_hard_add_expires_seconds= value->data.int64_val;
                DBG("[SPD] lifetime time-hard: %i",spd_lft_hard_add_expires_seconds);
            }
        }  

        else if (0 == strcmp("/used", name)) {
            if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                spd_lft_soft_use_expires_seconds = value->data.int64_val;
                DBG("[SPD] lifetime time-use-soft: %i",spd_lft_soft_use_expires_seconds);
            } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) {  
                spd_lft_hard_use_expires_seconds= value->data.int64_val;
                DBG("[SPD] lifetime time-use-hard: %i",spd_lft_hard_use_expires_seconds);
            }  
        }  




        sr_free_val(old_value);
        sr_free_val(new_value);

    } while(SR_ERR_OK == sr_get_change_next(sess, it, &oper, &old_value, &new_value));

    return rc;
}

int addIPSEC_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath, char *ipsec_id){
    DBG("Starting addIPSEC_conn_entry");
    int rc = SR_ERR_OK;
    rc = readIPSEC_conn_entry(sess, it, xpath, ipsec_id);
    if(rc != SR_ERR_OK){
        ERR("Failed to Add entry in verifyIPSEC_entry: %s", sr_strerror(rc));
        return SR_ERR_VALIDATION_FAILED;
    }
    DBG("Exiting addIPSEC_conn_entry");
    return SR_ERR_OK;
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

    DBG(" ========== IPSEC Notification  %s ============================================", ev_to_str(event));
    if (SR_EV_VERIFY == event) {

        DBG("========= VERIFY: IPSEC-ENTRY HAS CHANGED, CURRENT RUNNING CONFIG: ==========");
        rc = sr_get_changes_iter(session, ike_entry_xpath, &it);
        if(SR_ERR_OK != rc){
            ERR("Get changes iter failed for xpath %s: %s", ike_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while(SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)){
            switch(oper){
                case SR_OP_CREATED:
                    // DBG("<SR_OP_CREATED> ==> %s", new_value->xpath);
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

        DBG(" ========== APPLY: IPSEC CHANGES: =============================================");
        rc = sr_get_changes_iter(session, ike_entry_xpath, &it);
        if(SR_ERR_OK != rc){
            ERR("Get changes iter failed for xpath %s: %s", ike_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while(SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)){
            switch(oper){
                case SR_OP_CREATED:
                    // DBG("<SR_OP_CREATED>");
                    name = strrchr(new_value->xpath, '/');
                    if(0 == strncmp(token_ike, name, l)){
                        INFO("Add entry %s", sr_val_to_str(new_value));
                        strncpy(xpath, new_value->xpath, strlen(new_value->xpath));
                        if(!addIPSEC_conn_entry(session, it, xpath, sr_val_to_str(new_value))){
                            INFO("ipsec-conn-entry added");
                        }else{
                            rc = SR_ERR_OPERATION_FAILED;
                            ERR("Failed to add ipsec-conn-entry: %s", sr_strerror(rc));
                            goto cleanup;
                        }
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

