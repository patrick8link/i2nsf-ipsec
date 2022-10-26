from ncclient import manager
import sys

HOST_CLIENT = "10.0.1.204"
HOST_PORT = 830

PAD_NAME_1 = sys.argv[1]
print(f"PAD_NAME_1 = {sys.argv[1]}")
PAD_IP4ADDR_1 = sys.argv[2]
print(f"PAD_IP4ADDR_1 = {sys.argv[2]}")
PAD_AUTHPROTOCOL_1 = sys.argv[3]
print(f"PAD_AUTHPROTOCOL_1 = {sys.argv[3]}")
PAD_AUTHMETHOD_1 = sys.argv[4]
PAD_SECRET_1 = sys.argv[5]

PAD_NAME_2 = sys.argv[6]
PAD_IP4ADDR_2 = sys.argv[7]
PAD_AUTHPROTOCOL_2 = sys.argv[8]
PAD_AUTHMETHOD_2 = sys.argv[9]
PAD_SECRET_2 = sys.argv[10]

IKE_NAME = sys.argv[11]
IKE_AUTORUN = sys.argv[12]
IKE_VERSION = sys.argv[13]
IKE_REKEY = sys.argv[14]
IKE_REAUTH = sys.argv[15]
IKE_OVERTIME = sys.argv[16]
IKE_DHGROUP = sys.argv[17]
IKE_LOCALPADNAME = sys.argv[18]
IKE_REMOTEPADNAME = sys.argv[19]


with manager.connect(host=HOST_CLIENT, port=HOST_PORT, username="netconf", password="netconf", hostkey_verify=False) as m:
    c = m.get_config(source='running')
    # print(f'is manager connected?:  {m.connected}')
    # print(f'manager timeout: {m.timeout}')
    # print(f'manager session id: {m.session_id}')
    print(f'######################## SENDING RPC TO {HOST_CLIENT}:{HOST_PORT}########################')
    conf = f'''
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <ipsec-ike xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-ike" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <pad>
        <pad-entry>
            <name>{PAD_NAME_1}</name>
            <ipv4-address>{PAD_IP4ADDR_1}</ipv4-address>
            <auth-protocol>{PAD_AUTHPROTOCOL_1}</auth-protocol>
            <peer-authentication>
                <auth-method>{PAD_AUTHMETHOD_1}</auth-method>
                <pre-shared>
                    <secret>{PAD_SECRET_1}</secret>
                </pre-shared>
            </peer-authentication>
        </pad-entry>
        <pad-entry>
            <name>{PAD_NAME_2}</name>
            <ipv4-address>{PAD_IP4ADDR_2}</ipv4-address>
            <auth-protocol>{PAD_AUTHPROTOCOL_2}</auth-protocol>
            <peer-authentication>
                <auth-method>{PAD_AUTHMETHOD_2}</auth-method>
                <pre-shared>
                    <secret>{PAD_SECRET_2}</secret>
                </pre-shared>
            </peer-authentication>
        </pad-entry>
    </pad>
    <conn-entry>
        <name>{IKE_NAME}</name>
        <autostartup>{IKE_AUTORUN}</autostartup>
        <version>{IKE_VERSION}</version>
        <initial-contact>false</initial-contact>
        <fragmentation><enabled>false</enabled></fragmentation>
        <ike-sa-lifetime-soft>
           <rekey-time>{IKE_REKEY}</rekey-time>
           <reauth-time>{IKE_REAUTH}</reauth-time>
        </ike-sa-lifetime-soft>
        <ike-sa-lifetime-hard>
           <over-time>{IKE_OVERTIME}</over-time>
        </ike-sa-lifetime-hard>
        <!--AUTH_HMAC_SHA2_512_256-->
        <ike-sa-intr-alg>14</ike-sa-intr-alg>
        <!--ENCR_AES_CBC - 128 bits-->
        <ike-sa-encr-alg>
           <id>1</id>
        </ike-sa-encr-alg>
        <!--8192-bit MODP Group-->
        <dh-group>{IKE_DHGROUP}</dh-group>
        <half-open-ike-sa-timer>30</half-open-ike-sa-timer>
        <half-open-ike-sa-cookie-threshold>
           15
        </half-open-ike-sa-cookie-threshold>
        <local>
            <local-pad-entry-name>{IKE_LOCALPADNAME}</local-pad-entry-name>
        </local>
        <remote>
            <remote-pad-entry-name>{IKE_REMOTEPADNAME}</remote-pad-entry-name>
        </remote>
        <spd>
          <spd-entry>
             <name>gateway1</name>
             <ipsec-policy-config>
               <anti-replay-window-size>64</anti-replay-window-size>
               <traffic-selector>
                  <local-prefix>192.168.201.0/24</local-prefix>
                  <remote-prefix>192.168.202.0/24</remote-prefix>
                  <inner-protocol>6</inner-protocol>
               </traffic-selector>
               <processing-info>
                  <action>protect</action>
                  <ipsec-sa-cfg>
                     <pfp-flag>false</pfp-flag>
                     <ext-seq-num>true</ext-seq-num>
                     <seq-overflow>false</seq-overflow>
                     <stateful-frag-check>false</stateful-frag-check>
                     <mode>tunnel</mode>
                     <protocol-parameters>esp</protocol-parameters>
                     <esp-algorithms>
                        <!-- AUTH_HMAC_SHA1_96 -->
                        <integrity>2</integrity>
                         <encryption>
                             <!-- ENCR_AES_CBC -->
                             <id>1</id>
                             <algorithm-type>12</algorithm-type>
                             <key-length>128</key-length>
                         </encryption>
                         <encryption>
                             <!-- ENCR_3DES-->
                             <id>2</id>
                             <algorithm-type>3</algorithm-type>
                         </encryption>
                        <tfc-pad>false</tfc-pad>
                     </esp-algorithms>
                     <tunnel>
                        <local>192.168.123.100</local>
                        <remote>192.168.123.200</remote>
                        <df-bit>clear</df-bit>
                        <bypass-dscp>true</bypass-dscp>
                     </tunnel>
                  </ipsec-sa-cfg>
               </processing-info>
             </ipsec-policy-config>
          </spd-entry>
        </spd>
      </conn-entry>
    </ipsec-ike>
    </config>
    '''
    # print(conf)
    reply = m.edit_config(target="running", config = conf)
    print(reply)