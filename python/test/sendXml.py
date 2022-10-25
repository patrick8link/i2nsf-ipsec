from ncclient import manager

with manager.connect(host="10.0.1.200", port=830, username="netconf", password="netconf", hostkey_verify=False) as m:
    c = m.get_config(source='running')
    print(f'is manager connected?:  {m.connected}')
    print(f'manager timeout: {m.timeout}')
    print(f'manager session id: {m.session_id}')
    conf = '''
    <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <ipsec-ike xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-ike" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <pad>
        <pad-entry>
            <name>Host1</name>
            <ipv4-address>192.168.123.100</ipv4-address>
            <auth-protocol>ikev2</auth-protocol>
            <peer-authentication>
                <auth-method>pre-shared</auth-method>
                <pre-shared>
                    <secret>73:65:63:72:65:74:6F:5F:63:6F:6D:70:61:72:74:69:64:6F</secret>
                </pre-shared>
            </peer-authentication>
        </pad-entry>
        <pad-entry>
            <name>Host2</name>
            <ipv4-address>192.168.123.200</ipv4-address>
            <auth-protocol>ikev2</auth-protocol>
            <peer-authentication>
                <auth-method>pre-shared</auth-method>
                <pre-shared>
                    <secret>73:65:63:72:65:74:6F:5F:63:6F:6D:70:61:72:74:69:64:6F</secret>
                </pre-shared>
            </peer-authentication>
        </pad-entry>
    </pad>
    <conn-entry>
        <name>gateway1</name>
        <autostartup>start</autostartup>
        <version>ikev2</version>
        <initial-contact>false</initial-contact>
        <fragmentation><enabled>false</enabled></fragmentation>
        <ike-sa-lifetime-soft>
           <rekey-time>30</rekey-time>
           <reauth-time>60</reauth-time>
        </ike-sa-lifetime-soft>
        <ike-sa-lifetime-hard>
           <over-time>10</over-time>
        </ike-sa-lifetime-hard>
        <!--AUTH_HMAC_SHA2_512_256-->
        <ike-sa-intr-alg>14</ike-sa-intr-alg>
        <!--ENCR_AES_CBC - 128 bits-->
        <ike-sa-encr-alg>
           <id>1</id>
        </ike-sa-encr-alg>
        <!--8192-bit MODP Group-->
        <dh-group>18</dh-group>
        <half-open-ike-sa-timer>30</half-open-ike-sa-timer>
        <half-open-ike-sa-cookie-threshold>
           15
        </half-open-ike-sa-cookie-threshold>
        <local>
            <local-pad-entry-name>Host1</local-pad-entry-name>
        </local>
        <remote>
            <remote-pad-entry-name>Host2</remote-pad-entry-name>
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
    print(conf)
    reply = m.edit_config(target="running", config = conf)
    print(reply)