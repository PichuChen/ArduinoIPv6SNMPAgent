/*
Copyright 2014 Pichu Chen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "ipv6snmpd.h"
//
// Note: Works on an Arduino Uno with an ATMega328 and 
// an ENC28J60 Ethershield
//
// Please modify the following line. The MAC-address has to be unique
// in your local area network.

#include <SoftwareSerial.h>

SoftwareSerial mySerial(8, 9); // RX, TX

//SPEC Request Content Length Can not greater equal than LINE_BUF_SIZE (90)
static uint8_t mMAC[6] = {0x00,0x22,0x15,0x01,0x02,0x04};

//#define DEBUG 1

IPv6Snmpd ipv6ES = IPv6Snmpd();


#define RELAY_PIN 3
#define BUTTON_PIN 4
#define LINE_BUF_SIZE 90



const unsigned char sysNameOID[] =  "\x2b\x06\x01\x02\x01\x01\x05\x00"; // 1.3.5.1.2.1.1.5.0 
const unsigned char TIH_Expr_Arduino_Pin3_OID[] = "\x2b\x06\x01\x04\x01\x82\xd7\x22\x11\x01\x03"; // 1.3.6.1.4.1.43938.17.1.3

const unsigned char * snmpWalkTable[] = {sysNameOID,TIH_Expr_Arduino_Pin3_OID,NULL}; 
int sizeofOIDTable[] = {sizeof(sysNameOID) -1, sizeof(TIH_Expr_Arduino_Pin3_OID) -1};


char sysName[32] = "PikaPika";

unsigned long heartBeatInterval = 1 * 1000; // ms


boolean inState[4];
void setup() {
  Serial.begin(9600);
  // init network-device
  ipv6ES.initENC28J60(mMAC);
  ipv6ES.initTCPIP(mMAC, snmpd);  
  // add "Link Local Unicast" Address
  // for testing under Linux: ping6 -I eth0 fe80::1234
  ipv6ES.addAddress(0xfe80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1234);
  // add "Global Unicast Address"
  // for testing under Linux: ping6 2a00:eb0:100:15::1234
 // 2a00:eb0:100:15::1
  
  ipv6ES.addAddress(0x2001, 0x288, 0x8001, 0xd600, 0x00, 0x00, 0x00, 0x1234);  
 // ipv6ES.addAddress(0x2a00, 0xeb0, 0x0100, 0x15, 0x00, 0x00, 0x00, 0x2);
  // telnet listen
  ipv6ES.udpBind(161);    
  pinMode(3, OUTPUT);  
  pinMode(BUTTON_PIN, INPUT);  
}
extern int uip_slen;
#include "arduino-debug.h"
extern "C"{
  #include "uip-udp-packet.h"
}
#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])

struct Ber_t{
  unsigned char type;
  unsigned char length;
  unsigned char next; 
};

void snmpd(){
   
   arduino_debug_address( &(UIP_IP_BUF->srcipaddr));
   arduino_debug_address( &(UIP_IP_BUF->destipaddr));
//   ipv6ES.sendData("XXXXXXD",8);
//   Serial.print("uip_slen:");
//   Serial.println(uip_slen);
//Set IP,Port
   uip_ipaddr_copy(&uip_udp_conn->ripaddr,&(UIP_IP_BUF->srcipaddr));
   uip_udp_conn->rport = UIP_UDP_BUF->srcport;
  // uip_udp_packet_send(uip_udp_conn,"XDDDD",5);
   
   uip_slen = ntohs(UIP_UDP_BUF->udplen) -8;
//   memcpy(&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN], data, len > UIP_BUFSIZE? UIP_BUFSIZE: len);
   Serial.print("UIP_UDP_BUF: "); 
   Serial.println(sizeof(uip_buf));
   Ber_t* ptr = (Ber_t*)((unsigned char*)UIP_UDP_BUF + sizeof(uip_udp_hdr));
   Ber_t* endPtr;
   
   
   //   http://www.vijaymukhi.com/vmis/bersnmp.htm
   enum PDUs{get_request=0xa0,get_next_request=0xa1,get_response=0xa2,set_request=0xa3, get_bulk_requeset = 0xa5, inform_request = 0xa6, snmpv2_trap = 0xa7};
   enum ASN_1_TYPE{ASN_1_INTEGER = 0x02, ASN_1_STRING = 0x04, ASN_1_OBJECT = 0x06, ASN_1_SEQUENCE = 0x30};
   int communityNameLength;
   unsigned int requestIdLength; 
   PDUs receivePDU;
   
   // Fetch SNMP PDU Begin
   if(ptr->type == ASN_1_SEQUENCE){ // SEQUENCE	
     endPtr = (Ber_t*)(&ptr->next + ptr->length) ;
     ptr =  (Ber_t*)(&ptr->next);
   }else{
     return ; //Drop
   }
   
   // Fetch Version Begin
   if(ptr->type != ASN_1_INTEGER){ //INTEGER
     return ; // Drop
   }
   if(ptr->length != 1){
     Serial.println("Version Length Error");  
     return ; //Drop
   }
   // Assume == 2 , 2c
   ptr =  (Ber_t*)(&ptr->next + ptr->length);
   // Fetch Version End
   
   // Fetch Community Name Begin
   if(ptr->type != ASN_1_STRING){ //STRING
     return ; // Drop
   }
   Serial.println(ptr->length,DEC);
   if((communityNameLength = ptr->length) >= 32){
     Serial.println("community Name too Long");  
   }
   char communityName[32];
   memcpy(communityName,&ptr->next,ptr->length);
   communityName[ptr->length] = '\0';
   Serial.println(communityName);
   ptr =  (Ber_t*)(&ptr->next + ptr->length); // NEXT
   // Fetch Community Name End
   
   //Fetch Request Type Begin
   receivePDU = (PDUs)ptr->type;
   ptr =  (Ber_t*)(&ptr->next);// IN
   //Fetch Request Type End
   
   //Fetch Request-id Begin
   if(ptr->type != ASN_1_INTEGER){ //INTEGER
     return; // Drop
   }
    // IN RFC1157, the length of request-id is INTEGER, but in RFC 1905, request-id is Integer32
   requestIdLength = ptr->length;
   
   ptr =  (Ber_t*)(&ptr->next + ptr->length); // NEXT
   //Fetch Request-id End
   
   //Fetch Error-Status Begin
     //Skip
   ptr =  (Ber_t*)(&ptr->next + ptr->length); // NEXT
   //Fetch Error-Status End
   
   //Fetch Error-Index Begin
     //Skip
   ptr =  (Ber_t*)(&ptr->next + ptr->length); // NEXT
   //Fetch Error-Index End
   
   // Fetch Variable-bindings List Begin
   if(ptr->type != ASN_1_SEQUENCE){ // SEQUENCE	
     return ; //Drop
   }
   ptr =  (Ber_t*)(&ptr->next); // IN
   // Fetch Variable-Blindings List End
   
   // Fetch Variable-binding Begin
   if(ptr->type != ASN_1_SEQUENCE){ // SEQUENCE	
     return ; //Drop
   }
   ptr =  (Ber_t*)(&ptr->next); // IN
   // Fetch Variable-Blinding End
   
   // Fetch Object-id Begin
   if(ptr->type != ASN_1_OBJECT){ // OBJECT
     return ;//Drop
   }
   int Stat;
   
   const unsigned char ** ptrOID;
   
   if(receivePDU == get_request || receivePDU == set_request){
     for(ptrOID = snmpWalkTable;*ptrOID;++ptrOID){
      if(ptr->length != sizeofOIDTable[ptrOID - snmpWalkTable]){
        continue;
      }
      if(!memcmp(&ptr->next,*ptrOID,ptr->length)){
        break; 
      }
     }
   }else if(receivePDU == get_next_request || receivePDU == get_bulk_requeset ){
     for(ptrOID = snmpWalkTable;*ptrOID;++ptrOID){     
      int result = memcmp(&ptr->next,*ptrOID,ptr->length);
      if(result < 0){
        break; 
      }else if(result == 0 && (ptr->length != sizeofOIDTable[ptrOID - snmpWalkTable])){
        break;
      }
     }
     Serial.print("snmpwalk : ");
     Serial.println(ptrOID - snmpWalkTable);
     if(*ptrOID == NULL){
       ptrOID =  snmpWalkTable;
     }
   }
   
   if(*ptrOID == NULL){
     Stat = 0; 
   }else{
     Serial.println("FOUND");
     Serial.print("Stat : ");
     Stat =  ptrOID - snmpWalkTable + 1;
     
     Serial.println(Stat);
   }
   int oldOIDLength;
   char * startPtr = (char*)UIP_UDP_BUF + sizeof(uip_udp_hdr);
   if(receivePDU == get_next_request || receivePDU == get_bulk_requeset ){
     //Adjust OID
     oldOIDLength = ptr->length;
     ptr->length = sizeofOIDTable[ptrOID - snmpWalkTable];
     memcpy(&ptr->next,*ptrOID,ptr->length);
   uip_slen += ptr->length - oldOIDLength;
   Serial.print("Old OID Length = ");
   Serial.print(oldOIDLength);
   Serial.print("New Length = ");
   Serial.print( ptr->length);
   Serial.print("uip_slen : ");
   Serial.println(uip_slen);
   
   startPtr[1] += ptr->length - oldOIDLength; // Set Sequence
   startPtr[8 + communityNameLength] += ptr->length - oldOIDLength; // Add RESPONSE LENGTH
   startPtr[18 + communityNameLength + requestIdLength] +=ptr->length - oldOIDLength; //VarBind List LENGTH
   startPtr[20 + communityNameLength + requestIdLength] +=ptr->length - oldOIDLength; //VarBind LENGTH
     
   }
   
   ptr =  (Ber_t*)(&ptr->next + ptr->length); // NEXT
   // Fetch Object-id End
   switch(receivePDU){
   case set_request:
   case get_request:
     oldOIDLength = ptr->length ;
     break;
   case get_next_request:
   case get_bulk_requeset:
     oldOIDLength = 0;
     break;
   default:
     Serial.print("PDU ERR");
     return; //Drop
   }
   if(Stat == 1){ // Found SysName
     //Receive End, Resopnse..
     // Set String Begin
     if(receivePDU == set_request){
       if(ptr->length >= 31){
         Serial.println(" Too Long!!" );
          
       }else{
         memcpy(sysName,&ptr->next,ptr->length);
         sysName[ptr->length] = '\0'; 
       }
     }
     ptr->type = 0x04; // Set String
     ptr->length = strlen(sysName);  
     memcpy((char*)&ptr->next,sysName,ptr->length);
     // Set String End
   }else if(Stat == 2 ){ // Found Arudino Pin 3
     if(receivePDU == set_request){
       if(ptr->next != 0 && ptr->next != 1){
         Serial.println(" Value Error" );
       }else{
         inState[0] = ptr->next;
       }
     }
     ptr->type = 0x02; // Set Int  
     ptr->length = 1;
     ptr->next = inState[0];
   }else{
     ptr->type = 0x81; // Set No SuchInstance
   }
   
   uip_slen = uip_slen + ptr->length - oldOIDLength;
   startPtr[1] += ptr->length - oldOIDLength; // Set Sequence
   startPtr[7 + communityNameLength] = 0xa2; // Set RESPONSE
   startPtr[8 + communityNameLength] += ptr->length - oldOIDLength; // Add RESPONSE LENGTH
   startPtr[18 + communityNameLength + requestIdLength] +=ptr->length - oldOIDLength; //VarBind List LENGTH
   startPtr[20 + communityNameLength + requestIdLength] +=ptr->length - oldOIDLength; //VarBind LENGTH
   
   //Lanuch XD
   uip_process(UIP_UDP_SEND_CONN);
   tcpip_ipv6_output();
   uip_slen = 0;
   //Clear IP,Port
   uip_udp_conn->rport = 0;
   memset(&uip_udp_conn->ripaddr, 0, sizeof(uip_udp_conn->ripaddr));
   heartBeatInterval = 60 * 1000;
}

void heartBeat(){
  unsigned long currentMillis = millis();
  static unsigned long previousMillis = 0;
  if(currentMillis - previousMillis < heartBeatInterval) {
    return; 
  }
  previousMillis = currentMillis;
  
  Serial.println("coldStart");
   uip_ipaddr_t LpjServer;
//   uip_ip6addr(&LpjServer,0x2001,0x288,0x8001,0xd600,0x0000,0x0000,0x0000,0x115);
//   uip_ip6addr(&LpjServer,0x2a00, 0xeb0, 0x0100, 0x15, 0x00, 0x00, 0x00, 0x1);
   uip_ip6addr(&LpjServer,0x2001,0x288,0x8001,0xd600,0x226,0x18ff,0xfea7,0x13e7);
//   2a00:eb0:100:15::1
   
   arduino_debug_address( &(UIP_IP_BUF->srcipaddr));
   arduino_debug_address( &(UIP_IP_BUF->destipaddr));
   struct uip_udp_conn *conn = uip_udp_new(&LpjServer,htons(162));
   if(conn == NULL){
     Serial.println("!!"); 
   }else{
     uip_udp_bind(conn,htons(161)); 
   }
   char  pdu[]= "\x30\x33" // SEQUENCE
                "\x02\x01\x01" // Version 2c
                "\x04\x06""public"// Community Name 
                "\xa7\x26"// SNMP TRAPv2
                "\x02\x02\x6b\x9e" // requeit-id
                "\x02\x01\x00\x02\x01\x00" // Error status and index
                "\x30\x1a" // Var Bind List
                "\x30\x18" // Var Bind
                "\x06\x0a\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00"  // 1.3.6.1.6.3.1.1.4.1.0 SNMPv2-MIB::snmpTrapOID.0
                "\x06\x0a\x2b\x06\x01\x06\x03\x01\x01\x05\x01\x00"; // 1.3.6.1.6.3.1.1.5.1.0 SNMPv2-MIB::coldStart.0
   Ber_t* ptr = (Ber_t*)((unsigned char*)UIP_UDP_BUF + sizeof(uip_udp_hdr));
   memcpy((char*)ptr,pdu,sizeof(pdu));     
   uip_udp_conn = conn;
   uip_slen = sizeof(pdu);
   
   
   
   uip_process(UIP_UDP_SEND_CONN);
   tcpip_ipv6_output();
   uip_slen = 0; 
   uip_udp_remove(conn);
}


void sendMsg(){
  
  Serial.println("sendMsg");
   uip_ipaddr_t LpjServer;
//   uip_ip6addr(&LpjServer,0x2001,0x288,0x8001,0xd600,0x0000,0x0000,0x0000,0x115);
//   uip_ip6addr(&LpjServer,0x2a00, 0xeb0, 0x0100, 0x15, 0x00, 0x00, 0x00, 0x1);
   uip_ip6addr(&LpjServer,0x2001,0x288,0x8001,0xd600,0x226,0x18ff,0xfea7,0x13e7);
//   2a00:eb0:100:15::1
   
   arduino_debug_address( &(UIP_IP_BUF->srcipaddr));
   arduino_debug_address( &(UIP_IP_BUF->destipaddr));
   struct uip_udp_conn *conn = uip_udp_new(&LpjServer,htons(162));
   if(conn == NULL){
     Serial.println("!!"); 
   }else{
     uip_udp_bind(conn,htons(161)); 
   }
   char  pdu[]= "\x30\x33" // SEQUENCE
                "\x02\x01\x01" // Version 2c
                "\x04\x06""public"// Community Name 
                "\xa7\x26"// SNMP TRAPv2
                "\x02\x02\x6b\x9e" // requeit-id
                "\x02\x01\x00\x02\x01\x00" // Error status and index
                "\x30\x1a" // Var Bind List
                "\x30\x18" // Var Bind
                "\x06\x0a\x2b\x06\x01\x06\x03\x01\x01\x04\x01\x00"  // 1.3.6.1.6.3.1.1.4.1.0 SNMPv2-MIB::snmpTrapOID.0
                "\x06\x0a\x2b\x06\x01\x06\x03\x01\x01\x05\x02\x00"; // 1.3.6.1.6.3.1.1.5.1.0 SNMPv2-MIB::coldStart.0
   Ber_t* ptr = (Ber_t*)((unsigned char*)UIP_UDP_BUF + sizeof(uip_udp_hdr));
   memcpy((char*)ptr,pdu,sizeof(pdu));     
   uip_udp_conn = conn;
   uip_slen = sizeof(pdu);
   
   uip_process(UIP_UDP_SEND_CONN);
   tcpip_ipv6_output();
   uip_slen = 0; 
   uip_udp_remove(conn);
}

int keyDown = 0;

void loop() {
  heartBeat();
  digitalWrite(RELAY_PIN,(inState[0]?HIGH:LOW));
  inState[1] = digitalRead(BUTTON_PIN);
  if(keyDown == 1){
    if(inState[1] == 0){
      keyDown = 0;
      Serial.println(">///<");
      sendMsg();
    } 
  }else{
    if(inState[1] == 1){
      keyDown = 1;
    } 
  }
  
  
 ipv6ES.receivePacket();
  if (ipv6ES.newDataLength() != 0) { 
    if (ipv6ES.isIPv6Packet()) {
      ipv6ES.processTCPIP();
    }    
  }  
  ipv6ES.pollTimers();
}


