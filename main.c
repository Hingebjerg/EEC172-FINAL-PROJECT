//*****************************************************************************
//
// Copyright (C) 2014 Texas Instruments Incorporated - http://www.ti.com/
//
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//
//    Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
//    Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
//    Neither the name of Texas Instruments Incorporated nor the names of
//    its contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//*****************************************************************************


//*****************************************************************************
//
// Application Name     -   SSL Demo
// Application Overview -   This is a sample application demonstrating the
//                          use of secure sockets on a CC3200 device.The
//                          application connects to an AP and
//                          tries to establish a secure connection to the
//                          Google server.
// Application Details  -
// docs\examples\CC32xx_SSL_Demo_Application.pdf
// or
// http://processors.wiki.ti.com/index.php/CC32xx_SSL_Demo_Application
//
//*****************************************************************************


//*****************************************************************************
//
//! \addtogroup ssl
//! @{
//
//*****************************************************************************
#include <stdio.h>
#include <stdlib.h>
// Simplelink includes
#include "simplelink.h"

//Driverlib includes
#include "hw_types.h"
#include "hw_ints.h"
#include "rom.h"
#include "rom_map.h"
#include "interrupt.h"
#include "prcm.h"
#include "utils.h"
#include "uart.h"

//Common interface includes
#include "pinmux.h"
#include "gpio_if.h"
#include "common.h"
#include "uart_if.h"
#include "time.h"
#include "cJSON.h"

#define MAX_URI_SIZE 128
#define URI_SIZE MAX_URI_SIZE + 1


#define APPLICATION_NAME        "SSL"
#define APPLICATION_VERSION     "1.1.1"

#define SERVER_NAME                "A3SVKSN2AFXWNX.iot.us-east-1.amazonaws.com"
#define GOOGLE_DST_PORT             8443

#define SL_SSL_CA_CERT "/cert/rootCA.der"
#define SL_SSL_PRIVATE "/cert/private.der"
#define SL_SSL_CLIENT  "/cert/client.der"

//NEED TO UPDATE THIS FOR IT TO WORK!
#define DATE                26    /* Current Date */
#define MONTH               2     /* Month 1-12 */
#define YEAR                2016  /* Current year */
#define HOUR                23    /* Time - hours */
#define MINUTE              39    /* Time - minutes */
#define SECOND              0     /* Time - seconds */

#define GETHEADER "GET /things/cc3200_SC/shadow"
#define POSTHEADER "POST /things/cc3200_SC/shadow"
#define HOSTHEADER "Host: A3SVKSN2AFXWNX.iot.us-east-1.amazonaws.com\r\n"
//#define AUTHHEADER "Authorization: SharedAccessSignature sr=swiftsoftware-ns.servicebus.windows.net&sig=6sIkgCiaNbK9R0XEpsKJcQ2Clv8MUMVdQfEVQP09WkM%3d&se=1733661915&skn=EventHubPublisher\r\n"
#define CHEADER "Connection: Keep-Alive\r\n"
//#define CTHEADER "Content-Type: application/json; charset=utf-8\r\n"
#define CTHEADER "Content-Type: text/plain; charset=utf-8\r\n"
#define CLHEADER1 "Content-Length:"
#define CLHEADER2 "\r\n\r\n"
#define DATA1 "{\"MessageType\":\"CC3200 Sensor\",\"Temp\":"
#define DATA2 ",\"Humidity\":50,\"Location\":\"YourLocation\",\"Room\":\"YourRoom\",\"Info\":\"Sent from CC3200 LaunchPad\"}"

// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    LAN_CONNECTION_FAILED = -0x7D0,
    INTERNET_CONNECTION_FAILED = LAN_CONNECTION_FAILED - 1,
    DEVICE_NOT_IN_STATION_MODE = INTERNET_CONNECTION_FAILED - 1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;

typedef struct
{
   /* time */
   unsigned long tm_sec;
   unsigned long tm_min;
   unsigned long tm_hour;
   /* date */
   unsigned long tm_day;
   unsigned long tm_mon;
   unsigned long tm_year;
   unsigned long tm_week_day; //not required
   unsigned long tm_year_day; //not required
   unsigned long reserved[3];
}SlDateTime;


//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
volatile unsigned long  g_ulStatus = 0;//SimpleLink Status
unsigned long  g_ulPingPacketsRecv = 0; //Number of Ping Packets received
unsigned long  g_ulGatewayIP = 0; //Network Gateway IP address
unsigned char  g_ucConnectionSSID[SSID_LEN_MAX+1]; //Connection SSID
unsigned char  g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID
signed char    *g_Host = SERVER_NAME;
SlDateTime g_time;
#if defined(ccs) || defined(gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************
static int display = 0;
static int rt = 0;


//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static long WlanConnect();
static int set_time();
static void BoardInit(void);
static long InitializeAppVariables();
static int tls_connect(const char host[], int port, unsigned char ucMethod, unsigned int uiCipher, const char cert[]);
static int connectToAccessPoint();
static int http_post(int);

//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************


//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent)
{
    if(!pWlanEvent)
    {
        return;
    }

    switch(pWlanEvent->Event)
    {
        case SL_WLAN_CONNECT_EVENT:
        {
            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);

            //
            // Information about the connected AP (like name, MAC etc) will be
            // available in 'slWlanConnectAsyncResponse_t'.
            // Applications can use it if required
            //
            //  slWlanConnectAsyncResponse_t *pEventData = NULL;
            // pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
            //

            // Copy new connection SSID and BSSID to global parameters
            memcpy(g_ucConnectionSSID,pWlanEvent->EventData.
                   STAandP2PModeWlanConnected.ssid_name,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
            memcpy(g_ucConnectionBSSID,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
                   SL_BSSID_LENGTH);

            UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s , "
                       "BSSID: %x:%x:%x:%x:%x:%x\n\r",
                       g_ucConnectionSSID,g_ucConnectionBSSID[0],
                       g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                       g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                       g_ucConnectionBSSID[5]);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT:
        {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            // If the user has initiated 'Disconnect' request,
            //'reason_code' is SL_USER_INITIATED_DISCONNECTION
            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code)
            {
                UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
                    "BSSID: %x:%x:%x:%x:%x:%x on application's request \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            else
            {
                UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s, "
                           "BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
            memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
        }
        break;

        default:
        {
            UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
                       pWlanEvent->Event);
        }
        break;
    }
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent)
{
    if(!pNetAppEvent)
    {
        return;
    }

    switch(pNetAppEvent->Event)
    {
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT:
        {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            //Ip Acquired Event Data
            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;

            //Gateway IP address
            g_ulGatewayIP = pEventData->gateway;

            UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
                       "Gateway=%d.%d.%d.%d\n\r",
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,0),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,0));
        }
        break;

        default:
        {
            UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
                       pNetAppEvent->Event);
        }
        break;
    }
}


//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent,
                                  SlHttpServerResponse_t *pHttpResponse)
{
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent)
{
    if(!pDevEvent)
    {
        return;
    }

    //
    // Most of the general errors are not FATAL are are to be handled
    // appropriately by the application
    //
    UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
               pDevEvent->EventData.deviceEvent.status,
               pDevEvent->EventData.deviceEvent.sender);
}


//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock)
{
    if(!pSock)
    {
        return;
    }

    switch( pSock->Event )
    {
        case SL_SOCKET_TX_FAILED_EVENT:
            switch( pSock->socketAsyncEvent.SockTxFailData.status)
            {
                case SL_ECLOSE: 
                    UART_PRINT("[SOCK ERROR] - close socket (%d) operation "
                                "failed to transmit all queued packets\n\n", 
                                    pSock->socketAsyncEvent.SockTxFailData.sd);
                    break;
                default: 
                    UART_PRINT("[SOCK ERROR] - TX FAILED  :  socket %d , reason "
                                "(%d) \n\n",
                                pSock->socketAsyncEvent.SockTxFailData.sd, pSock->socketAsyncEvent.SockTxFailData.status);
                  break;
            }
            break;

        default:
        	UART_PRINT("[SOCK EVENT] - Unexpected Event [%x0x]\n\n",pSock->Event);
          break;
    }

}


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************


//*****************************************************************************
//
//! \brief This function initializes the application variables
//!
//! \param    0 on success else error code
//!
//! \return None
//!
//*****************************************************************************
static long InitializeAppVariables()
{
    g_ulStatus = 0;
    g_ulGatewayIP = 0;
    g_Host = SERVER_NAME;
    memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
    memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
    return SUCCESS;
}


//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************
static long ConfigureSimpleLinkToDefaultState()
{
    SlVersionFull   ver = {0};
    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {0};

    unsigned char ucVal = 1;
    unsigned char ucConfigOpt = 0;
    unsigned char ucConfigLen = 0;
    unsigned char ucPower = 0;

    long lRetVal = -1;
    long lMode = -1;

    lMode = sl_Start(0, 0, 0);
    ASSERT_ON_ERROR(lMode);

    // If the device is not in station-mode, try configuring it in station-mode 
    if (ROLE_STA != lMode)
    {
        if (ROLE_AP == lMode)
        {
            // If the device is in AP mode, we need to wait for this event 
            // before doing anything 
            while(!IS_IP_ACQUIRED(g_ulStatus))
            {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
            }
        }

        // Switch to STA role and restart 
        lRetVal = sl_WlanSetMode(ROLE_STA);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Stop(0xFF);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Start(0, 0, 0);
        ASSERT_ON_ERROR(lRetVal);

        // Check if the device is in station again 
        if (ROLE_STA != lRetVal)
        {
            // We don't want to proceed if the device is not coming up in STA-mode 
            return DEVICE_NOT_IN_STATION_MODE;
        }
    }
    
    // Get the device's version-information
    ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
    ucConfigLen = sizeof(ver);
    lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt, 
                                &ucConfigLen, (unsigned char *)(&ver));
    ASSERT_ON_ERROR(lRetVal);
    
    UART_PRINT("Host Driver Version: %s\n\r",SL_DRIVER_VERSION);
    UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
    ver.NwpVersion[0],ver.NwpVersion[1],ver.NwpVersion[2],ver.NwpVersion[3],
    ver.ChipFwAndPhyVersion.FwVersion[0],ver.ChipFwAndPhyVersion.FwVersion[1],
    ver.ChipFwAndPhyVersion.FwVersion[2],ver.ChipFwAndPhyVersion.FwVersion[3],
    ver.ChipFwAndPhyVersion.PhyVersion[0],ver.ChipFwAndPhyVersion.PhyVersion[1],
    ver.ChipFwAndPhyVersion.PhyVersion[2],ver.ChipFwAndPhyVersion.PhyVersion[3]);

    // Set connection policy to Auto + SmartConfig 
    //      (Device's default connection policy)
    lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, 
                                SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove all profiles
    lRetVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(lRetVal);

    

    //
    // Device in station-mode. Disconnect previous connection if any
    // The function returns 0 if 'Disconnected done', negative number if already
    // disconnected Wait for 'disconnection' event if 0 is returned, Ignore 
    // other return-codes
    //
    lRetVal = sl_WlanDisconnect();
    if(0 == lRetVal)
    {
        // Wait
        while(IS_CONNECTED(g_ulStatus))
        {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
        }
    }

    // Enable DHCP client
    lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,1,1,&ucVal);
    ASSERT_ON_ERROR(lRetVal);

    // Disable scan
    ucConfigOpt = SL_SCAN_POLICY(0);
    lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucConfigOpt, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Set Tx power level for station mode
    // Number between 0-15, as dB offset from max power - 0 will set max power
    ucPower = 0;
    lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 
            WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *)&ucPower);
    ASSERT_ON_ERROR(lRetVal);

    // Set PM policy to normal
    lRetVal = sl_WlanPolicySet(SL_POLICY_PM , SL_NORMAL_POLICY, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Unregister mDNS services
    lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove  all 64 filters (8*8)
    memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(lRetVal);

    lRetVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(lRetVal);

    InitializeAppVariables();
    
    return lRetVal; // Success
}


//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void BoardInit(void)
{
/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS
  //
  // Set vector table base
  //
#if defined(ccs)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif
    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}


//****************************************************************************
//
//! \brief Connecting to a WLAN Accesspoint
//!
//!  This function connects to the required AP (SSID_NAME) with Security
//!  parameters specified in te form of macros at the top of this file
//!
//! \param  None
//!
//! \return  0 on success else error code
//!
//! \warning    If the WLAN connection fails or we don't aquire an IP
//!            address, It will be stuck in this function forever.
//
//****************************************************************************
static long WlanConnect()
{
    SlSecParams_t secParams = {0};
    long lRetVal = 0;

    secParams.Key = SECURITY_KEY;
    secParams.KeyLen = strlen(SECURITY_KEY);
    secParams.Type = SECURITY_TYPE;

    lRetVal = sl_WlanConnect(SSID_NAME, strlen(SSID_NAME), 0, &secParams, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Wait for WLAN Event
    while((!IS_CONNECTED(g_ulStatus)) || (!IS_IP_ACQUIRED(g_ulStatus)))
    {
        // Toggle LEDs to Indicate Connection Progress
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOn(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
    }

    return SUCCESS;

}

//*****************************************************************************
//
//! This function updates the date and time of CC3200.
//!
//! \param None
//!
//! \return
//!     0 for success, negative otherwise
//!
//*****************************************************************************

static int set_time()
{
    long retVal;

    g_time.tm_day = DATE;
    g_time.tm_mon = MONTH;
    g_time.tm_year = YEAR;
    g_time.tm_sec = HOUR;
    g_time.tm_hour = MINUTE;
    g_time.tm_min = SECOND;

    retVal = sl_DevSet(SL_DEVICE_GENERAL_CONFIGURATION,
                          SL_DEVICE_GENERAL_CONFIGURATION_DATE_TIME,
                          sizeof(SlDateTime),(unsigned char *)(&g_time));

    ASSERT_ON_ERROR(retVal);
    return SUCCESS;
}

//*****************************************************************************
//
//! This function demonstrates how certificate can be used with SSL.
//! The procedure includes the following steps:
//! 1) connect to an open AP
//! 2) get the server name via a DNS request
//! 3) define all socket options and point to the CA certificate
//! 4) connect to the server via TCP
//!
//! \param None
//!
//! \return  0 on success else error code
//! \return  LED1 is turned solid in case of success
//!    LED2 is turned solid in case of failure
//!
//*****************************************************************************
int tcp_connect(const char host[], unsigned short usPort)
{
    int             iCounter;
    short           sTestBufLen;
    SlSockAddrIn_t  sAddr;
    int             iAddrSize;
    int             iSockID;
    int             iStatus;
    long            lLoopCount = 0;
    unsigned long	ip;
    int lRetVal;
    typedef enum{
        // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
        SOCKET_CREATE_ERROR = -0x7D0,
        BIND_ERROR = SOCKET_CREATE_ERROR - 1,
        LISTEN_ERROR = BIND_ERROR -1,
        SOCKET_OPT_ERROR = LISTEN_ERROR -1,
        CONNECT_ERROR = SOCKET_OPT_ERROR -1,
        ACCEPT_ERROR = CONNECT_ERROR - 1,
        SEND_ERROR = ACCEPT_ERROR -1,
        RECV_ERROR = SEND_ERROR -1,
        SOCKET_CLOSE_ERROR = RECV_ERROR -1,
        DEVICE_NOT_IN_STATION_MODE = SOCKET_CLOSE_ERROR - 1,
        STATUS_CODE_MAX = -0xBB8
    }e_AppStatusCodes;

//    // filling the buffer
//    for (iCounter=0 ; iCounter<BUF_SIZE ; iCounter++)
//    {
//        g_cBsdBuf[iCounter] = (char)(iCounter % 10);
//    }
//
//    sTestBufLen  = BUF_SIZE;

    lRetVal = sl_NetAppDnsGetHostByName(host, strlen(host), (unsigned long*)&ip, SL_AF_INET);
    if(lRetVal < 0) {
        puts("Device couldn't retrive the host name \n\r");
        return lRetVal;
    }

    //filling the TCP server socket address
    sAddr.sin_family = SL_AF_INET;
    sAddr.sin_port = sl_Htons((unsigned short)usPort);
    sAddr.sin_addr.s_addr = sl_Htonl((unsigned int)ip);

    iAddrSize = sizeof(SlSockAddrIn_t);

    // creating a TCP socket
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, 0);
    if( iSockID < 0 )
    {
        ASSERT_ON_ERROR(SOCKET_CREATE_ERROR);
    }

    // connecting to TCP server
    iStatus = sl_Connect(iSockID, ( SlSockAddr_t *)&sAddr, iAddrSize);
    if( iStatus < 0 )
    {
        // error
        sl_Close(iSockID);
        ASSERT_ON_ERROR(CONNECT_ERROR);
    }

    return iSockID;
//    // sending multiple packets to the TCP server
//    while (lLoopCount < g_ulPacketCount)
//    {
//        // sending packet
//        iStatus = sl_Send(iSockID, g_cBsdBuf, sTestBufLen, 0 );
//        if( iStatus < 0 )
//        {
//            // error
//            sl_Close(iSockID);
//            ASSERT_ON_ERROR(SEND_ERROR);
//        }
//        lLoopCount++;
//    }
//
//    Report("Sent %u packets successfully\n\r",g_ulPacketCount);
//
//    iStatus = sl_Close(iSockID);
//    //closing the socket after sending 1000 packets
//    ASSERT_ON_ERROR(iStatus);
//
//    return SUCCESS;
}


static int tls_connect(const char host[], int port, unsigned char ucMethod, unsigned int uiCipher, const char cert[])
{
    SlSockAddrIn_t    Addr;
    int    iAddrSize;
//	unsigned char    ucMethod = SL_SO_SEC_METHOD_TLSV1_2;
//	unsigned char    ucMethod = SL_SO_SEC_METHOD_TLSV1;
//	unsigned int uiIP, uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
//	unsigned int uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    unsigned int uiIP;


    long lRetVal = -1;
    int iSockID;

    //lRetVal = sl_NetAppDnsGetHostByName(g_Host, strlen((const char *)g_Host),(unsigned long*)&uiIP, SL_AF_INET);
    lRetVal = sl_NetAppDnsGetHostByName(host, strlen(host), (unsigned long*)&uiIP, SL_AF_INET);

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't retrive the host name \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    Addr.sin_family = SL_AF_INET;
    Addr.sin_port = sl_Htons(port);
    Addr.sin_addr.s_addr = sl_Htonl(uiIP);
    iAddrSize = sizeof(SlSockAddrIn_t);
    //
    // opens a secure socket 
    //
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, SL_SEC_SOCKET);
    if( iSockID < 0 )
    {
        UART_PRINT("Device unable to create secure socket \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //
    // configure the socket as TLS1.2
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECMETHOD, &ucMethod,\
                               sizeof(ucMethod));
    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    //
    //configure the socket as ECDHE RSA WITH AES256 CBC SHA
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECURE_MASK, &uiCipher,\
                           sizeof(uiCipher));
    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //
    //configure the socket with CA certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                           SL_SO_SECURE_FILES_CA_FILE_NAME, \
						   cert, \
                           strlen(cert));

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //configure the socket with Client Certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
    			SL_SO_SECURE_FILES_CERTIFICATE_FILE_NAME, \
									SL_SSL_CLIENT, \
                           strlen(SL_SSL_CLIENT));

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    //configure the socket with Private Key - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
    		SL_SO_SECURE_FILES_PRIVATE_KEY_FILE_NAME, \
			SL_SSL_PRIVATE, \
                           strlen(SL_SSL_PRIVATE));

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't set socket options \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }


    /* connect to the peer device - Google server */
    lRetVal = sl_Connect(iSockID, ( SlSockAddr_t *)&Addr, iAddrSize);

    if(lRetVal < 0)
    {
        UART_PRINT("Device couldn't connect to AWS server \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }
    else{
    	UART_PRINT("Device has connected to the website:");
    	UART_PRINT(host);
    	UART_PRINT("\n\r");
    }

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOn(MCU_GREEN_LED_GPIO);
    return iSockID;
}

int connectToAccessPoint(){
	long lRetVal = -1;
    GPIO_IF_LedConfigure(LED1|LED3);

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    lRetVal = InitializeAppVariables();
    ASSERT_ON_ERROR(lRetVal);

    //
    // Following function configure the device to default state by cleaning
    // the persistent settings stored in NVMEM (viz. connection profiles &
    // policies, power policy etc)
    //
    // Applications may choose to skip this step if the developer is sure
    // that the device is in its default state at start of applicaton
    //
    // Note that all profiles and persistent settings that were done on the
    // device will be lost
    //
    lRetVal = ConfigureSimpleLinkToDefaultState();
    if(lRetVal < 0)
    {
      if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
          UART_PRINT("Failed to configure the device in its default state \n\r");

      return lRetVal;
    }

    UART_PRINT("Device is configured in default state \n\r");

    CLR_STATUS_BIT_ALL(g_ulStatus);

    ///
    // Assumption is that the device is configured in station mode already
    // and it is in its default state
    //
    lRetVal = sl_Start(0, 0, 0);
    if (lRetVal < 0 || ROLE_STA != lRetVal)
    {
        UART_PRINT("Failed to start the device \n\r");
        return lRetVal;
    }

    UART_PRINT("Device started as STATION \n\r");

    //
    //Connecting to WLAN AP
    //
    lRetVal = WlanConnect();
    if(lRetVal < 0)
    {
        UART_PRINT("Failed to establish connection w/ an AP \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    UART_PRINT("Connection established w/ AP and IP is aquired \n\r");
    return 0;
}

//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************
int post(int iTLSSockID, const char *data)
{
    char acSendBuff[512];
    char acRecvBuff[1460];
    char* pcBufHeaders;
    int lRetVal = 0;
    char tmp[100];

	pcBufHeaders = acSendBuff;
	strcpy(pcBufHeaders, POSTHEADER);
	pcBufHeaders += strlen(POSTHEADER);
	strcpy(pcBufHeaders, " HTTP/1.1\r\n");
	pcBufHeaders += strlen(" HTTP/1.1\r\n");
	strcpy(pcBufHeaders, HOSTHEADER);
	pcBufHeaders += strlen(HOSTHEADER);
	strcpy(pcBufHeaders, CHEADER);
	pcBufHeaders += strlen(CHEADER);
	strcpy(pcBufHeaders, CTHEADER);
	pcBufHeaders += strlen(CTHEADER);
	strcpy(pcBufHeaders, CLHEADER1);
	pcBufHeaders += strlen(CLHEADER1);
	sprintf(tmp, "%d", strlen(data ));
	printf("%s\n", tmp);
	strcpy(pcBufHeaders, tmp);
	pcBufHeaders += strlen(tmp);
	strcpy(pcBufHeaders, CLHEADER2);
	pcBufHeaders += strlen(CLHEADER2);
	strcpy(pcBufHeaders, data);

	//
	// Send the packet to the server */
	//

	lRetVal = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
	if(lRetVal < 0)
	{
		UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal);
    	sl_Close(iTLSSockID);
    	GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    	return lRetVal;
	}

	lRetVal = sl_Recv(iTLSSockID, acRecvBuff, sizeof(acRecvBuff), 0);
	if(lRetVal < 0)
	{
		UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal);
	    //sl_Close(iSSLSockID);
	    GPIO_IF_LedOn(MCU_RED_LED_GPIO);
	       return lRetVal;
	}
	else
	{
		acRecvBuff[lRetVal+1] = '\0';
		UART_PRINT(acRecvBuff);
	}

	return lRetVal;
}

char* get(int iTLSSockID, const char host[], const char endpoint[])
{
    char acSendBuff[512];
    static char acRecvBuff[10000];
    char* pcBufHeaders;
    int lRetVal = 0;
    char tmp[100];

	pcBufHeaders = acSendBuff;
	strcpy(tmp, "GET ");
	strcat(tmp, endpoint);
	strcpy(pcBufHeaders, tmp);
	pcBufHeaders += strlen(tmp);
	strcpy(pcBufHeaders, " HTTP/1.1\r\n");
	pcBufHeaders += strlen(" HTTP/1.1\r\n");
	strcpy(tmp, "Host: ");
	strcat(tmp, host);
	strcat(tmp, "\r\n");
	strcpy(pcBufHeaders, tmp);
	pcBufHeaders += strlen(tmp);
	strcpy(pcBufHeaders, CHEADER);
	pcBufHeaders += strlen(CHEADER);
	strcpy(pcBufHeaders, "\r\n\r\n");

	lRetVal = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
	if(lRetVal < 0)
	{
		UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal);
    	sl_Close(iTLSSockID);
    	GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    	return lRetVal;
	}

	lRetVal = sl_Recv(iTLSSockID, acRecvBuff, sizeof(acRecvBuff), 0);
	if(lRetVal < 0)
	{
		UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal);
	    //sl_Close(iSSLSockID);
	    GPIO_IF_LedOn(MCU_RED_LED_GPIO);
	       return lRetVal;
	}
	else
	{
		acRecvBuff[lRetVal+1] = '\0';
		UART_PRINT(acRecvBuff);
	}

	return acRecvBuff;
}
static int http_post(int iTLSSockID){

    //post(iTLSSockID, "{\"state\": {\"desired\":{\"Charles\":\"Test\"}}}");
    //get(iTLSSockID, "anz.co.nz", "/");
	get(iTLSSockID, "ip-api.com", "/json");

	return 0;
}


//*****************************************************************************
//
//! Main
//!
//! \param  none
//!
//! \return None
//!
//*****************************************************************************
//void main()
//{
//    long lRetVal = -1;
//    //
//    // Initialize board configuration
//    //
//    BoardInit();
//
//    PinMuxConfig();
//
//    InitTerm();
//    //Connect the CC3200 to the local access point
//    lRetVal = connectToAccessPoint();
//    //Set time so that encryption can be used
//    lRetVal = set_time();
//    if(lRetVal < 0)
//    {
//        UART_PRINT("Unable to set time in the device");
//        LOOP_FOREVER();
//    }
//    //Connect to the website with TLS encryption
//    lRetVal = tls_connect();
//    if(lRetVal < 0)
//    {
//        ERR_PRINT(lRetVal);
//    }
//    http_post(lRetVal);
//
//    sl_Stop(SL_STOP_TIMEOUT);
//    LOOP_FOREVER();
//}





/// Standard includes
#include <string.h>

// Driverlib includes
#include "hw_types.h"
#include "hw_memmap.h"
#include "hw_common_reg.h"
#include "hw_ints.h"
#include "spi.h"
#include "rom.h"
#include "rom_map.h"
#include "utils.h"
#include "prcm.h"
#include "uart.h"
#include "interrupt.h"
#include "gpio.h"
#include "timer.h"

// Common interface includes
#include "uart_if.h"
#include "Adafruit_GFX.h"
#include "Adafruit_SSD1351.h"
#include "glcdfont.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>


#define APPLICATION_VERSION     "1.1.1"
#define CONSOLE              UARTA0_BASE
#define REMOTE				 UARTA1_BASE
#define UartGetChar()        MAP_UARTCharGet(CONSOLE)
#define UartPutChar(c)       MAP_UARTCharPut(CONSOLE,c)
#define RemoteGetChar()        MAP_UARTCharGet(REMOTE)
#define RemotePutChar(c)       MAP_UARTCharPut(REMOTE,c)
#define MAX_STRING_LENGTH    80

#define SPI_IF_BIT_RATE  20000000
#define TR_BUFF_SIZE     100

//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************

#if defined(ccs)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************

#define COMMON 8000,4000,550,450,550,450,550,1500,550,450,550,1500,550,450,550,450,550,450,550,4000	// 20 // This part of the waveform time intervals that are common to all of the keys

typedef struct {
	int values[60]; // We did not use the values array at the end
	int times[60];
} Key;

Key zero, one, two, three, four, five, six, seven, eight, nine;
Key enter, up, down, left, right, ok, volUp, volDown, chUp, chDown;
Key *keys[] = {&zero, &one, &two, &three, &four, &five, &six, &seven, &eight, &nine, &enter, &up, &down, &left, &right, &ok, &volUp, &volDown, &chUp, &chDown};
int globalBuffer[100];
int bufferSize = 0;
void initializeKeys(int len, int timestamps[], Key *key)
{
	int i;

	for (i = 0; i < len; i++) {
		key->times[i] = timestamps[i];
	}
	key->times[i] = -1; // Indicate the end of a time interval sequence
}

void init() // initialize the LUT
{

		int seq0[] = {COMMON,550,450,550,450,550,450,550,450,550,450,550,450,550,450,550,450,550};
		int seq1[] = {COMMON,550,1500,550,450,550,450,550,450,550,450,550,450,550,450,550,450,550};
		int seq2[] = {COMMON,550,450,550,1500,550,450,550,450,550,450,550,450,550,450,550,450,550};
		int seq3[] = {COMMON,550,1500,550,1500,550,450,550,450,550,450,550,450,550,450,550,450,550};
		int seq4[] = {COMMON,550,450,550,450,550,1500,550,450,550,450,550,450,550,450,550,450,550};
		int seq5[] = {COMMON,550,1500,550,450,550,1500,550,450,550,450,550,450,550,450,550,450,550};
		int seq6[] = {COMMON,550,450,550,1500,550,1500,550,450,550,450,550,450,550,450,550,450,550};
		int seq7[] = {COMMON,550,1500,550,1500,550,1500,550,450,550,450,550,450,550,450,550,450,550};
		int seq8[] = {COMMON,550,450,550,450,550,450,550,1500,550,450,550,450,550,450,550,450,550};
		int seq9[] = {COMMON,550,1500,550,450,550,450,550,1500,550,450,550,450,550,450,550,450,550};
		int seqenter[] = {COMMON,550,1500,550,1500,550,1500,550,450,550,1500,550,1500,550,450,550,450,550};
		int sequp[] = {COMMON,550,450,550,450,550,1500,550,1500,550,1500,550,450,550,450,550,450,550};
		int seqdown[] = {COMMON,550,1500,550,450,550,1500,550,1500,550,1500,550,450,550,450,550,450,550};
		int seqleft[] = {COMMON,550,450,550,1500,550,1500,550,1500,550,1500,550,450,550,450,550,450,550};
		int seqright[] = {COMMON,550,1500,550,1500,550,1500,550,1500,550,1500,550,450,550,450,550,450,550};
		int seqok[] = {COMMON,550,1500,550,1500,550,1500,550,450,550,1500,550,1500,550,450,550,450,550};
		int seqvolup[] = {COMMON,550,1500,550,1500,550,450,550,450,550,1500,550,450,550,450,550,450,550};
		int seqvoldown[] = {COMMON,550,450,550,450,550,1500,550,450,550,1500,550,450,550,450,550,450,550};
		int seqchup[] = {COMMON,550,1500,550,1500,550,1500,550,450,550,1500,550,450,550,450,550,450,550};
		int seqchdown[] = {COMMON,550,450,550,450,550,450,550,1500,550,1500,550,450,550,450,550,450,550};

	initializeKeys(37, seq0, keys[0]);
	initializeKeys(37, seq1, keys[1]);
	initializeKeys(37, seq2, keys[2]);
	initializeKeys(37, seq3, keys[3]);
	initializeKeys(37, seq4, keys[4]);
	initializeKeys(37, seq5, keys[5]);
	initializeKeys(37, seq6, keys[6]);
	initializeKeys(37, seq7, keys[7]);
	initializeKeys(37, seq8, keys[8]);
	initializeKeys(37, seq9, keys[9]);
	initializeKeys(37, seqenter, keys[10]);
	initializeKeys(37, sequp, keys[11]);
	initializeKeys(37, seqdown, keys[12]);
	initializeKeys(37, seqleft, keys[13]);
	initializeKeys(37, seqright, keys[14]);
	initializeKeys(37, seqok, keys[15]);
	initializeKeys(37, seqvolup, keys[16]);
	initializeKeys(37, seqvoldown, keys[17]);
	initializeKeys(37, seqchup, keys[18]);
	initializeKeys(37, seqchdown, keys[19]);
}

// This function will only update the global buffer only if there is a valid keystroke found
int search(int pattern[])
{
	int i, j;
	int actual, ref;
	long diff;
	int found;

	for (i = 0; i < 20; i++) { // there are a total number of 20 valid keys
		found = 1;
		for (j = 0; j < 37; j++) { // each valid waveform has 37 time intervals
			actual = pattern[j];
			ref = keys[i]->times[j];
			diff = 100 * (actual - ref) / ref;
			if (diff > 15 || diff < -15) {	// greater than 15% difference (error tolerance)
				found = 0;
				break; // break the current the iteration immediately when there is a mismatch, go to next key in LUT
			}
		}

		if (found) { // find a match in LUT table
			break;
		}
	}

	if (found) { // store the key stroke into the global buffer
		globalBuffer[bufferSize] = i;
		bufferSize++;
		return i;
	} else {
		return -1;
	}
}

enum {LEFT, RIGHT, UP, DOWN, VOLUP, VOLDOWN, CHUP, CHDOWN, ENTER, num_types};

// This function converts keystrokes history into a char
char convert(int keys[])
{
	//printf("convert\n");

	int i;
	int one = 0;
	int four = 0;
	int five = 0;
	int offset;

	// Get rid of redundant keystrokes

	for (i = 0; i <= (bufferSize-1) % 4; i++) {
		offset = (bufferSize - 1) / 4 * 4;
		four = 10 * four + keys[offset + i];
	}

	for (i = 0; i <= (bufferSize - 1) % 5; i++) {
		offset = (bufferSize - 1) / 5 * 5;
		five = 10 * five + keys[offset + i];
	}

	if (keys[0] == 0) {
		if (bufferSize % 2) {
			return '0';
		} else {
			return ' ';
		}
	}

	if (keys[0] == 1){
	      return '1';
	}

	// four options
	switch (four) {
	case 2:
	      return 'a';
	case 22:
	      return 'b';
	case 222:
	      return 'c';
	case 2222:
	      return '2';
	case 3:
	      return 'd';
	case 33:
	      return 'e';
	case 333:
	      return 'f';
	case 3333:
	      return '3';
	case 4:
	      return 'g';
	case 44:
	      return 'h';
	case 444:
	      return 'i';
	case 4444:
	      return '4';
	case 5:
	      return 'j';
	case 55:
	      return 'k';
	case 555:
	      return 'l';
	case 5555:
	      return '5';
	case 6:
	      return 'm';
	case 66:
	      return 'n';
	case 666:
	      return 'o';
	case 6666:
	      return '6';
	case 8:
	      return 't';
	case 88:
	      return 'u';
	case 888:
	      return 'v';
	case 8888:
	      return '8';
	}

	// five options
	switch (five) {
	case 7:
	      return 'p';
	case 77:
	      return 'q';
	case 777:
	      return 'r';
	case 7777:
	      return 's';
	case 77777:
	      return '7';
	case 9:
	      return 'w';
	case 99:
	      return 'x';
	case 999:
	      return 'y';
	case 9999:
	      return 'z';
	case 99999:
	      return '9';
	}

	switch (keys[0]) {
	case 10:
	case 15: // 10 & 15 are two different keys that have the same wave pattern
		return ENTER;
	case 11:
		return UP;
	case 12:
		return DOWN;
	case 13:
		return LEFT;
	case 14:
		return RIGHT;
	case 16:
		return VOLUP;
	case 17:
		return VOLDOWN;
	case 18:
		return CHUP;
	case 19:
		return CHDOWN;
	default:
		return 127;
	}
}



void initUART1() {
// Init UART1
	MAP_UARTConfigSetExpClk(UARTA1_BASE, PRCMPeripheralClockGet(PRCM_UARTA1), UART_BAUD_RATE,
			(UART_CONFIG_WLEN_8|UART_CONFIG_STOP_ONE|UART_CONFIG_PAR_NONE));
}

// Use this function to send string over UART 1
void Message2(const char *str)
{
    if(str != NULL)
    {
        while(*str!='\0')
        {
            MAP_UARTCharPut(REMOTE,*str++);
        }

    }
}



static int pos2 = 0;
static int vals[2000];
static int times[2000];

static int global_flag = 0;

void ir_handler(void)
{
	printf("IR handler\n");//
	rt = 1;
	//fillscreen(0);
	display++;
	if (display == 3)
		display = 0;

	global_flag = 1;
	static int pos3 = 0;
	static int buf[40];
	static int ready = 1;
	static int pressed = 0;
	int interval;
	int i;

	interval = ((40000000-TimerValueGet(TIMERA0_BASE, TIMER_A)) / 80); // in microseconds

if (interval > 50000) { // if interval is greater than this threshold, it means it’s a new press from the IR remote control
		ready = 1;
		pressed = 0;
	}

	if (interval > 15000) { // repetitive waveform or new waveform received
		if (!ready || pressed) return; // do not update the buf we received a repetitive message
		pos3 = 0;
	} else {
		if (!ready) return;
		buf[pos3++] = interval; // recording the current waveform
	}
	pressed = 1; // means the key is still being pressed by the user

	if (pos3 == 37) { // One complete waveform has been recorded
	    GPIOIntDisable(GPIOA3_BASE, 0x10);
		search(buf); // Turn off the interrupts to search buf in LUT then turn it back on
	    GPIOIntEnable(GPIOA3_BASE, 0x10);
	    ready = 0; // means finishing interpret the press
	}

	GPIOIntClear(GPIOA3_BASE, 0x10);
    TimerValueSet(TIMERA0_BASE,TIMER_A,40000000); // reset the timer, so we don’t have to worry about underflow.
}

static char U_buffer[30];
static int pos = 0;
static int lineNumber = 0;
static int print_flag = 0;
void uart1_handler(void)
{

	char c = RemoteGetChar();

	if (c == '\n' || c == '\r' || pos > 20) { // if enter is hit or the content is longer than one row, output the buffer
		U_buffer[pos] = '\0';
		pos = 0;
		print_flag = 1;
	} else { // else store the char into the buffer
		U_buffer[pos++] = c;
	}
}


cJSON* getJson(int socket, const char host[], const char path[])
{
    cJSON *json;

    while (NULL == (json = cJSON_Parse(strchr(get(socket, host, path), '{')))) {
    	puts("\nerror!!!");
    	UtilsDelay(100000000);
    }

    return json;
}

//*****************************************************************************
//
//! Main function for spi demo application
//!
//! \param none
//!
//! \return None.
//
//*****************************************************************************

void page1(cJSON *json_geo, cJSON *json_currently, cJSON *json_daily, int *reset)
{
	//while(1)
	//{
	//printf("flag is %d\n", global_flag);
	char temp[100];
	char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	time_t timep;
	struct tm *p;

    static char olddate[30] = {0};
    static char oldtime1[20] = {0};
    static char oldtime2[20] = {0};
    static char address[20] = {0};
    static char temperature[30] = {0};
    static char pressure[30] = {0};
    static char forecast[100] = {0};


    	//writeCommand(SSD1351_CMD_DISPLAYOFF);
    	//UtilsDelay(2000000);
    	//fillRect(0, 0, 100, 100, 0);
    	//writeCommand(SSD1351_CMD_DISPLAYON);
    	//writeCommand(SSD1351_CMD_NORMALDISPLAY);

     if (*reset) {
     	fillRect(0, 0, 128, 128, 0);
     	*olddate = *oldtime1 = *oldtime2 = *address = *temperature = *pressure = *forecast = 0;
     	*reset = 0;
     }
    	setCursor(0,0);
        time(&timep);
        p = localtime(&timep);

        setTextSize(2);
		sprintf (temp, "%02d/%02d/%d\n%s\n\n", (1 + p->tm_mon), p->tm_mday, (1900+p->tm_year), wday[p->tm_wday]);
		if (strcmp(olddate, temp) == 0) {
			Outstr("\n\n\n");
		} else {
			Outstr(temp);
			strcpy(olddate, temp);
		}

		setTextSize(3);
		sprintf(temp, "%02d:%02d", p->tm_hour, p->tm_min);
		if (strcmp(oldtime1, temp) == 0) {
			setCursor(getX()+5*6*getTextSize(), getY()+6);
		} else {
			Outstr(temp);
			setCursor(getX(), getY()+6);
			strcpy(oldtime1, temp);
		}

		setTextSize(2);
		sprintf(temp, " %02d\n\n", p->tm_sec);
		if (strcmp(oldtime2, temp) != 0) {
			Outstr(temp);
			strcpy(oldtime2, temp);
		}

		setTextSize(1);
	//        printf("%s, ", cJSON_GetObjectItem(json_geo, "city")->valuestring);
	//        printf("%s ", cJSON_GetObjectItem(json_geo, "region")->valuestring);
	//        printf("%s\n", cJSON_GetObjectItem(json_geo, "zip")->valuestring);

		sprintf(temp, "%s, %s %s\n", cJSON_GetObjectItem(json_geo, "city")->valuestring, cJSON_GetObjectItem(json_geo, "region")->valuestring, cJSON_GetObjectItem(json_geo, "zip")->valuestring);
		if (strcmp(address, temp) == 0) {
			Outstr("\n");
		}else{
			Outstr(temp);
			strcpy(address, temp);
		}

		if (p->tm_sec % 10 < 5) {
			sprintf(temp, "  Pressure : %.1f\n", cJSON_GetObjectItem(json_currently, "pressure")->valuedouble);
			if (strcmp(pressure, temp) != 0) {
				fillRect(getX(), getY(), SSD1351WIDTH, 24, 0);
				Outstr(temp);
				strcpy(pressure, temp);
			}sprintf(temp, "Temperature: %.1f\n", cJSON_GetObjectItem(json_currently, "temperature")->valuedouble);
			if (strcmp(temperature, temp) != 0) {
				Outstr(temp);
				strcpy(temperature, temp);
			}

			forecast[0] = '\0';
		} else {
			sprintf(temp, "%s\n", cJSON_GetObjectItem(json_daily, "summary")->valuestring);
			if (strcmp(forecast, temp) != 0) {
				fillRect(getX(), getY(), SSD1351WIDTH, 24, 0);
				Outstr(temp);
				strcpy(forecast, temp);
			}
			temperature[0] = '\0';
			pressure[0] = '\0';
		}

		if(global_flag)
		{
			global_flag = 0;
			//break;
		}

	//}
} // end of page 1

void page2(cJSON *json_geo, int *reset)
{
    static char temp[100];
    static char title1[20] = {0};
    static char title2[20] = {0};
    static char ip[20] = {0};
    static char isp[30] = {0};
    static char org[30] = {0};
    static char address[20] = {0};
    static char country[20] = {0};
    static char lat[20] = {0};
    static char lon[20] = {0};

    if (*reset) {
    	//printf("reset\n");
    	fillRect(0, 0, 128, 128, 0);
    	*title1 = *title2 = *ip = *isp = *org = *address = *country = *lat = *lon = 0;
    	*reset = 0;
    }

	//writeCommand(SSD1351_CMD_DISPLAYOFF);
	//UtilsDelay(2000000);
	//fillRect(0, 0, 100, 100, 0);
	//writeCommand(SSD1351_CMD_DISPLAYON);
	//writeCommand(SSD1351_CMD_NORMALDISPLAY);
    setCursor(0,0);

    setTextSize(2);
	sprintf (temp, "  %s\n", "IP Info");
	if (strcmp(title1, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(title1, temp);
	}

	setTextSize(1);
	sprintf (temp, "\nIP: %s\n", cJSON_GetObjectItem(json_geo, "query")->valuestring);
	if (strcmp(ip, temp) == 0) {
		Outstr("\n\n");
	} else {
		Outstr(temp);
		strcpy(ip, temp);
	}

	sprintf(temp, "ISP: %s\n", cJSON_GetObjectItem(json_geo, "isp")->valuestring);
	if (strcmp(isp, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(isp, temp);
	}

	sprintf(temp, "Org: %s\n\n", cJSON_GetObjectItem(json_geo, "org")->valuestring);
	if (strcmp(org, temp) == 0) {
		Outstr("\n\n");
	} else {
		Outstr(temp);
		strcpy(org, temp);
	}

    setTextSize(2);
	sprintf (temp, "  %s\n", "Geo Info");
	if (strcmp(title2, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(title2, temp);
	}

    setTextSize(1);
	sprintf(temp, "\n%s, %s %s\n", cJSON_GetObjectItem(json_geo, "city")->valuestring, cJSON_GetObjectItem(json_geo, "region")->valuestring, cJSON_GetObjectItem(json_geo, "zip")->valuestring);
	if (strcmp(address, temp) == 0) {
		Outstr("\n\n");
	}else{
		Outstr(temp);
		strcpy(address, temp);
	}

	sprintf(temp, "%s\n", cJSON_GetObjectItem(json_geo, "country")->valuestring);
	if (strcmp(country, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(country, temp);
	}

	sprintf(temp, "Lat: %.4f\n", cJSON_GetObjectItem(json_geo, "lat")->valuedouble);
	if (strcmp(lat, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(lat, temp);
	}

	sprintf(temp, "Lon: %.4f\n", cJSON_GetObjectItem(json_geo, "lon")->valuedouble);
	if (strcmp(lon, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(lon, temp);
	}
//
//	setTextSize(2);
//	sprintf(temp, " %02d\n\n", p->tm_sec);
//	if (strcmp(oldtime2, temp) != 0) {
//		Outstr(temp);
//		strcpy(oldtime2, temp);
//	}
	//printf("end of page 2");
} // end of page 2

void page3(cJSON *json_currently, cJSON *json_daily, int *reset)
{
    char temp[100];
    char *wday[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    time_t timep;
    struct tm *p;
    static char title[20] = {0};
    static char temperature[30] = {0};
    static char humidity[30] = {0};
    static char windspeed[30] = {0};
    static char windbearing[30] = {0};
    static char visibility[30] = {0};
    static char cloudcover[30] = {0};
    static char pressure[30] = {0};
    static char summary[60] = {0};
    static char forecast[60] = {0};

	//writeCommand(SSD1351_CMD_DISPLAYOFF);
	//UtilsDelay(2000000);
	//fillRect(0, 0, 100, 100, 0);
	//writeCommand(SSD1351_CMD_DISPLAYON);
	//writeCommand(SSD1351_CMD_NORMALDISPLAY);
    if (*reset) {
    	fillRect(0, 0, 128, 128, 0);
        *title = *temperature = *humidity = *windspeed = *windbearing = *visibility = *cloudcover = *pressure = *summary = *forecast = 0;
        *reset = 0;
    }

	setCursor(0,0);
    setTextSize(2);
	sprintf (temp, "  %s\n", "Weather");
	if (strcmp(title, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(title, temp);
	}

	setTextSize(1);
	sprintf (temp, "\nTemperature: %.1f F\n", cJSON_GetObjectItem(json_currently, "temperature")->valuedouble);
	if (strcmp(temperature, temp) == 0) {
		Outstr("\n\n");
	} else {
		Outstr(temp);
		strcpy(temperature, temp);
	}

	sprintf (temp, "Humidity   : %.0f%%\n", 100*cJSON_GetObjectItem(json_currently, "humidity")->valuedouble);
	if (strcmp(humidity, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(humidity, temp);
	}

	sprintf (temp, "Windspeed  : %.1f MPH\n", cJSON_GetObjectItem(json_currently, "windSpeed")->valuedouble);
	if (strcmp(windspeed, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(windspeed, temp);
	}

	sprintf (temp, "Windbearing: %d`\n", cJSON_GetObjectItem(json_currently, "windBearing")->valueint);
	if (strcmp(windbearing, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(windbearing, temp);
	}

	sprintf (temp, "Visibility : %.1f Mi\n", cJSON_GetObjectItem(json_currently, "visibility")->valuedouble);
	if (strcmp(visibility, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(visibility, temp);
	}

	sprintf (temp, "Cloudcover : %.0f%%\n", 100*cJSON_GetObjectItem(json_currently, "cloudCover")->valuedouble);
	if (strcmp(cloudcover, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(cloudcover, temp);
	}

	sprintf (temp, "Pressure  : %.1f kPa\n", 0.1 * cJSON_GetObjectItem(json_currently, "pressure")->valuedouble);
	if (strcmp(pressure, temp) == 0) {
		Outstr("\n");
	} else {
		Outstr(temp);
		strcpy(pressure, temp);
	}

	sprintf (temp, "Summary: %s\n", cJSON_GetObjectItem(json_currently, "summary")->valuestring);
	if (strcmp(summary, temp) == 0) {
		Outstr("\n\n");
	} else {
		Outstr(temp);
		strcpy(summary, temp);
	}

	sprintf (temp, "Forecast:\n  %s\n", cJSON_GetObjectItem(json_daily, "summary")->valuestring);
	if (strcmp(forecast, temp) == 0) {
		Outstr("\n\n");
	} else {
		Outstr(temp);
		strcpy(forecast, temp);
	}
} // end of page 3

void main()
{
    //
    // Initialize Board configurations
    //
    BoardInit();

    //
    // Muxing UART and SPI lines.
    //
    PinMuxConfig();

    //
    // Enable the SPI module clock
    //
    MAP_PRCMPeripheralClkEnable(PRCM_GSPI,PRCM_RUN_MODE_CLK);

    //
    // Reset the peripheral
    //
    MAP_PRCMPeripheralReset(PRCM_GSPI);

    MAP_SPIReset(GSPI_BASE);

    //
    // Configure SPI interface
    //
    MAP_SPIConfigSetExpClk(GSPI_BASE,MAP_PRCMPeripheralClockGet(PRCM_GSPI),
                     SPI_IF_BIT_RATE,SPI_MODE_MASTER,SPI_SUB_MODE_0,
                     (SPI_SW_CTRL_CS |
                     SPI_4PIN_MODE |
                     SPI_TURBO_OFF |
                     SPI_CS_ACTIVELOW |
                     SPI_WL_8));
    //
    // Enable the SPI communication
    //
    MAP_SPIEnable(GSPI_BASE);

    //
    // Initialize OLED screen
    //
    Adafruit_Init();

    //
    // Clear the OLED screen
    //
    fillScreen(0);

    //
    // Initialize the UART 1 interface
    //
    initUART1();

    //
    // Disable the UART1 FIFO
    //
    UARTFIFODisable(REMOTE);

    //
    // Register the uart1_handler into the interrupt table
    //
    UARTIntRegister(REMOTE, uart1_handler);

    //
    // Enable the UART1 interrupt
    //
    UARTIntEnable(REMOTE, UART_INT_RX);

    char c;
    char buffer[340];
    int pos = 0;

    //
    // Configure the GPIO interrupts
    //
    GPIOIntTypeSet(GPIOA3_BASE, 0x10, GPIO_BOTH_EDGES);
    GPIOIntRegister(GPIOA3_BASE, ir_handler);
    GPIOIntEnable(GPIOA3_BASE, 0x10);

    //
    // Configure the timer
    //
    PRCMPeripheralReset(PRCM_TIMERA0);
    TimerConfigure(TIMERA0_BASE, TIMER_CFG_A_PERIODIC);
    TimerLoadSet(TIMERA0_BASE,TIMER_A,40000000);
    TimerEnable(TIMERA0_BASE,TIMER_A);


    init();// initialize the LUT
	char OLEDbuf[22];
	char tmp[22];
	char preOLEDbuf[22];
	OLEDbuf[1] = '\0';
	int OLEDptr = 0;
	int ypos = 0; //screen pointer
    long lRetVal = -1;
    long socket_geo;
    long socket_weather1;
    long socket_weather2;
    long socket_weather3;

    cJSON *json_geo;
    cJSON *json_weather1;
    cJSON *json_currently1;
    cJSON *json_daily1;

    cJSON *json_weather2;
    cJSON *json_currently2;
    cJSON *json_daily2;

    cJSON *json_weather3;
    cJSON *json_currently3;
    cJSON *json_daily3;

    fillScreen(0);
    Outstr("Trying to connect...\n");

    lRetVal = connectToAccessPoint();	//Connect the CC3200 to the local access point
    lRetVal = set_time();				//Set time so that encryption can be used
    if(lRetVal < 0)
    {
        UART_PRINT("Unable to set time in the device");
        LOOP_FOREVER();
    }

    //Outstr("Welcome!\n");
    //UtilsDelay(8000);

    lRetVal = tcp_connect("ip-api.com", 80);
    if(lRetVal < 0) ERR_PRINT(lRetVal);
    socket_geo = lRetVal;
    json_geo = getJson(socket_geo, "ip-api.com", "/json");

	puts("\n");
	puts(cJSON_GetObjectItem(json_geo, "city")->valuestring);
	puts(cJSON_GetObjectItem(json_geo, "region")->valuestring);
	puts(cJSON_GetObjectItem(json_geo, "zip")->valuestring);
	puts(cJSON_GetObjectItem(json_geo, "org")->valuestring);
	printf("%lf\n", cJSON_GetObjectItem(json_geo, "lat")->valuedouble);
	printf("%lf\n", cJSON_GetObjectItem(json_geo, "lon")->valuedouble);


    //lRetVal = tcp_connect("www.timeapi.org", 80);
    //if(lRetVal < 0) ERR_PRINT(lRetVal);
    //socket_geo = lRetVal;
    //get(socket_geo, "www.timeapi.org", "/utc");

//    lRetVal = tls_connect("A3SVKSN2AFXWNX.iot.us-east-1.amazonaws.com", 8443, SL_SO_SEC_METHOD_TLSV1_2, SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "/cert/rootCA.der");	//Connect to the website with TLS encryption
//    if(lRetVal < 0) ERR_PRINT(lRetVal);
//    socket_weather = lRetVal;
//    get(socket_weather, "A3SVKSN2AFXWNX.iot.us-east-1.amazonaws.com", "/things/cc3200_SC/shadow");

//    lRetVal = tls_connect("api.forecast.io", 443, SL_SO_SEC_METHOD_TLSV1_2, SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "/cert/digicert.der");	//Connect to the website with TLS encryption
//    if(lRetVal < 0) ERR_PRINT(lRetVal);
//    socket_weather = lRetVal;
//    get(socket_weather, "api.forecast.io", "/forecast/b76fd26746296b8f3a5393dfe5ea1493/37.8267,-122.423");

    lRetVal = tls_connect("api.forecast.io", 443, SL_SO_SEC_METHOD_TLSV1_2, SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "/cert/digicert.der");	//Connect to the website with TLS encryption
    if(lRetVal < 0) ERR_PRINT(lRetVal);
    socket_weather1 = lRetVal;
    json_weather1 = getJson(socket_weather1, "api.forecast.io", "/forecast/b76fd26746296b8f3a5393dfe5ea1493/37.8267,-122.423?exclude=minutely,hourly,alerts,flags");
	json_daily1 = cJSON_GetObjectItem(json_weather1, "daily");
	json_daily1 = cJSON_GetObjectItem(json_daily1, "data");
	json_daily1 = cJSON_GetArrayItem(json_daily1, 0);
	json_currently1 = cJSON_GetObjectItem(json_weather1, "currently");
	puts("\n");
	printf("%.1f degrees\n", cJSON_GetObjectItem(json_currently1, "temperature")->valuedouble);
	puts(cJSON_GetObjectItem(json_daily1, "summary")->valuestring);


	//lRetVal = tls_connect("api.forecast.io", 443, SL_SO_SEC_METHOD_TLSV1_2, SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "/cert/digicert.der");	//Connect to the website with TLS encryption
	//if(lRetVal < 0) ERR_PRINT(lRetVal);
	//socket_weather2 = lRetVal;
    //json_weather2 = getJson(socket_weather2, "api.forecast.io", "/forecast/b76fd26746296b8f3a5393dfe5ea1493/40.7127,-74.0059?exclude=minutely,hourly,alerts,flags");
	//json_daily2 = cJSON_GetObjectItem(json_weather2, "daily");
	//json_daily2 = cJSON_GetObjectItem(json_daily2, "data");
	//json_daily2 = cJSON_GetArrayItem(json_daily2, 0);
	//json_currently2 = cJSON_GetObjectItem(json_weather2, "currently");
	//puts("\n");
	//printf("%.1f degrees\n", cJSON_GetObjectItem(json_currently2, "temperature")->valuedouble);
	//puts(cJSON_GetObjectItem(json_daily2, "summary")->valuestring);

    //json_weather3 = getJson(socket_weather, "api.forecast.io", "/forecast/b76fd26746296b8f3a5393dfe5ea1493/39.9167,116.3833?exclude=minutely,hourly,alerts,flags");
	//json_daily3 = cJSON_GetObjectItem(json_weather3, "daily");
	//json_daily3 = cJSON_GetObjectItem(json_daily3, "data");
	//json_daily3 = cJSON_GetArrayItem(json_daily3, 0);
	//json_currently3 = cJSON_GetObjectItem(json_weather3, "currently");

    /*
	char temp[100];
    char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    time_t timep;
    struct tm *p;
    char olddate[20];
    char oldtime1[20];
    char oldtime2[20];
	*/

//    while(1) {
//    	//writeCommand(SSD1351_CMD_DISPLAYOFF);
//    	//UtilsDelay(2000000);
//    	//fillRect(0, 0, 100, 100, 0);
//    	//writeCommand(SSD1351_CMD_DISPLAYON);
//    	//writeCommand(SSD1351_CMD_NORMALDISPLAY);
//    	setCursor(0,0);
//        time(&timep);
//        p = localtime(&timep);
//
//        setTextSize(2);
//		sprintf (temp, "%02d/%02d/%d\n%s\n\n", (1 + p->tm_mon), p->tm_mday, (1900+p->tm_year), wday[p->tm_wday]);
//		if (strcmp(olddate, temp) == 0) {
//			Outstr("\n\n\n");
//		} else {
//			Outstr(temp);
//			strcpy(olddate, temp);
//		}
//
//		setTextSize(3);
//		sprintf(temp, "%02d:%02d", p->tm_hour, p->tm_min);
//		if (strcmp(oldtime1, temp) == 0) {
//			setCursor(getX()+5*6*getTextSize(), getY()+6);
//		} else {
//			Outstr(temp);
//			setCursor(getX(), getY()+6);
//			strcpy(oldtime1, temp);
//		}
//
//		setTextSize(2);
//		sprintf(temp, " %02d\n\n", p->tm_sec);
//		if (strcmp(oldtime2, temp) != 0) {
//			Outstr(temp);
//			strcpy(oldtime2, temp);
//		}
//
//		sprintf(temp, "Temp: %d\n", p->tm_sec);
//		if (strcmp(oldtime2, temp) != 0) {
//			Outstr(temp);
//			strcpy(oldtime2, temp);
//		}
//
//    } // end of while true

//    http_post(lRetVal);

    fillScreen(0);
    global_flag = 0;
    //printf("hello\n");

    //printf("exit mainDisplay\n");

    char add1[100];
    char add2[100];
    char add3[100];

    sprintf(add1, "%s, %s %s\n", cJSON_GetObjectItem(json_geo, "city")->valuestring, cJSON_GetObjectItem(json_geo, "region")->valuestring, cJSON_GetObjectItem(json_geo, "zip")->valuestring);
    sprintf(add2, "%s, %s %s\n", "New York City", "NY", "USA");
    sprintf(add3, "%s, %s %s\n", "Shanghai", "China", "Asia");


    while(1)
    {
//    	if(print_flag)
//    	{
//    	    GPIOIntDisable(GPIOA3_BASE, 0x10);
//    	    UARTIntDisable(REMOTE, UART_INT_RX);
//
//    	    // atomic operation
//    	    setCursor(0,64 + lineNumber*8);
//    		Outstr(U_buffer);
//    		print_flag = 0;
//    		lineNumber++;
//
//    	    GPIOIntEnable(GPIOA3_BASE, 0x10);
//    	    UARTIntEnable(REMOTE, UART_INT_RX);
//    	}
    	if(display == 0)
    	{
    		//printf("page1\n");
        	page1(json_geo, json_currently1, json_daily1, &rt);
        	//MAP_UtilsDelay(1000);
    	}
    	else if(display == 1)
    	{
    		//printf("page2\n");
    		page2(json_geo,&rt);
    		//rt = 1;
    		//page1(add2, json_currently1, json_daily1);
    	}
    	else if (display == 2)
    	{
    		//printf("pag3\n");
    		page3(json_currently1, json_daily1, &rt);
    		//page1(add3, json_currently1, json_daily1);
    	}
    	int screen_count = 0;

    	//printf("case switch\n");
    	c = convert(globalBuffer); // convert key strokes history into character
    	if (c < num_types) {
    		// control character received

    		switch (c) {
    		printf("case switch\n");
    		case LEFT:

    			printf("Left\n");
    			fillScreen(0);
    			global_flag = 0;

    			setCursor(0,0); //
    			Outstr("LEFT\n"); //

    			//page1(add1, json_currently1, json_daily1, &reset);
    			rt = 1;
    			printf("exit page\n");
    			display = 0;
    			//setCursor(0,0);
    			//Outstr("left\n");
        		//fillRect(strlen(OLEDbuf) * 6 - 6,ypos,12,8,0);	// delete last 2 characters
        		//OLEDptr = OLEDptr - 1;
        		//OLEDbuf[OLEDptr--] = '\0';
        		globalBuffer[0] = -1;
    			break;

    		case RIGHT:

    			printf("Right\n");
    			fillScreen(0);
    			display = 1;
    			global_flag = 0;
    			page1(add2, json_currently1, json_daily1,&rt);
    			rt = 1;
    			//setCursor(0,0);
    			//Outstr("right\n");
    			globalBuffer[0] = -1;
    			break;

    		case UP:

    		    printf("UP\n");
    		    //fillScreen(0);
    		    display = 2;
    		    global_flag = 0;
    		    page2(json_geo,&rt);
    		    //page1(add3, json_currently1, json_daily1,&reset);
    		    rt = 1;
    		    //setCursor(0,0);
    		    //Outstr("up\n");
    		    globalBuffer[0] = -1;
    		    break;

    		case DOWN:
    			global_flag = 0;
    		    printf("DOWN\n");
    		    fillScreen(0);
    		    setCursor(0,0);
    		    Outstr("down\n");
    		    globalBuffer[0] = -1;
    		    break;

    		case ENTER: // Send the message
    			global_flag = 0;
    			printf("Enter\n");
    			global_flag = 0;

    			setCursor(0,0);
    			    printf("hello\n");
    			    //Main_display();
    			    printf("exit mainDisplay\n");
    			//fillScreen(0);

    		    //Outstr("Enter\n");

    			//OLEDbuf[OLEDptr++] = '\n';
    			//OLEDbuf[OLEDptr++] = '\0';
    			//Message2(OLEDbuf);
    			//OLEDbuf[strlen(OLEDbuf)-1] = '\0';
    			//strcpy(tmp, "{\"state\": {\"desired\":{\"data\":\"");
    			//strcat(tmp, OLEDbuf);
    			//strcat(tmp, "\"}}}");
    			//post(lRetVal,tmp);
    			//OLEDptr=0;
    			//OLEDbuf[1] = '\0';
    			//OLEDbuf[0] = ' ';
    			//bufferSize = 0;
    			globalBuffer[0] = -1;
    			//ypos += 8;
    			//if (ypos >= 64) { // if the screen are full, clear the screen.
    			//	fillRect(0, 0, 128, 128, 0);
    			//	ypos = 0; // reset the index for upper screen
    			//	lineNumber = 0; // reset the index for lower screen
    			//}
    			//setCursor(0, ypos);
    			//continue;
    		}
    		bufferSize = 0;
    	} else if (c < 127) { // if c is valid ASCII char just print it
    	//	OLEDbuf[OLEDptr] = c;
    	}

    	// remove char only when OLEDbuf changes
    	//if (strcmp(preOLEDbuf, OLEDbuf) != 0) {
    		// need to update
    	//	strcpy(preOLEDbuf, OLEDbuf);
    	//	fillRect(strlen(OLEDbuf) * 6 - 6,ypos,6,8,0); // clear the last char
    	//	setCursor(0,ypos);
        //	Outstr(OLEDbuf);
    	//}

    	if (TimerValueGet(TIMERA0_BASE, TIMER_A) < 5000) {
        	if (bufferSize != 0) { // every ~0.5s, clear the key strokes history, finish char switching
        		bufferSize = 0;
        		globalBuffer[0] = -1;
        		//OLEDptr++;
        		//OLEDbuf[OLEDptr+1] = '\0';
        	}
		}
	} // end of while loop
}
