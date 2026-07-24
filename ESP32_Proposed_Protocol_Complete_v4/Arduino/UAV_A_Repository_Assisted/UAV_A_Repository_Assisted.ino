/*
  UAV_A initiator, deployment mode A: repository-assisted paths.

  Before uploading:
    1. Set WIFI_SSID, WIFI_PASSWORD, and GCS_IP.
    2. Upload the matching UAV_B sketch first and set RESPONDER_IP to its printed address.
    3. Use RESET_Q_COUNTER=true only once for a newly provisioned LMS tree,
       then immediately change it back to false and upload again.

  The hardcoded PUF root and helper data are laboratory placeholders. Replace
  only the PUF/FE hook later; the LMS, protocol, and measurement code remains.
*/

#include <Arduino.h>
#include <ProposedUavProtocolAll.h>

using namespace puav;

static const char* WIFI_SSID = "YOUR_WIFI_NAME";
static const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
static const IPAddress GCS_IP(192, 168, 29, 2);
static const IPAddress RESPONDER_IP(192, 168, 29, 99);

static constexpr bool RESET_Q_COUNTER = false;

static const NodeConfig CONFIG = {
    Role::Initiator,
    PathDeliveryMode::RepositoryAssisted,
    WIFI_SSID,
    WIFI_PASSWORD,
    GCS_IP,
    RESPONDER_IP,
    DEFAULT_PROTOCOL_PORT,
    DEFAULT_GCS_PORT,
    5211,

    /* deviceId */
    {
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41
    },

    /* peerId */
    {
        0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
        0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
        0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
        0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42
    },

    /* Stable PUF-root placeholder, identical to the earlier ESP32 package. */
    {
        0x10,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x31,0x42,0x53,0x64,0x75,0x86,0x97,0xa8,
        0xb9,0xca,0xdb,0xec,0xfd,0x0e,0x1f,0x20,
        0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x11
    },

    /* Locally retained FE helper-data placeholder. It is never transmitted. */
    {
        0x5a,0x21,0x7c,0x93,0xe4,0x18,0xb6,0x0d,
        0x34,0x8f,0xc1,0x72,0x09,0xad,0x65,0xf0,
        0x1b,0x47,0x99,0x2e,0xd8,0x53,0x06,0xbc,
        0x7f,0x12,0xea,0x40,0x88,0x3d,0x56,0xa7
    },

    /* Independent LMS identifier for this deployment profile/version. */
    {
        0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
        0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0
    },

    1,       /* credentialVersion */
    1,       /* peerCredentialVersion */
    0,               /* expiry disabled in laboratory runs */
    "uavA_repo_v1",
    0,               /* firstQ */
    500,             /* measured sessions */
    RESET_Q_COUNTER
};

static ProposedUavProtocol protocol(CONFIG);

void setup()
{
    Serial.begin(115200);
    delay(2000);

    if (!protocol.begin()) {
        Serial.println();
        Serial.println("UAV_A initialization failed.");
        while (true) {
            delay(1000);
        }
    }
}

void loop()
{
    protocol.loop();
}
