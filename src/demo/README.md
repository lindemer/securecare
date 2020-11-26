## Demo alternatives

To compile the combined EST + DFU + LIDAR demo. Use S=1 if lidar sensor is present

```
make mapp
make mapp S=1
```

To determine the behaviour of the demo state machine, set these defines in mapp/project-conf.h:

```
#define CONFIG_INITIAL_STATE        <BACKGROUND_EST_IDLE || BACKGROUND_PERIODIC_IDLE || BACKGROUND_DFU_IDLE>
#define CONFIG_STATE_AFTER_EST      <BACKGROUND_PERIODIC_IDLE || BACKGROUND_DFU_IDLEC>
```

The resulting behaviours are as follows.

```
#define CONFIG_INITIAL_STATE        BACKGROUND_EST_IDLE         //Start with enrollment
#define CONFIG_INITIAL_STATE        BACKGROUND_PERIODIC_IDLE    //Start and end with periodic sensing
#define CONFIG_INITIAL_STATE        BACKGROUND_DFU_IDLE         //Start with DFU

#define CONFIG_STATE_AFTER_EST      BACKGROUND_PERIODIC_IDLE    //Continue with DFU
#define CONFIG_STATE_AFTER_EST      BACKGROUND_DFU_IDLE         //Continue and end with periodic sensing
```

## Default settings and local servers

Default EST setting: the node will try to contact an external Nexus EST server. Please note that to run the demo with a different EST server, the following project-conf defines should be updated accordingly:

```
#define est_remote_addr             <EST coaps address>
#define CUSTOM_EST_COAP_SECURE_PORT <EST coaps port>
```

Default DFU setting: the node will try to contact a local demo DFU server.

Default sensor setting: the node will try to put sensor data to a local demo server, at the path specified by

```
#define SENSOR_DATA_PATH "sensor"
```

Default sensor period, specified as

```
#define SENSOR_PERIOD    2000 //ms
```

## Corresponding demo-server settings

Run demo server from securecare/src/util as follows

To receive data from a node that has done enrollment with Nexus:

```
./build/demo-server -c ../../certs/nexus_enrolled_cert.pem -R ../../certs/nexus/ts/
```

To receive data from a node that has done enrollment with local test EST server:

```
./build/demo-server -c ../../certs/rfc-test-root.pem -C ../../certs/rfc-test-root.pem
```
## Needed custom OpenThread libs

Download and unzip to securecare/lib/openthread

```
https://drive.google.com/file/d/11jLNBr1zIQ14X9MzqY5HFAKeH10oepqQ/view?usp=sharing
```
