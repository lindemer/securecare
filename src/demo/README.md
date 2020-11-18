## Demo alternatives

To compile the combined EST + DFU + LIDAR demo. Use S=1 if lidar sensor is present

```
make mapp
make mapp S=1
```

To determine the behaviour of the demo state machine, update the folloing defines in mapp/project-conf.h:

CONFIG_INITIAL_STATE :== BACKGROUND_EST_IDLE || BACKGROUND_PERIODIC_IDLE || BACKGROUND_DFU_IDLE
BACKGROUND_EST_IDLE	 <==> Start with enrollment
BACKGROUND_PERIODIC_IDLE <==> Start and end with periodic sensing
BACKGROUND_DFU_IDLE	 <==> Start with DFU

and

CONFIG_STATE_AFTER_EST :== BACKGROUND_PERIODIC_IDLE || BACKGROUND_DFU_IDLE
BACKGROUND_PERIODIC_IDLE <==> Continue with DFU
BACKGROUND_PERIODIC_IDLE <==> Continue and end with periodic sensing

## Default settings

Default EST setting: the node will try to contact an external Nexus EST server.

Default DFU setting: the node will try to contact a local demo DFU server.

Default sensor setting: the node will try to put sensor data to a local demo server.

Default sensor period (SENSOR_PERIOD): 1000 ms

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
