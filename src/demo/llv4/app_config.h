/*
Copyright (c) 2018 Garmin Ltd. or its subsidiaries.

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

#ifndef APP_CONFIG_H
#define APP_CONFIG_H

// Logging options for individual modules. To enable logging in an individual
// module, logging must be enabled globally
// Log Enabled:
// <0=> Off
// <1=> On
// Log levels:
// <0=> Off
// <1=> Error
// <2=> Warning
// <3=> Info
// <4=> Debug
#define LL_TWI_CONFIG_LOG_ENABLED 1
#define LL_TWI_CONFIG_LOG_LEVEL   3

#define LL_TWI_PARSER_CONFIG_LOG_ENABLED 1
#define LL_TWI_PARSER_CONFIG_LOG_LEVEL   3

#define LL_NVM_CONFIG_LOG_ENABLED 1
#define LL_NVM_CONFIG_LOG_LEVEL   3

#define ANT_RP_CONFIG_LOG_ENABLED 0
#define ANT_RP_CONFIG_LOG_LEVEL   3

#define MAIN_CONFIG_LOG_ENABLED 1
#define MAIN_CONFIG_LOG_LEVEL   3

#endif
