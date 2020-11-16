PROJECT_NAME     := app 
TARGETS          := app
OUTPUT_DIRECTORY := build

ifeq ($(PSK), 1)
${info "Compiling with PSK}
CFLAGS += -DDEMO_USE_PSK=1
else
${info "Compiling with certs"}
endif

ifeq ($(UC),1)
${info Compiling with CBOR}
CFLAGS += -DUSE_CBOR_ENCODING=1
else
${info Compiling with standard format}
endif


ifeq ($(N), 1)
${info Compiling for Nexus EST testing}
CFLAGS += -DEST_WITH_NEXUS=1
else
 ${info Compiling for local EST testing}
endif

ifeq ($(SOT), 0)
 ${info Compiling with standard Openthread binaries, original config}
SDK_ROOT := /home/ubuntu/nRF5_SDK_0
else
ifeq ($(SOT), 1)
 ${info Compiling with standard Openthread binaries, modified config}
SDK_ROOT := /home/ubuntu/nRF5_SDK_1
else
${info Compiling with custom Openthread binaries}
SDK_ROOT := ${NRF5_SDK}
endif
endif
 
PROJ_DIR := .
KEYS_DIR := ../../../key

$(OUTPUT_DIRECTORY)/app.out: \
  LINKER_SCRIPT  := main.ld

#  $(SDK_ROOT)/components/boards/boards.c \
#  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc/micro_ecc_backend_ecc.c \
#  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc/micro_ecc_backend_ecdh.c \
#  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc/micro_ecc_backend_ecdsa.c \

#CB = crypto backend
#0 = vanilla micro ecc
#1 = software mbedtls, should work with cert but not with RNG
#2 = try to do cc310
#3 = try to combine micro ecc & cc310? 
ifeq ($(T), 1)
${info Compiling to test <some> function(s), do not expect normal behaviour}
#CFLAGS += -DTEST_ENROLL_SUBJECT=1
CFLAGS += -DTEST_PERIODIC_TIMER=1
endif

ifeq ($(CB), 1)
${info Compiling with mbedtls backend}
CFLAGS += -DNRF_CRYPTO_BACKEND_MBEDTLS_ENABLED=1
CFLAGS += -DNRF_CRYPTO_BACKEND_NRF_SW_ENABLED=0 #todo? nah 1 gives error
#CFLAGS += -DNRF_CRYPTO_BACKEND_CC310_ENABLED=1 #try to get rnd
#/home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/platform.c
#  /home/ubuntu/nRF5_SDK/external/mbedtls/library/platform.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/cipher.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/dhm.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509_crt.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/ssl_cli.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/ssl_tls.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/ssl_srv.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/debug.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/oid.c \
#/home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509_crt.c \

ifeq ($(N), 1)
${info Cheating for Nexus EST testing}
SRC_FILES += /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509_crt.c
endif

ifeq ($(UC),1)
SRC_FILES += $(PROJ_DIR)/../../est/util/xiot.c
endif


SRC_FILES += \
	$(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_aes.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdh.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdsa.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_hash.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_hmac.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_init.c \
  $(SDK_ROOT)/external/mbedtls/library/sha256.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_rng.c \
  $(SDK_ROOT)/external/mbedtls/library/ecdsa.c \
  $(SDK_ROOT)/external/mbedtls/library/hmac_drbg.c \
  $(SDK_ROOT)/external/mbedtls/library/threading.c \
  #software-only-threading  
  
  #$(SDK_ROOT)/external/mbedtls/library/ecp.c //collides with software lib...???
  #$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecc.c \ --rng-attempts
  #$(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_rng.c \
  #$(SDK_ROOT)/external/mbedtls/library/ecp_curves.c \
  #$(SDK_ROOT)/external/mbedtls/library/ecp.c
  

else ifeq ($(CB), 2)
${info "Compiling with cc310 backend"}
CFLAGS += -DNRF_CRYPTO_BACKEND_CC310_ENABLED=1
CFLAGS += -DNRF_CRYPTO_BACKEND_NRF_SW_ENABLED=0
SRC_FILES += \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecdh.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecdsa.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_hash.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_hmac.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_init.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_mutex.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_shared.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_rng.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_rng.c

else ifeq ($(CB), 3)
${info "Compiling with MIXED backend"}
CFLAGS += -DNRF_CRYPTO_BACKEND_MBEDTLS_ENABLED=1
CFLAGS += -DNRF_CRYPTO_BACKEND_CC310_ENABLED=1
CFLAGS += -DNRF_CRYPTO_BACKEND_NRF_SW_ENABLED=0 #or 0?
SRC_FILES += \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecdh.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_ecdsa.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_hash.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_hmac.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_init.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_mutex.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_shared.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310/cc310_backend_rng.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_aes.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdh.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdsa.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_hash.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_hmac.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_init.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_rng.c \

else ifeq ($(CB), 4)
${info Compiling with mbedtls HW backend}
CFLAGS += -DNRF_CRYPTO_BACKEND_MBEDTLS_ENABLED=1
CFLAGS += -DNRF_CRYPTO_BACKEND_NRF_SW_ENABLED=0 #todo? nah 1 gives error
#CFLAGS += -DNRF_CRYPTO_BACKEND_CC310_ENABLED=1 #try to get rnd
#/home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/platform.c
#  /home/ubuntu/nRF5_SDK/external/mbedtls/library/platform.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/cipher.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/dhm.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509_crt.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/ssl_cli.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/ssl_tls.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/ssl_srv.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/debug.c \
#  /home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/oid.c \
#/home/ubuntu/eclipse-workspace/openthread/third_party/mbedtls/repo/library/x509_crt.c \

SRC_FILES += \
	$(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_aes.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdh.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_ecdsa.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_hash.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_hmac.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls/mbedtls_backend_init.c \
  $(SDK_ROOT)/external/mbedtls/library/sha256.c \
  $(SDK_ROOT)/external/mbedtls/library/ecdsa.c \
  $(SDK_ROOT)/external/mbedtls/library/hmac_drbg.c \
  $(SDK_ROOT)/external/mbedtls/library/ecp.c \

else
${info "Compiling with micro ecc backend"}
CFLAGS += -DNRF_CRYPTO_BACKEND_MICRO_ECC_ENABLED=1
CFLAGS += -DNRF_CRYPTO_BACKEND_NRF_SW_ENABLED=1 #or 1?
SRC_FILES += \
  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc/micro_ecc_backend_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc/micro_ecc_backend_ecdh.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc/micro_ecc_backend_ecdsa.c
endif

ifeq ($(R), 1)
${info "Compiling with stupid hw rand backend"}
CFLAGS += -DNRF_CRYPTO_BACKEND_NRF_HW_RNG_ENABLED=1
SRC_FILES += \
  $(SDK_ROOT)/components/libraries/crypto/backend/nrf_hw/nrf_hw_backend_rng_mbedtls.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/nrf_hw/nrf_hw_backend_rng.c \
  $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_rng.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_rng.c
#  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_nvmc.c \
#  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_ecc.c 
else
${info "Compiling with no rand backend"}
endif

#CFLAGS += -DSEGGER_RTT_CONFIG_DEFAULT_MODE=2
#${info Warning, compiler with segger rtt in blocking mode}

# Source files common to all targets
SRC_FILES += \
  $(SDK_ROOT)/modules/nrfx/mdk/gcc_startup_nrf52840.S \
  $(SDK_ROOT)/components/libraries/bsp/bsp.c \
  $(SDK_ROOT)/components/libraries/bsp/bsp_thread.c \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_backend_rtt.c \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_backend_serial.c \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_default_backends.c \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_frontend.c \
  $(SDK_ROOT)/components/libraries/log/src/nrf_log_str_formatter.c \
  $(SDK_ROOT)/components/boards/boards.c \
  $(SDK_ROOT)/components/libraries/button/app_button.c \
  $(SDK_ROOT)/components/libraries/util/app_error.c \
  $(SDK_ROOT)/components/libraries/util/app_error_handler_gcc.c \
  $(SDK_ROOT)/components/libraries/util/app_error_weak.c \
  $(SDK_ROOT)/components/libraries/scheduler/app_scheduler.c \
  $(SDK_ROOT)/components/libraries/timer/app_timer2.c \
  $(SDK_ROOT)/components/libraries/util/app_util_platform.c \
  $(SDK_ROOT)/components/libraries/assert/assert.c \
  $(SDK_ROOT)/components/libraries/crc32/crc32.c \
  $(SDK_ROOT)/components/libraries/timer/drv_rtc.c \
  $(SDK_ROOT)/components/libraries/mem_manager/mem_manager.c \
  $(SDK_ROOT)/components/libraries/util/nrf_assert.c \
  $(SDK_ROOT)/components/libraries/atomic_fifo/nrf_atfifo.c \
  $(SDK_ROOT)/components/libraries/atomic/nrf_atomic.c \
  $(SDK_ROOT)/components/libraries/balloc/nrf_balloc.c \
  $(SDK_ROOT)/external/fprintf/nrf_fprintf.c \
  $(SDK_ROOT)/external/fprintf/nrf_fprintf_format.c \
  $(SDK_ROOT)/components/libraries/fstorage/nrf_fstorage.c \
  $(SDK_ROOT)/components/libraries/fstorage/nrf_fstorage_nvmc.c \
  $(SDK_ROOT)/components/libraries/memobj/nrf_memobj.c \
  $(SDK_ROOT)/components/libraries/pwr_mgmt/nrf_pwr_mgmt.c \
  $(SDK_ROOT)/components/libraries/queue/nrf_queue.c \
  $(SDK_ROOT)/components/libraries/ringbuf/nrf_ringbuf.c \
  $(SDK_ROOT)/components/libraries/experimental_section_vars/nrf_section_iter.c \
  $(SDK_ROOT)/components/libraries/sortlist/nrf_sortlist.c \
  $(SDK_ROOT)/components/libraries/strerror/nrf_strerror.c \
  $(SDK_ROOT)/components/libraries/sha256/sha256.c \
  $(SDK_ROOT)/modules/nrfx/mdk/system_nrf52840.c \
  $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_clock.c \
  $(SDK_ROOT)/components/drivers_nrf/nrf_soc_nosd/nrf_nvic.c \
  $(SDK_ROOT)/modules/nrfx/hal/nrf_nvmc.c \
  $(SDK_ROOT)/components/drivers_nrf/nrf_soc_nosd/nrf_soc.c \
  $(SDK_ROOT)/modules/nrfx/soc/nrfx_atomic.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_clock.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_gpiote.c \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_nvmc.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_ecc.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_ecdsa.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_hash.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_init.c \
  $(SDK_ROOT)/components/libraries/crypto/nrf_crypto_shared.c \
  $(SDK_ROOT)/external/infineon/examples/ecdsa_utils/ecdsa_utils.c \
  $(SDK_ROOT)/external/mbedtls/library/bignum.c \
  $(KEYS_DIR)/pub.c \
  $(PROJ_DIR)/main.c \
  $(PROJ_DIR)/coaps_dfu.c \
  $(PROJ_DIR)/addr_parse.c \
  $(PROJ_DIR)/background_dfu_state.c \
  $(SDK_ROOT)/components/iot/background_dfu/background_dfu_block.c \
  $(SDK_ROOT)/components/iot/background_dfu/background_dfu_operation.c \
  $(SDK_ROOT)/components/libraries/crypto/backend/nrf_sw/nrf_sw_backend_hash.c \
  $(PROJ_DIR)/../common/nrf_dfu.c \
  $(PROJ_DIR)/../common/nrf_dfu_flash.c \
  $(PROJ_DIR)/../common/nrf_dfu_handling_error.c \
  $(PROJ_DIR)/../common/nrf_dfu_mbr.c \
  $(PROJ_DIR)/../common/nrf_dfu_req_handler.c \
  $(PROJ_DIR)/../common/nrf_dfu_settings.c \
  $(PROJ_DIR)/../common/nrf_dfu_transport.c \
  $(PROJ_DIR)/../common/nrf_dfu_utils.c \
  $(PROJ_DIR)/../common/nrf_dfu_validation.c \
  $(PROJ_DIR)/../common/nrf_dfu_ver_validation.c \
  $(SDK_ROOT)/components/iot/coap/coap_block.c \
  $(SDK_ROOT)/components/iot/ipv6_parse/ipv6_parse.c \
  $(SDK_ROOT)/components/iot/ipv6_parse/ipv6_parse.c \
  $(SDK_ROOT)/external/segger_rtt/SEGGER_RTT.c \
  $(SDK_ROOT)/external/segger_rtt/SEGGER_RTT_Syscalls_GCC.c \
  $(SDK_ROOT)/external/segger_rtt/SEGGER_RTT_printf.c \
  $(SDK_ROOT)/components/thread/utils/thread_utils.c \
  $(PROJ_DIR)/../../../lib/NanoCBOR/src/encoder.c \
  $(PROJ_DIR)/../../../lib/NanoCBOR/src/decoder.c \
  $(PROJ_DIR)/../../cose/cose.c \
  $(PROJ_DIR)/../../cose/suit.c \
  $(PROJ_DIR)/../../est/est.c \
  $(PROJ_DIR)/../../est/est-asn1.c \
  $(PROJ_DIR)/../../est/est-base64.c \
  $(PROJ_DIR)/../../est/est-cms.c \
  $(PROJ_DIR)/../../est/est-oid.c \
  $(PROJ_DIR)/../../est/est-pkcs10.c \
  $(PROJ_DIR)/../../est/est-x509.c \
  $(PROJ_DIR)/../../est/mbedtls-wrapper.c \
  $(PROJ_DIR)/../../est/util/memb.c \
  $(SDK_ROOT)/external/mbedtls/library/version_features.c
  #$(SDK_ROOT)/external/mbedtls/library/ssl_tls.c



# Include folders common to all targets

#  $(SDK_ROOT)/external/openthread/project/config \
#  $(SDK_ROOT)/components/libraries/crypto/backend/cc310_bl \

#  $(SDK_ROOT)/components/libraries/mutex \
#  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc \
#  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls \

#/external/nrf_security/include
#vs
#/external/openthread/mbedtls/mbedtls/repo/include

INC_FOLDERS += \
  $(PROJ_DIR) \
  $(PROJ_DIR)/../common \
  $(PROJ_DIR)/../../cose \
  $(PROJ_DIR)/../../../lib/NanoCBOR/include \
  $(PROJ_DIR)/../../est \
  $(PROJ_DIR)/../../est/util \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310 \
  $(SDK_ROOT)/components/libraries/crypto/backend/cc310_bl \
  $(SDK_ROOT)/components/libraries/crypto/backend/mbedtls \
  $(SDK_ROOT)/components/libraries/crypto/backend/micro_ecc \
  $(SDK_ROOT)/components/libraries/crypto/backend/oberon \
  $(SDK_ROOT)/components/libraries/crypto/backend/optiga \
  $(SDK_ROOT)/external/nrf_cc310/include \
  $(SDK_ROOT)/external/nrf_security/include \
  $(SDK_ROOT)/components/libraries/crypto/backend/cifra \
  $(SDK_ROOT)/external/openthread/include \
  $(SDK_ROOT)/external/fprintf \
  $(SDK_ROOT)/components/boards \
  $(SDK_ROOT)/components/iot/background_dfu \
  $(SDK_ROOT)/components/iot/background_dfu/transport \
  $(SDK_ROOT)/components/libraries/atomic \
  $(SDK_ROOT)/components/iot/ipv6_parse \
  $(SDK_ROOT)/components/iot/ble_6lowpan \
  $(SDK_ROOT)/components/iot/coap \
  $(SDK_ROOT)/modules/nrfx/hal \
  $(SDK_ROOT)/components/libraries/atomic_fifo \
  $(SDK_ROOT)/external/nrf_security/mbedtls_plat_config \
  $(SDK_ROOT)/external/nRF-IEEE-802.15.4-radio-driver/src/fem/three_pin_gpio \
  $(SDK_ROOT)/components/libraries/delay \
  $(SDK_ROOT)/components/libraries/experimental_section_vars \
  $(SDK_ROOT)/external/segger_rtt \
  $(SDK_ROOT)/external/nrf_oberon/include \
  $(SDK_ROOT)/external/nrf_tls \
  $(SDK_ROOT)/components/libraries/crypto \
  $(SDK_ROOT)/components/toolchain/cmsis/include \
  $(SDK_ROOT)/components/libraries/balloc \
  $(SDK_ROOT)/components/libraries/mem_manager \
  $(SDK_ROOT)/components/libraries/log \
  $(SDK_ROOT)/external/nrf_oberon \
  $(SDK_ROOT)/components/libraries/memobj \
  $(SDK_ROOT)/components/libraries/stack_info \
  $(SDK_ROOT)/components \
  $(SDK_ROOT)/components/libraries/crypto/backend/nrf_sw \
  $(SDK_ROOT)/components/libraries/scheduler \
  $(SDK_ROOT)/components/libraries/strerror \
  $(SDK_ROOT)/components/libraries/crypto/backend/optiga \
  $(SDK_ROOT)/modules/nrfx/drivers/include \
  $(SDK_ROOT)/external/openthread/project/config \
  $(SDK_ROOT)/components/libraries/ringbuf \
  $(SDK_ROOT)/external/nrf_security/config \
  $(SDK_ROOT)/components/thread/utils \
  $(SDK_ROOT)/modules/nrfx \
  $(SDK_ROOT)/components/drivers_nrf/nrf_soc_nosd \
  $(SDK_ROOT)/components/libraries/log/src \
  $(SDK_ROOT)/external/openthread/project/nrf52840 \
  $(SDK_ROOT)/external/nrf_security/nrf_cc310_plat/include \
  $(SDK_ROOT)/components/libraries/sortlist \
  $(SDK_ROOT)/integration/nrfx \
  $(SDK_ROOT)/modules/nrfx/mdk \
  $(SDK_ROOT)/external/micro-ecc/micro-ecc \
  $(SDK_ROOT)/components/libraries/mutex \
  $(SDK_ROOT)/components/libraries/queue \
  $(SDK_ROOT)/components/libraries/pwr_mgmt \
  $(SDK_ROOT)/components/libraries/crypto/backend/nrf_hw \
  $(SDK_ROOT)/components/libraries/bsp \
  $(SDK_ROOT)/integration/nrfx/legacy \
  $(SDK_ROOT)/components/libraries/crc32 \
  $(SDK_ROOT)/components/libraries/fstorage \
  $(SDK_ROOT)/components/iot/common \
  $(SDK_ROOT)/components/libraries/timer \
  $(SDK_ROOT)/components/libraries/button \
  $(SDK_ROOT)/external/nRF-IEEE-802.15.4-radio-driver/src/fem \
  $(SDK_ROOT)/components/libraries/util \
  $(SDK_ROOT)/components/libraries/sha256 \
  $(SDK_ROOT)/components/softdevice/mbr/headers \
  $(SDK_ROOT)/external/mbedtls/include/mbedtls \
  # $(SDK_ROOT)/external/openthread/mbedtls/mbedtls/ 
  # /external/mbedtls/include/mbedtls/ == bignum.h 
  #$(SDK_ROOT)/components/libraries/crypto/backend/oberon \

# Libraries common to all targets

#  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-sdk.a \
#  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \

#  $(SDK_ROOT)/external/nrf_oberon/lib/cortex-m4/hard-float/liboberon_3.0.3.a \
#  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \


ifeq ($(CB), 1)
${info "Compiling with mbedtls software backend"}
LIB_FILES += \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-cli-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52833/gcc/libmbedcrypto.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-sdk.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libnordicsemi-nrf52840-radio-driver.a \
  $(SDK_ROOT)/external/micro-ecc/nrf52hf_armgcc/armgcc/micro_ecc_lib_nrf52.a \
  $(SDK_ROOT)/external/nrf_oberon/lib/cortex-m4/hard-float/liboberon_3.0.3.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
#$(SDK_ROOT)/external/openthread/lib/nrf52833/gcc/libmbedcrypto.a \#sic, see software only instructions
else ifeq ($(CB), 2)
${info "Compiling with cc310 backend"}
LIB_FILES += \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-cli-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-sdk.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libnordicsemi-nrf52840-radio-driver.a \
  $(SDK_ROOT)/external/micro-ecc/nrf52hf_armgcc/armgcc/micro_ecc_lib_nrf52.a \
  $(SDK_ROOT)/external/nrf_oberon/lib/cortex-m4/hard-float/liboberon_3.0.3.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310_0.9.12.a \
    
#NOT $(SDK_ROOT)/external/nrf_cc310/lib/cortex-m4/soft-float/libnrf_cc310_0.9.12.a
#NOT $(SDK_ROOT)/external/nrf_cc310/lib/cortex-m4/soft-float/short-wchar/libnrf_cc310_0.9.12.a
else ifeq ($(CB), 3)
${info "Compiling with MIXED backend"}
LIB_FILES += \
	$(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-cli-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-sdk.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libnordicsemi-nrf52840-radio-driver.a \
  $(SDK_ROOT)/external/micro-ecc/nrf52hf_armgcc/armgcc/micro_ecc_lib_nrf52.a \
  $(SDK_ROOT)/external/nrf_oberon/lib/cortex-m4/hard-float/liboberon_3.0.3.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310_0.9.12.a \

else ifeq ($(CB), 4)
${info "Compiling with mbedtls 'HW' backend"}
LIB_FILES += \
	$(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
	$(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
	$(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
	$(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
	$(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
	$(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-cli-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-sdk.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libnordicsemi-nrf52840-radio-driver.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \

#$(SDK_ROOT)/external/openthread/lib/nrf52833/gcc/libmbedcrypto.a 

else
${info "Compiling with micro ecc backend"}
LIB_FILES += \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-cli-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-ftd.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-sdk.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_cc310.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_glue_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libnordicsemi-nrf52840-radio-driver.a \
  $(SDK_ROOT)/external/micro-ecc/nrf52hf_armgcc/armgcc/micro_ecc_lib_nrf52.a \
  $(SDK_ROOT)/external/nrf_oberon/lib/cortex-m4/hard-float/liboberon_3.0.3.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_cc310_backend.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedcrypto_vanilla_backend.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-nrf52840-transport.a \
  $(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-platform-utils.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_base_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_tls_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libmbedtls_x509_vanilla.a \
  $(SDK_ROOT)/external/nrf_security/lib/libnrf_cc310_platform_0.9.2.a 
  
endif
  
  
  #$(SDK_ROOT)/external/openthread/lib/nrf52840/gcc/libopenthread-ftd.a 
	#debug.o

# Optimization flags
OPT = -O3 -g3
# Uncomment the line below to enable link time optimization
#OPT += -flto

# C flags common to all targets
CFLAGS += $(OPT)
CFLAGS += -DAPP_TIMER_V2
CFLAGS += -DAPP_TIMER_V2_RTC1_ENABLED
CFLAGS += -DBOARD_PCA10056
CFLAGS += -DCONFIG_GPIO_AS_PINRESET
CFLAGS += -DENABLE_FEM
CFLAGS += -DFLOAT_ABI_HARD
CFLAGS += -DMBEDTLS_CONFIG_FILE=\"nrf-config.h\"
CFLAGS += -DMBEDTLS_USER_CONFIG_FILE=\"nrf52840-mbedtls-config.h\"
CFLAGS += -DMBR_PRESENT
CFLAGS += -DNRF52840_XXAA
CFLAGS += -DNRF_DFU_NO_TRANSPORT
CFLAGS += -DNRF_DFU_SETTINGS_VERSION=2
CFLAGS += -DOPENTHREAD_CONFIG_ENABLE_BUILTIN_MBEDTLS=0
#TODO: testing from o to 1
CFLAGS += -DOPENTHREAD_CONFIG_FILE=\"openthread-config-wrap.h\"
CFLAGS += -DOPENTHREAD_FTD=1
CFLAGS += -DSVC_INTERFACE_CALL_AS_NORMAL_FUNCTION
CFLAGS += -DuECC_ENABLE_VLI_API=0
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=3
CFLAGS += -DuECC_SQUARE_FUNC=0
CFLAGS += -DuECC_SUPPORT_COMPRESSED_POINT=0
CFLAGS += -DuECC_VLI_NATIVE_LITTLE_ENDIAN=1
CFLAGS += -mcpu=cortex-m4
CFLAGS += -mthumb -mabi=aapcs
CFLAGS += -Wall -Werror
CFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
# keep every function in a separate section, this allows linker to discard unused ones
CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
CFLAGS += -fno-builtin -fshort-enums

# C flags for NanoCBOR
CFLAGS += -DNANOCBOR_BYTEORDER_HEADER=\"nanocbor/nanocbor.h\"
CFLAGS += -DNANOCBOR_HTOBE32_FUNC=__builtin_bswap32
CFLAGS += -DNANOCBOR_HTOBE64_FUNC=__builtin_bswap64
CFLAGS += -DNANOCBOR_BE64TOH_FUNC=__builtin_bswap64

# C flags for COSE
CFLAGS += -DCOSE_BACKEND_NRF




# C++ flags common to all targets
CXXFLAGS += $(OPT)
# Assembler flags common to all targets
ASMFLAGS += -g3
ASMFLAGS += -mcpu=cortex-m4
ASMFLAGS += -mthumb -mabi=aapcs
ASMFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
ASMFLAGS += -DAPP_TIMER_V2
ASMFLAGS += -DAPP_TIMER_V2_RTC1_ENABLED
ASMFLAGS += -DBOARD_PCA10056
ASMFLAGS += -DCONFIG_GPIO_AS_PINRESET
ASMFLAGS += -DENABLE_FEM
ASMFLAGS += -DFLOAT_ABI_HARD
ASMFLAGS += -DMBR_PRESENT
ASMFLAGS += -DNRF52840_XXAA
ASMFLAGS += -DNRF_DFU_NO_TRANSPORT
ASMFLAGS += -DNRF_DFU_SETTINGS_VERSION=2
ASMFLAGS += -DOPENTHREAD_FTD=1
ASMFLAGS += -DSVC_INTERFACE_CALL_AS_NORMAL_FUNCTION
ASMFLAGS += -DuECC_ENABLE_VLI_API=0
ASMFLAGS += -DuECC_OPTIMIZATION_LEVEL=3
ASMFLAGS += -DuECC_SQUARE_FUNC=0
ASMFLAGS += -DuECC_SUPPORT_COMPRESSED_POINT=0
ASMFLAGS += -DuECC_VLI_NATIVE_LITTLE_ENDIAN=1

# Linker flags
LDFLAGS += $(OPT)
LDFLAGS += -mthumb -mabi=aapcs -L$(SDK_ROOT)/modules/nrfx/mdk -T$(LINKER_SCRIPT)
LDFLAGS += -mcpu=cortex-m4
LDFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
# let linker dump unused sections
LDFLAGS += -Wl,--gc-sections
# use newlib in nano version
LDFLAGS += --specs=nano.specs

app: CFLAGS += -DCOAPS_DFU_DTLS_ENABLE=1
app: CFLAGS += -D__HEAP_SIZE=8192
app: CFLAGS += -D__STACK_SIZE=8192
app: ASMFLAGS += -D__HEAP_SIZE=8192
app: ASMFLAGS += -D__STACK_SIZE=8192
#app: CFLAGS += -D__HEAP_SIZE=12288
#app: CFLAGS += -D__STACK_SIZE=12288
#app: ASMFLAGS += -D__HEAP_SIZE=12288
#app: ASMFLAGS += -D__STACK_SIZE=12288
#TODO

# Add standard libraries at the very end of the linker input, after all objects
# that may need symbols provided by these libraries.
LIB_FILES += -lc -lnosys -lm -lstdc++


.PHONY: default help

# Default target - first one defined
default: app

# Print all targets that can be built
help:
	@echo following targets are available:
	@echo		app 	   - compile and link (default)
	@echo 		settings   - generate bootloader settings and merge
	@echo		flash      - flash binary
	@echo 		erase

TEMPLATE_PATH := $(SDK_ROOT)/components/toolchain/gcc


include $(TEMPLATE_PATH)/Makefile.common

$(foreach target, $(TARGETS), $(call define_target, $(target)))

.PHONY: flash erase

settings:
	@nrfutil settings generate --family NRF52840 --application               \
	    $(OUTPUT_DIRECTORY)/app.hex --application-version 1                   \
	    --bootloader-version 1 --bl-settings-version 2                       \
	    $(OUTPUT_DIRECTORY)/settings.hex
	@mergehex -m $(OUTPUT_DIRECTORY)/app.hex $(OUTPUT_DIRECTORY)/settings.hex \
	    -o $(OUTPUT_DIRECTORY)/merged.hex

flash:  default settings
	nrfjprog -f nrf52 -r --program $(OUTPUT_DIRECTORY)/merged.hex --sectorerase
	nrfjprog -f nrf52 --reset

erase:
	nrfjprog -f nrf52 --eraseall
