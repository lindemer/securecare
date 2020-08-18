#include "xiot.h"
//#include "cn-cbor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//#include "est-x509.h"
//#include "sha.h"
//#include "dtls.h"

//#include "uECC.h"


#if DEBUG_XIOT
#define PRINTF(...) printf(__VA_ARGS__)
static int debug_count = 0;
#else
#define PRINTF(...)
#endif

#define MAX_CHAIN_LEN 2
#define MAX_EXT_PARTS 6
static xiot_ext_t ext_storage[MAX_EXT_PARTS];
static int x_freep = 0;

// Helper functions
time_t my_timegm (struct tm *tm) {
    time_t ret;
    //char *tz;
    //tz = getenv("TZ");
    //setenv("TZ", "GMT", 1);
    //tzset();
    //ret = ext_mktime(tm);
    ret = ext_mktime(tm);
//    if(tz)
//        setenv("TZ", tz, 1);
//    else
//        unsetenv("TZ");
//    tzset();
    return ret; //ext_mktime(tm); //ret;
}

static xiot_ext_t * get_ext_space(void) {

  xiot_ext_t* ext;
  ext = &ext_storage[x_freep]; /* WAS: calloc(1, sizeof(xiot_ext_t)); */
  memset(ext, 0, sizeof(xiot_ext_t));
  //printf("x_freep:%d ", x_freep);
  //hdump(ext, sizeof(xiot_ext_t));

  x_freep = (x_freep + 1) % MAX_EXT_PARTS;
  return ext;
}

static size_t xiot_parse_eui64(char* buffer_out, char* buffer_in, size_t length)
{
    char tmp_str[3] = {0};
        
    int in = 0;
    size_t out = 0;
    while(in < length){
        if(buffer_in[in] == '-'){
            in ++;
            continue;
        }
        strncpy(tmp_str, (char*) buffer_in+in, 2);
        buffer_out[out] = strtol(tmp_str, NULL, 16);
        in += 2;
        out ++;
    }
    return out;
}

static xiot_ext_t* xiot_decode_extensions(uint8_t* buf, size_t length)
{
    xiot_ext_t* root = NULL;
    
    // Helper temporaries
    int n = 0;
    xiot_ext_t* ext;
    xiot_ext_t* last;
    
    // Loop over the buffer
    while(n < length){
        if(buf[n++] != 0x30 || buf[n] == 0x00){ // First byte not sequence or size equals 0
            break;
        }
        
        if(buf[n] & 0x80){
            n += buf[n] & 0x7F; // Jump over the size
        }
        n++; // Jump to OID
        
        if(buf[n++] != 0x06){ // First element always OID
            break;
        }


        // Create new xiot_ext_t
        ext = get_ext_space();

        if(root == NULL){
            root = ext;
        } else {
            last->next = ext;
        }
        last = ext;
        
        n += 3; // Jump to third byte of OID
        // Get the OID
        ext->oid = buf[n++];
        
        // Check critical
        if(buf[n] == 0x01){ // If set should not be false, since explicit tagging
            ext->critical = true;
            n += 3;
        }   
        
        // Get value
        n++; // Don't care about tag
        ext->length = buf[n++];
        ext->value = &buf[n];
        
        // Update for next extension
        n += ext->length;
        PRINTF("XIOT-DEBUG: Content of x_freep-1 after %d:\n", x_freep);
        //hdump(ext, sizeof(xiot_ext_t));
    }
    
    return root;
}

static void xiot_free_extensions(xiot_ext_t* root)
{
    if(root){
        if(root->next){
            xiot_free_extensions(root->next);
        }
        //free(root);
    }
}

static int xiot_encode_length(uint8_t* buf, int length)
{
    int n = 0;
    if(length < 0x80){
        buf[n++] = length;
        return 1;
    } else if (length <= 0xFF){
        buf[n++] = 0x81;
        buf[n++] = length;
        return 2;
    } else if (length <= 0xFFFF) {
        buf[n++] = 0x82;
        buf[n++] = length >> 8;
        buf[n++] = length;
        return 3;
    } else if (length <= 0xFFFFFF) {         
        buf[n++] = 0x83;
        buf[n++] = length >> 16;
        buf[n++] = length >> 8;
        buf[n++] = length;
        return 4;
    } else {
        buf[n++] = 0x84;
        buf[n++] = length >> 24;
        buf[n++] = length >> 16;
        buf[n++] = length >> 8;
        buf[n++] = length;
        return 5;
    }
}

static int xiot_encode_uint(uint8_t* buf, uint64_t integer)
{
    int n = 0;
    buf[n++] = 0x02;

    if(integer <= 0xFF){
        buf[n++] = 0x01;
        buf[n++] = integer;
    } else if(integer <= 0xFFFF){
        buf[n++] = 0x02;
        buf[n++] = integer >> 8;
        buf[n++] = integer;
    } else if(integer <= 0xFFFFFF){
        buf[n++] = 0x03;
        buf[n++] = integer >> 16;
        buf[n++] = integer >> 8;
        buf[n++] = integer;
    } else {
        buf[n++] = 0x04;
        buf[n++] = integer >> 24;
        buf[n++] = integer >> 16;
        buf[n++] = integer >> 8;
        buf[n++] = integer;
    }

    return n;
}

static int xiot_encode_cn(uint8_t* buf, const char* str, int length, uint8_t encoding, bool ca)
{
   /*
    * Note: Will only work for strings of 
    * size less than 115 characters
    */

    int n = 0;
    int encoded = 0;

    if(!ca){
        length = 23; // 01-23-45-67-89-AB-CD-EF  
    }

    buf[n++] = 0x30;
    encoded = xiot_encode_length(&buf[n], length+11);
    n += encoded;

    buf[n++] = 0x31;
    encoded = xiot_encode_length(&buf[n], length+9);
    n += encoded;

    buf[n++] = 0x30;
    encoded = xiot_encode_length(&buf[n], length+7);
    n += encoded;

    buf[n++] = 0x06;
    buf[n++] = 0x03;
    buf[n++] = 0x55;
    buf[n++] = 0x04;
    buf[n++] = 0x03;

    buf[n++] = encoding; // ASN1_TAG_UTF8_STRING or ASN1_TAG_PRINTABLE_STRING!

    encoded = xiot_encode_length(&buf[n], length);
    n += encoded;
    
    // TODO: Test this further
    if(ca){
        memcpy(&buf[n], str, length);
        n += length;
    } else {
        int i;
        uint8_t* tmp = (uint8_t*) str;

        for(i = 0; i < 8; i++){
            if(i != 0){
                buf[n++] = '-';
            }

            if(((tmp[i] >> 4) & 0x0F) < 0x0A){
                buf[n++] = 0x30 + ((tmp[i] >> 4) & 0x0F);
            } else {
                buf[n++] = 0x37 + ((tmp[i] >> 4) & 0x0F);
            }

            if((tmp[i] & 0x0F) < 0x0A){
                buf[n++] = 0x30 + (tmp[i] & 0x0F);
            } else {
                buf[n++] = 0x37 + (tmp[i] & 0x0F);
            }            
        }
    }

    return n;
}

static int xiot_encode_validity(uint8_t* buf, time_t not_before, time_t not_after)
{
    /*
    * Note: Will only work for dates
    * with year greater than 2000. 
    */
    int n = 0;
    struct tm *info;
    static struct tm input[2];
    time_t times[2] = {not_before, not_after};

    buf[n++] = 0x30;
    buf[n++] = 0x1E; // 0x1E if seconds, 0x1A if not

    int i;
    for(i = 0; i < 2; i++){
        //info = my_gmtime(&times[i], &input[i]); //Joel-TODO
        info = gmtime_r(&times[i], &input[i]); //Joel-TODO

        printf("Time: %d %d %d %d %d %d\n", info->tm_year, info->tm_mon, info->tm_mday, info->tm_hour, info->tm_min, info->tm_sec);
        buf[n++] = 0x17;
        buf[n++] = 0x0D; // 0x0D if seconds, 0x0B if not
        buf[n++] = 0x30 + (info->tm_year-100)/10;
        buf[n++] = 0x30 + info->tm_year-100-((info->tm_year-100)/10)*10;
        buf[n++] = 0x30 + (info->tm_mon+1)/10;
        buf[n++] = 0x30 + info->tm_mon+1 - ((info->tm_mon+1)/10)*10;
        buf[n++] = 0x30 + (info->tm_mday)/10;
        buf[n++] = 0x30 + info->tm_mday - ((info->tm_mday)/10)*10;
        buf[n++] = 0x30 + (info->tm_hour)/10;
        buf[n++] = 0x30 + info->tm_hour - ((info->tm_hour)/10)*10;
        buf[n++] = 0x30 + (info->tm_min)/10;
        buf[n++] = 0x30 + info->tm_min - ((info->tm_min)/10)*10;
        buf[n++] = 0x30 + (info->tm_sec)/10;
        buf[n++] = 0x30 + info->tm_sec - ((info->tm_sec)/10)*10;
        buf[n++] = 0x5A;

    }
    return n;
}

static int xiot_encode_key_info(uint8_t* buf, const uint8_t* key)
{
    int n = 0;

    int i;
    for(i = 0; i < strlen(XIOT_SUB_PUB_INSERT); i++){
        buf[n++] = XIOT_SUB_PUB_INSERT[i];
    }
    buf[n++] = 0x00;
    buf[n++] = 0x04;

    memcpy(&buf[n], key, 64);
    n += 64;

    return n;
}

static int xiot_encode_extension(uint8_t* buf, const uint8_t* value, int length, int id, bool critical)
{
    int encoded;
    int n = 0;    

    buf[n++] = 0x30;

    if(critical){
        encoded = xiot_encode_length(&buf[n], length+10);
    } else {
        encoded = xiot_encode_length(&buf[n], length+7);
    }    
    n += encoded;

    buf[n++] = 0x06;
    buf[n++] = 0x03;
    buf[n++] = 0x55;
    buf[n++] = 0x1D;
    buf[n++] = id;

    if(critical){
        buf[n++] = 0x01;
        buf[n++] = 0x01;
        buf[n++] = 0xFF;
    }

    buf[n++] = 0x04;

    encoded = xiot_encode_length(&buf[n], length);
    n += encoded;

    memcpy(&buf[n], value, length);
    n += length;

    return n;
}

static size_t xiot_construct_tbs(uint8_t* buf, xiot_cert_t* cert)
{
    int encoded;
    int n = 0;
    int i;

    buf[n++] = 0x30;
    n++; // Reserved for size, n == 1

    for(i = 0; i < strlen(XIOT_VERSION_INSERT); i++){
        buf[n++] = XIOT_VERSION_INSERT[i];
    }

    // Serial number
    encoded = xiot_encode_uint(&buf[n], cert->serial_number);
    n += encoded;

    // Signature
    for(i = 0; i < strlen(XIOT_SIG_ALG_INSERT); i++){
        buf[n++] = XIOT_SIG_ALG_INSERT[i];
    }

    // Issuer
    encoded = xiot_encode_cn(&buf[n], cert->issuer, cert->issuer_length, XIOT_ISSUER_STRING_ENCODING, true);
    n += encoded;

    // Validity
    encoded = xiot_encode_validity(&buf[n], cert->not_before, cert->not_after);
    n += encoded;

    // Subject
    encoded = xiot_encode_cn(&buf[n], cert->subject, cert->subject_length, XIOT_SUBJECT_STRING_ENCODING, cert->subject_ca);
    n += encoded;

    // Subject public key info
    encoded = xiot_encode_key_info(&buf[n], cert->public_key);
    n += encoded;

    // Extensions
    if(cert->extensions != NULL){
        int size = 0;
        int sizepos;

        buf[n++] = 0xA3;
        sizepos = n++;
        buf[n++] = 0x30;
        sizepos = n++;

        xiot_ext_t* extension = cert->extensions;

        while(extension != NULL){
            encoded = xiot_encode_extension(
                    &buf[n],
                    extension->value, 
                    extension->length,
                    extension->oid, 
                    extension->critical);
            n += encoded;
            size += encoded;
            
            extension = extension->next;
        }
        
        // TODO: Check if size needs 2 bytes or more
        buf[sizepos] = size;
        buf[sizepos-2] = size+2;
    }

    uint8_t tbs_length[8];
    encoded = xiot_encode_length(tbs_length, n-2);
    if(encoded > 1){
        memmove(&buf[1+encoded], &buf[2], n);
        n += encoded-1;
    }
    memcpy(&buf[1], tbs_length, encoded);

    return n;
}

static size_t xiot_construct_signature(uint8_t* buf, const uint8_t* signature)
{
    int n = 0;

    buf[n++] = 0x03;
    n++; // Size
    buf[n++] = 0x00;

    buf[n++] = 0x30;
    n++; // Size

    buf[n++] = 0x02;
    if(signature[0] & 0x80){
        buf[n++] = 0x21;
        buf[n++] = 0x00;
    } else {
        buf[n++] = 0x20;
    }
    memcpy(&buf[n], &signature[0], 32);
    n += 32;

    buf[n++] = 0x02;
    if(signature[32] & 0x80){
        buf[n++] = 0x21;
        buf[n++] = 0x00;
    } else {
        buf[n++] = 0x20;
    }
    memcpy(&buf[n], &signature[32], 32);
    n += 32;

    buf[1] = n-2;
    buf[4] = n-5;

    return n;
}
//#if 0 < uECC
static size_t xiot_sign_tbs(uint8_t* signature, const uint8_t* tbs_cert, size_t tbs_length, const uint8_t* private_key)
{
    const struct uECC_Curve_t* curve;
    curve = uECC_secp256r1();

    static uint8_t message_hash[32];
    SHA256Context sha;
    int err;

    err = SHA256Reset(&sha);
    if(err){
        printf("SHA256Reset Error %d.\n", err);
        return 0;
    }

    err = SHA256Input(&sha, tbs_cert, tbs_length);
    if(err){
        printf("SHA256Input Error %d.\n", err);
        return 0;
    }

    err = SHA256Result(&sha, message_hash);
    if(err){
        printf("SHA256Result Error %d.\n", err);
        return 0;
    }

    err = uECC_sign(private_key, message_hash, 32, signature, curve);
    if(!err){
        printf("uECC_sign Error %d.\n", err);
        return 0;
    }

    return 32;
}
//#endif //end of if WITH_ECC

// Library funtions
//size_t xiot_compress(uint8_t* compressed, const uint8_t* uncompressed, size_t length)
//{
//
//    int encoded;
//
//    // Create X.509 structure
//    x509_certificate *in;
//    uint8_t* pos = (uint8_t* ) uncompressed;
//    in = x509_decode_certificate(&pos, pos + length);
//    // Prepare CBOR output
//    cn_cbor_errback error;
//    cn_cbor *out;
//    out = cn_cbor_array_create(&error);
//
//
//    // Create the serial number
//
//    // TODO: decode serial numbers bigger than 1 byte
//    cn_cbor *serialNumber;
//    //int i = asn1_decode_integer(uint8_t **pos, uint8_t *end, uint32_t *value);
//    //uint32_t serialNumber_v = *in->serial_number.value;
//    uint64_t serialNumber_v = *in->serial_number.value;
//    serialNumber = cn_cbor_int_create(serialNumber_v, &error);
//    cn_cbor_array_append(out, serialNumber, &error);
//
//    // Create the issuer
//    cn_cbor *issuer;
//    static char issuer_v[XIOT_MAX_ISSUER_LENGTH + 1] = {0};
//    strncpy(issuer_v, ((char*) in->issuer_name.value)+11, in->issuer_name.length-11);	//11 bytes = control + DN OID
//    /* Add: string termination...! */
//    issuer_v[in->issuer_name.length-11] = 0;
//
//    issuer = cn_cbor_string_create(issuer_v, &error);
//    cn_cbor_array_append(out, issuer, &error);
//
//    // Create the validity
//    cn_cbor *validity;
//    validity = cn_cbor_array_create(&error);
//    cn_cbor *not_before;
//    cn_cbor *not_after;
//    time_t not_before_v;
//    time_t not_after_v;
//    struct tm tmp;
//
//    tmp.tm_year = in->validity.not_before.year-1900;
//    tmp.tm_mon = in->validity.not_before.month-1;
//    tmp.tm_mday = in->validity.not_before.day;
//    tmp.tm_hour = in->validity.not_before.hour;
//    tmp.tm_min = in->validity.not_before.minute;
//    tmp.tm_sec = in->validity.not_before.second;
//    not_before_v = my_timegm(&tmp);
//
//    tmp.tm_year = in->validity.not_after.year-1900;
//    tmp.tm_mon = in->validity.not_after.month-1;
//    tmp.tm_mday = in->validity.not_after.day;
//    tmp.tm_hour = in->validity.not_after.hour;
//    tmp.tm_min = in->validity.not_after.minute;
//    tmp.tm_sec = in->validity.not_after.second;
//    not_after_v = my_timegm(&tmp);
//
//    not_before = cn_cbor_int_create(not_before_v, &error);
//    not_after = cn_cbor_int_create(not_after_v, &error);
//    cn_cbor_array_append(validity, not_before, &error);
//    cn_cbor_array_append(validity, not_after, &error);
//    cn_cbor_array_append(out, validity, &error);
//
//    // Create the subject
//    cn_cbor *subject;
//    static char subject_v[XIOT_MAX_SUBJECT_LENGTH + 1] = {0};
//
//    // Match CA = true in extensions
//    char* ca_ptr;
//    if(in->extensions.value != NULL){
//      PRINTF("XIOT-DEBUG: check for CA\n");
//      ca_ptr = strstr(
//                (const char *) in->extensions.value,
//                //was: "\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");
//                "\x04\x05\x30\x03\x01\x01\xFF");
//    } else {
//        ca_ptr = NULL;
//    }
//
//    if(ca_ptr){ // Is CA -> create string
//      PRINTF("XIOT-DEBUG: IS CA!\n");
//        strncpy(subject_v, ((char*) in->subject_name.value)+11, in->subject_name.length-11);	//11 bytes = cotrol + CN OID
//        /* Add: string termination...! */
//        subject_v[in->subject_name.length-11] = 0;
//
//        subject = cn_cbor_string_create(subject_v, &error);
//    } else { // Is not CA -> parse EUI64
//        size_t eui_size = xiot_parse_eui64(subject_v, (char* ) in->subject_name.value+11, in->subject_name.length-11);
//        subject = cn_cbor_data_create((uint8_t*) subject_v, (int) eui_size, &error);
//    }
//
//    cn_cbor_array_append(out, subject, &error);
//
//    // Create the public key in compressed format
//    // Assumes 64+1 bytes with no check on format
//    cn_cbor *public_key;
//    static uint8_t public_v[33];
//
//    memcpy(public_v+1, in->pk_info.subject_public_key.bit_string+1, 32);
//    public_v[0] = 0x02 + (in->pk_info.subject_public_key.bit_string[64] & 0x01);
//
//    public_key = cn_cbor_data_create(public_v, 33, &error);
//    cn_cbor_array_append(out, public_key, &error);
//
//    // Create the extensions
//    xiot_ext_t* ext = xiot_decode_extensions(in->extensions.value, in->extensions.length);
//    if(ext){
//        cn_cbor *extensions;
//        extensions = cn_cbor_array_create(&error);
//#ifdef DEBUG_XIOT
//        debug_count = 0;
//#endif
//        while(ext){
//          PRINTF("XIOT-DEBUG: Decoding exts: %d\n", debug_count++);
//            cn_cbor *extension;
//            extension = cn_cbor_array_create(&error);
//
//            cn_cbor *oid;
//            oid = cn_cbor_int_create(ext->oid, &error);
//            cn_cbor_array_append(extension, oid, &error);
//
//            if(ext->critical == true){
//                cn_cbor* critical;
//                critical = cn_cbor_int_create(1, &error);
//                critical->type = CN_CBOR_SIMPLE;
//                critical->v.uint = 21;
//                cn_cbor_array_append(extension, critical, &error);
//            }
//
//            cn_cbor* value;
//            value = cn_cbor_data_create(ext->value, ext->length, &error);
//            cn_cbor_array_append(extension, value, &error);
//
//            cn_cbor_array_append(extensions, extension, &error);
//
//            ext = ext->next;
//        }
//
//        cn_cbor_array_append(out, extensions, &error);
//    }
//    xiot_free_extensions(ext);
//
//    // Create the signature
//    // TODO: sequence of integers?
//    cn_cbor *signature;
//    static uint8_t sig[64];
//    int sig_n = 4;
//
//    sig_n += in->certificate_signature.bit_string[3] & 0x01;
//    memcpy(sig, &(in->certificate_signature.bit_string[sig_n]), 32);
//    sig_n += 32;
//    sig_n += 2;
//    sig_n += in->certificate_signature.bit_string[sig_n-1] & 0x01;
//    memcpy(&sig[32], &(in->certificate_signature.bit_string[sig_n]), 32);
//
//
//    signature = cn_cbor_data_create(sig, 64, &error);
//    cn_cbor_array_append(out, signature, &error);
//
//    // Encode the structure
//    encoded = (int) cn_cbor_encoder_write(compressed, 0, XIOT_MAX_COMPRESSED, out);
//    //*compressed = realloc(*compressed, encoded);
//    cn_cbor_free(out);
//    x509_memb_remove_certificates(in);
//
//    return encoded;
//}

//size_t xiot_compress_pkcs(uint8_t* compressed, const uint8_t* uncompressed, size_t length)
//{
//
//    int encoded;
//
//    // Create X.509 structure
//    x509_certificate *in;
//    uint8_t* pos = (uint8_t* ) uncompressed;
//    in = x509_decode_certificate(&pos, pos + length);
//    // Prepare CBOR output
//    cn_cbor_errback error;
//    cn_cbor *out;
//    out = cn_cbor_array_create(&error);
//
//
//    // Create the serial number
//
//    // TODO: decode serial numbers bigger than 1 byte
//    cn_cbor *serialNumber;
//    //int i = asn1_decode_integer(uint8_t **pos, uint8_t *end, uint32_t *value);
//    //uint32_t serialNumber_v = *in->serial_number.value;
//    uint64_t serialNumber_v = *in->serial_number.value;
//    serialNumber = cn_cbor_int_create(serialNumber_v, &error);
//    cn_cbor_array_append(out, serialNumber, &error);
//
//    // Create the issuer
//    cn_cbor *issuer;
//    static char issuer_v[XIOT_MAX_ISSUER_LENGTH + 1] = {0};
//    strncpy(issuer_v, ((char*) in->issuer_name.value)+11, in->issuer_name.length-11); //11 bytes = control + DN OID
//    /* Add: string termination...! */
//    issuer_v[in->issuer_name.length-11] = 0;
//
//    issuer = cn_cbor_string_create(issuer_v, &error);
//    cn_cbor_array_append(out, issuer, &error);
//
//    // Create the validity
//    cn_cbor *validity;
//    validity = cn_cbor_array_create(&error);
//    cn_cbor *not_before;
//    cn_cbor *not_after;
//    time_t not_before_v;
//    time_t not_after_v;
//    struct tm tmp;
//
//    tmp.tm_year = in->validity.not_before.year-1900;
//    tmp.tm_mon = in->validity.not_before.month-1;
//    tmp.tm_mday = in->validity.not_before.day;
//    tmp.tm_hour = in->validity.not_before.hour;
//    tmp.tm_min = in->validity.not_before.minute;
//    tmp.tm_sec = in->validity.not_before.second;
//    not_before_v = my_timegm(&tmp);
//
//    tmp.tm_year = in->validity.not_after.year-1900;
//    tmp.tm_mon = in->validity.not_after.month-1;
//    tmp.tm_mday = in->validity.not_after.day;
//    tmp.tm_hour = in->validity.not_after.hour;
//    tmp.tm_min = in->validity.not_after.minute;
//    tmp.tm_sec = in->validity.not_after.second;
//    not_after_v = my_timegm(&tmp);
//
//    not_before = cn_cbor_int_create(not_before_v, &error);
//    not_after = cn_cbor_int_create(not_after_v, &error);
//    cn_cbor_array_append(validity, not_before, &error);
//    cn_cbor_array_append(validity, not_after, &error);
//    cn_cbor_array_append(out, validity, &error);
//
//    // Create the subject
//    cn_cbor *subject;
//    static char subject_v[XIOT_MAX_SUBJECT_LENGTH + 1] = {0};
//
//    // Match CA = true in extensions
//    char* ca_ptr;
//    if(in->extensions.value != NULL){
//      PRINTF("XIOT-DEBUG: check for CA\n");
//      ca_ptr = strstr(
//                (const char *) in->extensions.value,
//                //was: "\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");
//                "\x04\x05\x30\x03\x01\x01\xFF");
//    } else {
//        ca_ptr = NULL;
//    }
//
//    if(ca_ptr){ // Is CA -> create string
//      PRINTF("XIOT-DEBUG: IS CA!\n");
//        strncpy(subject_v, ((char*) in->subject_name.value)+11, in->subject_name.length-11);  //11 bytes = cotrol + CN OID
//        /* Add: string termination...! */
//        subject_v[in->subject_name.length-11] = 0;
//
//        subject = cn_cbor_string_create(subject_v, &error);
//    } else { // Is not CA -> parse EUI64
//        size_t eui_size = xiot_parse_eui64(subject_v, (char* ) in->subject_name.value+11, in->subject_name.length-11);
//        subject = cn_cbor_data_create((uint8_t*) subject_v, (int) eui_size, &error);
//    }
//
//    cn_cbor_array_append(out, subject, &error);
//
//    // Create the public key in compressed format
//    // Assumes 64+1 bytes with no check on format
//    cn_cbor *public_key;
//    static uint8_t public_v[33];
//
//    memcpy(public_v+1, in->pk_info.subject_public_key.bit_string+1, 32);
//    public_v[0] = 0x02 + (in->pk_info.subject_public_key.bit_string[64] & 0x01);
//
//    public_key = cn_cbor_data_create(public_v, 33, &error);
//    cn_cbor_array_append(out, public_key, &error);
//
//    // Create the extensions
//    xiot_ext_t* ext = xiot_decode_extensions(in->extensions.value, in->extensions.length);
//    if(ext){
//        cn_cbor *extensions;
//        extensions = cn_cbor_array_create(&error);
//#ifdef DEBUG_XIOT
//        debug_count = 0;
//#endif
//        while(ext){
//          PRINTF("XIOT-DEBUG: Decoding exts: %d\n", debug_count++);
//            cn_cbor *extension;
//            extension = cn_cbor_array_create(&error);
//
//            cn_cbor *oid;
//            oid = cn_cbor_int_create(ext->oid, &error);
//            cn_cbor_array_append(extension, oid, &error);
//
//            if(ext->critical == true){
//                cn_cbor* critical;
//                critical = cn_cbor_int_create(1, &error);
//                critical->type = CN_CBOR_SIMPLE;
//                critical->v.uint = 21;
//                cn_cbor_array_append(extension, critical, &error);
//            }
//
//            cn_cbor* value;
//            value = cn_cbor_data_create(ext->value, ext->length, &error);
//            cn_cbor_array_append(extension, value, &error);
//
//            cn_cbor_array_append(extensions, extension, &error);
//
//            ext = ext->next;
//        }
//
//        cn_cbor_array_append(out, extensions, &error);
//    }
//    xiot_free_extensions(ext);
//
//    // Create the signature
//    // TODO: sequence of integers?
//    cn_cbor *signature;
//    static uint8_t sig[64];
//    int sig_n = 4;
//
//    sig_n += in->certificate_signature.bit_string[3] & 0x01;
//    memcpy(sig, &(in->certificate_signature.bit_string[sig_n]), 32);
//    sig_n += 32;
//    sig_n += 2;
//    sig_n += in->certificate_signature.bit_string[sig_n-1] & 0x01;
//    memcpy(&sig[32], &(in->certificate_signature.bit_string[sig_n]), 32);
//
//
//    signature = cn_cbor_data_create(sig, 64, &error);
//    cn_cbor_array_append(out, signature, &error);
//
//    // Encode the structure
//    encoded = (int) cn_cbor_encoder_write(compressed, 0, XIOT_MAX_COMPRESSED, out);
//    //*compressed = realloc(*compressed, encoded);
//    cn_cbor_free(out);
//    x509_memb_remove_certificates(in);
//
//    return encoded;
//}


//size_t xiot_decompress_chain(uint8_t* decompressed_chain, const uint8_t* compressed_chain) {
//
//  PRINTF("XIOT-DEBUG: decompress chain\n");
//  size_t tot_decomp_len;
//  uint16_t tot_comp_len;
//  //uint16_t decoded_len;
//  int comp_cp = 0, decomp_cp = 0;
//  uint8_t *pos_for_full_len;
//
//  size_t comp_cert_len, decomp_cert_len;
//
//  //uint8_t decompressed_chain[MAX_CHAIN_LEN*XIOT_MAX_DECOMPRESSED];
////#ifndef DTLS_HS_LENGTH
////#define DTLS_HS_LENGTH sizeof(dtls_handshake_header_t)
////#endif
//  memcpy(decompressed_chain, compressed_chain, DTLS_HS_LENGTH);
//
//  comp_cp += DTLS_HS_LENGTH;
//  decomp_cp += DTLS_HS_LENGTH;
//  pos_for_full_len = &decompressed_chain[decomp_cp];
//
//  tot_comp_len = dtls_uint24_to_int(compressed_chain+comp_cp);
//
//  PRINTF("XIOT-DEBUG: decompress chain, tot_comp_len: %d\n", tot_comp_len);
//
//  /* Later, below we have
//   * dtls_int_to_uint24(decompressed_chain, tot_decomp_len)
//   */
//
//  comp_cp += sizeof(uint24);
//  decomp_cp += sizeof(uint24);
//
//  /* Check the 3 byte length field for the Certificate chains.*/
//  comp_cert_len = dtls_uint24_to_int(compressed_chain+comp_cp);
//  PRINTF("XIOT-DEBUG: decompress chain, comp_cert_len: %d\n", comp_cert_len);
//  comp_cp += sizeof(uint24);
//  //The decomp_cp += sizeof(uint24) is done _after_ decompression and len-update
//
//while (comp_cert_len) {
//  PRINTF("XIOT-DEBUG: START decomp_cert_len, decomp_cp, comp_cert_len, comp_cp - %d %d %d %d\n", decomp_cert_len, decomp_cp, comp_cert_len, comp_cp);
//
//  decomp_cert_len = xiot_decompress(decompressed_chain+decomp_cp + sizeof(uint24), compressed_chain+comp_cp, comp_cert_len);
//  dtls_int_to_uint24(decompressed_chain+decomp_cp, decomp_cert_len);
//
//  comp_cp += comp_cert_len;
//  decomp_cp += sizeof(uint24) + decomp_cert_len;
//  PRINTF("XIOT-DEBUG: decompress chain, MID decomp_cert_len, decomp_cp, comp_cert_len, comp_cp - %d %d %d %d\n", decomp_cert_len, decomp_cp, comp_cert_len, comp_cp);
//  if(tot_comp_len < comp_cp) {
//    comp_cert_len = 0;
//  } else {
//    comp_cert_len = dtls_uint24_to_int(compressed_chain+comp_cp);
//    comp_cp += sizeof(uint24);
//  }
//  PRINTF("XIOT-DEBUG: decompress chain, END decomp_cert_len, decomp_cp, comp_cert_len, comp_cp - %d %d %d %d\n", decomp_cert_len, decomp_cp, comp_cert_len, comp_cp);
//}
//  tot_decomp_len = decomp_cp;// - DTLS_HS_LENGTH - 3;
//  PRINTF("XIOT-DEBUG: decompress chain, writing in tot_decomp_len as %d\n", tot_decomp_len-DTLS_HS_LENGTH - 3);
//  dtls_int_to_uint24(pos_for_full_len, tot_decomp_len-DTLS_HS_LENGTH-3);
//  dtls_int_to_uint24(pos_for_full_len-3, tot_decomp_len-DTLS_HS_LENGTH);
//  dtls_int_to_uint24(pos_for_full_len-11, tot_decomp_len-DTLS_HS_LENGTH);
//  //result = decompressed_chain;
//#if DEBUG_XIOT
//  hdump(decompressed_chain, tot_decomp_len);
//#endif
//
//  return tot_decomp_len;
//}


//size_t xiot_decompress(uint8_t* decompressed, const uint8_t* compressed, size_t length)
//{
//#ifdef DEBUG_XIOT
//  PRINTF("Dump before decompression, with len %d\n", length);
//  hdump(compressed, length);
//#endif
//
//  if(NORMAL_CERT_SIGNATURE_1 == compressed[0]) {
//    PRINTF("Not compressed: copy & return\n");
//    memcpy(decompressed, compressed, length);
//    return length;
//  }
//
//    static xiot_cert_t intermediate;
//
//#if 4==ENERGEST_SCOPE
//  start_energest();
//  PRINTF("starting energest in mode 4\n");
//#endif
//
//    xiot_decode_compressed(&intermediate, compressed, length);
//
//#if 4==ENERGEST_SCOPE
//  stop_energest(num_run);
//  num_run++;
//  PRINTF("stopping energest in mode 4\n");
//#endif
//
//    size_t constructed;
//    constructed = xiot_construct(decompressed, &intermediate, NULL);
//
//    return constructed;
//}

size_t xiot_construct(uint8_t* decompressed, xiot_cert_t* cert, uint8_t* ca_private)
{
    int encoded;
    int n = 0;
    int i;

    //*decompressed = calloc(1, XIOT_MAX_DECOMPRESSED);
    uint8_t* buf = decompressed;

    buf[n++] = 0x30;
    n++; // Reserved for size, n == 1


    // Construct tbs
    encoded = xiot_construct_tbs(&buf[n], cert);
    n += encoded;

    // Construct signature algorithm
    for(i = 0; i < strlen(XIOT_SIG_ALG_INSERT); i++){
        buf[n++] = XIOT_SIG_ALG_INSERT[i];
    }

    // Construct sign
    if(cert->signature[0] == 0){
        uint8_t signature[64];
        if(xiot_sign_tbs(signature, &buf[2], encoded, ca_private) == 0){
            return 0;
        }
        encoded = xiot_construct_signature(&buf[n], signature);
        n += encoded;

    } else {
        encoded = xiot_construct_signature(&buf[n], cert->signature);
        n += encoded;
    }

    // Set length
    static uint8_t length[8];
    encoded = xiot_encode_length(length, n-2);
    if(encoded > 1){
        memmove(&buf[1+encoded], &buf[2], n);
        n += encoded-1;
    }
    memcpy(&buf[1], length, encoded);

    return n;
}

//int xiot_decode_compressed(xiot_cert_t* cert, const uint8_t* compressed, size_t length)
//{
//    cn_cbor_errback decode_error;
//    cn_cbor* cbor;
//    PRINTF("XIOT-DEBUG: DECODE\n");
//    cbor = cn_cbor_decode(compressed, length, &decode_error);
//
//    // Serial number
//    cn_cbor* serial_number = cn_cbor_index(cbor, 0);
//    //printf("3-serial_number: %lu\n",serial_number->v.uint);
//    // Issuer
//    cn_cbor* issuer = cn_cbor_index(cbor, 1);
//    //printf("4-%d",issuer);
//    // Validity
//    cn_cbor* validity = cn_cbor_index(cbor, 2);
//    //printf("5");
//    // Subject
//    cn_cbor* subject = cn_cbor_index(cbor, 3);
//    //printf("6");
//    // Subject public key info
//    cn_cbor* subpub = cn_cbor_index(cbor, 4);
//    //printf("7");
//    // Signature
//    cn_cbor* signature = cbor->last_child;
//    //printf("8"); //: %d,",serial_number->v.uint);
//
//    cert->serial_number = serial_number->v.uint;
//    //printf("9");
//    memcpy(cert->issuer, issuer->v.str, issuer->length);
//
//    //printf("\n\nDEBUG\n\ncbor issuer: %s with len %d\n", issuer->v.str, issuer->length);
//    cert->issuer_length = issuer->length;
//    //printf("cert->issuer: %s with len %d\n", cert->issuer, cert->issuer_length);
//
//#if BYTE_ORDER==BIG_ENDIAN
//    cert->not_before = dtls_uint32_to_int((char*)&(validity->first_child->v.sint));
//    cert->not_after = dtls_uint32_to_int((char*)&(validity->last_child->v.sint));
//    //hdump(&(cert->not_before), sizeof(time_t));
//#else
//    cert->not_before = validity->first_child->v.sint;
//    cert->not_after = validity->last_child->v.sint;
//#endif
//
//    memcpy(cert->subject, subject->v.bytes, subject->length);
//    cert->subject_length = subject->length;
//    //printf("10");
//
//#if 5==ENERGEST_SCOPE
//  start_energest();
//  PRINTF("starting energest in mode 5\n");
//#endif
//
//    const struct uECC_Curve_t* curve;
//    curve = uECC_secp256r1();
//    uECC_decompress(subpub->v.bytes, cert->public_key, curve);
//
//#if 5==ENERGEST_SCOPE
//  stop_energest(num_run);
//  num_run++;
//  PRINTF("stopping energest in mode 5\n");
//#endif
//
//    bool subject_is_ca = false;
//    xiot_ext_t* root_ext = NULL;
//
//    if(cbor->length == 7){
//        cn_cbor* extensions = cn_cbor_index(cbor, 5);
//
//        bool critical = false;
//        xiot_ext_t* tmp_ext = NULL;
//
//        cn_cbor* extension = extensions->first_child;
//#if DEBUG_XIOT
//            debug_count = 0;
//#endif
//
//        while(extension != NULL){
//            if(extension->length > 2){
//                critical = true;
//            } else {
//                critical = false;
//            }
//#if DEBUG_XIOT
//            debug_count++;
//#endif
//            if(root_ext == NULL){
//                root_ext = get_ext_space(); /* WAS: calloc(1, sizeof(xiot_ext_t)); */
//                tmp_ext = root_ext;
//
//            } else {
//                tmp_ext->next = get_ext_space(); /* WAS: calloc(1, sizeof(xiot_ext_t)); */
//                tmp_ext = tmp_ext->next;
//            }
//
//            tmp_ext->oid = extension->first_child->v.uint;
//            tmp_ext->critical = critical;
//            tmp_ext->value = (uint8_t*) extension->last_child->v.bytes;
//            tmp_ext->length = extension->last_child->length;
//
//            if(tmp_ext->oid == 0x13){ // basic constraints
//                if(tmp_ext->length > 4 && tmp_ext->value[2] == 0x01 && tmp_ext->value[4] == 0xFF){
//                   subject_is_ca = true;
//                }
//            }
//
//            extension = extension->next;
//        }
//    }
//
//    cert->extensions = root_ext;
//    PRINTF("XIOT-DEBUG: Extensions, exts=%d:\n", debug_count);
//
//    memcpy(cert->signature, signature->v.bytes, 64);
//
//    cert->subject_ca = subject_is_ca;
//    cn_cbor_free(cbor);
//
//    // TODO: Check if it fails, then return 0
//    return 1;
//}

//size_t xiot_encode_compressed(uint8_t* compressed, xiot_cert_t* cert)
//{
//    // Prepare CBOR output
//    cn_cbor_errback error;
//    cn_cbor *out;
//    out = cn_cbor_array_create(&error);
//
//    // Serial number
//    cn_cbor* serial_number;
//    //serial_number = cn_cbor_uint_create(cert->serial_number, &error);
//    serial_number = cn_cbor_int_create(cert->serial_number, &error);
//    cn_cbor_array_append(out, serial_number, &error);
//
//    // Issuer
//    cn_cbor* issuer;
//    static char issuer_v[XIOT_MAX_ISSUER_LENGTH + 1] = {0};
//    memcpy(issuer_v, cert->issuer, cert->issuer_length);
//    issuer = cn_cbor_string_create(issuer_v, &error);
//    cn_cbor_array_append(out, issuer, &error);
//
//    // Validity
//    cn_cbor *validity;
//    validity = cn_cbor_array_create(&error);
//    cn_cbor *not_before;
//    cn_cbor *not_after;
//    not_before = cn_cbor_int_create(cert->not_before, &error);
//    not_after = cn_cbor_int_create(cert->not_after, &error);
//    cn_cbor_array_append(validity, not_before, &error);
//    cn_cbor_array_append(validity, not_after, &error);
//    cn_cbor_array_append(out, validity, &error);
//
//    // Subject
//    cn_cbor *subject;
//    if(cert->subject_ca){
//        static char subject_v[XIOT_MAX_SUBJECT_LENGTH + 1] = {0};
//        memcpy(subject_v, cert->subject, cert->subject_length);
//        subject = cn_cbor_string_create(subject_v, &error);
//    } else {
//        subject = cn_cbor_data_create((uint8_t*) cert->subject, cert->subject_length, &error);
//    }
//    cn_cbor_array_append(out, subject, &error);
//
//    // Public key
//    cn_cbor *public_key;
//    static uint8_t pub_comp[33];
//
//    const struct uECC_Curve_t* curve;
//    curve = uECC_secp256r1();
//    uECC_compress(cert->public_key, pub_comp, curve);
//
//    public_key = cn_cbor_data_create(pub_comp, 33, &error);
//    cn_cbor_array_append(out, public_key, &error);
//
//    // Extensions
//    xiot_ext_t* ext = cert->extensions;
//    if(ext){
//        cn_cbor *extensions;
//        extensions = cn_cbor_array_create(&error);
//        while(ext){
//            cn_cbor *extension;
//            extension = cn_cbor_array_create(&error);
//
//            cn_cbor *oid;
//            oid = cn_cbor_int_create(ext->oid, &error);
//            cn_cbor_array_append(extension, oid, &error);
//
//            if(ext->critical == true){
//                cn_cbor* critical;
//                critical = cn_cbor_int_create(1, &error);
//                critical->type = CN_CBOR_SIMPLE;
//                critical->v.uint = 21;
//                cn_cbor_array_append(extension, critical, &error);
//            }
//
//            cn_cbor* value;
//            value = cn_cbor_data_create(ext->value, ext->length, &error);
//            cn_cbor_array_append(extension, value, &error);
//
//            cn_cbor_array_append(extensions, extension, &error);
//
//            ext = ext->next;
//        }
//        cn_cbor_array_append(out, extensions, &error);
//    }
//
//    // Signature
//    if(cert->signature != NULL){
//        cn_cbor* signature;
//        signature = cn_cbor_data_create(cert->signature, 64, &error);
//        cn_cbor_array_append(out, signature, &error);
//    }
//
//    // Encode CBOR
//    //*compressed = malloc(XIOT_MAX_COMPRESSED);
//    int encoded = (int) cn_cbor_encoder_write(compressed, 0, XIOT_MAX_COMPRESSED, out);
//    //*compressed = realloc(*compressed, encoded);
//
//    return encoded;
//}

//int xiot_verify_signature(xiot_cert_t* cert, uint8_t* public_key)
//{
//    static uint8_t tbs[XIOT_MAX_DECOMPRESSED];
//    size_t tbs_length = xiot_construct_tbs(tbs, cert);
//
//    // est
//    static x509_key_context pk_ctx;
//    pk_ctx.pk_alg = ECC_PUBLIC_KEY;
//    pk_ctx.sign = ECDSA_WITH_SHA256;
//    pk_ctx.curve = SECP256R1_CURVE;
//    memcpy(pk_ctx.pub_x, public_key, 32);
//    memcpy(pk_ctx.pub_y, public_key+32, 32);
//
//    new_ecc_init();
//
//    static uint8_t asn1_sign[80];
//    size_t asn1_sign_size = xiot_construct_signature(asn1_sign, cert->signature);
//    int valid = x509_verify_signature(tbs, tbs_length, asn1_sign, asn1_sign_size, &pk_ctx);
//    if(valid < 0){
//        return 0;
//    } else {
//        return 1;
//    }
//
//    // uECC
//    // const struct uECC_Curve_t * curve;
//    // curve = uECC_secp256r1();
//    // static uint8_t message_hash[32];
//    // SHA256Context sha;
//    // int err;
//
//    // err = SHA256Reset(&sha);
//    // if(err){
//    //     printf("SHA256Reset Error %d.\n", err);
//    //     return 0;
//    // }
//
//    // err = SHA256Input(&sha, tbs, tbs_length);
//    // if(err){
//    //     printf("SHA256Input Error %d.\n", err);
//    //     return 0;
//    // }
//
//    // err = SHA256Result(&sha, message_hash);
//    // if(err){
//    //     printf("SHA256Result Error %d.\n", err);
//    //     return 0;
//    // }
//
//    // int valid = uECC_verify(public_key, message_hash, 32, cert->signature, curve);
//    // if(!valid){
//    //     printf("uECC_verify Error.\n");
//    // }
//
//    // return valid;
//}

//int xiot_verify_validity(xiot_cert_t* cert, time_t time)
//{
//    if(cert->not_before > time || cert->not_after < time ){
//        return 0;
//    } else {
//        return 1;
//    }
//}

//hdump was here, now in debug.c

#ifdef DEBUG_XIOT

void xiot_print_bytes(const uint8_t* buffer, size_t length)
{
    printf("(%zu bytes):\n", length);
    int k = 0;
    for (k = 0; k < length; k++)
    {
        printf ("%02x ", buffer[k]);
        if(k % 16 == 15)
            printf("\n");
    }
    printf("\n");
}

void xiot_print_line(const uint8_t* buffer, size_t length)
{
    int k = 0;
    for (k = 0; k < length; k++)
    {
        printf ("%02x", buffer[k]);
    }
    printf("\n");
}


void xiot_print_hex_array(const uint8_t* buffer, size_t length)
{
    int k = 0;
    printf("{ ");
    for (k = 0; k < length; k++)
    {
        printf("0x%02x%c", buffer[k], k==length-1 ? '}' : ',');
    }
    printf("\n");
}

#endif //DEBUG_XIOT
