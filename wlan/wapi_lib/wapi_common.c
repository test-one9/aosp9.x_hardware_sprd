/** @file common.c
  * @brief This file contains functions for common, include random, print, ecc
 *
 *  Copyright (C) 2001-2008, Iwncomm Ltd.
 */

#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

//#include "hmac_sha256.h"
#include "alg_comm.h"
#include "wapi_common.h"
#include "wapi_interface.h"

#define ANDROID 1
#ifdef ANDROID
#include <android/log.h>
#endif

static int iwn_debug_level = MSG_DEBUG;

void iwn_wpa_printf(int level, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (level >= iwn_debug_level) {
#ifdef ANDROID
        int android_level = ANDROID_LOG_DEBUG;
        if (level == MSG_DEBUG)
            android_level = ANDROID_LOG_DEBUG;
        else if (level == MSG_INFO)
            android_level = ANDROID_LOG_INFO;
        else if (level == MSG_WARNING)
            android_level = ANDROID_LOG_WARN;
        else if (level == MSG_ERROR)
            android_level = ANDROID_LOG_ERROR;

        __android_log_vprint(android_level, "wapilib", fmt, ap);
#else
        vprintf(fmt, ap);
        printf("\n");
#endif
    }
    va_end(ap);
}

void iwn_wpa_hexdump(int level, const char *title, const u8 *buf, size_t len)
{
    if (level >= iwn_debug_level)
    {
        print_buf(title, buf, len);
    }
}

void print_buf(const char* title, const void* buf, int len)
{
    int cl = (len-1)/16 + 1;
    int i;
    int j;
    char txt[512] = {0};
    
    iwn_wpa_printf(MSG_DEBUG, "\n%s(len=%d,0x%X)\n", title, len, len);
    
    for (i=0; i<cl; i++)
    {
        int n = 16;
        const unsigned char* p = NULL;
        if (i == cl-1)
        {
            n = len%16;
            if (0 == n)
            {
                n = 16;
            }
        }
        memset(txt, 0, sizeof(txt));
        snprintf(txt, sizeof(txt), "%.4X  ", i*16);
        p = (const unsigned char*)buf + i*16;
        for (j=0; j<n; j++)
        {
            char tmp[4];
            snprintf(tmp, sizeof(tmp), "%.2X", p[j]);
            strlcat(txt, tmp, sizeof(txt));
            if (j == n-1)
            {
                if (16 == n)
                {
                    strlcat(txt, "  ", sizeof(txt));
                }
                else
                {
                    int k;
                    for (k=strlen(txt); k<60; k++)
                    {
                        if (k < (int)sizeof(txt) - 1)
                            txt[k] = ' ';
                    }
                }
            }
            else if (3 == j%4)
            {
                strlcat(txt, " ", sizeof(txt));
            }
        }
        for (j=0; j<n; j++)
        {
            int c = p[j];
            if (c < 32 || (c>127 && c<160))
            {
                c = '.';
            }
            char tmp[2] = {(char)c, 0};
            strlcat(txt, tmp, sizeof(txt));
        }
        iwn_wpa_printf(MSG_DEBUG, "%s", txt);
    }
    iwn_wpa_printf(MSG_DEBUG, "\n");
}

/* ---------------------------------------------------------------------------------------
 * [Name]      x509_ecc_verify
 * [Function]   verify the sign information with the public key
 * [Input]       const unsigned char *pub_s
 *                  int pub_sl,
 *                  ......
 * [Output]     NULL
 * [Return]     int
 *                              1   success
 *                              0   fail
 * [Limitation] NULL
 * ---------------------------------------------------------------------------------------
 */
int x509_ecc_verify(const unsigned char *pub_s, int pub_sl, unsigned char *in, int in_len, unsigned char *sign, int sign_len)
{
    int ret = 0;
    
    if (pub_s == NULL || pub_sl <= 0 || in == NULL || in_len <= 0 || sign == NULL || sign_len <= 0)
    {
        return ret;
    }
    else
    {
        ret = ecc192_verify(pub_s, in, in_len, sign, sign_len);
    }

    if (ret <= 0)
        ret = 0;
    else
        ret = 1;

    return ret;
}


/* ---------------------------------------------------------------------------------------
 * [Name]      x509_ecc_sign
 * [Function]   sign with the private key
 * [Input]       const unsigned char *priv_s
 *                  int priv_sl,
 *                  const unsigned char *int,
 *                  int in_len
 * [Output]     unsigned char *out 
 * [Return]     int
 *                              > 0   success
 *                              0      fail
 * [Limitation] NULL
 * ---------------------------------------------------------------------------------------
 */
int x509_ecc_sign(const unsigned char *priv_s, int priv_sl, const unsigned char *in, int in_len, unsigned char *out)
{
    (void)priv_sl; /* disable warning */
    if (priv_s == NULL || in == NULL || in_len <= 0 || out == NULL)
    {
        return 0;
    }
    else
    {
        return ecc192_sign(priv_s, in, in_len, out);
    }
}



/* ---------------------------------------------------------------------------------------
 * [Name]      x509_ecc_verify_key
 * [Function]   verify the public key and the private key
 * [Input]       const unsigned char *pub_s
 *                  int pub_sl,
 *                  const unsigned char *priv_s
 *                  int priv_sl
 * [Output]     NULL
 * [Return]     int
 *                              1   success
 *                              0   fail
 * [Limitation] NULL
 * ---------------------------------------------------------------------------------------
 */
int x509_ecc_verify_key(const unsigned char *pub_s, int pub_sl, const unsigned char *priv_s, int priv_sl)
{
#define EC962_SIGN_LEN      48
    unsigned char data[] = "123456abcd";
    unsigned char sign[EC962_SIGN_LEN+1];
    int ret = 0;

    if (pub_s == NULL || pub_sl <= 0 || priv_s == NULL || priv_sl <= 0)
    {
        return 0;
    }

    memset(sign, 0, sizeof(sign));
    ret = ecc192_sign(priv_s, data, strlen((char*)data), sign);
    if (ret != EC962_SIGN_LEN)
    {
        printf("ecc192_sign call fail \n");
        ret = 0;
        return ret;
    }

    ret = ecc192_verify(pub_s, data, strlen((char*)data), sign, EC962_SIGN_LEN);
    if (ret <= 0)
    {
        printf("ecc192_verify call fail \n");
        ret = 0;
    }

    return ret;

}
