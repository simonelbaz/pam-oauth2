#include <curl/system.h>
#include <security/_pam_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <curl/curl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "cJSON.h"

struct response {
    char *ptr;
    size_t len;
};

struct st_authbearer {
    char a[256];
    char host[1024];
    int port;
    char bearer[1024];
    char token[1024];
};

static int check_response(struct response token_info, const char * const user) {
    int i = 1;
    int status = 0;
    cJSON *active = NULL;
    cJSON *sub = NULL;
    cJSON *p = NULL;

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: response_data '%s'", token_info.ptr);
    
    p = cJSON_Parse(token_info.ptr);

    if (p == NULL) {
	    const char *error_ptr = cJSON_GetErrorPtr();
	    if (error_ptr != NULL) {
              syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: cJSON '%s'", error_ptr);
	    }
	    status = 1;
	    goto end;
    }

    active = cJSON_GetObjectItemCaseSensitive(p, "active");
    if (cJSON_IsTrue(active)) {
      syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: cJSON  active is True");
    }
    else {
      status = 2;
      goto end;
    }

    sub = cJSON_GetObjectItemCaseSensitive(p, "sub");
    if (cJSON_IsString(sub) && (sub->valuestring != NULL)) {
      syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: cJSON  sub '%s'", sub->valuestring);
    }

    status = strcmp(user, sub->valuestring);

end:
    cJSON_Delete(p);
    return status;
}

static size_t read_introspect_result(char *contents, size_t size, size_t nmemb, void *userdata) {
  size_t realsize = size * nmemb;
  struct response *mem = (struct response *)userdata;
 
  char *pointer = realloc(mem->ptr, mem->len + realsize + 1);
  if(!pointer) {
    /* out of memory! */
    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: not enough memory (realloc returned NULL)");
    return 0;
  }
 
  mem->ptr = pointer;
  memcpy(&(mem->ptr[mem->len]), contents, realsize);
  mem->len += realsize;
  mem->ptr[mem->len] = 0;
 
  return realsize;
}

static int query_token_info(const char * const tokeninfo_url, const char * const authtok, const char * const client_id, const char * const client_secret, long *response_code, struct response *token_info) {
    int ret = 0;
    char *url, *userpassword;
    int user_len = 0, password_len = 0;
    CURLcode result;
    char errbuf[CURL_ERROR_SIZE];
    size_t len;
    curl_mime *mime;
    curl_mimepart *part;

    result = curl_global_init(CURL_GLOBAL_ALL);
    if(result != CURLE_OK)
      return (int)result;

    CURL *session = curl_easy_init();

    if ((token_info->ptr = malloc(1)) == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: memory allocation failed");
        return PAM_AUTHINFO_UNAVAIL;
    }

    token_info->len = 0;

    if (!session) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't initialize curl");
        return ret;
    }

    mime = curl_mime_init(session);

    if (mime == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: cannot initialize mime");
        return ret;
    }

    part = curl_mime_addpart(mime);

    if (part == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: cannot initialize part");
        return ret;
    }

    curl_mime_data(part, authtok, strlen(authtok));
    curl_mime_name(part, "token");

    user_len = strlen(client_id);
    password_len = strlen(client_secret);

    if ((userpassword = malloc(user_len + password_len + 1 + 1))) {
	  strcpy(userpassword, client_id);
	  strcat(userpassword, ":");
	  strcat(userpassword, client_secret);
    }

    /* Post and send it */
    curl_easy_setopt(session, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(session, CURLOPT_URL, tokeninfo_url);

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: url '%s'", tokeninfo_url);
    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: userpassword '%s'", userpassword);

    /* set username and password for the authentication */
    curl_easy_setopt(session, CURLOPT_USERPWD, userpassword);

    /* Set the default value: strict certificate check please (disable) */
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 0L);

    /* provide a buffer to store errors in */
    curl_easy_setopt(session, CURLOPT_ERRORBUFFER, errbuf);
 
    /* set write callback */
    curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, read_introspect_result);
    curl_easy_setopt(session, CURLOPT_WRITEDATA, (void *)token_info);

    /* some servers do not like requests that are made without a user-agent
       field, so we provide one */
    curl_easy_setopt(session, CURLOPT_USERAGENT, "libcurl-agent/1.0");
 
    /* set the error buffer as empty before performing a request */
    errbuf[0] = 0;

    if ((ret = curl_easy_perform(session)) == CURLE_OK) { 
	curl_off_t cl;
	curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, response_code); 
	curl_easy_getinfo(session, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl); 
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: content-length '%ld'", cl);
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: %lu bytes retrieved", (unsigned long)token_info->len);
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: retrieved message '%s'", (char *)token_info->ptr);
    } else {
	len = strlen(errbuf);
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: return_code: '%d'", ret);

	if (len) {
          syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: '%s%s'", errbuf,
                ((errbuf[len - 1] != '\n') ? "\n" : ""));
	}
	else {
          syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: strerror: '%s'", curl_easy_strerror(result));
	}

        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: failed to perform curl request");
    }

    curl_easy_cleanup(session);
    curl_mime_free(mime);
    curl_global_cleanup();

    free(userpassword);

    return ret;
}

static int extract_token(struct st_authbearer *authbearer_parsed, char **token) {
    int ret = 0;
    char *authBearer = "auth=Bearer";

    *token = malloc(1024);
    /* + 1 to step over space before token */
    strcpy(*token, authbearer_parsed->bearer + strlen(authBearer) + 1);
    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: token '%s'", *token);

    return ret;
}

static int parse_authbearer(const char * const authbearer_decoded, struct st_authbearer *authbearer_parsed) {
    int ret = 0;
    char *next;
    char *left;
    char *delim = "";

    next = strtok(authbearer_decoded, delim);

    if (next != NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: username '%s'", next);
        strcpy(authbearer_parsed->a, next);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get username");
        return 1;
    }

    next = strtok(NULL, delim);

    if (next != NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: hostname '%s'", next);
        strcpy(authbearer_parsed->host, next);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get hostname");
        return 1;
    }

    next = strtok(NULL, delim);

    if (next != NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: port '%s'", next);
        authbearer_parsed->port = atoi(next);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get port");
        return 1;
    }

    next = strtok(NULL, delim);

    if (next != NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: bearer '%s'", next);
        strcpy(authbearer_parsed->bearer, next);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get bearer");
        return 1;
    }

    return ret;
}

static int decode_authbearer(const char * const authbearer, char **authbearer_decoded) {
    int ret = 0;
    BIO *bio, *b64;
    int authbearer_len = strlen(authbearer);

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authbearer_to_decode '%s'", authbearer);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(authbearer, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);/* No newline handling */

    *authbearer_decoded = (unsigned char *)malloc(authbearer_len);

    ret = BIO_read(b64, *authbearer_decoded, authbearer_len);

    BIO_free_all(bio);

    return ret;
}

static int oauth2_authenticate(const char * const tokeninfo_url, const char * const user, const char * const authbearer, const char * const client_id, const char * const client_secret) {
    struct response token_info;
    struct st_authbearer authbearer_parsed;
    long response_code = 0;
    char *authbearer_decoded;
    char *token;
    int ret, authtok_len;

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authbearer_oauth2 '%s'", authbearer);

    if (decode_authbearer(authbearer, &authbearer_decoded) < 0) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: unable to decode authbearer '%s'", authbearer);
        return PAM_AUTHINFO_UNAVAIL;
    }

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authbearer_decoded '%s'", authbearer_decoded);

    if (parse_authbearer(authbearer_decoded, &authbearer_parsed) != 0) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: unable to parse authbearer");
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* free malloc memory before going further */
    free(authbearer_decoded);

    if (extract_token(&authbearer_parsed, &token) != 0) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: unable to parse authbearer");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (query_token_info(tokeninfo_url, token, client_id, client_secret, &response_code, &token_info) != 0) {
        ret = PAM_AUTHINFO_UNAVAIL;
    } else if (response_code == 200) {
        ret = check_response(token_info, user);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authentication failed with response_code=%li", response_code);
        ret = PAM_AUTH_ERR;
    }

    free(token_info.ptr);
    free(authbearer_decoded);
    free(token);

    return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tokeninfo_url = NULL, *user = NULL, *authbearer = NULL;
    const char *client_id = NULL, *client_secret = NULL;
    int i, ct_len = 1;

    if (argc != 3) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: Expects 3 arguments (url, client_id, client_secret)");
        return PAM_AUTHINFO_UNAVAIL;
    }

    tokeninfo_url = argv[0];
    client_id = argv[1];
    client_secret = argv[2];

    if (tokeninfo_url == NULL || *tokeninfo_url == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: tokeninfo_url is not defined or invalid");
        return PAM_AUTHINFO_UNAVAIL;
    }

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: tokeninfo_url '%s'", tokeninfo_url);

    if (client_id == NULL || *client_id == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: client_id is not defined or empty");
        return PAM_AUTHINFO_UNAVAIL;
    }

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: client_id '%s'", client_id);

    if (client_secret == NULL || *client_secret == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: client_secret is not defined or empty");
        return PAM_AUTHINFO_UNAVAIL;
    }

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: client_secret '%s'", client_secret);

    if (pam_get_authtok(pamh, PAM_AUTHTOK, &authbearer, NULL) != PAM_SUCCESS || authbearer == NULL || *authbearer == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get authbearer");
        return PAM_AUTHINFO_UNAVAIL;
    }

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authbearer_pam '%s'", authbearer);

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't get user");
        return PAM_AUTHINFO_UNAVAIL;
    }

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: user '%s'", user);

    return oauth2_authenticate(tokeninfo_url, user, authbearer, client_id, client_secret);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_CRED_UNAVAIL;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
