#include <curl/system.h>
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

struct check_tokens {
    const char *key;
    int key_len;
    const char *value;
    int value_len;
    int match;
};

struct st_authbearer {
    char a[256];
    char host[1024];
    int port;
    char bearer[1024];
    char token[1024];
};

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct response *r) {
    size_t data_size = size * nmemb;
    size_t new_len = r->len + data_size;
    char *new_ptr = realloc(r->ptr, new_len + 1);

    if (new_ptr == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: memory allocation failed");
        return 0;
    }

    r->ptr = new_ptr;

    memcpy(r->ptr + r->len, ptr, data_size);
    r->ptr[r->len = new_len] = '\0';

    return data_size;
}

/*
static int skip_object(const jsmntok_t *t, const int count) {
    int i;
    if (count <= 0) return 0; *//* should not happen */

    /*
    if (t->type == JSMN_PRIMITIVE || t->type == JSMN_STRING) {
        return 1;
    } else if (t->type == JSMN_OBJECT) {
        int ret = 1;
        for (i = 0; i < t->size; ++i) {
            ret += skip_object(t + ret, count - ret);
            ret += skip_object(t + ret, count - ret);
        }
        return ret;
    } else if (t->type == JSMN_ARRAY) {
        int ret = 1;
        for (i = 0; i < t->size; ++i)
            ret += skip_object(t + ret, count - ret);
        return ret;
    } else return 0;
}
    */

static int check_response(const struct response token_info, struct check_tokens *ct) {
    const char * const response_data = token_info.ptr;
    struct check_tokens *cti;
    int r, i = 1;
    cJSON *p;
    /* jsmntok_t t[128]; *//* We expect no more than 128 tokens */

    /*
    jsmn_init(&p);
    if ((r = jsmn_parse(&p, response_data, token_info.len, t, sizeof(t)/sizeof(t[0]))) < 0) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: Failed to parse tokeninfo JSON response");
        return PAM_AUTHINFO_UNAVAIL;
    }

    */
    /* Assume the top-level element is an object */
    /*
    if (r-- < 1 || t[0].type != JSMN_OBJECT) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: tokeninfo response: JSON Object expected");
        return PAM_AUTHINFO_UNAVAIL;
    }

    while (r > 0) {
        if (t[i].type == JSMN_STRING) {
            --r;
    */
            /* try to find "interesting" keys in the top-level element object */
    /*
            for (cti = ct; cti->key != NULL; ++cti) {
                if (cti->key_len == t[i].end - t[i].start &&
                        strncmp(response_data + t[i].start, cti->key, cti->key_len) == 0) {
                    ++i;
                    if (t[i].type == JSMN_STRING && cti->value_len == t[i].end - t[i].start &&
                            strncmp(response_data + t[i].start, cti->value, cti->value_len) == 0) {
                        ++i; --r;
                        cti->match = 1;
                        break;
                    } else {
                        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: '%.*s' value doesn't meet expectation: '%.*s' != '%.*s'",
                            cti->key_len, cti->key, t[i].end - t[i].start, response_data + t[i].start, cti->value_len, cti->value);
                        return PAM_AUTH_ERR;
                    }
                }
            }

    */
            /* skip value, because key was not interesting for us */
    /*
            if (cti->key == NULL) {
                int skipped = skip_object(t + ++i, r);
                r -= skipped; i += skipped;
            }
        } else {
            int skipped = skip_object(t + i, r);
            r -= skipped; i += skipped;
            skipped = skip_object(t + i, r);
            r -= skipped; i += skipped;
        }
    }

    r = PAM_SUCCESS;
    for (cti = ct; cti->key != NULL; ++cti) {
        if (cti->match == 0) {
            syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't find '%.*s' field in the tokeninfo JSON response object",
                cti->key_len, cti->key);
    */
    /*
            if (cti == ct) {  *//* login token field always come first */
    /*
                r = PAM_USER_UNKNOWN;
            } else if (r != PAM_USER_UNKNOWN) {
                r = PAM_AUTH_ERR;
            }
        }
    }

    */

    if (r == PAM_SUCCESS)
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: successfully authenticated '%.*s'", ct->value_len, ct->value);

    return r;
}

static int read_introspect_result(CURL *session, struct response *token_info, curl_off_t cl) {
      int ret = 0;
      char buf[256];
      char raw_introspect[cl];
      size_t nread, total_nread = 0;
      curl_socket_t sockfd;
      CURLcode result;
 
      /* Extract the socket from the curl handle - we need it for waiting. */
      result = curl_easy_getinfo(session, CURLINFO_ACTIVESOCKET, &sockfd);
 
      /* read data */
      result = curl_easy_recv(session, buf, sizeof(buf), &nread);

      while (total_nread < cl) {
        if (result == CURLE_OK) {
	      total_nread += nread;
	      strcpy(raw_introspect, buf);
	      result = curl_easy_recv(session, buf, sizeof(buf), &nread);
	} else if (result == CURLE_AGAIN) {
              if ((ret = listen(sockfd, 10)) == 0) {
	          result = curl_easy_recv(session, buf, sizeof(buf), &nread);
	      } else {
                  syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: listen failed");
	      }
	} else {
		break;
	}

      }

      syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: raw_introspect '%s'", raw_introspect);

      return ret;
}

static int query_token_info(const char * const tokeninfo_url, const char * const authtok, const char * const client_id, const char * const client_secret, long *response_code, struct response *token_info) {
    int ret = 1;
    char *url, *userpassword;
    int user_len = 0, password_len = 0;
    CURLcode result;
    char errbuf[CURL_ERROR_SIZE];
    size_t len;
    CURL *session = curl_easy_init();
    curl_mime *mime;
    curl_mimepart *part;

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
 
    /* set the error buffer as empty before performing a request */
    errbuf[0] = 0;

    if ((ret = curl_easy_perform(session)) == CURLE_OK) { 
	curl_off_t cl;
	curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, response_code); 
	curl_easy_getinfo(session, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl); 
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: content-length '%ld'", cl);

	if (cl > 0) {
		read_introspect_result(session, token_info, cl);
	}

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

static int decode_authbearer(const char * const authbearer, unsigned char **authbearer_decoded) {
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

static int oauth2_authenticate(const char * const tokeninfo_url, const char * const authbearer, const char * const client_id, const char * const client_secret, struct check_tokens *ct) {
    struct response token_info;
    struct st_authbearer authbearer_parsed;
    long response_code = 0;
    unsigned char *authbearer_decoded;
    char *token;
    int ret, authtok_len;

    syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: authbearer_oauth2 '%s'", authbearer);

    if ((token_info.ptr = malloc(1)) == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: memory allocation failed");
        return PAM_AUTHINFO_UNAVAIL;
    }
    token_info.ptr[token_info.len = 0] = '\0';

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
        ret = check_response(token_info, ct);
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
    const char *tokeninfo_url = NULL, *authbearer = NULL;
    const char *client_id = NULL, *client_secret = NULL;
    struct check_tokens ct[argc];
    int i, ct_len = 1;
    ct->key = ct->value = NULL;

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

    return oauth2_authenticate(tokeninfo_url, authbearer, client_id, client_secret, ct);
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
