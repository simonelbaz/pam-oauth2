OAuth2 PAM module
=================

This PAM module enables login with OAuth2 token instead of password.

## How to install it:

```bash
$ sudo apt-get install libcurl4-openssl-dev libpam-dev
$ git submodule init
$ git submodule update
$ make
$ sudo make install
```

## Configuration

```
auth sufficient pam_oauth2.so <instrospect url> <client_id> <client_secret>
account sufficient pam_oauth2.so
```

## How it works

Lets assume that configuration is looking like:

```
auth sufficient pam_oauth2.so https://foo.org/oauth2/introspect pamoauth2 mysecret
```

And somebody is trying to login with authbearer:
```
   C: t1 AUTHENTICATE OAUTHBEARER bixhPXVzZXJAZXhhbXBsZS5jb20sAWhv
         c3Q9c2VydmVyLmV4YW1wbGUuY29tAXBvcnQ9MTQzAWF1dGg9QmVhcmVyI
         HZGOWRmdDRxbVRjMk52YjNSbGNrQmhiSFJoZG1semRHRXVZMjl0Q2c9PQ
         EB
```

Base64 decoded

```
n,a=user@example.com,^Ahost=server.example.com^Aport=143^A
auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==^A^A
```

pam\_oauth2 module will make http request:
```
curl -s -u pamoauth2:mysecret -X POST -d 'token=vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==' 'https://foo.org/oauth2/introspect'
```

If the response code is not 200 - authentication will fail. After that it will check response content:

```json
{
   "active" : true,
   "client_id" : "pamoauth2",
   "exp" : 1630684115,
   "iss" : "https://foo.org/",
   "scope" : "openid profile email",
   "sub" : "dwho"
}
```

If some keys haven't been found or values don't match with expectation - authentication will fail.

### Issues and Contributing

Oauth2 PAM module welcomes questions via our [issues tracker](https://github.com/CyberDem0n/pam-oauth2/issues). We also greatly appreciate fixes, feature requests, and updates; before submitting a pull request, please visit our [contributor guidelines](https://github.com/CyberDem0n/pam-oauth2/blob/master/CONTRIBUTING.rst).

License
-------

This project uses the [MIT license](https://github.com/CyberDem0n/pam-oauth2/blob/master/LICENSE).
