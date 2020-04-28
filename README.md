
url-encrypt
==========

URL encrypting and verifying  
Used to encrypt and verify URLs using OAuth signature encryption standards, for authentication purposes between services.

##### Install

```sh
$ npm install url-encrypt --save
```

##### Encrypting

After encryption, security parameters will be added to the URL, such as an encrypted signature.

```javascript
const encryptor = require('url-encrypt')();

encryptor.config({secretKey: 'some-secret-key'});
encryptor.encrypt('https://example.com/posts?postId=15');

// The output will be something like this
// https://example.com/posts?postId=15&prfx_nonce=...&prfx_timestamp=15..&prfx_method=sha256&prfx_signature=...
```

##### Verification

Then verifying an URL using the same configuration and the secret key

```javascript
encryptor.verify('https://example.co....')
// returns true or false
```


##### Expiration

Each encryption has its own expiration date after an outflow of expiration date URL verification will turn into failure.
The default expired date is 15 minutes, but it's configurable.

```javascript
 // Setting up expired time 1 hour
 const signature = new Signature({ secretKey: 'some-secret-key', expiredAfterSeconds: 3600 });
```

##### Configurations
 
More useful configurations for setting up a working flow

```javascript
encryptor.config({
    /*
     * default secret is empty string
     */
    secretKey: 'some-secret-key',

    /*
    * query parameters prefixes (default is "es1_")
    * This can be useful to avoid matching the given URL parameters 
    * with the package additional query parameters.
    */
    prefix: 'psx_',

    /*
     * Expiration date after given seconds 
     * default is 900 seconds = 15 minutes
     */
    expiredAfterSeconds: 3600,

    /*
     * Signature encoding algorithm
     * default is sha256
     * more info about supported algorithms could be found here: 
     * https://nodejs.org/api/crypto.html
     */
    algorithm: 'sha512',

    /*
    * This parameter describes time control between separated systems, using different machines.
    * for example, the time of one server may be later than the time of another server 
    * In this case, you can adjust the differences by this parameter
    */
    oversight: 12
});
```
