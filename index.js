
/*!
 * accepts
 * Copyright(c) 2020 Manvel Khnkoyan
 * MIT Licensed
 */

const urlParser = require('url');
const queryString = require('querystring');
const crypto = require('crypto');

/**
 * Constructor of UrlEncrypt
 * @param config - setting up config
 * @returns void
 */
function UrlEncrypt(config) {
  const conf = (typeof config === 'object') ? config : {};
  this.secretKey = conf.secretKey || '';
  this.prefix = conf.prefix || 'es1_';
  this.algorithm = conf.algorithm || 'sha256';
  this.expiredAfterSeconds = conf.expiredAfterSeconds || 15 * 60;
  this.oversight = conf.oversight || 30;
}

/**
 * Adding prefix given name
 * @param name
 * @returns string
 */
UrlEncrypt.prototype.withPrefix = function withPrefix(name) { return `${this.prefix}${name}`; };

/**
 * Set Up Configuration
 * @param config
 */
UrlEncrypt.prototype.config = function configuration(config) {
  if (typeof config !== 'object') return this;
  if (config.prefix) this.prefix = config.prefix;
  if (config.secretKey) this.secretKey = config.secretKey;
  if (('expiredAfterSeconds' in config) && !Number.isNaN(this.expiredAfterSeconds)) {
    this.expiredAfterSeconds = config.expiredAfterSeconds;
  }
  if (config.algorithm) this.algorithm = config.algorithm;
  if (('oversight' in config) && !Number.isNaN(this.oversight)) this.oversight = config.oversight;
  return this;
};

/**
 * Generating signature by given params
 * @param params
 * @returns string
 */
UrlEncrypt.prototype.hashOf = function hashOf(params) {
  const ordered = {};
  /* ordering query params
   * and excluding signature keyword
   */
  Object.keys(params.query).sort().forEach((key) => {
    if (key !== this.withPrefix('signature')) {
      ordered[key] = params.query[key];
    }
  });

  /*
   * building path that should be encoded
   */
  const path = `${encodeURIComponent(`${params.protocol}//${params.host}/${params.path}`)}`
      + `&${encodeURIComponent(queryString.stringify(ordered))}`;

  /*
   * encoding using crypto module
   */
  return crypto.createHmac(params.query[this.withPrefix('algorithm')], this.secretKey)
    .update(path)
    .digest('hex');
};

/**
 * Converting url into parameters
 * @param url - standard http url
 * @returns string
 */
UrlEncrypt.prototype.parseUrl = function parseUrl(url) {
  const params = urlParser.parse(url);
  const query = queryString.parse(params.query);
  return {
    protocol: params.protocol,
    host: params.host,
    path: params.pathname,
    signature: query.signature,
    query,
  };
};

/**
 * Making secure url
 * @param url - standard http url
 * @returns string
 */
UrlEncrypt.prototype.encrypt = function encrypt(url) {
  const params = this.parseUrl(url);

  /*
  * creating new object based on params.query
  */
  const query = { ...params.query };

  /*
  * Adding main required marameters
  */
  query[this.withPrefix('nonce')] = `${Math.random().toString(36).substring(3)}`;
  query[this.withPrefix('timestamp')] = `${Math.floor(Date.now() / 1000)}`;
  query[this.withPrefix('algorithm')] = `${this.algorithm}`;

  /*
  * deleting signature from the query
  */
  if (query[this.withPrefix('signature')]) delete query[this.withPrefix('signature')];

  /*
   * generating signature
   */
  const signature = this.hashOf({ ...params, query });

  /*
   * encoding signature into base64
   * adding signature into the query
   */
  query[this.withPrefix('signature')] = Buffer.from(signature).toString('base64');

  //
  return `${params.protocol}//${params.host}${params.path}?${queryString.stringify(query)}`;
};


/**
 * Validating given url
 * @param url - standard http url
 * @returns boolean
 */
UrlEncrypt.prototype.verify = function verify(url) {
  const params = this.parseUrl(url);
  const { query } = params;

  /*
  * Checking existence of required parameters
  * */
  if (!query[this.withPrefix('signature')]
      || !query[this.withPrefix('timestamp')]
      || !query[this.withPrefix('algorithm')]
      || !query[this.withPrefix('nonce')]) {
    return false;
  }

  /*
   * Check is signature type is string
   */
  if (typeof query[this.withPrefix('signature')] !== 'string') {
    return false;
  }

  const signature = Buffer
    .from(query[this.withPrefix('signature')], 'base64')
    .toString('ascii');

  /*
   * Comparing given signature from query with generating new signature
   */
  try {
    if (this.hashOf(params) !== signature) {
      return false;
    }
  } catch (e) {
    return false;
  }

  //
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const signatureTimestamp = +query[this.withPrefix('timestamp')];
  const { expiredAfterSeconds, oversight } = this;

  /*
   * Checking given signature expired time
   */

  return !((signatureTimestamp < currentTimestamp - expiredAfterSeconds - oversight)
      || (signatureTimestamp > currentTimestamp + oversight));
};


module.exports = function encryptor(config) {
  return new UrlEncrypt(config);
};
