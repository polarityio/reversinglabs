'use strict';

const request = require('request');
const async = require('async');
const fs = require('fs');
const config = require('./config/config');
const crypto = require('crypto');

const SEVERITY_LEVELS = {
  0: 'none',
  1: 'low',
  2: 'medium',
  3: 'medium',
  4: 'high',
  5: 'high'
};

const STATUS_TYPES = ['KNOWN', 'UNKNOWN', 'MALICIOUS', 'SUSPICIOUS'];

const BUG_ICON = `<svg aria-hidden="true" focusable="false" data-prefix="fas" data-icon="bug" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="svg-inline--fa fa-bug fa-w-16"><path fill="currentColor" d="M511.988 288.9c-.478 17.43-15.217 31.1-32.653 31.1H424v16c0 21.864-4.882 42.584-13.6 61.145l60.228 60.228c12.496 12.497 12.496 32.758 0 45.255-12.498 12.497-32.759 12.496-45.256 0l-54.736-54.736C345.886 467.965 314.351 480 280 480V236c0-6.627-5.373-12-12-12h-24c-6.627 0-12 5.373-12 12v244c-34.351 0-65.886-12.035-90.636-32.108l-54.736 54.736c-12.498 12.497-32.759 12.496-45.256 0-12.496-12.497-12.496-32.758 0-45.255l60.228-60.228C92.882 378.584 88 357.864 88 336v-16H32.666C15.23 320 .491 306.33.013 288.9-.484 270.816 14.028 256 32 256h56v-58.745l-46.628-46.628c-12.496-12.497-12.496-32.758 0-45.255 12.498-12.497 32.758-12.497 45.256 0L141.255 160h229.489l54.627-54.627c12.498-12.497 32.758-12.497 45.256 0 12.496 12.497 12.496 32.758 0 45.255L424 197.255V256h56c17.972 0 32.484 14.816 31.988 32.9zM257 0c-61.856 0-112 50.144-112 112h224C369 50.144 318.856 0 257 0z" class=""></path></svg>`;

let log = null;
let requestWithDefaults;

function startup(logger) {
  let defaults = {};
  log = logger;

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _getReversingLabsType(entity) {
  if (entity.isMD5) {
    return 'md5';
  }
  if (entity.isSHA256) {
    return 'sha256';
  }
  if (entity.isSHA1) {
    return 'sha1';
  }
}

function isUri(entity) {
  return entity.isURL || entity.isIP || entity.isDomain || entity.isEmail;
}

function _lookupUriHashes(entity, options, cb) {
  log.trace('looking up entity ' + entity.value);

  let ro = {
    uri: options.url + '/api/uri_index/v1/query',
    method: 'POST',
    auth: {
      user: options.username,
      pass: options.password
    },
    body: {
      rl: {
        query: {
          uri: entity.value
        }
      }
    },
    json: true
  };

  requestWithDefaults(ro, function(err, response, body) {
    log.trace('done looking up entity ' + entity.value);

    _handleRequestError(err, response, function(err) {
      if (err) {
        log.trace('error looking up entity ' + entity.value);
        cb(err);
        return;
      }

      if (!body) {
        log.trace('no results looking up entity ' + entity.value);
        cb(null, null);
        return;
      }

      log.trace('got result looking up entity ' + entity.value);

      // Anything set on this details object must be copied explicitly in `onDetails`
      let details = {
        sha1_list: body.rl.uri_index.sha1_list.slice(0, options.numHashes),
        url: options.a1000,
        isUriToHash: true
      };

      cb(null, details);
    });
  });
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  async.each(
    entities,
    (entity, next) => {
      if (isUri(entity)) {
        lookupUriStats(entity, options, function(err, details) {
          if (err) {
            return next(err);
          }

          if (!details) {
            lookupResults.push({
              entity: entity,
              data: null
            });
            return next();
          }

          let stats = details.rl.uri_state;

          lookupResults.push({
            entity: entity,
            data: {
              summary: [
                stats.uri_type,
                stats.counters.known ? `Known: ${stats.counters.known}` : null,
                stats.counters.malicious ? `Malicious: ${stats.counters.malicious}` : null,
                stats.counters.suspicious ? `Suspicious: ${stats.counters.suspicious}` : null
              ].filter((entry) => !!entry),
              details: {
                hasStats: true,
                stats: stats
              }
            }
          });
          next();
        });
      } else {
        let rlType = _getReversingLabsType(entity);
        _lookupEntity(entity, rlType, options, function(err, result) {
          if (err) {
            return next(err);
          }

          // null results are ignored as they have been filtered out based on user options
          if (result !== null) {
            lookupResults.push(result);
          }

          next();
        });
      }
    },
    (err) => {
      cb(err, lookupResults);
    }
  );
}

function _getEntitySearchUrl(rlType, entity, options) {
  if (rlType !== 'sha1' && rlType !== 'md5' && rlType !== 'sha256') {
    log.error(entity);
    throw new Error('invalid entity type provided to _getEntitySearchUrl');
  }

  return `${options.url}/api/databrowser/malware_presence/query/${rlType}/${entity.value}?extended=true&format=json`;
}

function _getEntityXRefSearchUrl(rlType, entity, options) {
  if (rlType !== 'sha1' && rlType !== 'md5' && rlType !== 'sha256') {
    log.error(entity);
    throw new Error('invalid entity type provided to _getEntityXRefSearchUrl');
  }

  return `${options.url}/api/xref/v2/query/${rlType}/${entity.value}?extended=true&format=json`;
}

function _lookupEntity(entity, rlType, options, cb) {
  let requestOptions = {
    uri: _getEntitySearchUrl(rlType, entity, options),
    method: 'GET',
    auth: {
      username: options.username,
      password: options.password
    },
    json: true
  };

  requestWithDefaults(requestOptions, function(err, response, body) {
    _handleRequestError(err, response, function(jsonApiError) {
      if (jsonApiError) {
        cb(jsonApiError);
        return;
      }

      if (
        response.statusCode === 404 ||
        body == null ||
        body.rl == null ||
        body.rl.malware_presence.status === 'UNKNOWN'
      ) {
        return cb(null, {
          entity: entity,
          data: null
        });
      }

      // Check if we need to ignore this result because the user as opted to ignore known samples
      let malwarePresence = body.rl.malware_presence;
      if (malwarePresence.status === 'KNOWN' && options.ignoreKnownSamples) {
        return cb(null, null);
      }

      cb(null, {
        entity: entity,
        data: {
          summary: [
            `${malwarePresence.status} ${rlType.toUpperCase()}`,
            `${malwarePresence.scanner_match} ${BUG_ICON}/ ${malwarePresence.scanner_count}`,
            `Threat: ${SEVERITY_LEVELS[malwarePresence.threat_level]}`
          ],
          details: body.rl
        }
      });
    });
  });
}

function _lookupEntityXref(entityObj, type, options, cb) {
  let requestOptions = {
    uri: _getEntityXRefSearchUrl(type, entityObj, options),
    method: 'GET',
    auth: {
      username: options.username,
      password: options.password
    },
    json: true
  };

  requestWithDefaults(requestOptions, function(err, response, body) {
    _handleRequestError(err, response, function(jsonApiError) {
      if (jsonApiError) {
        return cb(jsonApiError);
      }

      if (response.statusCode === 404 || body.rl == null || body.rl.sample.xref === '') {
        return cb(null, null);
      }

      cb(null, body);
    });
  });
}

function lookupUriStats(entity, options, cb) {
  let shasum = crypto.createHash('sha1');
  shasum.update(entity.value);
  let sha1 = shasum.digest('hex');

  log.trace(`looking up stats for uri ${entity.value} with sha ${sha1}`);

  let ro = {
    uri: `${options.url}/api/uri/statistics/uri_state/sha1/${sha1}?format=json`,
    method: 'GET',
    auth: {
      user: options.username,
      pass: options.password
    },
    json: true
  };

  requestWithDefaults(ro, function(err, resp, result) {
    if (resp.statusCode == 404) {
      log.trace(`No Results for Entity ${entity.value}`);
      return cb(null, null);
    }

    if (err || resp.statusCode !== 200) {
      log.error(err || resp.statusCode);
      return cb(err || resp.statusCode);
    }

    log.trace(result, 'lookupUriStats');

    cb(null, result);
  });
}

function onDetails(lookupObject, options, cb) {
  let rlType = _getReversingLabsType(lookupObject.entity);

  if (isUri(lookupObject.entity)) {
    return _lookupUriHashes(lookupObject.entity, options, function(err, result) {
      if (err) {
        return cb(err);
      }

      lookupObject.data.details.sha1_list = result.sha1_list;
      lookupObject.data.details.url = result.url;
      lookupObject.data.details.isUriToHash = result.isUriToHash;

      cb(null, lookupObject.data);
    });
  }

  _lookupEntityXref(lookupObject.entity, rlType, options, (err, result) => {
    if (err) {
      return cb(err);
    }

    if (result !== null) {
      lookupObject.data.details.scanner_match = result.rl.sample.xref[0].scanner_match;
      lookupObject.data.details.scanner_count = result.rl.sample.xref[0].scanner_count;
      lookupObject.data.details.scanned_on = result.rl.sample.xref[0].scanned_on;
      lookupObject.data.details.results = result.rl.sample.xref[0].results;
    }

    cb(null, lookupObject.data);
  });
}

function _handleRequestError(err, response, cb) {
  if (err) {
    cb(
      _createJsonErrorPayload('HTTP Request Failed', null, '500', '2A', 'HTTP Error', {
        err: err
      })
    );
    return;
  }

  // don't consider this an error as we treat it as a cache miss
  if (response.statusCode === 404) {
    cb(null);
    return;
  }

  if (response.statusCode === 401) {
    cb(
      _createJsonErrorPayload('Request requires user authentication', null, '401', '2A', 'Unauthorized', {
        err: err
      })
    );
    return;
  }

  if (response.statusCode === 400) {
    cb(
      _createJsonErrorPayload(
        'Request could not be understood by the server due to malformed syntax',
        null,
        '400',
        '2A',
        'Bad Request',
        {
          err: err
        }
      )
    );
    return;
  }
  if (response.statusCode === 403) {
    cb(
      _createJsonErrorPayload(
        'The server understood the request, but is refusing to fulfill it',
        null,
        '403',
        '2A',
        'Forbidden',
        {
          err: err
        }
      )
    );
    return;
  }

  if (response.statusCode === 500) {
    cb(
      _createJsonErrorPayload(
        'Server encountered an unexpected condition which prevented it from fulfilling the request',
        null,
        '500',
        '2A',
        'Internal Server Error',
        {
          err: err
        }
      )
    );
    return;
  }

  if (response.statusCode === 503) {
    cb(
      _createJsonErrorPayload(
        'Server is currently unable to handle the request due to a temporary overloading or maintenance of the server',
        null,
        '503',
        '2A',
        'Service Unavailable ',
        {
          err: err
        }
      )
    );
    return;
  }

  if (response.statusCode !== 200) {
    cb(
      _createJsonErrorPayload(
        'The integration received an unexpected non-200 HTTP status code',
        null,
        response.statusCode.toString(),
        '2A',
        'Unexpected Non-200 HTTP Code',
        {
          err: err
        }
      )
    );
    return;
  }

  cb(null);
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.password.value !== 'string' ||
    (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)
  ) {
    errors.push({
      key: 'password',
      message: 'You must provide a valid password'
    });
  }

  if (
    typeof userOptions.username.value !== 'string' ||
    (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)
  ) {
    errors.push({
      key: 'username',
      message: 'You must provide a Reversing Labs Username'
    });
  }

  cb(null, errors);
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  let errors = [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)];

  log.error({ errors: errors });

  return { errors: errors };
}

// function that creates the Json object to be passed to the payload
function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'RL_' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions,
  onDetails: onDetails
};
