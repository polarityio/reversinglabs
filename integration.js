'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let async = require('async');
let log = null;
let fs = require('fs');
let config = require('./config/config');
let crypto = require('crypto');

const HASH_ICON = '<i class="fa fa-bug"></i>';
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

function _lookupUriHashes(entityObjs, options, cb) {
    log.trace('uri to hash lookup starting');

    let results = [];

    async.each(entityObjs, (entity, next) => {
        log.trace('looking up entity ' + entity.value);

        let roHashes = {
            uri: 'https://' + options.url + '/api/uri_index/v1/query',
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

        let shasum = crypto.createHash('sha1');
        shasum.update(entity.value);
        let hashedUri = shasum.digest('hex');

        log.trace('hashed uri', hashedUri);

        let roStats = {
            uri: 'https://' + options.url + '/api/uri/statistics/uri_state/sha1/' + hashedUri,
            method: 'GET',
            qs: {
                format: 'json'
            },
            auth: {
                user: options.username,
                pass: options.password
            },
            json: true
        };

        async.parallel({
            hashes: (done) => {
                requestWithDefaults(roHashes, function (err, response, body) {
                    log.trace('done looking up entity hashes ' + entity.value);

                    _handleRequestError(err, response, function (err) {
                        if (err) {
                            log.trace('error looking up entity ' + entity.value);
                            done(err);
                            return;
                        }

                        done(null, body);
                    });
                });
            },
            stats: (done) => {
                requestWithDefaults(roStats, function (err, response, body) {
                    log.trace('done looking up entity stats ' + entity.value);

                    _handleRequestError(err, response, function (err) {
                        if (err) {
                            log.trace('error looking up entity ' + entity.value);
                            done(err);
                            return;
                        }

                        done(null, body);
                    });
                });
            }
        }, (err, uri) => {
            if (err) {
                next(err);
                return;
            }

            if (!uri.hashes || !uri.hashes.rl || !uri.stats || !uri.stats.rl) {
                log.trace('no results looking up entity ' + entity.value);
                results.push({
                    entity: entity,
                    data: null
                });
                next();
                return
            }

            let details = {
                sha1_list: uri.hashes.rl.uri_index.sha1_list.slice(0, options.numHashes),
                url: options.a1000,
                isUriToHash: true
            };

            let stats = uri.stats.rl.uri_state.counters;
            let malicous = 'Malicous: ' + (stats.malicous ? stats.malicous : 0);
            let known = 'Known: ' + (stats.known ? stats.known : 0);
            let suspecious = 'Suspecious: ' + (stats.suspecious ? stats.suspecious : 0);

            results.push({
                entity: entity,
                data: {
                    summary: [malicous, known, suspecious],
                    details: details
                }
            });
            next();
        });
    }, err => {
        if (err) {
            cb(err);
            return;
        }

        log.trace('sending uri hash lookup results', results);

        cb(null, results);
    });
}

function isUri(entity) {
    return entity.isURL || entity.isIP || entity.isDomain || entity.isEmail
}

function doLookup(entities, options, cb) {
    log.debug({
        entities: entities.map(entity => {
            return entity.value;
        })
    }, 'doLookup Entity Values');
    log.trace({ entities: entities }, "doLookup Entity Objects");
    log.trace('options', options);

    let sha256Elements = [];
    let md5Elements = [];
    let sha1Elements = [];
    let lookupResultsSha1 = [];
    let lookupResultsSha256 = [];
    let lookupResultsMd = [];
    let lookupResultsHashes = [];
    let uriElements = [];

    for (let i = 0; i < entities.length; i++) {
        let entityObj = entities[i];

        if (entityObj.isSHA256 && options.lookupSha256) {
            sha256Elements.push(entityObj);
        } else if (entityObj.isSHA1 && options.lookupSha1) {
            sha1Elements.push(entityObj);
        } else if (entityObj.isMD5 && options.lookupMd5) {
            md5Elements.push(entityObj);
        } else if (isUri(entityObj)) {
            uriElements.push(entityObj);
        }
    }

    async.parallel({
        sha1: function (done) {
            _lookupEntitySHA1(sha1Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                done(null, results);
            });
        },
        md5: function (done) {
            _lookupEntityMD5(md5Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                done(null, results);
            });
        },
        sha256: function (done) {
            _lookupEntitySha256(sha256Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                done(null, results);
            });
        },
        sha1xref: function (done) {
            _lookupEntitySHA1Xref(sha1Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                done(null, results);
            });
        },
        md5xref: function (done) {
            _lookupEntityMD5Xref(md5Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                done(null, results);
            });
        },
        sha256xref: function (done) {
            _lookupEntitySha256Xref(sha256Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                done(null, results);
            });
        },
        uriToHashes: function (done) {
            _lookupUriHashes(uriElements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }

                done(null, results);
            });
        }
    }, function (err, results) {
        if (err) {
            cb(err);
        } else {
            log.debug({
                sha1: results.sha1.map(result => {
                    return result.entity.value;
                }),
                sha1xref: results.sha1xref.map(result => {
                    return result.entity.value;
                }),
                md5: results.md5.map(result => {
                    return result.entity.value;
                }),
                md5xref: results.md5xref.map(result => {
                    return result.entity.value;
                }),
                sha256: results.sha256.map(result => {
                    return result.entity.value;
                }),
                sha256xref: results.sha256xref.map(result => {
                    return result.entity.value;
                }),
                uriToHashes: results.uriToHashes.map(result => {
                    return result.entity.value;
                })
            }, 'Lookup Result Summary (Entities with Results)');

            log.trace({ results: results }, "Lookup Results:");

            results.sha1.forEach(function (result) {
                lookupResultsSha1.push(result);
            });
            results.md5.forEach(function (result) {
                lookupResultsMd.push(result);
            });
            results.sha256.forEach(function (result) {
                lookupResultsSha256.push(result);
            });
            results.sha1xref.forEach(function (result) {
                lookupResultsSha1.push(result);
            });
            results.md5xref.forEach(function (result) {
                lookupResultsMd.push(result);
            });
            results.sha256xref.forEach(function (result) {
                lookupResultsSha256.push(result);
            });
            results.uriToHashes.forEach(function (result) {
                lookupResultsHashes.push(result);
            });

            //uriToHashes

            let totalResultsSha1 = _.reduce(lookupResultsSha1, _reduceResults, {});
            let totalResultsSha256 = _.reduce(lookupResultsSha256, _reduceResults, {});
            let totalResultsMd = _.reduce(lookupResultsMd, _reduceResults, {});
            let totalResultHashes = _.reduce(lookupResultsHashes, _reduceResults, {});

            let finalTotalLookupResults = [];

            _.forEach(_.keys(totalResultsSha1), function (key) {
                finalTotalLookupResults.push(totalResultsSha1[key]);
            });

            _.forEach(_.keys(totalResultsSha256), function (key) {
                finalTotalLookupResults.push(totalResultsSha256[key]);
            });

            _.forEach(_.keys(totalResultsMd), function (key) {
                finalTotalLookupResults.push(totalResultsMd[key]);
            });

            _.forEach(_.keys(totalResultHashes), function (key) {
                finalTotalLookupResults.push(totalResultHashes[key]);
            });

            log.trace({ LookupResults: finalTotalLookupResults }, "Final Lookup Results");

            cb(null, finalTotalLookupResults);
        }
    });
}

function _reduceResults(reduced, entityResult) {
    if (!entityResult) {
        return reduced;
    }

    let entityValue = entityResult.entity.value;

    if (_.isNil(reduced[entityValue]) || _.isNil(reduced[entityValue].data)) {
        // set the initial value for this entity if we don't have a value already or the value was a miss
        reduced[entityValue] = entityResult;
    } else if (!_.isNil(entityResult.data)) {
        reduced[entityValue].data.summary = _.concat(reduced[entityValue].data.summary,
            Array.isArray(entityResult.data.summary) ? entityResult.data.summary : []);
        _.merge(reduced[entityValue].data.details, entityResult.data.details);
    }

    return reduced;
}

function _handleRequestError(err, response, cb) {
    if (err) {
        cb(_createJsonErrorPayload("HTTP Request Failed", null, '500', '2A', 'HTTP Error', {
            err: err
        }));
        return;
    }

    log.trace('response status code', response.statusCode);

    // don't consider this an error as we treat it as a cache miss
    if (response.statusCode === 404) {
        cb(null);
        return;
    }

    if (response.statusCode === 401) {
        cb(_createJsonErrorPayload("Request requires user authentication", null, '401', '2A', 'Unauthorized', {
            err: err
        }));
        return;
    }

    if (response.statusCode === 400) {
        cb(_createJsonErrorPayload("Request could not be understood by the server due to malformed syntax", null, '400', '2A', 'Bad Request', {
            err: err
        }));
        return;
    }
    if (response.statusCode === 403) {
        cb(_createJsonErrorPayload("The server understood the request, but is refusing to fulfill it", null, '403', '2A', 'Forbidden', {
            err: err
        }));
        return;
    }

    if (response.statusCode === 500) {
        cb(_createJsonErrorPayload("Server encountered an unexpected condition which prevented it from fulfilling the request", null, '500', '2A', 'Internal Server Error', {
            err: err
        }));
        return;
    }

    if (response.statusCode === 503) {
        cb(_createJsonErrorPayload("Server is currently unable to handle the request due to a temporary overloading or maintenance of the server", null, '503', '2A', 'Service Unavailable ', {
            err: err
        }));
        return;
    }

    if (response.statusCode !== 200) {
        cb(_createJsonErrorPayload("The integration received an unexpected non-200 HTTP status code", null, response.statusCode.toString(), '2A', 'Unexpected Non-200 HTTP Code', {
            err: err
        }));
        return;
    }

    cb(null);
}

function _lookupEntitySHA1Xref(sha1XrefEntities, options, cb) {
    if (sha1XrefEntities.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];

    async.each(sha1XrefEntities, (entity, done) => {
        let uri = 'https://' + options.url + '/api/xref/v2/query/sha1/' + entity.value + '?extended=true&format=json';

        log.debug({ entity: entity.value, uri: uri }, 'SHA1 XRef Request Info');

        requestWithDefaults({
            uri: uri,
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            _handleRequestError(err, response, function (jsonApiError) {
                if (jsonApiError) {
                    done(jsonApiError);
                    return;
                }

                // We consider this a miss
                if (response.statusCode === 404 || body == null || body.rl == null || body.rl.sample.xref === "") {
                    lookupResults.push({
                        entity: entity,
                        data: null
                    });
                    done(null);
                    return;
                }

                log.trace({ body: body }, "SHA1 Xref Response Body Results");

                // The lookup results returned is an array of lookup objects with the following format
                lookupResults.push({
                    entity: entity,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.sample.xref[0].scanner_match + " " + HASH_ICON + " " + body.rl.sample.xref[0].scanner_count],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            scanner_match: body.rl.sample.xref[0].scanner_match,
                            scanner_count: body.rl.sample.xref[0].scanner_count,
                            scanned_on: body.rl.sample.xref[0].scanned_on,
                            results: body.rl.sample.xref[0].results,
                            a1000: _getA1000Link(options, entity)
                        }
                    }
                });

                done(null);
            });
        });
    }, function (err) {
        cb(err, lookupResults);
    });
}

function _lookupEntitySHA1(sha1Entities, options, cb) {
    if (sha1Entities.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];

    async.each(sha1Entities, (entity, done) => {
        let uri = 'https://' + options.url + '/api/databrowser/malware_presence/query/sha1/' + entity.value +
            '?extended=true&format=json';

        log.debug({ entity: entity.value, uri: uri }, 'SHA1 Request Info');

        requestWithDefaults({
            uri: uri,
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            _handleRequestError(err, response, function (jsonApiError) {
                if (jsonApiError) {
                    done(jsonApiError);
                    return;
                }

                if (response.statusCode === 404 || body == null || body.rl == null || body.rl.malware_presence.status === "UNKNOWN") {
                    lookupResults.push({
                        entity: entity,
                        data: null
                    });
                    done(null);
                    return;
                }

                log.trace({ body: body }, "SHA1 Response Body Results");

                // The lookup results returned is an array of lookup objects with the following format
                if (body.rl.malware_presence.status === "MALICIOUS") {
                    lookupResults.push({
                        entity: entity,
                        // Required: this is the string value that is displayed in the template
                        entity_name: entity.value,
                        // Required: An object containing everything you want passed to the template
                        data: {
                            displayValue: entity.value,
                            // Required: These are the tags that are displayed in your template
                            summary: [body.rl.malware_presence.status + " SHA1"],
                            // Data that you want to pass back to the notification window details block
                            details: {
                                scanner_detection: body.rl.malware_presence.scanner_percent + ".00 % - " + body.rl.malware_presence.scanner_match + " of " + body.rl.malware_presence.scanner_count + " AV Engine Detections",
                                threat: body.rl.malware_presence.threat_level + '/' + body.rl.malware_presence.trust_factor + " " + body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                                threats: body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                                datas: body.rl,
                                a1000: _getA1000Link(options, entity)
                            }
                        }
                    });
                    done(null);
                } else {
                    // The lookup results returned is an array of lookup objects with the following format
                    lookupResults.push({
                        // Required: This is the entity object pass ed into the integration doLookup method
                        entity: entity,
                        // Required: this is the string value that is displayed in the template
                        entity_name: entity.value,
                        // Required: An object containing everything you want passed to the template
                        data: {
                            // Required: These are the tags that are displayed in your template
                            summary: [body.rl.malware_presence.status + " SHA1"],
                            // Data that you want to pass back to the notification window details block
                            details: {
                                datas: body.rl,
                                a1000: _getA1000Link(options, entity)
                            }
                        }
                    });
                    done(null);
                }
            });
        });
    }, function (err) {
        cb(err, lookupResults);
    });
}


function _lookupEntitySha256Xref(sha256Entities, options, cb) {
    if (sha256Entities.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];

    async.each(sha256Entities, (entity, done) => {
        let uri = 'https://' + options.url + '/api/xref/v2/query/sha256/' + entity.value + '?extended=true&format=json';

        log.debug({ entity: entity.value, uri: uri }, 'SHA1 Request Info');

        requestWithDefaults({
            uri: uri,
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            _handleRequestError(err, response, function (jsonApiError) {
                if (jsonApiError) {
                    done(jsonApiError);
                    return;
                }

                if (response.statusCode === 404 || body.rl == null || body.rl.sample.xref === "") {
                    lookupResults.push({
                        entity: entity,
                        data: null
                    });
                    done(null);
                    return;
                }

                log.trace({ body: body }, "SHA256 Xref Results Body");

                lookupResults.push({
                    entity: entity,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.sample.xref[0].scanner_match + " " + HASH_ICON + " " + body.rl.sample.xref[0].scanner_count],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            scanner_match: body.rl.sample.xref[0].scanner_match,
                            scanner_count: body.rl.sample.xref[0].scanner_count,
                            scanned_on: body.rl.sample.xref[0].scanned_on,
                            results: body.rl.sample.xref[0].results,
                            a1000: _getA1000Link(options, entity)
                        }
                    }
                });

                done(null);
            });
        });
    }, function (err) {
        cb(err, lookupResults);
    });
}


function _lookupEntityMD5Xref(md5Entities, options, cb) {
    if (md5Entities.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];

    async.each(md5Entities, (entity, done) => {
        let uri = 'https://' + options.url + '/api/xref/v2/query/md5/' + entity.value + '?extended=true&format=json';

        log.debug({ entity: entity.value, uri: uri }, 'MD5 Xref Request Info');

        requestWithDefaults({
            uri: uri,
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            _handleRequestError(err, response, function (jsonApiError) {
                if (jsonApiError) {
                    done(jsonApiError);
                    return;
                }

                if (response.statusCode === 404 || body.rl == null || body.rl.sample.xref === "") {
                    lookupResults.push({
                        entity: entity,
                        data: null
                    });
                    done(null);
                    return;
                }

                log.trace({ body: body }, "MD5 Xref Response Body Results");

                lookupResults.push({
                    entity: entity,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.sample.xref[0].scanner_match + " " + HASH_ICON + " " + body.rl.sample.xref[0].scanner_count],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            scanner_match: body.rl.sample.xref[0].scanner_match,
                            scanner_count: body.rl.sample.xref[0].scanner_count,
                            scanned_on: body.rl.sample.xref[0].scanned_on,
                            results: body.rl.sample.xref[0].results,
                            a1000: _getA1000Link(options, entity)
                        }
                    }
                });
                done(null);
            });
        });
    }, function (err) {
        cb(err, lookupResults);
    });
}

function _lookupEntitySha256(sha256Entities, options, cb) {
    if (sha256Entities.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];

    async.each(sha256Entities, (entity, done) => {
        let uri = 'https://ticloud-cdn-api.reversinglabs.com/api/databrowser/malware_presence/query/sha256/' +
            entity.value + '?extended=true&format=json';

        log.debug({ entity: entity.value, uri: uri }, 'SHA 256 Request Info');

        requestWithDefaults({
            uri: uri,
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            _handleRequestError(err, response, function (jsonApiError) {
                if (jsonApiError) {
                    done(jsonApiError);
                    return;
                }

                if (response.statusCode === 404 || body.rl == null || body.rl.malware_presence.status === "UNKNOWN") {
                    lookupResults.push({
                        entity: entity,
                        data: null
                    });
                    done(null);
                    return;
                }

                log.trace({ body: body }, "SHA256 Request Body Results");

                if (body.rl.malware_presence.status === "MALICIOUS") {
                    lookupResults.push({
                        entity: entity,
                        // Required: An object containing everything you want passed to the template
                        data: {
                            // Required: These are the tags that are displayed in your template
                            summary: [body.rl.malware_presence.status + " SHA256"],
                            // Data that you want to pass back to the notification window details block
                            details: {
                                scanner_detection: body.rl.malware_presence.scanner_percent + ".00 % - " + body.rl.malware_presence.scanner_match + " of " + body.rl.malware_presence.scanner_count + " AV Engine Detections",
                                threat: body.rl.malware_presence.threat_level + '/' + body.rl.malware_presence.trust_factor + " " + body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                                threats: body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                                datas: body.rl,
                                a1000: _getA1000Link(options, entity)
                            }
                        }
                    });
                    done(null);
                } else {
                    // The lookup results returned is an array of lookup objects with the following format
                    lookupResults.push({
                        // Required: This is the entity object pass ed into the integration doLookup method
                        entity: entity,
                        // Required: An object containing everything you want passed to the template
                        data: {
                            // Required: These are the tags that are displayed in your template
                            summary: [body.rl.malware_presence.status + " SHA256"],
                            // Data that you want to pass back to the notification window details block
                            details: {
                                datas: body.rl,
                                a1000: _getA1000Link(options, entity)
                            }
                        }
                    });
                    done(null);
                }
            });
        });
    }, function (err) {
        cb(err, lookupResults);
    });
}


function _lookupEntityMD5(md5Entities, options, cb) {
    if (md5Entities.length === 0) {
        cb(null, []);
        return;
    }

    let lookupResults = [];

    async.each(md5Entities, (entity, done) => {
        let uri = 'https://' + options.url + '/api/databrowser/malware_presence/query/md5/' +
            entity.value + '?extended=true&format=json';

        log.debug({ entity: entity.value, uri: uri }, 'MD5 Request Info');

        requestWithDefaults({
            uri: uri,
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            _handleRequestError(err, response, function (jsonApiError) {
                if (jsonApiError) {
                    done(jsonApiError);
                    return;
                }

                if (response.statusCode === 404 || body.rl == null || body.rl.malware_presence.status === "UNKNOWN") {
                    lookupResults.push({
                        entity: entity,
                        data: null
                    });
                    done(null);
                    return;
                }

                log.trace({ body: body }, "MD5 Response Body Results");

                if (body.rl.malware_presence.status === "MALICIOUS") {
                    lookupResults.push({
                        entity: entity,
                        // Required: An object containing everything you want passed to the template
                        data: {
                            // Required: These are the tags that are displayed in your template
                            summary: [body.rl.malware_presence.status + " MD5"],
                            // Data that you want to pass back to the notification window details block
                            details: {
                                scanner_detection: body.rl.malware_presence.scanner_percent + ".00 % - " + body.rl.malware_presence.scanner_match + " of " + body.rl.malware_presence.scanner_count + " AV Engine Detections",
                                threat: body.rl.malware_presence.threat_level + '/' + body.rl.malware_presence.trust_factor + " " + body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                                threats: body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                                datas: body.rl,
                                a1000: _getA1000Link(options, entity)
                            }
                        }

                    });
                    done(null);
                } else {
                    // The lookup results returned is an array of lookup objects with the following format
                    lookupResults.push({
                        // Required: This is the entity object pass ed into the integration doLookup method
                        entity: entity,
                        // Required: An object containing everything you want passed to the template
                        data: {
                            // Required: These are the tags that are displayed in your template
                            summary: [body.rl.malware_presence.status + " MD5"],
                            // Data that you want to pass back to the notification window details block
                            details: {
                                datas: body.rl,
                                a1000: _getA1000Link(options, entity)
                            }
                        }
                    });
                    done(null);
                }
            });
        });
    }, function (err) {
        cb(err, lookupResults);
    });
}

function _getA1000Link(options, entityObj) {
    return options.lookupA1000 && options.a1000.length > 0 ?
        'https://' + options.a1000 + '/?q=' + entityObj.value : null;
}


function validateOptions(userOptions, cb) {
    let errors = [];
    if (typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)) {
        errors.push({
            key: 'password',
            message: 'You must provide a valid password'
        })
    }

    if (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) {
        errors.push({
            key: 'username',
            message: 'You must provide a Reversing Labs Username'
        })
    }

    cb(null, errors);
}

// function that takes the ErrorObject and passes the error message to the notification window
var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
    let errors = [
        _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
    ];

    log.error({ errors: errors });

    return { errors: errors };
};

// function that creates the Json object to be passed to the payload
var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
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
};

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions,

    // Testing Exports
    _reduceResults: _reduceResults
};