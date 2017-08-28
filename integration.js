'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let async = require('async');
let log = null;


function startup(logger) {
    log = logger;
}


var hashIcon = '<i class="fa fa-bug"></i>';

function doLookup(entities, options, cb) {
    log.debug({entities: entities}, "Entities");


    let entityObjLookup = [];
    let sha256Elements = [];
    let md5Elements = [];
    let sha1Elements = [];
    let lookupResults = [];
    let lookupResultsSha = [];
    let lookupResultsMd = [];

    for (let i = 0; i < entities.length; i++) {
        let entityObj = entities[i];


        if (entityObj.isSHA256 && options.lookupSha256) {
            sha256Elements.push(entityObj);
        } else if (entityObj.isSHA1 && options.lookupSha1) {
            sha1Elements.push(entityObj);
        } else if (entityObj.isMD5 && options.lookupMd5) {
            md5Elements.push(entityObj);
        }
    }




    async.parallel({
        sha1: function (done) {
            _lookupEntitySHA1(sha1Elements, options, function (err, results) {
                if (err) {
                    done(err);
                    return;
                }
                log.debug({results: results}, "Checking the results of a sha1");
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
            _lookupEntity(sha256Elements, options, function (err, results) {
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
                log.debug({results: results}, "Checking the results of a sha1xref");
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
        }

    }, function (err, results) {
        if (err) {
            cb(err);
        } else {
            log.debug({results: results}, "Lookup Results:");

            results.sha1.forEach(function (result) {
                lookupResults.push(result);
            });
            results.md5.forEach(function (result) {
                lookupResultsMd.push(result);
            });
            results.sha256.forEach(function (result) {
                lookupResultsSha.push(result);
            });
            results.sha1xref.forEach(function (result) {
                lookupResults.push(result);
            });
            results.md5xref.forEach(function (result) {
                lookupResultsMd.push(result);
            });
            results.sha256xref.forEach(function (result) {
                lookupResultsSha.push(result);
            });

            let totalResults = _.reduce(lookupResults, function (reduced, entityResult) {
                if (!entityResult) {
                    return reduced;
                }
                if (typeof(reduced[entityResult.entity]) != "object") {
                    reduced[entityResult.entity] = entityResult;
                } else {
                    reduced[entityResult.entity].data.summary = _.concat(reduced[entityResult.entity].data.summary, entityResult.data.summary);

                    _.merge(reduced[entityResult.entity].data.details, entityResult.data.details);
                }
                return reduced;
            }, {});

            let totalResultsSha = _.reduce(lookupResultsSha, function (reduced, entityResult) {
                if (!entityResult) {
                    return reduced;
                }
                if (typeof(reduced[entityResult.entity]) != "object") {
                    reduced[entityResult.entity] = entityResult;
                } else {
                    reduced[entityResult.entity].data.summary = _.concat(reduced[entityResult.entity].data.summary, entityResult.data.summary);

                    _.merge(reduced[entityResult.entity].data.details, entityResult.data.details);
                }
                return reduced;
            }, {});

            let totalResultsMd = _.reduce(lookupResultsMd, function (reduced, entityResult) {
                if (!entityResult) {
                    return reduced;
                }
                if (typeof(reduced[entityResult.entity]) != "object") {
                    reduced[entityResult.entity] = entityResult;
                } else {
                    reduced[entityResult.entity].data.summary = _.concat(reduced[entityResult.entity].data.summary, entityResult.data.summary);

                    _.merge(reduced[entityResult.entity].data.details, entityResult.data.details);
                }
                return reduced;
            }, {});

            var results = [];
            _.forEach(_.keys(totalResults), function (key) {
                results.push(totalResults[key]);
            });

            var resultsSha = [];
            _.forEach(_.keys(totalResultsSha), function (key) {
                results.push(totalResultsSha[key]);
            });

            var resultsMd = [];
            _.forEach(_.keys(totalResultsMd), function (key) {
                results.push(totalResultsMd[key]);
            });

            log.debug({LookupResults: results}, "Checking the results of everything::");
            cb(null, results, resultsSha, resultsMd);
        }
    });
}


function _lookupEntitySHA1Xref(entityObj, options, cb) {

    if (entityObj.length === 0) {
        cb(null, []);
        return;
    }


    if(options.lookupA1000) {
        var a1000 = 'https://' + options.a1000 + '/?q=' + entityObj[0].value;
    }

    log.debug({entity: entityObj[0].value}, "What is the entity for sha1");
    log.debug({uri: 'https://' + options.url + '/api/xref/v2/query/sha1/' + entityObj[0].value + '?extended=true&format=json'}, "URI Parameter");
    let lookupResults = [];
    if (entityObj[0].value)
        request({
            uri: 'https://' + options.url + '/api/xref/v2/query/sha1/' + entityObj[0].value + '?extended=true&format=json',
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj[0].value,
                    data: null
                });
                log.error({err: err}, "Logging error");
                return;
            }

            if (response.statusCode === 401) {
                cb(_createJsonErrorPayload("Request requires user authentication", null, '401', '2A', 'Unauthorized', {
                    err: err
                }));
                return;
            }

            if (response.statusCode === 404) {
                cb(null, []);
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
                cb(body);
                return;
            }

            if (body == null || body.rl == null || body.rl.sample.xref === "") {
                cb(null, []);
                return;
            }


            log.debug({body: body}, "Printing out the results of Body ");

            // The lookup results returned is an array of lookup objects with the following format
            lookupResults.push({
                entity: entityObj[0],
                // Required: this is the string value that is displayed in the template
                entity_name: entityObj[0].value,
                // Required: An object containing everything you want passed to the template
                data: {
                    // Required: These are the tags that are displayed in your template
                    summary: [body.rl.sample.xref[0].scanner_match + " " + hashIcon + " " + body.rl.sample.xref[0].scanner_count],
                    // Data that you want to pass back to the notification window details block
                    details: {
                        scanner_match: body.rl.sample.xref[0].scanner_match,
                        scanner_count: body.rl.sample.xref[0].scanner_count,
                        scanned_on: body.rl.sample.xref[0].scanned_on,
                        results: body.rl.sample.xref[0].results,
                        a1000: a1000
                    }
                }

            });
            cb(null, lookupResults);
        });
}

function _lookupEntitySHA1(entityObj, options, cb) {
    if (entityObj.length === 0) {
        cb(null, []);
        return;
    }

    if(options.lookupA1000) {
        var a1000 = 'https://' + options.a1000 + '/?q=' + entityObj[0].value;
    }

    log.debug({entity: entityObj[0].value}, "What is the entity for sha1 malwarepresence");

    log.debug({uri: 'https://' + options.url + '/api/xref/v2/query/sha1/' + entityObj[0].value + '?extended=true&format=json'}, "URI Parameter for malwarepresence");

    let lookupResults = [];
    if (entityObj[0].value)
        request({
            uri: 'https://' + options.url + '/api/databrowser/malware_presence/query/sha1/' + entityObj[0].value + '?extended=true&format=json',
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj[0].value,
                    data: null
                });
                log.error({err: err}, "Logging error");
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

            if (response.statusCode === 404) {
                cb(null, []);
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
                cb(body);
                return;
            }

            if (body == null || body.rl == null || body.rl.malware_presence.status === "UNKNOWN") {
                cb(null, []);
                return;
            }


            log.debug({body: body}, "Printing out the results of Body for maleware presence");

            // The lookup results returned is an array of lookup objects with the following format
            if (body.rl.malware_presence.status === "MALICIOUS") {
                lookupResults.push({
                    entity: entityObj[0],
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        displayValue: entityObj[0].value,
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.malware_presence.status + " SHA1 Hash"],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            scanner_detection: body.rl.malware_presence.scanner_percent + ".00 % - " + body.rl.malware_presence.scanner_match + " of " + body.rl.malware_presence.scanner_count + " AV Engine Detections",
                            threat: body.rl.malware_presence.threat_level + '/' + body.rl.malware_presence.trust_factor + " " + body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                            threats: body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                            datas: body.rl,
                            a1000: a1000
                        }
                    }

                });
                cb(null, lookupResults);
            } else {
                // The lookup results returned is an array of lookup objects with the following format
                lookupResults.push({
                    // Required: This is the entity object pass ed into the integration doLookup method
                    entity: entityObj[0],
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.malware_presence.status + " SHA1 Hash"],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            datas: body.rl,
                            a1000: a1000
                        }
                    }
                });
                log.debug({lookupResults: lookupResults}, "Malware LookupREsults:");
                cb(null, lookupResults);
            }
        });
}


function _lookupEntitySha256Xref(entityObj, options, cb) {
    if (entityObj.length === 0) {
        cb(null, []);
        return;
    }



    log.debug({entity: entityObj[0].value}, "What is the entity");

    let lookupResults = [];

    if(options.lookupA1000) {
        var a1000 = 'https://' + options.a1000 + '/?q=' + entityObj[0].value;
    }

    if (entityObj[0].value)
        request({
            uri: 'https://' + options.url + '/api/xref/v2/query/sha256/' + entityObj[0].value + '?extended=true&format=json',
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj[0].value,
                    data: null
                });
                log.error({err: err}, "Logging error");
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

            if (response.statusCode === 404) {
                cb(null, []);
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
                cb(body);
                return;
            }

            if (body.rl == null || body.rl.sample.xref === "") {
                cb(null, []);
                return;
            }


            log.debug({results: body.rl.sample.xref[0].results}, "What do scanner results look like:");
            log.debug({body: body}, "Printing out the results of Body ");


            lookupResults.push({
                entity: entityObj[0],
                // Required: An object containing everything you want passed to the template
                data: {
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: These are the tags that are displayed in your template
                    summary: [body.rl.sample.xref[0].scanner_match + " " + hashIcon + " " + body.rl.sample.xref[0].scanner_count],
                    // Data that you want to pass back to the notification window details block
                    details: {
                        scanner_match: body.rl.sample.xref[0].scanner_match,
                        scanner_count: body.rl.sample.xref[0].scanner_count,
                        scanned_on: body.rl.sample.xref[0].scanned_on,
                        results: body.rl.sample.xref[0].results,
                        a1000: a1000
                    }
                }

            });
            cb(null, lookupResults);
        });
}


function _lookupEntityMD5Xref(entityObj, options, cb) {
    if (entityObj.length === 0) {
        cb(null, []);
        return;
    }



    let lookupResults = [];
    log.debug({entity: entityObj[0].value}, "What is the entity");

    if(options.lookupA1000) {
        var a1000 = 'https://' + options.a1000 + '/?q=' + entityObj[0].value;
    }

    if (entityObj[0].value)
        request({
            uri: 'https://' + options.url + '/api/xref/v2/query/md5/' + entityObj[0].value + '?extended=true&format=json',
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj[0].value,
                    data: null
                });
                log.error({err: err}, "Logging error");
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

            if (response.statusCode === 404) {
                cb(null, []);
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
                cb(body);
                return;
            }

            if (body.rl == null || body.rl.sample.xref === "") {
                cb(null, []);
                return;
            }


            log.debug({results: body.rl.sample.xref[0].results}, "What do scanner results look like:");
            log.debug({body: body}, "Printing out the results of Body ");

            lookupResults.push({
                entity: entityObj[0],
                // Required: An object containing everything you want passed to the template
                data: {
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: These are the tags that are displayed in your template
                    summary: [body.rl.sample.xref[0].scanner_match + " " + hashIcon + " " + body.rl.sample.xref[0].scanner_count],
                    // Data that you want to pass back to the notification window details block
                    details: {
                        scanner_match: body.rl.sample.xref[0].scanner_match,
                        scanner_count: body.rl.sample.xref[0].scanner_count,
                        scanned_on: body.rl.sample.xref[0].scanned_on,
                        results: body.rl.sample.xref[0].results,
                        a1000: a1000
                    }
                }

            });
            cb(null, lookupResults);
        });
}

function _lookupEntity(entityObj, options, cb) {
    if (entityObj.length === 0) {
        cb(null, []);
        return;
    }


    log.debug({entity: entityObj[0].value}, "What is the entity");

    let lookupResults = [];

    if(options.lookupA1000) {
        var a1000 = 'https://' + options.a1000 + '/?q=' + entityObj[0].value;
    }

    log.debug({a1000: a1000}, "What does the URL Look like");

    if (entityObj[0].value)
        request({
            uri: 'https://ticloud-cdn-api.reversinglabs.com/api/databrowser/malware_presence/query/sha256/' + entityObj[0].value + '?extended=true&format=json',
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj[0].value,
                    data: null
                });
                log.error({err: err}, "Logging error");
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

            if (response.statusCode === 404) {
                cb(null, []);
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
                cb(body);
                return;
            }

            if (body.rl == null || body.rl.malware_presence.status === "UNKNOWN") {
                cb(null, []);
                return;
            }


            log.debug({body: body}, "Printing out the results of Body ");

            if (body.rl.malware_presence.status === "MALICIOUS") {
                lookupResults.push({
                    entity: entityObj[0],
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        displayValue: entityObj[0].value,
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.malware_presence.status + " SHA256 Hash"],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            scanner_detection: body.rl.malware_presence.scanner_percent + ".00 % - " + body.rl.malware_presence.scanner_match + " of " + body.rl.malware_presence.scanner_count + " AV Engine Detections",
                            threat: body.rl.malware_presence.threat_level + '/' + body.rl.malware_presence.trust_factor + " " + body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                            threats: body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                            datas: body.rl,
                            a1000: a1000
                        }
                    }

                });
                cb(null, lookupResults);
            } else {
                // The lookup results returned is an array of lookup objects with the following format
                lookupResults.push({
                    // Required: This is the entity object pass ed into the integration doLookup method
                    entity: entityObj[0],
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.malware_presence.status + " SHA256 Hash"],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            datas: body.rl,
                            a1000: a1000
                        }
                    }
                });
                log.debug({lookupResults: lookupResults}, "Malware LookupREsults:");
                cb(null, lookupResults);
            }
        });
}


function _lookupEntityMD5(entityObj, options, cb) {
    if (entityObj.length === 0) {
        cb(null, []);
        return;
    }



    log.debug({entity: entityObj[0].value}, "What is the entity");
    let lookupResults = [];

    if(options.lookupA1000) {
        var a1000 = 'https://' + options.a1000 + '/?q=' + entityObj[0].value;
    }

    if (entityObj[0].value)
        request({
            uri: 'https://' + options.url + '/api/databrowser/malware_presence/query/md5/' + entityObj[0].value + '?extended=true&format=json',
            method: 'GET',
            auth: {
                'username': options.username,
                'password': options.password
            },
            json: true
        }, function (err, response, body) {
            if (err) {
                cb(null, {
                    entity: entityObj,
                    data: null
                });
                log.error({err: err}, "Logging error");
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

            if (response.statusCode === 404) {
                cb(null, []);
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
                cb(body);
                return;
            }

            if (body.rl == null || body.rl.malware_presence.status === "UNKNOWN") {
                cb(null, []);
                return;
            }


            log.debug({body: body}, "Printing out the results of Body ");

            if (body.rl.malware_presence.status === "MALICIOUS") {
                lookupResults.push({
                    entity: entityObj[0],
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        displayValue: entityObj[0].value,
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.malware_presence.status + " MD5 Hash"],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            scanner_detection: body.rl.malware_presence.scanner_percent + ".00 % - " + body.rl.malware_presence.scanner_match + " of " + body.rl.malware_presence.scanner_count + " AV Engine Detections",
                            threat: body.rl.malware_presence.threat_level + '/' + body.rl.malware_presence.trust_factor + " " + body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                            threats: body.rl.malware_presence.classification.platform + "." + body.rl.malware_presence.classification.type + "." + body.rl.malware_presence.classification.family_name,
                            datas: body.rl,
                            a1000: a1000
                        }
                    }

                });
                cb(null, lookupResults);
            } else {
                // The lookup results returned is an array of lookup objects with the following format
                lookupResults.push({
                    // Required: This is the entity object pass ed into the integration doLookup method
                    entity: entityObj[0],
                    // Required: this is the string value that is displayed in the template
                    entity_name: entityObj[0].value,
                    // Required: An object containing everything you want passed to the template
                    data: {
                        // Required: These are the tags that are displayed in your template
                        summary: [body.rl.malware_presence.status + " MD5 Hash"],
                        // Data that you want to pass back to the notification window details block
                        details: {
                            datas: body.rl,
                            a1000: a1000
                        }
                    }
                });
                log.debug({lookupResults: lookupResults}, "Malware LookupREsults:");
                cb(null, lookupResults);
            }
        });
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
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
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
    validateOptions: validateOptions
};