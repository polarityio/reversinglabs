let expect = require('chai').expect;

let bunyan = require('bunyan');
let logger = bunyan.createLogger({name: 'mocha-test', level: bunyan.ERROR});
let integration = require('../integration');


describe('Polarity Reversing Labs Integration', () => {
    before(() => {
        integration.startup(logger);
    });

    describe('_reduceResults', () => {
        it('should set initial value when missed result', (done) => {
            let result = integration._reduceResults({}, {
                entity: {
                    value: 'test'
                },
                data: null
            });

            //console.info(JSON.stringify(result, null, 4));

            expect(result).to.deep.equal({
                    "test": {
                        "entity": {
                            "value": "test"
                        },
                        "data": null
                    }
                }
            );
            done();
        });

        it('should set initial value when has result', (done) => {
            let result = integration._reduceResults({}, {
                entity: {
                    value: 'test'
                },
                data: {
                    summary: ['test'],
                    details: {
                        test: 'test'
                    }
                }
            });

            //console.info(JSON.stringify(result, null, 4));

            expect(result).to.deep.equal({
                    "test": {
                        "entity": {
                            "value": "test"
                        },
                        "data": {
                            "summary": [
                                "test"
                            ],
                            "details": {
                                "test": "test"
                            }
                        }
                    }
                }
            );
            done();
        });

        it('should set initial value when has result but data is null', (done) => {
            let result = integration._reduceResults({
                test: {
                    data: null
                }
            }, {
                entity: {
                    value: 'test'
                },
                data: {
                    summary: ['test'],
                    details: {
                        test: 'test'
                    }
                }
            });

            //console.info(JSON.stringify(result, null, 4));

            expect(result).to.deep.equal({
                    "test": {
                        "entity": {
                            "value": "test"
                        },
                        "data": {
                            "summary": [
                                "test"
                            ],
                            "details": {
                                "test": "test"
                            }
                        }
                    }
                }
            );
            done();
        });

        it('should merge values when has result', (done) => {
            let result = integration._reduceResults({
                test: {
                    entity: {
                        value: 'test'
                    },
                    data: {
                        summary: ['original'],
                        details: {
                            original: 'original'
                        }
                    }
                }
            }, {
                entity: {
                    value: 'test'
                },
                data: {
                    summary: ['test'],
                    details: {
                        test: 'test'
                    }
                }
            });

            //console.info(JSON.stringify(result, null, 4));

            expect(result).to.deep.equal({
                    "test": {
                        "entity": {
                            "value": "test"
                        },
                        "data": {
                            "summary": [
                                "original",
                                "test"
                            ],
                            "details": {
                                "original": "original",
                                "test": "test"
                            }
                        }
                    }
                }
            );
            done();
        });

        it('should not merge miss into existing result', (done) => {
            let result = integration._reduceResults({
                test: {
                    entity: {
                        value: 'test'
                    },
                    data: {
                        summary: ['original'],
                        details: {
                            original: 'original'
                        }
                    }
                }
            }, {
                entity: {
                    value: 'test'
                },
                data: null
            });

            //console.info(JSON.stringify(result, null, 4));

            expect(result).to.deep.equal({
                    "test": {
                        "entity": {
                            "value": "test"
                        },
                        "data": {
                            "summary": [
                                "original"
                            ],
                            "details": {
                                "original": "original"
                            }
                        }
                    }
                }
            );
            done();
        });
    });
});
