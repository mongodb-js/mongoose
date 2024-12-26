
'use strict';

const assert = require('assert');
const start = require('./common');

const mongoose = start.mongoose;
const Schema = mongoose.Schema;

function has(object, property) {
    if (typeof object !== 'object') {
        throw new Error('cannot check keys of non-object');
    }
    if (object === null) {
        throw new Error('expected object to exist but it did not.');
    }
    return Boolean(Object.entries(object).find(([k]) => k === property));
}

describe.only('encrypted schema declaration', function () {
    describe('String', function () {
        it('allows declaring', function () {
            const schema = new Schema({
                name: {
                    type: String, encrypt: {
                        type: 'equality'
                    }
                }
            });

            assert.ok(has(schema.encryptedFields, 'name'));
        });
    });
});
