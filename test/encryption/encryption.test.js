'use strict';

const assert = require('assert');
const mdb = require('mongodb');
const isBsonType = require('../../lib/helpers/isBsonType');
const { Schema, createConnection } = require('../../lib');
const { ObjectId, Double, Int32, Decimal128 } = require('bson');

const LOCAL_KEY = Buffer.from('Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFBMUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk', 'base64');

describe('ci', () => {
  describe('environmental variables', () => {
    it('MONGOOSE_TEST_URI is set', async function() {
      const uri = process.env.MONGOOSE_TEST_URI;
      assert.ok(uri);
    });

    it('CRYPT_SHARED_LIB_PATH is set', async function() {
      const shared_library_path = process.env.CRYPT_SHARED_LIB_PATH;
      assert.ok(shared_library_path);
    });
  });

  let keyId, keyId2;
  let utilClient;

  beforeEach(async function() {
    const keyVaultClient = new mdb.MongoClient(process.env.MONGOOSE_TEST_URI);
    await keyVaultClient.connect();
    await keyVaultClient.db('keyvault').collection('datakeys');
    const clientEncryption = new mdb.ClientEncryption(keyVaultClient, {
      keyVaultNamespace: 'keyvault.datakeys',
      kmsProviders: { local: { key: LOCAL_KEY } }
    });
    keyId = await clientEncryption.createDataKey('local');
    keyId2 = await clientEncryption.createDataKey('local');
    await keyVaultClient.close();

    utilClient = new mdb.MongoClient(process.env.MONGOOSE_TEST_URI);
  });

  afterEach(async function() {
    await utilClient.db('db').dropDatabase({
      w: 'majority'
    });
    await utilClient.close();
  });

  describe('Tests that fields of valid schema types can be declared as encrypted schemas', function() {
    const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA_512-Random';
    let connection;
    let schema;
    let model;

    const basicSchemaTypes = [
      { type: String, name: 'string', input: 3, expected: 3 },
      { type: Schema.Types.Boolean, name: 'boolean', input: true, expected: true },
      { type: Schema.Types.Buffer, name: 'buffer', input: Buffer.from([1, 2, 3]) },
      { type: Date, name: 'date', input: new Date(12, 12, 2012), expected: new Date(12, 12, 2012) },
      { type: ObjectId, name: 'objectid', input: new ObjectId() },
      { type: BigInt, name: 'bigint', input: 3n },
      { type: Decimal128, name: 'Decimal128', input: new Decimal128('1.5') },
      { type: Int32, name: 'int32', input: new Int32(5), expected: 5 },
      { type: Double, name: 'double', input: new Double(1.5) }
    ];

    for (const { type, name, input, expected } of basicSchemaTypes) {

      this.afterEach(async function() {
        await connection?.close();
      });

      // eslint-disable-next-line no-inner-declarations
      async function test() {
        const [{ _id }] = await model.insertMany([{ field: input }]);
        const encryptedDoc = await utilClient.db('db').collection('schemas').findOne({ _id });

        assert.ok(isBsonType(encryptedDoc.field, 'Binary'));
        assert.ok(encryptedDoc.field.sub_type === 6);

        const doc = await model.findOne({ _id });
        if (Buffer.isBuffer(input)) {
          // mongoose's Buffer does not support deep equality - instead use the Buffer.equals method.
          assert.ok(doc.field.equals(input));
        } else {
          assert.deepEqual(doc.field, expected ?? input);
        }
      }

      describe('CSFLE', function() {
        beforeEach(async function() {
          schema = new Schema({
            field: {
              type, encrypt: { keyId: [keyId], algorithm }
            }
          }, {
            encryptionType: 'csfle'
          });

          connection = createConnection();
          model = connection.model('Schema', schema);
          await connection.openUri(process.env.MONGOOSE_TEST_URI, {
            dbName: 'db', autoEncryption: {
              keyVaultNamespace: 'keyvault.datakeys',
              kmsProviders: { local: { key: LOCAL_KEY } },
              extraOptions: {
                cryptdSharedLibRequired: true,
                cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
              }
            }
          });
        });

        it(`${name} encrypts and decrypts`, test);
      });

      describe('QE', function() {
        beforeEach(async function() {
          schema = new Schema({
            field: {
              type, encrypt: { keyId: keyId }
            }
          }, {
            encryptionType: 'qe'
          });

          connection = createConnection();
          model = connection.model('Schema', schema);
          await connection.openUri(process.env.MONGOOSE_TEST_URI, {
            dbName: 'db', autoEncryption: {
              keyVaultNamespace: 'keyvault.datakeys',
              kmsProviders: { local: { key: LOCAL_KEY } },
              extraOptions: {
                cryptdSharedLibRequired: true,
                cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
              }
            }
          });
        });

        it(`${name} encrypts and decrypts`, test);
      });
    }

    describe('nested object schemas', function() {
      const tests = {
        'nested object schemas for CSFLE': {
          modelFactory: () => {
            const schema = new Schema({
              a: {
                b: {
                  c: {
                    type: String,
                    encrypt: { keyId: [keyId], algorithm }
                  }
                }
              }
            }, {
              encryptionType: 'csfle'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };

          }
        },
        'nested object schemas for QE': {
          modelFactory: () => {
            const schema = new Schema({
              a: {
                b: {
                  c: {
                    type: String,
                    encrypt: { keyId: keyId }
                  }
                }
              }
            }, {
              encryptionType: 'qe'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };

          }
        },
        'nested schemas for csfle': {
          modelFactory: () => {
            const nestedSchema = new Schema({
              b: {
                c: {
                  type: String,
                  encrypt: { keyId: [keyId], algorithm }
                }
              }
            }, {
              encryptionType: 'csfle'
            });

            const schema = new Schema({
              a: nestedSchema
            }, {
              encryptionType: 'csfle'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };

          }
        },
        'nested schemas for QE': {
          modelFactory: () => {
            const nestedSchema = new Schema({
              b: {
                c: {
                  type: String,
                  encrypt: { keyId: keyId }
                }
              }
            }, {
              encryptionType: 'qe'
            });
            const schema = new Schema({
              a: nestedSchema
            }, {
              encryptionType: 'qe'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };

          }
        }
      };

      for (const [description, { modelFactory }] of Object.entries(tests)) {
        describe(description, function() {
          it('encrypts and decrypts', async function() {
            const { model } = modelFactory();

            await connection.openUri(process.env.MONGOOSE_TEST_URI, {
              dbName: 'db', autoEncryption: {
                keyVaultNamespace: 'keyvault.datakeys',
                kmsProviders: { local: { key: LOCAL_KEY } },
                extraOptions: {
                  cryptdSharedLibRequired: true,
                  cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
                }
              }
            });

            const [{ _id }] = await model.insertMany([{ a: { b: { c: 'hello' } } }]);
            const encryptedDoc = await utilClient.db('db').collection('schemas').findOne({ _id });

            assert.ok(isBsonType(encryptedDoc.a.b.c, 'Binary'));
            assert.ok(encryptedDoc.a.b.c.sub_type === 6);

            const doc = await model.findOne({ _id });
            assert.deepEqual(doc.a.b.c, 'hello');
          });
        });
      }
    });

    describe('array encrypted fields', function() {
      const tests = {
        'array fields for CSFLE': {
          modelFactory: () => {
            const schema = new Schema({
              a: {
                type: [Int32],
                encrypt: {
                  keyId: [keyId],
                  algorithm
                }
              }
            }, {
              encryptionType: 'csfle'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };
          }
        },
        'array field for QE': {
          modelFactory: () => {
            const schema = new Schema({
              a: {
                type: [Int32],
                encrypt: {
                  keyId
                }
              }
            }, {
              encryptionType: 'qe'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };
          }
        }
      };

      for (const [description, { modelFactory }] of Object.entries(tests)) {
        describe(description, function() {
          it('encrypts and decrypts', async function() {
            const { model } = modelFactory();
            await connection.openUri(process.env.MONGOOSE_TEST_URI, {
              dbName: 'db', autoEncryption: {
                keyVaultNamespace: 'keyvault.datakeys',
                kmsProviders: { local: { key: LOCAL_KEY } },
                extraOptions: {
                  cryptdSharedLibRequired: true,
                  cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
                }
              }
            });

            const [{ _id }] = await model.insertMany([{ a: [new Int32(3)] }]);
            const encryptedDoc = await utilClient.db('db').collection('schemas').findOne({ _id });

            assert.ok(isBsonType(encryptedDoc.a, 'Binary'));
            assert.ok(encryptedDoc.a.sub_type === 6);

            const doc = await model.findOne({ _id });
            assert.deepEqual(doc.a, [3]);
          });
        });
      }
    });

    describe('multiple encrypted fields in a model', function() {
      const tests = {
        'multiple fields in a schema for CSFLE': {
          modelFactory: () => {
            const encrypt = {
              keyId: [keyId],
              algorithm
            };

            const schema = new Schema({
              a: {
                type: String,
                encrypt
              },
              b: {
                type: BigInt
              },
              c: {
                d: {
                  type: String,
                  encrypt
                }
              }
            }, {
              encryptionType: 'csfle'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };
          }
        },
        'multiple fields in a schema for QE': {
          modelFactory: () => {
            const schema = new Schema({
              a: {
                type: String,
                encrypt: {
                  keyId
                }
              },
              b: {
                type: BigInt
              },
              c: {
                d: {
                  type: String,
                  encrypt: {
                    keyId: keyId2
                  }
                }
              }
            }, {
              encryptionType: 'qe'
            });

            connection = createConnection();
            model = connection.model('Schema', schema);
            return { model };
          }
        }
      };

      for (const [description, { modelFactory }] of Object.entries(tests)) {
        describe(description, function() {
          it('encrypts and decrypts', async function() {
            const { model } = modelFactory();
            await connection.openUri(process.env.MONGOOSE_TEST_URI, {
              dbName: 'db', autoEncryption: {
                keyVaultNamespace: 'keyvault.datakeys',
                kmsProviders: { local: { key: LOCAL_KEY } },
                extraOptions: {
                  cryptdSharedLibRequired: true,
                  cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
                }
              }
            });

            const [{ _id }] = await model.insertMany([{ a: 'hello', b: 1n, c: { d: 'world' } }]);
            const encryptedDoc = await utilClient.db('db').collection('schemas').findOne({ _id });

            assert.ok(isBsonType(encryptedDoc.a, 'Binary'));
            assert.ok(encryptedDoc.a.sub_type === 6);
            assert.ok(typeof encryptedDoc.b === 'number');
            assert.ok(isBsonType(encryptedDoc.c.d, 'Binary'));
            assert.ok(encryptedDoc.c.d.sub_type === 6);

            const doc = await model.findOne({ _id }, {});
            assert.deepEqual(doc.a, 'hello');
            assert.deepEqual(doc.b, 1n);
            assert.deepEqual(doc.c, { d: 'world' });
          });
        });
      }
    });

    describe('multiple schemas', function() {
      const tests = {
        'multiple schemas for CSFLE': {
          modelFactory: () => {
            connection = createConnection();
            const encrypt = {
              keyId: [keyId],
              algorithm
            };
            const model1 = connection.model('Model1', new Schema({
              a: {
                type: String,
                encrypt
              }
            }, {
              encryptionType: 'csfle'
            }));
            const model2 = connection.model('Model2', new Schema({
              b: {
                type: String,
                encrypt
              }
            }, {
              encryptionType: 'csfle'
            }));

            return { model1, model2 };
          }
        },
        'multiple schemas for QE': {
          modelFactory: () => {
            connection = createConnection();
            const model1 = connection.model('Model1', new Schema({
              a: {
                type: String,
                encrypt: {
                  keyId
                }
              }
            }, {
              encryptionType: 'qe'
            }));
            const model2 = connection.model('Model2', new Schema({
              b: {
                type: String,
                encrypt: {
                  keyId
                }
              }
            }, {
              encryptionType: 'qe'
            }));

            return { model1, model2 };
          }
        }
      };

      for (const [description, { modelFactory }] of Object.entries(tests)) {
        describe(description, function() {
          it('encrypts and decrypts', async function() {
            const { model1, model2 } = modelFactory();
            await connection.openUri(process.env.MONGOOSE_TEST_URI, {
              dbName: 'db', autoEncryption: {
                keyVaultNamespace: 'keyvault.datakeys',
                kmsProviders: { local: { key: LOCAL_KEY } },
                extraOptions: {
                  cryptdSharedLibRequired: true,
                  cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
                }
              }
            });

            {
              const [{ _id }] = await model1.insertMany([{ a: 'hello' }]);
              const encryptedDoc = await utilClient.db('db').collection('model1').findOne({ _id });

              assert.ok(isBsonType(encryptedDoc.a, 'Binary'));
              assert.ok(encryptedDoc.a.sub_type === 6);

              const doc = await model1.findOne({ _id });
              assert.deepEqual(doc.a, 'hello');
            }

            {
              const [{ _id }] = await model2.insertMany([{ b: 'world' }]);
              const encryptedDoc = await utilClient.db('db').collection('model2').findOne({ _id });

              assert.ok(isBsonType(encryptedDoc.b, 'Binary'));
              assert.ok(encryptedDoc.b.sub_type === 6);

              const doc = await model2.findOne({ _id });
              assert.deepEqual(doc.b, 'world');
            }
          });
        });
      }
    });

    describe('CSFLE and QE schemas on the same connection', function() {
      it('encrypts and decrypts', async function() {
        connection = createConnection();
        const model1 = connection.model('Model1', new Schema({
          a: {
            type: String,
            encrypt: {
              keyId
            }
          }
        }, {
          encryptionType: 'qe'
        }));
        const model2 = connection.model('Model2', new Schema({
          b: {
            type: String,
            encrypt: {
              keyId: [keyId],
              algorithm
            }
          }
        }, {
          encryptionType: 'csfle'
        }));
        await connection.openUri(process.env.MONGOOSE_TEST_URI, {
          dbName: 'db', autoEncryption: {
            keyVaultNamespace: 'keyvault.datakeys',
            kmsProviders: { local: { key: LOCAL_KEY } },
            extraOptions: {
              cryptdSharedLibRequired: true,
              cryptSharedLibPath: process.env.CRYPT_SHARED_LIB_PATH
            }
          }
        });

        {
          const [{ _id }] = await model1.insertMany([{ a: 'hello' }]);
          const encryptedDoc = await utilClient.db('db').collection('model1').findOne({ _id });

          assert.ok(isBsonType(encryptedDoc.a, 'Binary'));
          assert.ok(encryptedDoc.a.sub_type === 6);

          const doc = await model1.findOne({ _id });
          assert.deepEqual(doc.a, 'hello');
        }

        {
          const [{ _id }] = await model2.insertMany([{ b: 'world' }]);
          const encryptedDoc = await utilClient.db('db').collection('model2').findOne({ _id });

          assert.ok(isBsonType(encryptedDoc.b, 'Binary'));
          assert.ok(encryptedDoc.b.sub_type === 6);

          const doc = await model2.findOne({ _id });
          assert.deepEqual(doc.b, 'world');
        }
      });
    });
  });
});
