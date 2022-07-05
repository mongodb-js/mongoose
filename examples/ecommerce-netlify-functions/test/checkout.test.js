'use strict';

const { describe, it, before, after } = require('mocha');
const assert = require('assert');
const { handler: addToCart } = require('../functions/addToCart');
const { handler: checkout } = require('../functions/checkout');
const mongoose = require('mongoose');
const fixtures = require('./fixtures');
const sinon = require('sinon');
const stripe = require('../integrations/stripe')

describe('Checkout', function() {
  before(async() => {
    await mongoose.connect('mongodb://localhost:27017/netlify');
    await mongoose.connection.dropDatabase();
  });

  after(async() => {
    await mongoose.disconnect();
  });
  it('Should do a successful checkout run', async function() {
    const products = await fixtures.createProducts({product: [{ productName: 'A Test Products', productPrice: 500 }, {productName: 'Another Test Product', productPrice: 600 }]})
    .then((res) => res.products);
    const params = {
      body: {
        cartId: null,
        items: [
          { productId: products[0]._id, quantity: 2 },
          { productId: products[1]._id, quantity: 1 }
        ]
      }
    };
    const result = await addToCart(params);
    assert(result.body);
    assert(result.body.items.length);
    params.body.cartId = result.body._id;
    sinon.stub(stripe.paymentIntents, 'retrieve').returns({status: 'succeeded', id: '123', brand: 'visa', last4: '1234'});
    sinon.stub(stripe.paymentMethods, 'retrieve').returns({status: 'succeeded', id: '123', brand: 'visa', last4: '1234'});
    sinon.stub(stripe.checkout.sessions, 'create').returns({status: 'succeeded', id: '123', brand: 'visa', last4: '1234'});
    params.body.product = params.body.items;
    params.body.name = 'Test Testerson';
    params.body.email = 'test@localhost.com';
    params.body.address1 = '12345 Syndey Street';
    params.body.city = 'Miami';
    params.body.state = 'Florida';
    params.body.zip = '33145';
    params.body.shipping = 'standard';
    const finish = await checkout(params);
    assert(finish.body.order);
    assert(finish.body.cart);
  });
});
