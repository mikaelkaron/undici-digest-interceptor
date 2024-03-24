'use strict'

const test = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const { request, Agent } = require('undici')
const { ServerDigestAuth, QOP_AUTH, QOP_AUTH_INT } = require('@mreal/digest-auth')
const { createDigestInterceptor } = require('../')

test('make a request without auth (not intercepted)', async (t) => {
  const server = http.createServer((req, res) => {
    reqCount++
    res
      .writeHead(200)
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const username = 'username'
  const password = 'password'
  let reqCount = 0

  const dispatcher = new Agent({
    keepAliveTimeout: 10,
    keepAliveMaxTimeout: 10,
    interceptors: {
      Pool: [createDigestInterceptor({
        username,
        password
      })]
    }
  })

  const { statusCode } = await request(targetUrl, { dispatcher })

  assert.strictEqual(statusCode, 200, 'status code should match')
  assert.strictEqual(reqCount, 1, 'should have one request')
})

test('make a request without auth (intercepted)', async (t) => {
  const server = http.createServer((req, res) => {
    reqCount++
    res
      .writeHead(200)
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const username = 'username'
  const password = 'password'
  let reqCount = 0

  const dispatcher = new Agent({
    keepAliveTimeout: 10,
    keepAliveMaxTimeout: 10,
    interceptors: {
      Pool: [createDigestInterceptor({
        urls: [targetUrl],
        username,
        password
      })]
    }
  })

  const { statusCode } = await request(targetUrl, { dispatcher })

  assert.strictEqual(statusCode, 200, 'status code should match')
  assert.strictEqual(reqCount, 1, 'should have one request')
})

test('make a request with digest auth', async (t) => {
  const server = http.createServer((req, res) => {
    reqCount++
    const { headers: { authorize, host }, url, method } = req
    if (authorize) {
      const uri = `http://${host}${url}`
      const digest = ServerDigestAuth.analyze(authorize, false)
      if (ServerDigestAuth.verifyByPassword(digest, password, {
        method,
        uri
      })) {
        resCount200++
        res
          .writeHead(200)
          .end()
        return
      }
    }
    resCount401++
    res
      .writeHead(401, {
        'www-authenticate': ServerDigestAuth.generateResponse(realm).raw
      })
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const realm = 'test realm'
  const username = 'username'
  const password = 'password'
  let reqCount = 0
  let resCount200 = 0
  let resCount401 = 0

  const dispatcher = new Agent({
    keepAliveTimeout: 10,
    keepAliveMaxTimeout: 10,
    interceptors: {
      Pool: [createDigestInterceptor({
        urls: [targetUrl],
        username,
        password
      })]
    }
  })

  const { statusCode } = await request(targetUrl, { dispatcher })

  assert.strictEqual(statusCode, 200, 'status code should match')
  assert.strictEqual(reqCount, 2, 'should have two requests')
  assert.strictEqual(resCount401, 1, 'should have one 401 request')
  assert.strictEqual(resCount200, 1, 'should have one 200 request')
})

test('make a request with digest auth { qop: "auth" }', async (t) => {
  const server = http.createServer((req, res) => {
    reqCount++
    const { headers: { authorize, host }, url, method } = req
    if (authorize) {
      const uri = `http://${host}${url}`
      const digest = ServerDigestAuth.analyze(authorize, [qop])
      if (ServerDigestAuth.verifyByPassword(digest, password, {
        method,
        uri
      })) {
        resCount200++
        res
          .writeHead(200)
          .end()
        return
      }
    }
    resCount401++
    res
      .writeHead(401, {
        'www-authenticate': ServerDigestAuth.generateResponse(realm, { qop }).raw
      })
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const realm = 'test realm'
  const username = 'username'
  const password = 'password'
  const qop = QOP_AUTH
  let reqCount = 0
  let resCount200 = 0
  let resCount401 = 0

  const dispatcher = new Agent({
    keepAliveTimeout: 10,
    keepAliveMaxTimeout: 10,
    interceptors: {
      Pool: [createDigestInterceptor({
        urls: [targetUrl],
        username,
        password
      })]
    }
  })

  const { statusCode } = await request(targetUrl, { dispatcher })

  assert.strictEqual(statusCode, 200, 'status code should match')
  assert.strictEqual(reqCount, 2, 'should have two requests')
  assert.strictEqual(resCount401, 1, 'should have one 401 request')
  assert.strictEqual(resCount200, 1, 'should have one 200 request')
})

test('make a request with digest auth { qop: "auth-int" }', async (t) => {
  const server = http.createServer((req, res) => {
    const chunks = []
    reqCount++
    req
      .on('data', chunk => chunks.push(chunk))
      .on('end', () => {
        const entryBody = Buffer
          .concat(chunks)
          .toString()
        const { headers: { authorize, host }, url, method } = req
        if (authorize) {
          const uri = `http://${host}${url}`
          const digest = ServerDigestAuth.analyze(authorize, [qop])
          if (ServerDigestAuth.verifyByPassword(digest, password, {
            method,
            uri,
            entryBody
          })) {
            resCount200++
            res
              .writeHead(200)
              .end(entryBody)
            return
          }
        }
        resCount401++
        res
          .writeHead(401, {
            'www-authenticate': ServerDigestAuth.generateResponse(realm, { qop }).raw
          })
          .end()
      })
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const realm = 'test realm'
  const username = 'username'
  const password = 'password'
  const qop = QOP_AUTH_INT
  let reqCount = 0
  let resCount200 = 0
  let resCount401 = 0

  const dispatcher = new Agent({
    keepAliveTimeout: 10,
    keepAliveMaxTimeout: 10,
    interceptors: {
      Pool: [createDigestInterceptor({
        urls: [targetUrl],
        username,
        password
      })]
    }
  })

  const { statusCode, body } = await request(targetUrl, {
    method: 'PUT',
    body: 'test',
    dispatcher
  })

  assert.strictEqual(statusCode, 200, 'status code should match')
  assert.strictEqual(await body.text(), 'test', 'body should match')
  assert.strictEqual(reqCount, 2, 'should have two requests')
  assert.strictEqual(resCount401, 1, 'should have one 401 request')
  assert.strictEqual(resCount200, 1, 'should have one 200 request')
})

test('make two request with digest auth { qop: "auth" }', async (t) => {
  const server = http.createServer((req, res) => {
    reqCount++
    const { headers: { authorize, host }, url, method } = req
    if (authorize) {
      const uri = `http://${host}${url}`
      const digest = ServerDigestAuth.analyze(authorize, [qop])
      if (ServerDigestAuth.verifyByPassword(digest, password, {
        method,
        uri
      })) {
        resCount200++
        res
          .writeHead(200)
          .end()
        return
      }
    }
    resCount401++
    res
      .writeHead(401, {
        'www-authenticate': ServerDigestAuth.generateResponse(realm, { qop }).raw
      })
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const realm = 'test realm'
  const username = 'username'
  const password = 'password'
  const qop = QOP_AUTH
  let reqCount = 0
  let resCount200 = 0
  let resCount401 = 0

  const dispatcher = new Agent({
    keepAliveTimeout: 10,
    keepAliveMaxTimeout: 10,
    interceptors: {
      Pool: [createDigestInterceptor({
        urls: [targetUrl],
        username,
        password
      })]
    }
  })

  {
    const { statusCode } = await request(targetUrl, { dispatcher })
    assert.strictEqual(statusCode, 200, 'status code should match')
    }
  {
    const { statusCode } = await request(targetUrl, { dispatcher })
    assert.strictEqual(statusCode, 200, 'status code should match')
  }

  assert.strictEqual(reqCount, 3, 'should have three requests')
  assert.strictEqual(resCount401, 1, 'should have one 401 request')
  assert.strictEqual(resCount200, 2, 'should have two 200 requests')
})
