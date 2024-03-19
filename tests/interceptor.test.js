'use strict'

const test = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const { request, Agent } = require('undici')
const { ServerDigestAuth, QOP_AUTH, QOP_AUTH_INT } = require('@mreal/digest-auth')
const { createDigestInterceptor } = require('../')

test('make a request without auth (not intercepted)', async (t) => {
  const server = http.createServer((req, res) => {
    requestCount++
    res
      .writeHead(200)
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const username = 'username'
  const password = 'password'
  let requestCount = 0

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

  assert.strictEqual(statusCode, 200)
  assert.strictEqual(requestCount, 1)
})

test('make a request without auth (intercepted)', async (t) => {
  const server = http.createServer((req, res) => {
    requestCount++
    res
      .writeHead(200)
      .end()
  })
  server.listen(0)

  t.after(() => server.close())

  const targetUrl = `http://localhost:${server.address().port}`
  const username = 'username'
  const password = 'password'
  let requestCount = 0

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

  assert.strictEqual(statusCode, 200)
  assert.strictEqual(requestCount, 1)
})

test('make a request with digest auth', async (t) => {
  const server = http.createServer((req, res) => {
    requestCount++
    const { headers: { authorize, host }, url, method } = req
    if (authorize) {
      const uri = `http://${host}${url}`
      const digest = ServerDigestAuth.analyze(authorize, false)
      if (ServerDigestAuth.verifyByPassword(digest, password, {
        method,
        uri
      })) {
        res
          .writeHead(200)
          .end()
        return
      }
    }

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
  let requestCount = 0

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

  assert.strictEqual(statusCode, 200)
  assert.strictEqual(requestCount, 2)
})

test('make a request with digest auth { qop: "auth" }', async (t) => {
  const server = http.createServer((req, res) => {
    requestCount++
    const { headers: { authorize, host }, url, method } = req
    if (authorize) {
      const uri = `http://${host}${url}`
      const digest = ServerDigestAuth.analyze(authorize, [qop])
      if (ServerDigestAuth.verifyByPassword(digest, password, {
        method,
        uri
      })) {
        res
          .writeHead(200)
          .end()
        return
      }
    }

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
  let requestCount = 0

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

  assert.strictEqual(statusCode, 200)
  assert.strictEqual(requestCount, 2)
})

test('make a request with digest auth { qop: "auth-int" }', async (t) => {
  const server = http.createServer((req, res) => {
    const chunks = []
    requestCount++
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
            res
              .writeHead(200)
              .end(entryBody)
            return
          }
        }

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
  let requestCount = 0

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

  assert.strictEqual(statusCode, 200)
  assert.strictEqual(requestCount, 2)
  assert.strictEqual(await body.text(), 'test')
})
