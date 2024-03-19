'use strict'

const { RetryHandler } = require('undici')
const { kRetryHandlerDefaultRetry } = require('undici/lib/core/symbols')
const { ClientDigestAuth, QOP_AUTH, QOP_AUTH_INT } = require('@mreal/digest-auth')

const defaultRetry = RetryHandler[kRetryHandlerDefaultRetry]

function createDigestInterceptor (options) {
  const {
    retryOnStatusCodes = [401],
    urls = [],
    username,
    password
  } = options

  return dispatch => function DigestIntercept (opts, handler) {
    if (!urls.includes(opts.origin)) {
      // do not attempt intercept
      return dispatch(opts, handler)
    }

    const counter = 1
    let authorize

    const retryHandler = new RetryHandler({
      ...opts,
      retryOptions: {
        retry (err, context, callback) {
          const { headers: { 'www-authenticate': authenticate } = {} } = err
          if (authenticate) {
            const { opts: { method, origin, path, body: entryBody } } = context
            const uri = `${origin}${path}`
            const serverDigest = ClientDigestAuth.analyze(authenticate)
            switch (serverDigest.qop) {
              case QOP_AUTH_INT:
                authorize = ClientDigestAuth.generateProtectionAuthInt(serverDigest, username, password, {
                  method,
                  uri,
                  counter,
                  entryBody
                }).raw
                break
              case QOP_AUTH:
                authorize = ClientDigestAuth.generateProtectionAuth(serverDigest, username, password, {
                  method,
                  uri,
                  counter
                }).raw
                break
              default:
                authorize = ClientDigestAuth.generateUnprotected(serverDigest, username, password, {
                  method,
                  uri
                }).raw
            }
          }
          defaultRetry.call(retryHandler, err, context, callback)
        },
        statusCodes: retryOnStatusCodes,
        maxRetries: 1,
        retryAfter: 0,
        minTimeout: 0,
        timeoutFactor: 1
      }
    }, {
      dispatch ({ headers, ...opts }, handler) {
        return dispatch({ ...opts, headers: { ...headers, authorize } }, handler)
      },
      handler
    })

    return dispatch(opts, retryHandler)
  }
}

module.exports = createDigestInterceptor
module.exports.createDigestInterceptor = createDigestInterceptor
