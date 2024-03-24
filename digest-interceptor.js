'use strict'

const { analyze } = require('./lib/utils')
const { RetryHandler } = require('undici')
const { kRetryHandlerDefaultRetry } = require('undici/lib/core/symbols')

const defaultRetry = RetryHandler[kRetryHandlerDefaultRetry]

function createDigestInterceptor (options) {
  const {
    urls = [],
    username,
    password,
    retryOptions = {
      statusCodes: [401],
      maxRetries: 1,
      retryAfter: 0,
      minTimeout: 0,
      timeoutFactor: 1
    }
  } = options
  
  return dispatch =>  {
    let generate

    function authorized({ headers, ...opts }, handler) {
      const { method, origin, path, body: entryBody } = opts
      const uri = `${origin}${path}`
      const { raw: authorize } = generate(username, password, {
        method,
        uri,
        entryBody
      })
      return dispatch({ ...opts, headers: { ...headers, authorize } }, handler)
    }

    return function DigestIntercept (opts, handler) {
      const { origin } = opts
      if (!urls.includes(origin)) {
        // do not attempt intercept
        return dispatch(opts, handler)
      }

      if (generate) {
        return authorized(opts, handler)
      }

      const retryHandler = new RetryHandler({
        ...opts,
        retryOptions: {
          ...retryOptions,
          retry (err, context, callback) {
            const { headers: { 'www-authenticate': wwwAuthenticate } = {} } = err
            if (wwwAuthenticate) {
              generate = analyze(wwwAuthenticate)
            }
            defaultRetry.call(retryHandler, err, context, callback)
          }
        }
      }, {
        dispatch (opts, handler) {
          return authorized(opts, handler)
        },
        handler
      })

      return dispatch(opts, retryHandler)
    }
  }
}

module.exports = createDigestInterceptor
module.exports.createDigestInterceptor = createDigestInterceptor
