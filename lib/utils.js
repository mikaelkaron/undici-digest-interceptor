'use strict'

const { ClientDigestAuth, QOP_AUTH, QOP_AUTH_INT } = require('@mreal/digest-auth')

function analyze(header) {
  let counter = 0
  const serverDigest = ClientDigestAuth.analyze(header)

  switch (serverDigest.qop) {
    case QOP_AUTH_INT:
      return function generate(username, password, { method, uri, entryBody }) {
        counter += 1
        return ClientDigestAuth.generateProtectionAuthInt(serverDigest, username, password, {
          method,
          uri,
          counter,
          entryBody
        })
      }
      case QOP_AUTH:
        return function generate(username, password, { method, uri }) {
          counter += 1
          return ClientDigestAuth.generateProtectionAuth(serverDigest, username, password, {
            method,
            uri,
            counter
          })
      }
      default:
        return function generate(username, password, { method, uri }) {
          return ClientDigestAuth.generateUnprotected(serverDigest, username, password, {
          method,
          uri
        })
      }
    }
}

module.exports = {
  analyze
}