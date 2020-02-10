/*!
 * lib/serializer/encrypting.js
 */

/**
 * Encrypting serializer
 */
module.exports = class SerializerEncrypting {
  /**
   * @param {string} secret
   */
  constructor (secret) {
    this.crypto = require('./crypto.js')
    this.crypto.init({ secret })
  }

  /**
   * @param {string} dataString
   * @returns {Object}
   */
  deserialize (dataString) {
    return JSON.parse(this.crypto.get(dataString))
  }

  /**
   * @param {Object} data
   * @returns {string}
   */
  serialize (data) {
    return this.crypto.set(data)
  }
}
