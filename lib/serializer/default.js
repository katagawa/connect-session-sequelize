/*!
 * lib/serializer/default.js
 */

/**
 * Default serializer
 */
module.exports = class SerializerDefault {
  /**
   * @param {string} dataString
   * @returns {Object}
   */
  deserialize (dataString) {
    return JSON.parse(dataString)
  }

  /**
   * @param {Object} data
   * @returns {string}
   */
  serialize (data) {
    return JSON.stringify(data)
  }
}
