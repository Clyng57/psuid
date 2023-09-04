
import randomBytes from '@neumatter/random-bytes'
import ByteView from 'byteview'
import SHA3 from './lib/SHA3.js'

const BASE32_UID = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
const BASE32_UID_REGEX = /^[2-9A-HJ-NP-Z]{8}-[2-9A-HJ-NP-Z]{8}-[2-9A-HJ-NP-Z]{8}-[1-9][2-9A-HJ-NP-Z]{7}$/
const SYMBOL_IS_UID = Symbol.for('neumatter.PSUID.isPSUID')

const addDash = (length) => {
  let res

  switch (length) {
    case 8:
    case 17:
    case 26:
      res = '-'
      break
    default:
      res = ''
      break
  }

  return res
}

function encodeBase32UID (byteView, padding = false) {
  if (!ByteView.isView(byteView)) {
    throw new Error('[Base32[encode]] did not recieve valid type')
  }

  const { length } = byteView
  let index = -1
  let bits = 0
  let value = 0
  let response = ''

  while (++index < length) {
    const byte = byteView[index]
    value = (value << 0x8) | byte
    bits += 8

    while (bits >= 5) {
      response += BASE32_UID[(value >>> (bits - 5)) & 0x1F]
      response += addDash(response.length)

      bits -= 5
    }
  }

  if (bits > 0) {
    response += BASE32_UID[(value << (5 - bits)) & 0x1F]
    response += addDash(response.length)
  }

  if (padding) {
    while (response.length % 8 !== 0) {
      response += '='
    }
  }

  return response
}

function base32ByteLength (string) {
  let { length } = string
  length -= 3
  let validLength = string.indexOf('=')
  if (validLength === -1) validLength = length

  const placeHoldersLength = validLength === length
    ? 0
    : length - validLength

  return (((length - placeHoldersLength) * 5) / 8) | 0
}

function decodeBase32UID (string) {
  const { length } = string
  let bits = 0
  let value = 0
  let index = 0
  const bytes = new ByteView(base32ByteLength(string))
  let i = -1

  while (++i < length) {
    if (string[i] === '=' || string[i] === '-') continue
    value = (value << 5) | BASE32_UID.indexOf(string[i])
    bits += 5

    if (bits >= 8) {
      bytes[index++] = (value >>> (bits - 8)) & 0xFF
      bits -= 8
    }
  }

  return bytes
}

let PROCESS_FINGERPRINT = null

export default class PSUID {
  static #index = randomBytes(2).getUint16(0)

  static isPSUID (input) {
    return (
      typeof input === 'object' &&
      input !== null &&
      typeof input[SYMBOL_IS_UID] === 'boolean' &&
      input[SYMBOL_IS_UID]
    )
  }

  static generate () {
    const index = (++this.#index) % 0xffff

    if (PROCESS_FINGERPRINT === null) {
      const globals = ByteView.from(
        Object.keys(
          typeof globalThis !== 'undefined'
            ? globalThis
            : { process: '' }
        ).toString()
      )

      const fingerprintSHA3 = new SHA3('224')
      fingerprintSHA3.update(
        ByteView.concat([globals, randomBytes(28)])
      )

      PROCESS_FINGERPRINT = fingerprintSHA3.digest().slice(0, 4)
    }

    const byteView = new ByteView(19)
    byteView.setUint32(0, Date.now() / 1000 | 0)
    byteView.setUint16(4, index)
    byteView.set(randomBytes(9), 6)
    byteView.set(PROCESS_FINGERPRINT, 15)

    return byteView
  }

  #version = 1
  #id
  #idCache = null

  constructor (uid) {
    switch (typeof uid) {
      case 'undefined':
        this.#id = PSUID.generate()
        break
      case 'object':
        if (uid === null) {
          this.#id = PSUID.generate()
          break
        } else if (PSUID.isPSUID(uid)) {
          uid = uid.toString() // fall through
        } else if (ByteView.isView(uid) && uid.byteLength === 19) {
          uid = encodeBase32UID(uid) // fall through
        } else {
          throw new Error('Argument passed in does not match the accepted types')
        }
      /* eslint-disable no-fallthrough */
      case 'string':
        if (uid.length === 35 && BASE32_UID_REGEX.test(uid)) {
          this.#id = decodeBase32UID(uid)
          this.#idCache = uid
        } else {
          throw new Error(
            'Argument passed in to UIDConstructor must be a string of 4 7 base32uid character chunks'
          )
        }
        break
      default:
        throw new Error('Argument passed in does not match the accepted types')
        break
    }
  }

  get version () {
    return this.#version
  }

  get timestamp () {
    return this.#id.getUint32(0)
  }

  get [SYMBOL_IS_UID] () {
    return true
  }

  toString () {
    if (this.#idCache) return this.#idCache
    const tmpid = encodeBase32UID(this.#id)
    const id = tmpid.slice(0, 27) + String(this.#version) + tmpid.slice(27)
    this.#idCache = id
    return id
  }

  inspect () {
    return `PSUID('${this.toString()}')`
  }

  [Symbol.for('nodejs.util.inspect.custom')] () {
    return `PSUID(\x1b[32m'${this.toString()}'\x1b[0m)`
  }

  [Symbol.toPrimitive] () {
    return this.toString()
  }

  toJSON () {
    return this.toString()
  }

  toBVON () {
    return this.toString()
  }

  toBSON () {
    return this.toString()
  }
}
