
import randomBytes from '@neumatter/random-bytes'
import ByteView from 'byteview'
import SHA3 from './lib/SHA3.js'
import * as os from 'os'
import { spawnSync } from 'child_process'

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

function getMacName (release) {
  let [releaseMajor, releaseMinor] = (release || os.release()).split('.')
  releaseMajor = Number(releaseMajor)
  releaseMinor = Number(releaseMinor)

  switch (releaseMajor) {
    case 22:
      return [
        'Ventura',
        releaseMinor === 0
          ? '13.0'
          : releaseMinor === 1
            ? '13.0.1'
            : `13.${releaseMinor - 1}`
      ]
    case 21:
      return [
        'Monterey',
        releaseMinor === 0
          ? '12.0'
          : releaseMinor === 1
            ? '12.0.1'
            : `12.${releaseMinor - 1}`
      ]
    case 20:
      return [
        'Big Sur',
        releaseMinor === 0
          ? '11.0'
          : releaseMinor === 1
            ? '11.0.1'
            : `11.${releaseMinor - 1}`
      ]
    case 19:
      return ['Catalina', '10.15']
    case 18:
      return ['Mojave', '10.14']
    case 17:
      return ['High Sierra', '10.13']
    case 16:
      return ['Sierra', '10.12']
    case 15:
      return ['El Capitan', '10.11']
    case 14:
      return ['Yosemite', '10.10']
    default:
      return ['Unknown', 'Unknown']
  }
}

function getWindowsName (release) {
  const version = /(\d+\.\d+)(?:\.(\d+))?/.exec(release || os.release())

  if (release && !version) {
		return ['Windows', 'Unknown']
	}

  let ver = version[1] || ''
  const build = version[2] || ''

  if ((!release || release === os.release()) && ['6.1', '6.2', '6.3', '10.0'].includes(ver)) {
		let stdout

		try {
			stdout = spawnSync('wmic', ['os', 'get', 'Caption']).stdout.toString()
		} catch {
      stdout = undefined
		}

    if (stdout === undefined) {
      try {
        stdout = spawnSync(
          'powershell',
          ['(Get-CimInstance -ClassName Win32_OperatingSystem).caption']
        ).stdout.toString()
      } catch {
        stdout = 'unknown'
      }
    }

		const year = (stdout.match(/2008|2012|2016|2019|2022/) || [])[0]

		if (year) {
			return ['Windows', `Server ${year}`]
		}
	}

	if (ver === '10.0' && build.startsWith('22')) {
		ver = '10.0.22'
	}

  switch (ver) {
    case '10.0.22':
      return ['Windows', '11']
    case '10.0':
      return ['Windows', '10']
    case '6.3':
      return ['Windows', '8.1']
    case '6.2':
      return ['Windows', '8']
    case '6.1':
      return ['Windows', '7']
    case '6.0':
      return ['Windows', 'Vista']
    case '5.2':
      return ['Windows', 'Server 2003']
    default:
      return ['Windows', '0.0']
  }
}

function getOSName (platform, release) {
  switch (platform) {
    case 'darwin': {
      const prefix = release ? (Number(release.split('.')[0]) > 15 ? 'macOS' : 'OS X') : 'macOS'
      const [name, ver] = getMacName(release)

      if (name === 'Unknown') {
        return prefix
      }
  
      return prefix + ' ' + name + ' ' + ver
    }
    case 'linux': {
      const id = release ? release.replace(/^(\d+\.\d+).*/, '$1') : ''
		  return 'Linux' + (id ? ' ' + id : '')
    }
    case 'win32': {
		  return getWindowsName(release).join(' ')
    }

    default:
      return platform
  }
}

class OSInfo {
  constructor () {
    const platform = os.platform()
    const release = os.release()
    this.name = getOSName(platform, release)
    this.architecture = os.arch()
    this.platform = platform
    this.kernel = release
  }

  toString () {
    return `${this.name} [${this.platform}-${this.architecture}-${this.kernel}]`
  }
}

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
        ).toString() + new OSInfo().toString()
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

console.log(new PSUID())