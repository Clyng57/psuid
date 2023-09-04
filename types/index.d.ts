import type ByteView from "byteview"

declare module 'psuid'

export default class PSUID {
  static isPSUID (input: any): boolean
  static generate (): ByteView
  constructor (uid?: PSUID | string | ByteView)
  get version (): number
  get timestamp (): number
  toString (): string
  inspect (): string
  [Symbol.for('nodejs.util.inspect.custom')] (): string
  [Symbol.toPrimitive] (): string
  toJSON (): string
  toBVON (): string
  toBSON (): string
}
