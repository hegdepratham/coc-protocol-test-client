const net = require('net')
const RC4 = require('simple-rc4')

const SERVER_IP = '127.0.0.1'
const SERVER_PORT = 9339
const RC4_KEY = 'fhsd6f86f67rt8fw78fw789we78r9789wer6re' // must match Server.RC4Key in config.json

class ByteWriter {
  constructor() { this.bytes = [] }
  writeByte(value) { this.bytes.push(value & 0xFF) }
  writeInt(value) {
    this.writeByte(value >> 24); this.writeByte(value >> 16)
    this.writeByte(value >> 8); this.writeByte(value)
  }
  writeString(value) {
    const buf = Buffer.from(value ?? '', 'utf8')
    this.writeInt(buf.length)
    for (const b of buf) this.writeByte(b)
  }
  writeVInt(value) {
    let temp = (value >> 25) & 0x40
    let flipped = value ^ (value >> 31)
    temp |= value & 0x3F
    value >>= 6
    flipped >>= 6
    if (flipped === 0) { this.writeByte(temp); return }
    this.writeByte(temp | 0x80)
    flipped >>= 7
    let r = flipped ? 0x80 : 0
    this.writeByte((value & 0x7F) | r)
    value >>= 7
    while (flipped !== 0) {
      flipped >>= 7
      r = flipped ? 0x80 : 0
      this.writeByte((value & 0x7F) | r)
      value >>= 7
    }
  }
  toBuffer() { return Buffer.from(this.bytes) }
}

// Reads fields back out of a decrypted server response
class ByteReader {
  constructor(buffer) { this.buffer = buffer; this.offset = 0 }
  readInt() {
    const v = this.buffer.readInt32BE(this.offset)
    this.offset += 4
    return v
  }
  readString() {
    const length = this.readInt()
    if (length <= 0 || length > 90000) return ''
    const str = this.buffer.subarray(this.offset, this.offset + length).toString('utf8')
    this.offset += length
    return str
  }
}

class CryptoRc4 {
  constructor(key) {
    // Each call makes a FRESH buffer -- reusing one across calls corrupts it,
    // since RC4's .update() mutates its input buffer in place
    this.streamOut = new RC4(Buffer.concat([Buffer.from(key), Buffer.from('nonce')]))
    this.streamOut.update(Buffer.concat([Buffer.from(key), Buffer.from('nonce')]))
    this.streamIn = new RC4(Buffer.concat([Buffer.from(key), Buffer.from('nonce')]))
    this.streamIn.update(Buffer.concat([Buffer.from(key), Buffer.from('nonce')]))
  }
  encryptOutgoing(data) { return this.streamOut.update(data) }
  decryptIncoming(data) { return this.streamIn.update(data) }
}

const crypto = new CryptoRc4(RC4_KEY)

function sendPacket(socket, id, version, payloadBuffer) {
  const encrypted = crypto.encryptOutgoing(payloadBuffer)
  const header = Buffer.alloc(7)
  header.writeUInt16BE(id, 0)
  header.writeUIntBE(encrypted.length, 2, 3)
  header.writeUInt16BE(version, 5)
  socket.write(Buffer.concat([header, encrypted]))
}

const socket = net.createConnection(SERVER_PORT, SERVER_IP, () => {
  console.log('Connected to server, sending ClientHello...')
  const writer = new ByteWriter()
  writer.writeVInt(1); writer.writeVInt(0); writer.writeVInt(1); writer.writeVInt(0); writer.writeVInt(1)
  sendPacket(socket, 10100, 0, writer.toBuffer())
})

function sendLogin(socket) {
  console.log('Handshake OK -- sending Login (new player, blank token)...')
  const writer = new ByteWriter()
  writer.writeInt(0)        // HighID
  writer.writeInt(0)        // LowID
  writer.writeString('')    // Token (blank = create new player)
  writer.writeInt(6)        // Major
  writer.writeInt(0)        // Minor
  writer.writeInt(56)       // Build (6.56 -- matches a supported version)
  sendPacket(socket, 10101, 1, writer.toBuffer())
}

let receiveBuffer = Buffer.alloc(0)
socket.on('data', (data) => {
  receiveBuffer = Buffer.concat([receiveBuffer, data])
  while (receiveBuffer.length >= 7) {
    const payloadLength = receiveBuffer.readUIntBE(2, 3)
    const packetLength = 7 + payloadLength
    if (receiveBuffer.length < packetLength) return
    const packet = receiveBuffer.subarray(0, packetLength)
    receiveBuffer = receiveBuffer.subarray(packetLength)
    const id = packet.readUInt16BE(0)
    const decrypted = crypto.decryptIncoming(packet.subarray(7))

    if (id === 20100) {
      console.log('Received ServerHelloMessage (20100) -- handshake confirmed.')
      sendLogin(socket)
    } else if (id === 20104) {
      const r = new ByteReader(decrypted)
      const highID = r.readInt(); const lowID = r.readInt()
      r.readInt(); r.readInt() // duplicate HighID/LowID pair the server sends
      const token = r.readString()
      console.log('Received LoginOkMessage (20104) -- real player from MongoDB!')
      console.log(`  highID: ${highID}, lowID: ${lowID}`)
      console.log(`  token:  ${token}`)
    } else if (id === 20103) {
      console.log('Received LoginFailedMessage (20103) -- login was rejected.')
    } else {
      console.log(`Received packet id ${id}, ${decrypted.length} bytes`)
    }
  }
})

socket.on('error', (err) => console.log('Connection error:', err.message))
socket.on('close', () => console.log('Connection closed.'))