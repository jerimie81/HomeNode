package com.homenode.service.files

import com.homenode.core.storage.FileEntry
import com.homenode.core.storage.FileStat
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.WriteMode
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer

/**
 * Binary Frame Codec & Protocol v2 Wire Codec on tunnel port 7001 (§9, ADR-005, Slice S5).
 * Frame layout: `| len:u32 (<= MAX_FRAME_BYTES) | type:u8 | flags:u8 | requestId:u32 | payload |`.
 * Uses deterministic length-prefixed binary fields (no Java/Kotlin reflection serialization on network input).
 */
enum class FrameType(val code: Byte) {
  HELLO(0x01),
  LIST(0x02),
  STAT(0x03),
  READ(0x04),
  WRITE(0x05),
  MKDIR(0x06),
  DELETE(0x07),
  MOVE(0x08),
  CANCEL(0x09),
  OK(0x10),
  DATA(0x11),
  END(0x12),
  ERROR(0x13),
  ;

  companion object {
    fun fromCode(code: Byte): FrameType? = entries.firstOrNull { it.code == code }
  }
}

data class WireFrame(
  val type: FrameType,
  val flags: Byte = 0,
  val requestId: Int,
  val payload: ByteArray,
)

sealed interface CodecResult<out T> {
  data class Success<T>(val value: T) : CodecResult<T>
  data class Malformed(val code: String, val message: String) : CodecResult<Nothing>
}

object FrameCodec {
  const val HEADER_BYTES = 10 // len:4 + type:1 + flags:1 + requestId:4
  const val MAX_FRAME_BYTES = 1024 * 1024 // 1 MiB hard pre-allocation bound (§9)
  const val MAX_ERROR_MESSAGE_BYTES = 256
  const val PROTOCOL_VERSION_V2 = 2

  fun encodeFrame(frame: WireFrame, maxPayloadBytes: Int = MAX_FRAME_BYTES): ByteArray {
    require(frame.payload.size <= maxPayloadBytes) {
      "Payload ${frame.payload.size} exceeds maxPayloadBytes $maxPayloadBytes"
    }
    val buf = ByteBuffer.allocate(HEADER_BYTES + frame.payload.size)
    buf.putInt(frame.payload.size)
    buf.put(frame.type.code)
    buf.put(frame.flags)
    buf.putInt(frame.requestId)
    buf.put(frame.payload)
    return buf.array()
  }

  fun decodeFrame(rawBytes: ByteArray, negotiatedMaxPayload: Int = MAX_FRAME_BYTES): CodecResult<WireFrame> {
    if (rawBytes.size < HEADER_BYTES) {
      return CodecResult.Malformed("BAD_REQUEST", "Frame shorter than $HEADER_BYTES-byte header")
    }
    val buf = ByteBuffer.wrap(rawBytes)
    val payloadLen = buf.int
    val limit = negotiatedMaxPayload.coerceAtMost(MAX_FRAME_BYTES)
    if (payloadLen < 0 || payloadLen > limit) {
      return CodecResult.Malformed("FRAME_TOO_LARGE", "Frame payload length $payloadLen out of bounds (max $limit)")
    }
    if (rawBytes.size != HEADER_BYTES + payloadLen) {
      return CodecResult.Malformed("BAD_REQUEST", "Frame length mismatch: header=$payloadLen actual=${rawBytes.size - HEADER_BYTES}")
    }
    val typeCode = buf.get()
    val flags = buf.get()
    val requestId = buf.int
    val frameType = FrameType.fromCode(typeCode)
      ?: return CodecResult.Malformed("UNKNOWN_TYPE", "Unknown frame type 0x${typeCode.toString(16)}")
    val payload = ByteArray(payloadLen)
    buf.get(payload)
    return CodecResult.Success(WireFrame(frameType, flags, requestId, payload))
  }
}

sealed interface ProtocolMessage {
  data class Hello(val version: Int, val maxFrameBytes: Int) : ProtocolMessage
  data class ListReq(val virtualPath: String, val pageSize: Int = 100, val pageToken: String? = null) : ProtocolMessage
  data class StatReq(val virtualPath: String) : ProtocolMessage
  data class ReadReq(val virtualPath: String, val offset: Long = 0L, val length: Long = Long.MAX_VALUE) : ProtocolMessage
  data class WriteReq(val virtualPath: String, val mode: WriteMode, val expectedSize: Long) : ProtocolMessage
  data class MkdirReq(val virtualPath: String) : ProtocolMessage
  data class DeleteReq(val virtualPath: String, val recursive: Boolean) : ProtocolMessage
  data class MoveReq(val srcVirtualPath: String, val dstVirtualPath: String) : ProtocolMessage
  data class CancelReq(val targetRequestId: Int) : ProtocolMessage

  data class OkStatResp(val stat: FileStat) : ProtocolMessage
  data class OkListResp(val entries: List<FileEntry>, val nextPageToken: String?) : ProtocolMessage
  data object OkUnitResp : ProtocolMessage
  data class ErrorResp(val errorCode: String, val safeMessage: String) : ProtocolMessage
}

object ProtocolV2PayloadCodec {
  private const val MAX_STRING_BYTES = 2048

  private fun DataOutputStream.writeBoundedUtf8(value: String) {
    val bytes = value.encodeToByteArray()
    require(bytes.size <= MAX_STRING_BYTES) { "String exceeds max wire length" }
    writeShort(bytes.size)
    write(bytes)
  }

  private fun DataInputStream.readBoundedUtf8(maxBytes: Int = MAX_STRING_BYTES): String {
    val len = readUnsignedShort()
    if (len > maxBytes) throw IllegalArgumentException("String length $len > $maxBytes")
    val bytes = ByteArray(len)
    readFully(bytes)
    return bytes.decodeToString(throwOnInvalidSequence = true)
  }

  fun encodeHello(msg: ProtocolMessage.Hello): ByteArray = buildBytes {
    writeInt(msg.version)
    writeInt(msg.maxFrameBytes)
  }

  fun decodeHello(bytes: ByteArray): CodecResult<ProtocolMessage.Hello> = readBytes(bytes) {
    ProtocolMessage.Hello(version = readInt(), maxFrameBytes = readInt())
  }

  fun encodeListReq(msg: ProtocolMessage.ListReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.virtualPath)
    writeInt(msg.pageSize)
    writeBoundedUtf8(msg.pageToken.orEmpty())
  }

  fun decodeListReq(bytes: ByteArray): CodecResult<ProtocolMessage.ListReq> = readBytes(bytes) {
    val path = readBoundedUtf8()
    val pageSize = readInt()
    val token = readBoundedUtf8().ifEmpty { null }
    ProtocolMessage.ListReq(path, pageSize, token)
  }

  fun encodeStatReq(msg: ProtocolMessage.StatReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.virtualPath)
  }

  fun decodeStatReq(bytes: ByteArray): CodecResult<ProtocolMessage.StatReq> = readBytes(bytes) {
    ProtocolMessage.StatReq(readBoundedUtf8())
  }

  fun encodeReadReq(msg: ProtocolMessage.ReadReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.virtualPath)
    writeLong(msg.offset)
    writeLong(msg.length)
  }

  fun decodeReadReq(bytes: ByteArray): CodecResult<ProtocolMessage.ReadReq> = readBytes(bytes) {
    ProtocolMessage.ReadReq(readBoundedUtf8(), readLong(), readLong())
  }

  fun encodeWriteReq(msg: ProtocolMessage.WriteReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.virtualPath)
    writeByte(msg.mode.ordinal)
    writeLong(msg.expectedSize)
  }

  fun decodeWriteReq(bytes: ByteArray): CodecResult<ProtocolMessage.WriteReq> = readBytes(bytes) {
    val path = readBoundedUtf8()
    val modeOrd = readByte().toInt()
    val mode = WriteMode.entries.getOrNull(modeOrd) ?: throw IllegalArgumentException("Bad WriteMode")
    val expected = readLong()
    ProtocolMessage.WriteReq(path, mode, expected)
  }

  fun encodeMkdirReq(msg: ProtocolMessage.MkdirReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.virtualPath)
  }

  fun decodeMkdirReq(bytes: ByteArray): CodecResult<ProtocolMessage.MkdirReq> = readBytes(bytes) {
    ProtocolMessage.MkdirReq(readBoundedUtf8())
  }

  fun encodeDeleteReq(msg: ProtocolMessage.DeleteReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.virtualPath)
    writeBoolean(msg.recursive)
  }

  fun decodeDeleteReq(bytes: ByteArray): CodecResult<ProtocolMessage.DeleteReq> = readBytes(bytes) {
    ProtocolMessage.DeleteReq(readBoundedUtf8(), readBoolean())
  }

  fun encodeMoveReq(msg: ProtocolMessage.MoveReq): ByteArray = buildBytes {
    writeBoundedUtf8(msg.srcVirtualPath)
    writeBoundedUtf8(msg.dstVirtualPath)
  }

  fun decodeMoveReq(bytes: ByteArray): CodecResult<ProtocolMessage.MoveReq> = readBytes(bytes) {
    ProtocolMessage.MoveReq(readBoundedUtf8(), readBoundedUtf8())
  }

  fun encodeOkStat(stat: FileStat): ByteArray = buildBytes {
    writeByte(1) // subtype = STAT
    writeBoundedUtf8(stat.name)
    writeBoolean(stat.isDirectory)
    writeLong(stat.sizeBytes)
    writeLong(stat.lastModifiedEpochMillis)
  }

  fun encodeOkList(entries: List<FileEntry>, nextPageToken: String?): ByteArray = buildBytes {
    writeByte(2) // subtype = LIST
    writeInt(entries.size)
    for (entry in entries) {
      writeBoundedUtf8(entry.name)
      writeBoolean(entry.isDirectory)
      writeLong(entry.sizeBytes)
      writeLong(entry.lastModifiedEpochMillis)
    }
    writeBoundedUtf8(nextPageToken.orEmpty())
  }

  fun encodeOkUnit(): ByteArray = buildBytes {
    writeByte(0) // subtype = UNIT
  }

  fun decodeOkPayload(bytes: ByteArray): CodecResult<ProtocolMessage> = readBytes(bytes) {
    when (val subtype = readByte().toInt()) {
      0 -> ProtocolMessage.OkUnitResp
      1 -> ProtocolMessage.OkStatResp(
        FileStat(
          name = readBoundedUtf8(),
          isDirectory = readBoolean(),
          sizeBytes = readLong(),
          lastModifiedEpochMillis = readLong(),
        )
      )
      2 -> {
        val count = readInt()
        if (count < 0 || count > 1000) throw IllegalArgumentException("Invalid list count")
        val list = ArrayList<FileEntry>(count)
        repeat(count) {
          list.add(
            FileEntry(
              name = readBoundedUtf8(),
              isDirectory = readBoolean(),
              sizeBytes = readLong(),
              lastModifiedEpochMillis = readLong(),
            )
          )
        }
        val next = readBoundedUtf8().ifEmpty { null }
        ProtocolMessage.OkListResp(list, next)
      }
      else -> throw IllegalArgumentException("Unknown OK subtype $subtype")
    }
  }

  fun encodeError(code: String, message: String): ByteArray = buildBytes {
    writeBoundedUtf8(code.take(40))
    val truncatedMsg = message.encodeToByteArray().let {
      if (it.size <= FrameCodec.MAX_ERROR_MESSAGE_BYTES) message
      else it.copyOfRange(0, FrameCodec.MAX_ERROR_MESSAGE_BYTES).decodeToString()
    }
    writeBoundedUtf8(truncatedMsg)
  }

  fun encodeStorageError(error: StorageError, message: String): ByteArray =
    encodeError(error.name, message)

  fun decodeError(bytes: ByteArray): CodecResult<ProtocolMessage.ErrorResp> = readBytes(bytes) {
    ProtocolMessage.ErrorResp(
      errorCode = readBoundedUtf8(64),
      safeMessage = readBoundedUtf8(FrameCodec.MAX_ERROR_MESSAGE_BYTES),
    )
  }

  private inline fun buildBytes(block: DataOutputStream.() -> Unit): ByteArray {
    val bos = ByteArrayOutputStream()
    DataOutputStream(bos).use { it.block() }
    return bos.toByteArray()
  }

  private inline fun <T> readBytes(bytes: ByteArray, block: DataInputStream.() -> T): CodecResult<T> {
    return try {
      DataInputStream(ByteArrayInputStream(bytes)).use {
        val decoded = it.block()
        if (it.available() != 0) {
          throw IllegalArgumentException("Trailing bytes after protocol payload")
        }
        CodecResult.Success(decoded)
      }
    } catch (e: Exception) {
      CodecResult.Malformed("BAD_REQUEST", "Malformed message payload")
    }
  }
}
