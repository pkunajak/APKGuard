package com.apkguard.app.data.apk

import java.io.File
import java.io.RandomAccessFile

/**
 * Reads the APK Signing Block (the region right before the ZIP central directory)
 * to detect v2/v3 signature schemes. Implemented on raw bytes so we do not depend
 * on any external signing library.
 */
object ApkSigningBlockReader {

    private val MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
    private const val V2_BLOCK_ID = 0x7109871aL
    private const val V3_BLOCK_ID = 0xf05368c0L

    data class Schemes(val hasV2: Boolean, val hasV3: Boolean)

    fun read(file: File): Schemes = try {
        RandomAccessFile(file, "r").use { raf -> read(raf) }
    } catch (_: Exception) {
        Schemes(hasV2 = false, hasV3 = false)
    }

    private fun read(raf: RandomAccessFile): Schemes {
        val length = raf.length()
        if (length < 22L) return Schemes(false, false)

        // 1) Locate the End Of Central Directory record by scanning backwards.
        val searchLen = minOf(length, 65557L).toInt()
        raf.seek(length - searchLen)
        val tail = ByteArray(searchLen)
        raf.readFully(tail)

        var eocdIdx = -1
        var i = tail.size - 22
        while (i >= 0) {
            if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4b.toByte() &&
                tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()
            ) {
                eocdIdx = i
                break
            }
            i--
        }
        if (eocdIdx < 0) return Schemes(false, false)

        val cdOffset = readU32Le(tail, eocdIdx + 16).toInt()
        if (cdOffset <= 24 || cdOffset > length) return Schemes(false, false)

        // 2) The signing block footer sits immediately before the central directory:
        //    [block size u64][magic "APK Sig Block 42" (16 bytes)] ending at cdOffset.
        raf.seek(cdOffset - 24L)
        val footer = ByteArray(24)
        raf.readFully(footer)
        val blockSize = readU64Le(footer, 0)
        val magicOk = (0 until 16).all { footer[8 + it] == MAGIC[it] }
        if (!magicOk || blockSize <= 0 || blockSize > cdOffset) return Schemes(false, false)

        // 3) Walk the ID-value pairs from the block start (skip leading size field).
        var pos = cdOffset - 24L - blockSize + 8L
        val end = cdOffset - 24L
        var hasV2 = false
        var hasV3 = false
        val header = ByteArray(12)
        while (pos + 12 <= end) {
            raf.seek(pos)
            raf.readFully(header)
            val pairLen = readU64Le(header, 0)
            if (pairLen <= 0 || pos + 8L + pairLen > end) break
            val id = ((header[8].toLong() and 0xff) shl 24) or
                ((header[9].toLong() and 0xff) shl 16) or
                ((header[10].toLong() and 0xff) shl 8) or
                (header[11].toLong() and 0xff)
            if (id == V2_BLOCK_ID) hasV2 = true
            if (id == V3_BLOCK_ID) hasV3 = true
            pos += 8L + pairLen
        }
        return Schemes(hasV2, hasV3)
    }

    private fun readU32Le(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = v or ((b[off + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    private fun readU64Le(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[off + i].toLong() and 0xff) shl (8 * i))
        return v
    }
}
