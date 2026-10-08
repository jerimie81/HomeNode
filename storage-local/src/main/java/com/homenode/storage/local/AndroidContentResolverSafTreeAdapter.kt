package com.homenode.storage.local

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageException
import com.homenode.core.storage.WriteMode
import java.io.FileInputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.UUID

/**
 * Production Android SAF [SafTreeAdapter] backed by [ContentResolver] and [DocumentsContract] (§8.5, Slice S7).
 * Designed for Samsung Galaxy S8+ (Android 9 / API 28):
 * - Resolves documents strictly via `DocumentsContract.buildChildDocumentsUriUsingTree` and
 *   `DocumentsContract.buildDocumentUriUsingTree` — NEVER concatenates raw path strings into a URI.
 * - Verifies descendant containment using `DocumentsContract.isChildDocument` (API 24+) plus documentId prefix/query
 *   containment fallback so provider bugs or symlink escapes fail closed.
 * - Checks persisted URI permissions via `ContentResolver.getPersistedUriPermissions()` and removable microSD
 *   mount state via `StorageManager.getStorageVolume(Uri)` / `Environment.getExternalStorageState()`.
 */
class AndroidContentResolverSafTreeAdapter(
  private val context: Context,
  val treeUri: Uri,
  private val isRemovableStorage: Boolean = false,
) : SafTreeAdapter {

  private val contentResolver: ContentResolver = context.contentResolver

  override val rootDocumentId: String = DocumentsContract.getTreeDocumentId(treeUri)

  override val isSimulated: Boolean = false

  override fun isMediaMounted(): Boolean {
    return try {
      val storageManager = context.getSystemService(StorageManager::class.java)
      if (storageManager != null) {
        val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootDocumentId)
        val volume = runCatching { storageManager.getStorageVolume(docUri) }.getOrNull()
        if (volume != null) {
          val state = volume.state
          return state == Environment.MEDIA_MOUNTED || state == Environment.MEDIA_MOUNTED_READ_ONLY
        }
      }
      val extState = Environment.getExternalStorageState()
      extState == Environment.MEDIA_MOUNTED || extState == Environment.MEDIA_MOUNTED_READ_ONLY
    } catch (e: Exception) {
      !isRemovableStorage
    }
  }

  override fun verifyPermissionGranted(requireWrite: Boolean): Boolean {
    val persisted = contentResolver.persistedUriPermissions
    return persisted.any { perm ->
      perm.uri == treeUri && perm.isReadPermission && (!requireWrite || perm.isWritePermission)
    }
  }

  override fun isChildDocument(parentDocumentId: String, candidateDocumentId: String): Boolean {
    if (parentDocumentId == candidateDocumentId) return true
    val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocumentId)
    val candidateUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, candidateDocumentId)
    return try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
        if (DocumentsContract.isChildDocument(contentResolver, parentUri, candidateUri)) {
          return true
        }
      }
      // Fallback containment check for providers on API 28 that only check direct children in isChildDocument:
      // confirm candidateDocumentId starts with "$parentDocumentId/" or "$parentDocumentId:" AND has no ".." segment
      if (candidateDocumentId.contains("..")) return false
      candidateDocumentId.startsWith("$parentDocumentId/") ||
        candidateDocumentId.startsWith("$parentDocumentId:")
    } catch (se: SecurityException) {
      false
    } catch (e: Exception) {
      false
    }
  }

  override fun queryChildren(parentDocumentId: String): List<SafDocumentMetadata> {
    val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocumentId)
    val results = mutableListOf<SafDocumentMetadata>()
    contentResolver.query(childrenUri, PROJECTION, null, null, null)?.use { cursor ->
      val idIdx = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
      val nameIdx = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
      val mimeIdx = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
      val sizeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
      val modIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)

      while (cursor.moveToNext()) {
        val docId = cursor.getString(idIdx) ?: continue
        val name = cursor.getString(nameIdx) ?: continue
        val mime = cursor.getString(mimeIdx) ?: ""
        val isDir = mime == DocumentsContract.Document.MIME_TYPE_DIR
        val size = if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) cursor.getLong(sizeIdx) else 0L
        val lastMod = if (modIdx >= 0 && !cursor.isNull(modIdx)) cursor.getLong(modIdx) else 0L
        results.add(
          SafDocumentMetadata(
            documentId = docId,
            displayName = name,
            isDirectory = isDir,
            sizeBytes = if (isDir) 0L else size.coerceAtLeast(0L),
            lastModifiedEpochMillis = lastMod.coerceAtLeast(0L),
          )
        )
      }
    } ?: throw StorageException(StorageError.UNAVAILABLE, "Failed to query SAF children for $parentDocumentId")
    return results
  }

  override fun statDocument(documentId: String): SafDocumentMetadata? {
    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
    contentResolver.query(docUri, PROJECTION, null, null, null)?.use { cursor ->
      if (!cursor.moveToFirst()) return null
      val idIdx = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
      val nameIdx = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
      val mimeIdx = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
      val sizeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
      val modIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)

      val docId = cursor.getString(idIdx) ?: documentId
      val name = cursor.getString(nameIdx) ?: "/"
      val mime = cursor.getString(mimeIdx) ?: ""
      val isDir = mime == DocumentsContract.Document.MIME_TYPE_DIR
      val size = if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) cursor.getLong(sizeIdx) else 0L
      val lastMod = if (modIdx >= 0 && !cursor.isNull(modIdx)) cursor.getLong(modIdx) else 0L
      return SafDocumentMetadata(
        documentId = docId,
        displayName = name,
        isDirectory = isDir,
        sizeBytes = if (isDir) 0L else size.coerceAtLeast(0L),
        lastModifiedEpochMillis = lastMod.coerceAtLeast(0L),
      )
    }
    return null
  }

  override fun readBytes(documentId: String, offset: Long, length: Int): ByteArray {
    if (length <= 0) return ByteArray(0)
    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
    contentResolver.openFileDescriptor(docUri, "r")?.use { pfd ->
      FileInputStream(pfd.fileDescriptor).use { fis ->
        val channel = fis.channel
        channel.position(offset)
        val buf = ByteBuffer.allocate(length)
        var totalRead = 0
        while (totalRead < length) {
          val n = channel.read(buf)
          if (n <= 0) break
          totalRead += n
        }
        return if (totalRead <= 0) {
          ByteArray(0)
        } else if (totalRead == length) {
          buf.array()
        } else {
          buf.array().copyOf(totalRead)
        }
      }
    } ?: throw StorageException(StorageError.NOT_FOUND, "Unable to open SAF descriptor for reading")
  }

  override fun createOrReplaceFile(
    parentDocumentId: String,
    displayName: String,
    mode: WriteMode,
    bytes: ByteArray,
  ): SafDocumentMetadata {
    val existing = queryChildren(parentDocumentId).firstOrNull { it.displayName == displayName }
    val targetDocUri: Uri = if (existing != null) {
      if (mode == WriteMode.CREATE_NEW) {
        throw StorageException(StorageError.EXISTS, "SAF file '$displayName' already exists")
      }
      if (existing.isDirectory) {
        throw StorageException(StorageError.PATH_INVALID, "Target '$displayName' is a directory")
      }
      DocumentsContract.buildDocumentUriUsingTree(treeUri, existing.documentId)
    } else {
      val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocumentId)
      DocumentsContract.createDocument(
        contentResolver,
        parentUri,
        "application/octet-stream",
        displayName
      ) ?: throw StorageException(StorageError.INTERNAL, "DocumentsContract.createDocument returned null")
    }

    contentResolver.openOutputStream(targetDocUri, "wt")?.use { out ->
      out.write(bytes)
      out.flush()
    } ?: throw StorageException(StorageError.INTERNAL, "Unable to open SAF output stream")

    val targetDocId = DocumentsContract.getDocumentId(targetDocUri)
    return statDocument(targetDocId) ?: SafDocumentMetadata(
      documentId = targetDocId,
      displayName = displayName,
      isDirectory = false,
      sizeBytes = bytes.size.toLong(),
      lastModifiedEpochMillis = System.currentTimeMillis(),
    )
  }

  override fun createTemporaryFile(parentDocumentId: String, displayName: String): SafDocumentMetadata {
    if (!verifyPermissionGranted(requireWrite = true)) throw SecurityException("Write permission not granted")
    val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocumentId)
    val createdUri = DocumentsContract.createDocument(
      contentResolver,
      parentUri,
      "application/octet-stream",
      displayName,
    ) ?: throw StorageException(StorageError.INTERNAL, "Unable to create SAF staging document")
    val id = DocumentsContract.getDocumentId(createdUri)
    return statDocument(id) ?: SafDocumentMetadata(id, displayName, false, 0L, System.currentTimeMillis())
  }

  override fun openOutputStream(documentId: String): OutputStream {
    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
    return contentResolver.openOutputStream(docUri, "w")
      ?: throw StorageException(StorageError.INTERNAL, "Unable to open SAF staging output")
  }

  override fun commitTemporaryFile(
    parentDocumentId: String,
    temporaryDocumentId: String,
    displayName: String,
    mode: WriteMode,
  ): SafDocumentMetadata {
    val temp = statDocument(temporaryDocumentId)
      ?: throw StorageException(StorageError.NOT_FOUND, "SAF staging document disappeared")
    if (!isChildDocument(parentDocumentId, temporaryDocumentId)) {
      throw StorageException(StorageError.DENIED, "SAF staging document escaped its parent")
    }
    val matches = queryChildren(parentDocumentId).filter { it.displayName == displayName }
    if (matches.size > 1) throw StorageException(StorageError.DUPLICATE_NAME, "Duplicate SAF target '$displayName'")
    val existing = matches.singleOrNull()
    if (existing?.isDirectory == true) throw StorageException(StorageError.PATH_INVALID, "Target is a directory")
    if (existing != null && mode == WriteMode.CREATE_NEW) {
      throw StorageException(StorageError.EXISTS, "SAF file '$displayName' already exists")
    }

    val tempUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, temporaryDocumentId)
    if (existing == null) {
      val renamed = DocumentsContract.renameDocument(contentResolver, tempUri, displayName)
        ?: throw StorageException(StorageError.UNSUPPORTED, "SAF provider cannot rename staged files")
      val id = DocumentsContract.getDocumentId(renamed)
      return statDocument(id) ?: temp.copy(displayName = displayName)
    }

    val existingUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, existing.documentId)
    val backupName = ".homenode-backup-${UUID.randomUUID()}"
    val backupUri = DocumentsContract.renameDocument(contentResolver, existingUri, backupName)
      ?: throw StorageException(StorageError.UNSUPPORTED, "SAF provider cannot safely replace files")
    val committedUri = try {
      DocumentsContract.renameDocument(contentResolver, tempUri, displayName)
        ?: throw StorageException(StorageError.UNSUPPORTED, "SAF provider cannot rename staged files")
    } catch (failure: Exception) {
      runCatching { DocumentsContract.renameDocument(contentResolver, backupUri, displayName) }
      throw failure
    }
    runCatching { DocumentsContract.deleteDocument(contentResolver, backupUri) }
    val id = DocumentsContract.getDocumentId(committedUri)
    return statDocument(id) ?: temp.copy(displayName = displayName)
  }

  override fun createDirectory(parentDocumentId: String, displayName: String): SafDocumentMetadata {
    val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, parentDocumentId)
    val createdUri = DocumentsContract.createDocument(
      contentResolver,
      parentUri,
      DocumentsContract.Document.MIME_TYPE_DIR,
      displayName
    ) ?: throw StorageException(StorageError.INTERNAL, "DocumentsContract.createDirectory returned null")
    val createdDocId = DocumentsContract.getDocumentId(createdUri)
    return statDocument(createdDocId) ?: SafDocumentMetadata(
      documentId = createdDocId,
      displayName = displayName,
      isDirectory = true,
      sizeBytes = 0L,
      lastModifiedEpochMillis = System.currentTimeMillis(),
    )
  }

  override fun deleteDocument(parentDocumentId: String, documentId: String, recursive: Boolean) {
    val meta = statDocument(documentId)
      ?: throw StorageException(StorageError.NOT_FOUND, "SAF document not found for delete")
    if (meta.isDirectory && !recursive) {
      val children = queryChildren(documentId)
      if (children.isNotEmpty()) {
        throw StorageException(StorageError.DENIED, "SAF directory is not empty and recursive=false")
      }
    }
    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
    val deleted = DocumentsContract.deleteDocument(contentResolver, docUri)
    if (!deleted) {
      throw StorageException(StorageError.INTERNAL, "DocumentsContract.deleteDocument returned false")
    }
  }

  override fun moveDocument(
    sourceParentDocId: String,
    targetParentDocId: String,
    documentId: String,
    newDisplayName: String,
  ): SafDocumentMetadata {
    val existingInTarget = queryChildren(targetParentDocId).firstOrNull { it.displayName == newDisplayName }
    if (existingInTarget != null) {
      throw StorageException(StorageError.EXISTS, "Destination '$newDisplayName' already exists")
    }

    var currentDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)
    if (sourceParentDocId != targetParentDocId && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      val srcParentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, sourceParentDocId)
      val dstParentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, targetParentDocId)
      currentDocUri = DocumentsContract.moveDocument(
        contentResolver,
        currentDocUri,
        srcParentUri,
        dstParentUri
      ) ?: throw StorageException(StorageError.UNSUPPORTED, "SAF provider rejected moveDocument")
    }

    val currentDocId = DocumentsContract.getDocumentId(currentDocUri)
    val currentMeta = statDocument(currentDocId)
    if (currentMeta != null && currentMeta.displayName != newDisplayName) {
      currentDocUri = DocumentsContract.renameDocument(
        contentResolver,
        currentDocUri,
        newDisplayName
      ) ?: throw StorageException(StorageError.UNSUPPORTED, "SAF provider rejected renameDocument")
    }

    val finalDocId = DocumentsContract.getDocumentId(currentDocUri)
    return statDocument(finalDocId)
      ?: throw StorageException(StorageError.INTERNAL, "Failed to stat moved SAF document")
  }

  companion object {
    private val PROJECTION = arrayOf(
      DocumentsContract.Document.COLUMN_DOCUMENT_ID,
      DocumentsContract.Document.COLUMN_DISPLAY_NAME,
      DocumentsContract.Document.COLUMN_MIME_TYPE,
      DocumentsContract.Document.COLUMN_SIZE,
      DocumentsContract.Document.COLUMN_LAST_MODIFIED,
    )
  }
}
