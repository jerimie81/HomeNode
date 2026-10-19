package com.homenode.storage.cloud

/**
 * Production registry. There is deliberately NO default/in-memory fallback:
 * a provider without a configured adapter throws ProviderUnavailable.
 */
class CloudUploadRegistry(
    private val adapters: Map<CloudProvider, CloudUploadAdapter>,
    private val maxTransientRetries: Int = 2,
) {
    fun uploaderFor(provider: CloudProvider): StreamingUploader =
        StreamingUploader(
            adapter = adapters[provider] ?: throw UploadException.ProviderUnavailable(provider),
            maxTransientRetries = maxTransientRetries,
        )

    fun maxObjectBytes(provider: CloudProvider): Long = adapters[provider]?.maxObjectBytes ?: 0L

    companion object {
        fun production(http: HttpTransport, tokens: (CloudProvider) -> TokenProvider?): CloudUploadRegistry {
            val m = mutableMapOf<CloudProvider, CloudUploadAdapter>()
            tokens(CloudProvider.GOOGLE_DRIVE)?.let { m[CloudProvider.GOOGLE_DRIVE] = GoogleDriveUploadAdapter(http, it) }
            tokens(CloudProvider.ONEDRIVE)?.let { m[CloudProvider.ONEDRIVE] = OneDriveUploadAdapter(http, it) }
            tokens(CloudProvider.DROPBOX)?.let { m[CloudProvider.DROPBOX] = DropboxUploadAdapter(http, it) }
            return CloudUploadRegistry(m)
        }
    }
}
