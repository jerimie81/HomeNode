package com.example

import android.app.Application
import com.homenode.service.node.HomeNodeFacade
import com.homenode.service.node.OAuthClientIdConfig

class HomeNodeApplication : Application() {
  lateinit var facade: HomeNodeFacade
    private set

  override fun onCreate() {
    super.onCreate()
    val oauthConfig = OAuthClientIdConfig(
      googleDriveClientId = BuildConfig.GOOGLE_DRIVE_CLIENT_ID,
      oneDriveClientId = BuildConfig.ONEDRIVE_CLIENT_ID,
      dropboxClientId = BuildConfig.DROPBOX_CLIENT_ID,
    )
    facade = HomeNodeFacade(
      storageDir = noBackupFilesDir,
      appContext = applicationContext,
      oauthClientIds = oauthConfig,
    )
  }
}
