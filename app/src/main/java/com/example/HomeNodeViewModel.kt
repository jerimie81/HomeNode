package com.example

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.homenode.service.node.HomeNodeFacade
import com.homenode.service.node.HomeNodeUiState
import com.homenode.service.node.OAuthClientIdConfig
import kotlinx.coroutines.flow.StateFlow

class HomeNodeViewModel(application: Application) : AndroidViewModel(application) {
  val facade: HomeNodeFacade =
    (application as? HomeNodeApplication)?.facade ?: HomeNodeFacade(
      storageDir = application.noBackupFilesDir,
      appContext = application.applicationContext,
      oauthClientIds = OAuthClientIdConfig(
        googleDriveClientId = BuildConfig.GOOGLE_DRIVE_CLIENT_ID,
        oneDriveClientId = BuildConfig.ONEDRIVE_CLIENT_ID,
        dropboxClientId = BuildConfig.DROPBOX_CLIENT_ID,
      ),
    )

  val uiState: StateFlow<HomeNodeUiState> = facade.uiState
}
