package com.apkguard.app.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import com.apkguard.app.domain.model.LocalizedText

/** True when the effective UI locale is Thai (in-app choice or system default). */
@Composable
fun isThaiNow(): Boolean =
    LocalConfiguration.current.locales[0]?.language == "th"

@Composable
fun LocalizedText.localized(): String = resolve(isThaiNow())
