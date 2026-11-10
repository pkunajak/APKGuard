package com.apkguard.app

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.compose.setContent
import com.apkguard.app.ui.ApkGuardApp
import com.apkguard.app.ui.theme.ApkGuardTheme

/**
 * AppCompatActivity (not ComponentActivity) is required for per-app locale
 * switching via AppCompatDelegate.setApplicationLocales.
 */
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ApkGuardTheme {
                ApkGuardApp()
            }
        }
    }
}
