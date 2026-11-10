package com.apkguard.app

import android.app.Application

/**
 * No analytics, no trackers — nothing to initialize. The class exists so the
 * manifest can reference a concrete Application instance.
 */
class ApkGuardApplication : Application()
