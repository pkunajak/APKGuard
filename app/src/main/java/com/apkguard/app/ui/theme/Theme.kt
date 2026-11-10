package com.apkguard.app.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import com.apkguard.app.domain.model.Verdict

private val LightColors = lightColorScheme(
    primary = Color(0xFF1B6E4A),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFA9F2C7),
    onPrimaryContainer = Color(0xFF002112),
    secondary = Color(0xFF4C6357),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCEE9D9),
    onSecondaryContainer = Color(0xFF092017),
    tertiary = Color(0xFF3D6373),
    error = Color(0xFFBA1A1A),
    onError = Color.White,
    background = Color(0xFFFBFDF9),
    onBackground = Color(0xFF191C1A),
    surface = Color(0xFFFBFDF9),
    onSurface = Color(0xFF191C1A),
    surfaceVariant = Color(0xFFDCE5DC),
    onSurfaceVariant = Color(0xFF404944),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF8DD6AC),
    onPrimary = Color(0xFF003824),
    primaryContainer = Color(0xFF005236),
    onPrimaryContainer = Color(0xFFA9F2C7),
    secondary = Color(0xFFB3CCBC),
    onSecondary = Color(0xFF1F352B),
    secondaryContainer = Color(0xFF354B41),
    onSecondaryContainer = Color(0xFFCEE9D9),
    tertiary = Color(0xFFA1CADA),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    background = Color(0xFF191C1A),
    onBackground = Color(0xFFE1E3DF),
    surface = Color(0xFF191C1A),
    onSurface = Color(0xFFE1E3DF),
    surfaceVariant = Color(0xFF404944),
    onSurfaceVariant = Color(0xFFBFC9C0),
)

@Composable
fun ApkGuardTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S,
    content: @Composable () -> Unit,
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    MaterialTheme(colorScheme = colorScheme, content = content)
}

/** Fixed semantic colors for verdicts — must stay readable in both themes. */
val Verdict.color: Color
    get() = when (this) {
        Verdict.SAFE -> Color(0xFF2E7D32)
        Verdict.SUSPICIOUS -> Color(0xFFEF6C00)
        Verdict.DANGEROUS -> Color(0xFFC62828)
    }
