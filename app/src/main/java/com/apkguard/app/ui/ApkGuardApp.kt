package com.apkguard.app.ui

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.apkguard.app.ui.screens.HomeScreen
import com.apkguard.app.ui.screens.InstalledAppsScreen
import com.apkguard.app.ui.screens.ResultScreen
import com.apkguard.app.ui.screens.ScanningScreen
import com.apkguard.app.ui.screens.SettingsScreen

object Routes {
    const val HOME = "home"
    const val INSTALLED = "installed"
    const val SCANNING = "scanning"
    const val RESULT = "result"
    const val SETTINGS = "settings"
}

@Composable
fun ApkGuardApp(vm: ScanViewModel = viewModel()) {
    val navController = rememberNavController()

    fun backHome() {
        navController.popBackStack(Routes.HOME, inclusive = false)
    }

    NavHost(navController = navController, startDestination = Routes.HOME) {
        composable(Routes.HOME) {
            HomeScreen(
                vm = vm,
                onScanStarted = { navController.navigate(Routes.SCANNING) },
                onOpenInstalled = { navController.navigate(Routes.INSTALLED) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.INSTALLED) {
            InstalledAppsScreen(
                vm = vm,
                onBack = { navController.popBackStack() },
                onScanStarted = { navController.navigate(Routes.SCANNING) },
            )
        }
        composable(Routes.SCANNING) {
            ScanningScreen(
                vm = vm,
                onDone = {
                    navController.navigate(Routes.RESULT) {
                        popUpTo(Routes.HOME)
                    }
                },
                onAbort = ::backHome,
            )
        }
        composable(Routes.RESULT) {
            ResultScreen(
                vm = vm,
                onScanAgain = ::backHome,
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
                vm = vm,
                onBack = { navController.popBackStack() },
            )
        }
    }
}
