@echo off
rem Gradle 8.9 cannot run on Java 25 (the only JDKs installed system-wide),
rem so use the JBR 21 that Android Studio downloaded for this project instead.
set "JAVA_HOME=C:\Users\AdMiN\.jdks\jbr-21.0.11"
set "PATH=%JAVA_HOME%\bin;%PATH%"
cd /d "%~dp0"
rem Stop daemons previously started with the wrong JDK (Java 25).
call gradlew.bat --stop --console=plain
call gradlew.bat testDebugUnitTest --console=plain %*
