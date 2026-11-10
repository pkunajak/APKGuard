# APK Guard — ตรวจก่อนติดตั้ง 🔐

แอป Android สำหรับตรวจสอบความปลอดภัยของไฟล์ APK และแอปที่ติดตั้งแล้ว ออกแบบมาเพื่อ **ผู้ใช้ทั่วไป** — แสดงผลแบบง่าย (ปลอดภัย / น่าสงสัย / อันตราย) พร้อมคำอธิบายภาษาชาวบ้าน และกดดูรายละเอียดเชิงเทคนิคได้เมื่อต้องการ

An Android app that checks APK files and installed apps for security risks, built for everyday users: a clear verdict (SAFE / SUSPICIOUS / DANGEROUS) with plain-language explanations, plus full technical details on demand.

---

## ✨ ฟีเจอร์ / Features

- **สแกนไฟล์ APK** ที่เลือกจากเครื่อง (ผ่าน file picker ของระบบ — แอปไม่ขอสิทธิ์พื้นที่จัดเก็บ)
  Scan any `.apk` file via the system file picker (no storage permission needed).
- **ตรวจแอปที่ติดตั้งแล้ว** พร้อมบอกว่าติดตั้งจาก Play Store หรือ sideload
  Audit installed apps, including their install source.
- **วิเคราะห์บนเครื่อง (ออฟไลน์ 100%)**: สิทธิ์ที่เสี่ยง, ชุดสิทธิ์แบบ spyware/dropper, ลายเซ็น v1/v2/v3, debug certificate, ใบรับรองหมดอายุ, target SDK โบราณ, บริการ Accessibility/Notification-listener, สตริงที่น่าสงสัย (URL / IP เปล่า ๆ / คีย์เวิร์ด root / DexClassLoader)
  Fully offline static analysis: risky permissions, spyware/dropper permission combos, v1/v2/v3 signature schemes, debug certificates, expired certs, ancient targetSdk, accessibility & notification-listener services, and suspicious embedded strings.
- **คะแนนความเสี่ยง 0–100** → ปลอดภัย (0–29) / น่าสงสัย (30–69) / อันตราย (70+)
  0–100 risk score → SAFE / SUSPICIOUS / DANGEROUS.
- **VirusTotal (โหมดเสริม ปิดไว้โดยดีฟอลต์)**: ใช้ API key ฟรีของผู้ใช้เอง — ค้นหาด้วย hash ก่อนเสมอ อัปโหลดไฟล์จริงเฉพาะเมื่อผู้ใช้กดยืนยัน และคุมโควตา 4 คำขอ/นาทีให้อัตโนมัติ
  Optional VirusTotal (off by default, your own free API key): hash lookup first, file upload only with explicit consent, automatic 4-req/min throttling.
- **แชร์รายงาน** เป็นข้อความหรือการ์ดรูปภาพ / Share the report as text or an image card.
- **สองภาษา** ไทย/อังกฤษ สลับได้ในแอป / Thai + English with in-app switch.
- **ไม่เก็บประวัติ ไม่มีโฆษณา ไม่มี tracker** — ผลการตรวจอยู่ในหน่วยความจำเท่านั้น
  No scan history, no ads, no trackers — results live in memory only.

## 🛠 สิ่งที่ต้องมี / Requirements

- Android Studio (Koala หรือใหม่กว่า) ที่มี AGP 8.5 รองรับ
- JDK 17+ (Android Studio มีให้อยู่แล้ว)
- อุปกรณ์/อีมูเลเตอร์ Android 8.0 (API 26) ขึ้นไป

## 🚀 วิธี build / Building

```bash
# เปิดโฟลเดอร์ ApkGuard ใน Android Studio แล้วกด Run
# หรือ build ด้วยคำสั่ง:
gradlew.bat assembleDebug        # Windows
./gradlew assembleDebug          # macOS/Linux
```

ไฟล์ APK ที่ build เสร็จอยู่ที่ `app/build/outputs/apk/debug/app-debug.apk`

> หาก Gradle wrapper ยังไม่ถูกดาวน์โหลดมาพร้อมโปรเจกต์ ให้เปิดใน Android Studio (จะจัดการให้อัตโนมัติ) หรือรัน `gradle wrapper --gradle-version 8.9` ครั้งเดียว

## 🧪 รันทดสอบ / Tests

```bash
gradlew.bat testDebugUnitTest
```

ครอบคลุม: เครื่องยนต์ให้คะแนน, แค็ตตาล็อกความเสี่ยงของสิทธิ์, กฎการวิเคราะห์, ตัวสแกนสตริง, และการ parse ผลตอบกลับ VirusTotal

## 🔑 การใช้ VirusTotal

1. สมัครบัญชีฟรีที่ [virustotal.com](https://www.virustotal.com)
2. ไปที่โปรไฟล์ → คัดลอก **API key**
3. ในแอป: การตั้งค่า → วาง key → บันทึก
4. หน้าผลการตรวจจะมีปุ่ม “ตรวจกับ VirusTotal”

บัญชีฟรี: 4 คำขอ/นาที, อัปโหลดไฟล์ได้สูงสุด 32MB — แอปจัดการทั้งสองข้อให้แล้ว

## 📱 สิทธิ์ที่แอปนี้ขอ / App permissions

| สิทธิ์ | เหตุผล |
|---|---|
| `INTERNET` | ใช้เฉพาะเมื่อผู้ใช้กดตรวจกับ VirusTotal เท่านั้น |
| `QUERY_ALL_PACKAGES` | ดึงรายการแอปที่ติดตั้งแล้วเพื่อตรวจสอบ |

> ⚠️ Google Play จำกัดการใช้ `QUERY_ALL_PACKAGES` — แอปนี้ออกแบบมาเพื่อแจกจ่ายแบบ sideload / FOSS (จุดยืนเดิมตามข้อกำหนดโปรเจกต์) หากต้องการขึ้น Play Store ต้องถอดสิทธิ์นี้และใช้ `<queries>` เจาะจงแทน

## ⚠️ ข้อจำกัด / Limitations (v1)

- ไม่รองรับ `.xapk` / split APK (แจ้งผู้ใช้แบบเป็นมิตเมื่อเลือกไฟล์)
- การตรวจ exported components / debuggable ของ *ไฟล์* APK ทำได้จำกัด (ทำได้เต็มรูปแบบกับแอปที่ติดตั้งแล้วผ่าน ApplicationInfo)
- การสแกนสตริงเป็น heuristic — อ่านไฟล์ dex/assets แบบจำกัด 24MB เพื่อกันไฟล์ก่อกวน ผลบวกปลอมเป็นไปได้ จึงกำหนดความรุนแรงไว้ต่ำ
- อ่านไฟล์ APK ของแอปที่ติดตั้งแล้วไม่ได้ในบางเครื่อง → ระบบจะ fallback ไปวิเคราะห์จาก metadata ของระบบอย่างอัตโนมัติ
- VirusTotal อัปโหลดต่อครั้งต้องรอ poll ~15–60 วินาที หากเกินเวลาจะแจ้งให้กดตรวจใหม่ภายหลัง (แอปใช้ hash เดิมดึงผลกลับมา)

## 🏗 โครงสร้าง / Architecture

```
app/src/main/java/com/apkguard/app/
├── domain/          # Kotlin ล้วน ทดสอบได้ ไม่พึ่ง Android
│   ├── model/       # ScanReport, Finding, Verdict, ...
│   └── scanner/     # PermissionRiskCatalog, ScoringEngine, ApkStaticAnalyzer, StringsAnalyzer
├── data/
│   ├── apk/         # ApkFileParser (apk-parser), ApkSigningBlockReader (v2/v3)
│   ├── installed/   # InstalledAppProvider (PackageManager)
│   ├── vt/          # VirusTotal Retrofit client + DTOs
│   ├── settings/    # DataStore (เก็บแค่ API key เท่านั้น)
│   └── share/       # รายงานข้อความ + การ์ดรูปภาพ
└── ui/              # Jetpack Compose (Material 3) + MVVM
```

**เทคโนโลยี**: Kotlin 2.0, Jetpack Compose (Material 3), MVVM + StateFlow, Retrofit + kotlinx.serialization, DataStore, minSdk 26 / targetSdk 35

**เหตุผลที่เลือกไลบรารี**: `apk-parser` สำหรับอ่าน manifest ของไฟล์ APK เฉพาะทาง (PackageManager อ่านไฟล์อิสระไม่ได้), ตัวตรวจ signing scheme v2/v3 เขียนเองเพื่อไม่พึ่งไลบรารีเพิ่ม, ส่วน certificate ใช้ `java.security` มาตรฐาน

## 🔒 ความเป็นส่วนตัว / Privacy

- การวิเคราะห์ทั้งหมดทำงานบนเครื่อง
- ไม่มีการเก็บประวัติ/ฐานข้อมูล, ไม่มี analytics/โฆษณา/tracker
- ข้อมูลออกจากเครื่องเฉพาะเมื่อผู้ใช้กด “ตรวจกับ VirusTotal” — โดยส่ง hash ก่อนเสมอ และอัปโหลดไฟล์เมื่อผู้ใช้ยืนยันเท่านั้น

---

Made with APK Guard — ตรวจก่อนติดตั้ง
