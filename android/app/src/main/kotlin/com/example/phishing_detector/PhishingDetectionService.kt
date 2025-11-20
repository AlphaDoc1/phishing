package com.example.phishing_detector

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log

class PhishingDetectionService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d("PhishingDetectionService", "Service started")
        return START_STICKY
    }

    override fun onDestroy() {
        Log.d("PhishingDetectionService", "Service stopped")
        super.onDestroy()
    }
} 