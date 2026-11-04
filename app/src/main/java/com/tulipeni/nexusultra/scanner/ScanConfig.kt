package com.tulipeni.nexusultra.scanner
data class ScanConfig(val maxPages:Int=250,val maxResponseBytes:Int=512*1024,val maxDiscoveredLinks:Int=1000,val connectTimeoutMs:Int=6000,val readTimeoutMs:Int=8000,val activeChecksEnabled:Boolean=false) {
 init { require(maxPages in 1..250); require(maxResponseBytes in 16384..512*1024); require(maxDiscoveredLinks in 1..1000) }
}