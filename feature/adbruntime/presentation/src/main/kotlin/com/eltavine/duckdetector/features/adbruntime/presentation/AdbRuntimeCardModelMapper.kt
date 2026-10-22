/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.adbruntime.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbDaemonState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbFindingKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolResponseKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeFinding
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeReport
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeSample
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeStage
import com.eltavine.duckdetector.features.adbruntime.domain.findings
import com.eltavine.duckdetector.features.adbruntime.domain.isAdbActive
import com.eltavine.duckdetector.features.adbruntime.domain.toDetectorStatus
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeCardModel
import com.eltavine.duckdetector.features.adbruntime.presentation.model.AdbRuntimeDetailRowModel

/** Projects the domain verdict and raw source observations without re-deciding detector semantics. */
class AdbRuntimeCardModelMapper {

    fun map(report: AdbRuntimeReport): AdbRuntimeCardModel {
        val findings = report.findings()
        return AdbRuntimeCardModel(
            title = TITLE,
            subtitle = SUBTITLE,
            status = report.toDetectorStatus(),
            verdict = verdict(report, findings),
            summary = summary(report, findings),
            signalRows = findings.map(::findingRow),
            scanRows = scanRows(report),
            headerFacts = headerFacts(report),
            impactRows = impactRows(report),
            methodRows = methodRows(report),
        )
    }

    private fun verdict(report: AdbRuntimeReport, findings: List<AdbRuntimeFinding>): String =
        when (report.stage) {
            AdbRuntimeStage.LOADING -> "Scanning"
            AdbRuntimeStage.FAILED -> "Scan failed"
            AdbRuntimeStage.READY -> when {
                findings.isNotEmpty() -> "Runtime contradiction"
                report.isAdbActive() -> "ADB enabled"
                !report.probed -> "Not evaluated"
                else -> "ADB state consistent"
            }
        }

    private fun summary(report: AdbRuntimeReport, findings: List<AdbRuntimeFinding>): String =
        when (report.stage) {
            AdbRuntimeStage.LOADING -> "Correlating Android debugging settings, USB runtime, properties and wireless ADB discovery."
            AdbRuntimeStage.FAILED -> report.errorMessage ?: "The scan failed before it collected evidence."
            AdbRuntimeStage.READY -> when {
                findings.isNotEmpty() ->
                    "Independent ADB state sources disagree. The rows below show the persistent contradictions."
                report.isAdbActive() ->
                    "ADB is enabled or runtime activity was observed; no persistent hard runtime contradiction was confirmed."
                !report.probed ->
                    report.unavailableReason ?: "No ADB state source was observable from this app process."
                else ->
                    "No persistent contradiction was observed across the ADB state sources that were available."
            }
        }

    private fun findingRow(finding: AdbRuntimeFinding): AdbRuntimeDetailRowModel =
        AdbRuntimeDetailRowModel(
            label = finding.kind.label(),
            value = "Contradiction",
            status = DetectorStatus.danger(),
            detail = finding.detail(),
        )

    private fun AdbRuntimeFinding.detail(): String = when (kind) {
        AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL ->
            "The local ${endpoint.serviceKind.label()} endpoint ${endpoint.address}:${endpoint.port} " +
                "answered with the ${endpoint.responseKind.label()} in both discovery passes while " +
                "init.svc.adbd stayed stopped."
    }

    private fun scanRows(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> {
        if (report.stage != AdbRuntimeStage.READY) {
            return listOf(AdbRuntimeDetailRowModel("Scan", if (report.stage == AdbRuntimeStage.LOADING) "Pending" else "Failed",
                report.toDetectorStatus(), report.errorMessage))
        }
        val sample = report.samples.lastOrNull() ?: return listOf(
            infoRow("Probe", "Unavailable", report.unavailableReason),
            mdnsRow(report.latestMdns),
        )
        return listOf(
            infoRow("Platform API", report.platformApiLevel?.toString() ?: "Unavailable"),
            infoRow("Debugging restricted", sample.debuggingFeaturesRestricted.enabledLabel()),
            infoRow("Test harness mode", sample.properties.testHarnessMode ?: "Unavailable"),
            settingRow("USB debugging setting", sample.usbDebuggingEnabled, report, usbSetting = true),
            settingRow("Wireless debugging setting", sample.wirelessDebuggingEnabled, report),
            infoRow("init.svc.adbd", sample.properties.initAdbdState ?: "Unavailable").copy(
                status = when (sample.properties.daemonState) {
                    AdbDaemonState.RUNNING -> DetectorStatus.warning()
                    AdbDaemonState.STOPPED -> DetectorStatus.allClear()
                    AdbDaemonState.OTHER, null -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            usbRuntimeRow(sample),
            mdnsRow(report.latestMdns),
            infoRow("sys.usb.state", sample.properties.sysUsbState ?: "Unavailable").copy(
                status = observationStatus(sample.properties.usbAdbFunctionEnabled),
            ),
        )
    }

    private fun headerFacts(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> {
        if (report.stage != AdbRuntimeStage.READY) {
            val value = if (report.stage == AdbRuntimeStage.LOADING) "Pending" else "Unavailable"
            return listOf("ADB", "Contradictions", "USB", "Network").map {
                AdbRuntimeDetailRowModel(it, value, report.toDetectorStatus())
            }
        }
        val pending = "Unavailable"
        val status = report.toDetectorStatus()
        val sample = report.samples.lastOrNull()
        return listOf(
            AdbRuntimeDetailRowModel("ADB", if (report.stage == AdbRuntimeStage.READY && report.probed) {
                if (report.isAdbActive()) "Active" else "Not observed"
            } else pending, status),
            AdbRuntimeDetailRowModel("Contradictions", if (report.stage == AdbRuntimeStage.READY && report.probed) {
                report.findings().size.toString()
            } else pending, if (report.findings().isNotEmpty()) DetectorStatus.danger() else DetectorStatus.info(InfoKind.SUPPORT)),
            sample?.let(::usbRuntimeRow)?.copy(label = "USB") ?: infoRow("USB", pending),
            if (report.stage == AdbRuntimeStage.READY) mdnsRow(report.latestMdns).copy(label = "Network") else infoRow("Network", pending),
        )
    }

    private fun impactRows(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> = listOf(
        AdbRuntimeDetailRowModel("Interpretation", verdict(report, report.findings()), report.toDetectorStatus(),
            when {
                report.stage != AdbRuntimeStage.READY -> "No completed runtime conclusion is available."
                report.findings().isNotEmpty() -> "A stable, protocol-confirmed ADB endpoint disagrees with the observed adbd lifecycle. This does not identify a root or hiding implementation."
                report.isAdbActive() -> "Debugging settings or runtime activity were observed. ADB can be enabled on an ordinary device and does not establish root access."
                else -> "Only available sources were evaluated. Permission restrictions, discovery failures and lifecycle transitions limit negative observations."
            }),
    )

    private fun methodRows(report: AdbRuntimeReport): List<AdbRuntimeDetailRowModel> {
        if (report.stage != AdbRuntimeStage.READY) {
            val status = report.toDetectorStatus()
            return listOf("Settings and policy", "USB runtime", "ADB mDNS", "ADB protocol vs init").map {
                AdbRuntimeDetailRowModel(it, if (report.stage == AdbRuntimeStage.LOADING) "Pending" else "Unavailable", status)
            }
        }
        val sample = report.samples.lastOrNull()
        val protocol = report.latestMdns.protocol
        return listOf(
            infoRow("Settings and policy", if (sample == null) "Unavailable" else "Context collected",
                "Debugging restrictions and Test Harness Mode qualify settings; settings and USB gadget state are not hard contradictions against init."),
            sample?.let(::usbRuntimeRow) ?: infoRow("USB runtime", "Unavailable"),
            mdnsRow(report.latestMdns),
            AdbRuntimeDetailRowModel("ADB protocol vs init", when {
                report.findings().isNotEmpty() -> "Persistent contradiction"
                protocol.confirmed -> "No contradiction established"
                else -> "Not established"
            }, when {
                report.findings().isNotEmpty() -> DetectorStatus.danger()
                protocol.state == AdbProbeState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
                "${report.samples.size} lifecycle sample(s), ${report.mdnsSamples.size} discovery pass(es); latest protocol=${protocol.label()}. A contradiction requires the same confirmed listener in repeated passes while init reports stopped."),
        )
    }

    private fun settingRow(label: String, enabled: Boolean?, report: AdbRuntimeReport, usbSetting: Boolean = false): AdbRuntimeDetailRowModel {
        val sample = report.samples.lastOrNull()
        val qualified = sample?.debuggingFeaturesRestricted == false &&
            !(usbSetting && (report.platformApiLevel ?: 0) >= 33 && sample.properties.testHarnessEnabled)
        return infoRow(label, enabled.enabledLabel()).copy(
            status = if (qualified) observationStatus(enabled) else DetectorStatus.info(InfoKind.SUPPORT),
            detail = if (qualified) null else "Settings are context only while policy or Test Harness Mode prevents an ordinary activity interpretation.",
        )
    }

    private fun observationStatus(active: Boolean?): DetectorStatus = when (active) {
        true -> DetectorStatus.warning()
        false -> DetectorStatus.allClear()
        null -> DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun probeStatus(state: AdbProbeState, active: Boolean): DetectorStatus = when (state) {
        AdbProbeState.OBSERVED, AdbProbeState.NOT_OBSERVED -> observationStatus(active)
        AdbProbeState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
        AdbProbeState.PERMISSION_REQUIRED, AdbProbeState.NOT_PROBED -> DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun usbRuntimeRow(sample: AdbRuntimeSample): AdbRuntimeDetailRowModel {
        val usb = sample.usb
        val value = when (usb.state) {
            AdbProbeState.OBSERVED, AdbProbeState.NOT_OBSERVED ->
                usb.functions.takeIf(Set<String>::isNotEmpty)?.joinToString(",") ?: "No functions"
            AdbProbeState.PERMISSION_REQUIRED -> "Permission required"
            AdbProbeState.NOT_PROBED -> "Not probed"
            AdbProbeState.UNAVAILABLE -> "Unavailable"
        }
        return infoRow(
            label = "USB runtime",
            value = value,
            detail = "connected=${usb.connected ?: "?"}, configured=${usb.configured ?: "?"}" +
                usb.detail?.let { ", $it" }.orEmpty(),
        ).copy(status = probeStatus(usb.state, usb.adbFunctionEnabled))
    }

    private fun mdnsRow(mdns: AdbMdnsSnapshot): AdbRuntimeDetailRowModel {
        val value = when (mdns.state) {
            AdbProbeState.OBSERVED -> when (mdns.serviceKind) {
                AdbMdnsServiceKind.TLS_CONNECT -> "Local Wireless ADB TLS service"
                AdbMdnsServiceKind.LEGACY_TCP -> "Local legacy ADB TCP service"
                null -> "Local ADB service"
            }
            AdbProbeState.NOT_OBSERVED -> "Not observed"
            AdbProbeState.PERMISSION_REQUIRED -> "Permission required"
            AdbProbeState.NOT_PROBED -> "Not probed"
            AdbProbeState.UNAVAILABLE -> "Unavailable"
        }
        val detail = buildList {
            if (mdns.address != null && mdns.port != null) {
                add("${mdns.address}:${mdns.port}; protocol=${mdns.protocol.label()}")
            }
            if (mdns.state == AdbProbeState.PERMISSION_REQUIRED) {
                add("Android 17 allows silent NsdManager discovery only with the local network permission. " +
                    "Duck Detector never asks for it during a scan; grant it in the app's system settings " +
                    "to evaluate network ADB.")
            }
            mdns.detail?.takeIf { it.isNotBlank() }?.let(::add)
            mdns.protocol.detail?.takeIf { it.isNotBlank() }?.let { add("Protocol: $it") }
        }.distinct().joinToString("\n").ifBlank { null }
        val status = if (mdns.state == AdbProbeState.OBSERVED && !mdns.localServiceObserved) {
            DetectorStatus.info(InfoKind.SUPPORT)
        } else {
            probeStatus(mdns.state, mdns.localServiceObserved)
        }
        return infoRow("ADB mDNS", value, detail).copy(status = status)
    }

    private fun infoRow(label: String, value: String, detail: String? = null) =
        AdbRuntimeDetailRowModel(
            label = label,
            value = value,
            status = DetectorStatus.info(InfoKind.SUPPORT),
            detail = detail,
        )

    private fun AdbFindingKind.label(): String = when (this) {
        AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL -> "ADB protocol vs init"
    }

    private fun AdbMdnsServiceKind.label(): String = when (this) {
        AdbMdnsServiceKind.LEGACY_TCP -> "legacy ADB"
        AdbMdnsServiceKind.TLS_CONNECT -> "Wireless debugging secure-connect"
    }

    private fun AdbProtocolResponseKind.label(): String = when (this) {
        AdbProtocolResponseKind.AUTH_TOKEN -> "ADB AUTH token"
        AdbProtocolResponseKind.CONNECT -> "ADB CNXN banner"
        AdbProtocolResponseKind.START_TLS -> "ADB STLS request"
    }

    private fun AdbProtocolSnapshot.label(): String =
        responseKind?.takeIf { confirmed }?.label() ?: when (state) {
            AdbProbeState.OBSERVED -> "confirmed"
            AdbProbeState.NOT_OBSERVED -> "not confirmed"
            AdbProbeState.UNAVAILABLE -> "unavailable"
            AdbProbeState.PERMISSION_REQUIRED -> "permission required"
            AdbProbeState.NOT_PROBED -> "not probed"
        }

    private fun Boolean?.enabledLabel(): String = when (this) {
        true -> "Enabled"
        false -> "Disabled"
        null -> "Unavailable"
    }

    private companion object {
        const val TITLE = "ADB Runtime"
        const val SUBTITLE = "Cross-check debugging state across independent Android subsystems"
    }
}
