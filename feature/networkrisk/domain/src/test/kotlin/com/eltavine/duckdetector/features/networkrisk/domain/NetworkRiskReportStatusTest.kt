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

package com.eltavine.duckdetector.features.networkrisk.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import org.junit.Assert.*
import org.junit.Test

class NetworkRiskReportStatusTest {
    @Test fun `VPN proxy and installed clients never raise severity`() {
        val report = NetworkRiskReport(
            NetworkRiskStage.READY,
            network = window(SampleConsistency.REPEATED),
            modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK, NetworkObservation.observed("v5.1"))),
        )
        assertEquals(DetectorStatus.info(InfoKind.SUPPORT), report.toDetectorStatus())
        assertEquals(DetectorStatus.info(InfoKind.ERROR), NetworkRiskReport.failed("failure").toDetectorStatus())
    }

    @Test fun `network change invalidates both positive and negative correlations`() {
        val sample = window(SampleConsistency.CHANGED)
        assertEquals(ObservationState.INCONCLUSIVE, sample.stateFor(ObservationState.OBSERVED))
        assertEquals(ObservationState.INCONCLUSIVE, sample.stateFor(ObservationState.NOT_OBSERVED))
        listOf(ObservationState.PERMISSION_LIMITED, ObservationState.UNAVAILABLE, ObservationState.UNSUPPORTED).forEach {
            assertEquals(it, sample.stateFor(it))
        }
    }

    @Test fun `pins require exact current signer set and catalogued package`() {
        val definition = NetworkClientCatalog.entries.first { it.releaseCertificateSha256 != null }
        val pin = requireNotNull(definition.releaseCertificateSha256)
        assertEquals(ClientIdentity.SIGNATURE_VERIFIED, definition.verifyCurrentSigners(setOf(pin)))
        assertEquals(ClientIdentity.IDENTITY_UNVERIFIED, definition.verifyCurrentSigners(setOf(pin, "other")))
        assertEquals(ClientIdentity.IDENTITY_UNVERIFIED, definition.verifyCurrentSigners(emptySet()))
        assertEquals(ClientIdentity.IDENTITY_UNVERIFIED, definition.copy(releaseCertificateSha256 = null).verifyCurrentSigners(setOf(pin)))
        assertEquals(NetworkClientCatalog.entries.size, NetworkClientCatalog.entries.map { it.packageName }.distinct().size)
    }

    private fun window(consistency: SampleConsistency) = NetworkSampleWindow(
        NetworkSnapshot(NetworkObservation.observed(1), NetworkObservation.absent(),
            NetworkObservation.observed(ProxyConfiguration(ProxyKind.PAC, -1, 0)), NetworkObservation.observed(emptyList())),
        consistency, 100, 2, 1,
    )
}
