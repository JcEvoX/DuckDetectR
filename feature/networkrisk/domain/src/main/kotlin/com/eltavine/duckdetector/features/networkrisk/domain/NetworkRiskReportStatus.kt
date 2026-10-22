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

/** VPNs, proxy configuration and installed software are context, with no adverse verdict. */
fun ObservationState.toDetectorStatus(failure: ProbeFailure? = null): DetectorStatus = DetectorStatus.info(
    if (failure.isProbeError()) InfoKind.ERROR else InfoKind.SUPPORT,
)

fun NetworkRiskReport.toDetectorStatus(): DetectorStatus = when {
    stage == NetworkRiskStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
    stage == NetworkRiskStage.READY && hasProbeErrors() -> DetectorStatus.info(InfoKind.ERROR)
    else -> DetectorStatus.info(InfoKind.SUPPORT)
}

/** Collectors retain failures as values, so READY describes completion, not successful coverage. */
fun NetworkRiskReport.hasProbeErrors(): Boolean =
    network?.snapshot?.hasProbeErrors() == true || clients?.state == ObservationState.UNAVAILABLE ||
        clients?.clients.orEmpty().any { it.signingFailure.isProbeError() } ||
        modules.any { it.metadata.failure.isProbeError() }

private fun NetworkSnapshot.hasProbeErrors(): Boolean =
    listOf(defaultNetwork, boundNetwork, defaultProxy, visibleNetworks).any { it.failure.isProbeError() } ||
        proxySources?.jvmHttpProxy?.failure.isProbeError() || visibleNetworks.value.orEmpty().any {
            it.transports.failure.isProbeError() || it.link.failure.isProbeError()
        }

private fun ProbeFailure?.isProbeError(): Boolean = when (this) {
    ProbeFailure.PLATFORM_FAILURE, ProbeFailure.READ_LIMIT, ProbeFailure.INVALID_METADATA,
    ProbeFailure.DISAPPEARED -> true
    ProbeFailure.ACCESS_DENIED, ProbeFailure.NOT_EVALUATED, null -> false
}

/** A changing sample cannot support correlations, including an assertion of absence. */
fun NetworkSampleWindow.stateFor(state: ObservationState): ObservationState = when {
    consistency == SampleConsistency.CHANGED &&
        state in setOf(ObservationState.OBSERVED, ObservationState.NOT_OBSERVED) -> ObservationState.INCONCLUSIVE
    else -> state
}
