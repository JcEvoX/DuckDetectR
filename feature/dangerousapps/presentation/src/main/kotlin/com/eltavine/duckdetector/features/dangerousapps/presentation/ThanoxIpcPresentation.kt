// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcReport
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcState
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsContextItemModel

internal fun ThanoxIpcReport.toContextItem(): DangerousAppsContextItemModel =
    DangerousAppsContextItemModel("Thanox runtime IPC", buildString {
        append(when (state) {
            ThanoxIpcState.NOT_COLLECTED -> "Not collected."
            ThanoxIpcState.NOT_OBSERVED -> "No compatible runtime service observed."
            ThanoxIpcState.MATCHED -> "Compatible runtime interface observed; manager APK installation and concealment are unconfirmed."
            ThanoxIpcState.UNAVAILABLE -> "Probe unavailable; no package presence or concealment is inferred."
            ThanoxIpcState.INCONCLUSIVE -> "Reply unrecognized; no package presence or concealment is inferred."
        })
        observedDescriptor?.let { append(" Returned interface: $it.") }
        detail?.let { append(" $it") }
    })
