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

package com.eltavine.duckdetector.features.locationrisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.features.locationrisk.domain.*
import org.junit.Assert.*
import org.junit.Test

class LocationRiskCardModelMapperTest {
    private val mapper = LocationRiskCardModelMapper()
    @Test fun `empty checks say not evaluated`() {
        assertEquals("Local contracts not evaluated", mapper.map(ready()).verdict)
    }
    @Test fun `App and SDK export share verdict and severity`() {
        val report = ready().copy(contracts = listOf(LocationContractCheck(
            LocationContract.VALUES, LocationState.OBSERVED, setOf(LocationField.LATITUDE),
        )))
        val model = mapper.map(report)
        val export = model.toDetectorReport()
        assertEquals(model.verdict, export.verdict)
        assertEquals(DetectionSeverity.WARNING, export.severity)
        assertTrue(export.blocks.filterIsInstance<ReportBlock.Rows>().flatMap { it.rows }.any { it.detail?.contains("LATITUDE") == true })
    }
    @Test fun `synthetic mock mismatch is separate from real cached mock context`() {
        val model = mapper.map(ready().copy(contracts = listOf(LocationContractCheck(LocationContract.MOCK_FLAG, LocationState.OBSERVED))))
        assertEquals("Unavailable", model.headerFacts[1].value)
        assertEquals(DetectionSeverity.WARNING, model.headerFacts[0].status.severity)
    }
    @Test fun `cached mock remains INFO and stale cache is inconclusive`() {
        val model = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.OBSERVED,
            samples = listOf(CachedLocationCheck(CachedProvider.GPS, LocationState.OBSERVED, true, CacheAge.STALE)),
        )))
        val rows = model.sections.single { it.key == "cache" }.rows
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(rows.any { it.value == "Inconclusive" })
        assertEquals("Observed", model.headerFacts[1].value)
    }
    @Test fun `denied and disabled access remain distinct`() {
        val denied = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.PERMISSION_LIMITED, failure = LocationFailure.ACCESS_DENIED)))
        val disabled = mapper.map(ready().copy(cache = CachedLocationContext(LocationState.UNAVAILABLE, failure = LocationFailure.DISABLED_BY_USER)))
        assertEquals("Permission limited", denied.headerFacts[3].value)
        assertEquals("Unavailable", disabled.headerFacts[3].value)
        assertTrue(disabled.sections.single { it.key == "cache" }.rows.first().detail!!.contains("Disabled by default"))
    }
    @Test fun `package is unverified scoped context and not activity`() {
        val model = mapper.map(ready().copy(installedPackage = LocationPackageContext(LocationState.OBSERVED, "RESTRICTED")))
        val details = model.sections.single { it.key == "package" }.rows.mapNotNull { it.detail }.joinToString()
        assertTrue(details.contains("identity unverified"))
        assertTrue(details.contains("caller user/profile"))
        assertEquals(DetectionSeverity.INFO, model.headerFacts[2].status.severity)
    }
    private fun ready() = LocationRiskReport(LocationRiskStage.READY)
}
