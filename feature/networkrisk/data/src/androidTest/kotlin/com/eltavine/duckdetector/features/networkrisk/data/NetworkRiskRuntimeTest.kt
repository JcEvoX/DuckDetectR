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

package com.eltavine.duckdetector.features.networkrisk.data

import android.os.Build
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.features.networkrisk.data.clients.NetworkClientCollector
import com.eltavine.duckdetector.features.networkrisk.data.network.AndroidNetworkCollector
import com.eltavine.duckdetector.features.networkrisk.data.modules.Box4MagiskCollector
import com.eltavine.duckdetector.features.networkrisk.data.modules.BoxForRootCollector
import com.eltavine.duckdetector.features.networkrisk.domain.*
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Ordinary-UID smoke tests; fixture packages and proxy setting are configured outside the app. */
@RunWith(AndroidJUnit4::class)
class NetworkRiskRuntimeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val arguments = InstrumentationRegistry.getArguments()

    @Test fun frameworkQueriesRemainScopedAndUnprivileged() {
        assertTrue(Process.myUid() >= 10000)
        val window = AndroidNetworkCollector(context).collect()
        assertTrue(window.attempts in 1..2)
        assertTrue(window.durationMs >= 0)
        assertNotEquals(ObservationState.UNAVAILABLE, window.snapshot.defaultNetwork.state)
        assertEquals(ObservationState.OBSERVED, window.snapshot.visibleNetworks.state)
        when (arguments.getString("expectedProxy")) {
            "present" -> assertEquals(ObservationState.OBSERVED, window.snapshot.defaultProxy.state)
            "absent" -> assertEquals(ObservationState.NOT_OBSERVED, window.snapshot.defaultProxy.state)
        }
    }

    @Test fun installedReleaseFixturesUseExactPackageAndSigningIdentity() {
        val inventory = NetworkClientCollector(context).collect()
        assertEquals(ObservationState.OBSERVED, inventory.state)
        assertEquals(if (Build.VERSION.SDK_INT >= 30) InstalledPackageVisibility.RESTRICTED else InstalledPackageVisibility.FULL, inventory.visibility)
        arguments.getString("expectedClients").orEmpty().split(',').filter { it.isNotEmpty() }.forEach { packageName ->
            val hit = inventory.clients.single { it.packageName == packageName }
            assertEquals(packageName, ObservationState.OBSERVED, hit.state)
            assertEquals(packageName, ClientIdentity.SIGNATURE_VERIFIED, hit.identity)
        }
    }

    @Test fun cleanEmulatorMetadataIsAbsentOrPermissionLimited() {
        listOf(Box4MagiskCollector().collect(), BoxForRootCollector().collect()).forEach { evidence ->
            assertTrue(evidence.metadata.state in setOf(ObservationState.NOT_OBSERVED, ObservationState.PERMISSION_LIMITED))
        }
    }
}
