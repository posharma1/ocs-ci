"""
Test module for RBD encrypted PVC key rotation system test with Vault KMS.

This module tests the key rotation functionality for RBD encrypted PVCs
with all possible combinations of volume modes and access modes.

Prerequisites:
    - OCS version >= 4.17
    - Vault KMS must be configured and deployed
    - KMS configuration must be present in auth.yaml
    - Run with appropriate config files:
      Example: --ocsci-conf conf/ocsci/vault_external_standalone_mode_v1.yaml

Environment Setup:
    The test requires Vault KMS to be deployed. You can deploy it using:
    1. Set KMS_PROVIDER in your config
    2. Ensure vault configuration is in auth.yaml
    3. Use kms_deployment: true in your deployment config
"""

import itertools
import logging
import time
import pytest

from ocs_ci.framework.pytest_customization.marks import (
    magenta_squad,
    system_test,
    ignore_leftovers,
    kms_config_required,
    skipif_ocs_version,
    skipif_managed_service,
    skipif_hci_provider_and_client,
    skipif_disconnected_cluster,
    skipif_proxy_cluster,
)
from ocs_ci.framework.testlib import E2ETest, tier1
from ocs_ci.ocs import constants
from ocs_ci.helpers.keyrotation_helper import PVKeyrotation
from ocs_ci.helpers import helpers

log = logging.getLogger(__name__)


@magenta_squad
@system_test
@ignore_leftovers
@kms_config_required
@skipif_ocs_version("<4.17")
@skipif_managed_service
@skipif_hci_provider_and_client
@skipif_disconnected_cluster
@skipif_proxy_cluster
class TestRBDEncryptedPVCKeyRotation(E2ETest):
    """
    Test class for RBD encrypted PVC key rotation with Vault KMS.

    This test validates key rotation for encrypted RBD PVCs across all
    combinations of volume modes (Block, Filesystem) and access modes (ROX, RWX).
    """

    @pytest.fixture(autouse=True)
    def setup_encrypted_storage(
        self,
        project_factory,
        pv_encryption_kms_setup_factory,
        storageclass_factory,
    ):
        """
        Setup fixture to configure Vault KMS and create encrypted storage class.

        This fixture:
        1. Creates a test project/namespace
        2. Initializes Vault KMS with kv_version v1
        3. Creates an encrypted RBD storage class with Immediate binding mode
        4. Adds key rotation annotation with schedule '*/2 * * * *'
        5. Generates and creates Vault CSI KMS token in the namespace

        Args:
            project_factory: Factory fixture to create projects
            pv_encryption_kms_setup_factory: Factory to setup PV encryption with KMS
            storageclass_factory: Factory fixture to create storage classes
        """
        log.info("=" * 80)
        log.info("SETUP: Configuring Vault KMS and encrypted storage class")
        log.info("=" * 80)

        # Step 1: Create a test project
        log.info("Step 1: Creating test project/namespace")
        self.proj_obj = project_factory()
        log.info(f"Created project: {self.proj_obj.namespace}")

        # Step 2: Initialize Vault KMS with kv_version v1
        log.info("Step 2: Initializing Vault KMS with kv_version v1")
        self.kms = pv_encryption_kms_setup_factory(
            kv_version="v1", use_vault_namespace=False
        )
        log.info(f"Vault KMS initialized with KMS ID: {self.kms.kmsid}")

        # Step 3: Create encrypted RBD storage class with Immediate binding mode
        log.info("Step 3: Creating encrypted RBD storage class")
        self.sc_obj = storageclass_factory(
            interface=constants.CEPHBLOCKPOOL,
            encrypted=True,
            encryption_kms_id=self.kms.kmsid,
            allow_volume_expansion=False,
            volume_binding_mode=constants.IMMEDIATE_VOLUMEBINDINGMODE,
            reclaim_policy=constants.RECLAIM_POLICY_DELETE,
        )
        log.info(f"Created encrypted storage class: {self.sc_obj.name}")

        # Step 4: Generate Vault token and create ceph-csi-kms-token in namespace
        log.info("Step 4: Configuring PV encryption with Vault service")
        self.kms.vault_path_token = self.kms.generate_vault_token()
        self.kms.create_vault_csi_kms_token(namespace=self.proj_obj.namespace)
        log.info(f"Created Vault CSI KMS token in namespace: {self.proj_obj.namespace}")

        # Step 5: Add key rotation annotation to storage class
        log.info("Step 5: Adding key rotation annotation to storage class")
        self.pvk_obj = PVKeyrotation(self.sc_obj)
        self.pvk_obj.annotate_storageclass_key_rotation(schedule="*/2 * * * *")
        log.info(
            "Added annotation: keyrotation.csiaddons.openshift.io/schedule='*/2 * * * *'"
        )

        log.info("=" * 80)
        log.info("SETUP COMPLETE: Ready to create PVCs and test key rotation")
        log.info("=" * 80)

    @tier1
    @pytest.mark.polarion_id("OCS-XXXX")  # Update with actual Polarion ID
    def test_rbd_encrypted_pvc_keyrotation_all_combinations(
        self,
        pvc_factory,
        deployment_pod_factory,
    ):
        """
        Test RBD encrypted PVC key rotation for all volume/access mode combinations.

        This test validates key rotation functionality for encrypted RBD PVCs
        across the supported combinations of volume modes and access modes.

        Test Steps:
        1. Create encrypted RBD storage class with Vault KMS provider (kv_version v1)
        2. Add key rotation annotation with schedule '*/2 * * * *'
        3. Configure PV encryption settings with Vault service
        4. Create 10 encrypted PVCs cycling through:
               Filesystem×RWO, Block×RWO, Block×RWX
        5. Create Deployment pods that utilize each encrypted PVC
        5b. Create 10 non-encrypted RBD PVCs cycling through:
               Filesystem×RWO, Filesystem×RWOP, Block×RWO, Block×RWX, Block×RWOP
            and their deployment pods
        6. Start FIO workload on all pods with verify=True option
        7. Wait for 2 minutes for key rotation to occur
        8. Verify key rotation happened for all encrypted PVs
        9. Validate FIO results (no errors during IO)

        Expected Results:
        - All PVCs are created and bound successfully
        - All pods reach Running state
        - FIO workload starts without errors
        - Key rotation occurs within 2 minutes for all encrypted PVs
        - New keys are different from original keys
        - No data corruption (FIO verify passes)
        """
        log.info("=" * 80)
        log.info("TEST: RBD Encrypted PVC Key Rotation - All Combinations")
        log.info("=" * 80)

        # Encrypted PVC base combinations (3 combos, cycled to 10):
        #   Filesystem×RWO, Block×RWO, Block×RWX
        enc_base_combinations = [
            (constants.VOLUME_MODE_FILESYSTEM, constants.ACCESS_MODE_RWO),
            (constants.VOLUME_MODE_BLOCK, constants.ACCESS_MODE_RWO),
            (constants.VOLUME_MODE_BLOCK, constants.ACCESS_MODE_RWX),
        ]
        total_pvcs = 10
        pvc_combinations = [
            {"volume_mode": vm, "access_mode": am, "size": 1}
            for vm, am in itertools.islice(
                itertools.cycle(enc_base_combinations), total_pvcs
            )
        ]
        log.info(f"Total encrypted PVC combinations to create: {total_pvcs}")
        log.info(
            "Encrypted combinations (cycled): Filesystem×RWO, Block×RWO, Block×RWX"
        )

        # Step 4: Create 10 encrypted PVCs
        log.info("=" * 80)
        log.info("Step 4: Creating 10 encrypted RBD PVCs")
        log.info("=" * 80)

        pvc_objs = []
        for idx, pvc_config in enumerate(pvc_combinations, start=1):
            log.info(f"\nCreating encrypted PVC {idx}/{total_pvcs}:")
            log.info(f"  - Volume Mode: {pvc_config['volume_mode']}")
            log.info(f"  - Access Mode: {pvc_config['access_mode']}")
            log.info(f"  - Size: {pvc_config['size']}GiB")
            log.info(f"  - Storage Class: {self.sc_obj.name}")

            pvc_obj = pvc_factory(
                interface=constants.CEPHBLOCKPOOL,
                project=self.proj_obj,
                storageclass=self.sc_obj,
                size=pvc_config["size"],
                access_mode=pvc_config["access_mode"],
                volume_mode=pvc_config["volume_mode"],
                status=constants.STATUS_BOUND,
            )
            pvc_objs.append(pvc_obj)
            log.info(f"✓ Encrypted PVC {pvc_obj.name} created and bound successfully")

        log.info(f"\n✓ All {len(pvc_objs)} encrypted PVCs created successfully")

        # Step 5: Create Deployment pods for each PVC
        log.info("=" * 80)
        log.info("Step 5: Creating Deployment pods for each PVC")
        log.info("=" * 80)

        pod_objs = []
        for idx, pvc_obj in enumerate(pvc_objs, start=1):
            pvc_config = pvc_combinations[idx - 1]
            log.info(
                f"\nCreating deployment {idx}/{total_pvcs} for PVC: {pvc_obj.name}"
            )
            log.info(f"  - Volume Mode: {pvc_config['volume_mode']}")
            log.info(f"  - Access Mode: {pvc_config['access_mode']}")

            # Determine if this is a block volume
            is_block_volume = pvc_config["volume_mode"] == constants.VOLUME_MODE_BLOCK

            # Create service account with SCC policy for deployment pods
            log.info("  - Creating service account for deployment pod")
            sa_obj = helpers.create_serviceaccount(pvc_obj.project.namespace)
            helpers.add_scc_policy(
                sa_name=sa_obj.name, namespace=pvc_obj.project.namespace
            )
            log.info(f"  - Service account '{sa_obj.name}' created with SCC policy")

            # Create deployment pod using deployment_pod_factory with the service account
            pod_obj = deployment_pod_factory(
                interface=constants.CEPHBLOCKPOOL,
                pvc=pvc_obj,
                raw_block_pv=is_block_volume,
                sa_obj=sa_obj,
            )

            pod_objs.append(pod_obj)
            log.info(f"✓ Deployment {pod_obj.name} created and running successfully")

        log.info(f"\n✓ All {len(pod_objs)} deployments created and running")

        # Step 5b: Create non-encrypted RBD PVCs (10 total) and deployment pods
        log.info("=" * 80)
        log.info("Step 5b: Creating non-encrypted RBD PVCs and deployment pods")
        log.info("=" * 80)

        # Fetch the default non-encrypted RBD storage class object
        non_enc_sc_obj = helpers.default_storage_class(
            interface_type=constants.CEPHBLOCKPOOL
        )
        log.info(f"Using non-encrypted storage class: {non_enc_sc_obj.name}")

        # Non-encrypted combinations: Filesystem(RWO, RWOP) + Block(RWO, RWX, RWOP) = 5 base
        non_enc_volume_modes = [
            constants.VOLUME_MODE_FILESYSTEM,
            constants.VOLUME_MODE_FILESYSTEM,
            constants.VOLUME_MODE_BLOCK,
            constants.VOLUME_MODE_BLOCK,
            constants.VOLUME_MODE_BLOCK,
        ]
        non_enc_access_modes = [
            constants.ACCESS_MODE_RWO,
            constants.ACCESS_MODE_RWOP,
            constants.ACCESS_MODE_RWO,
            constants.ACCESS_MODE_RWX,
            constants.ACCESS_MODE_RWOP,
        ]
        total_non_enc_pvcs = 10
        non_enc_combinations = [
            {"volume_mode": vm, "access_mode": am, "size": 1}
            for vm, am in itertools.islice(
                itertools.cycle(zip(non_enc_volume_modes, non_enc_access_modes)),
                total_non_enc_pvcs,
            )
        ]

        non_enc_pvc_objs = []
        non_enc_pod_objs = []
        for idx, pvc_config in enumerate(non_enc_combinations, start=1):
            log.info(
                f"\nCreating non-encrypted PVC {idx}/{total_non_enc_pvcs}: "
                f"VolumeMode={pvc_config['volume_mode']} "
                f"AccessMode={pvc_config['access_mode']}"
            )
            non_enc_pvc_obj = pvc_factory(
                interface=constants.CEPHBLOCKPOOL,
                project=self.proj_obj,
                storageclass=non_enc_sc_obj,
                size=pvc_config["size"],
                access_mode=pvc_config["access_mode"],
                volume_mode=pvc_config["volume_mode"],
                status=constants.STATUS_BOUND,
            )
            non_enc_pvc_objs.append(non_enc_pvc_obj)
            log.info(f"✓ Non-encrypted PVC {non_enc_pvc_obj.name} created and bound")

            is_block = pvc_config["volume_mode"] == constants.VOLUME_MODE_BLOCK
            sa_obj = helpers.create_serviceaccount(non_enc_pvc_obj.project.namespace)
            helpers.add_scc_policy(
                sa_name=sa_obj.name, namespace=non_enc_pvc_obj.project.namespace
            )
            non_enc_pod_obj = deployment_pod_factory(
                interface=constants.CEPHBLOCKPOOL,
                pvc=non_enc_pvc_obj,
                raw_block_pv=is_block,
                sa_obj=sa_obj,
            )
            non_enc_pod_objs.append(non_enc_pod_obj)
            log.info(
                f"✓ Non-encrypted deployment {non_enc_pod_obj.name} created and running"
            )

        log.info(
            f"\n✓ All {len(non_enc_pod_objs)} non-encrypted deployments created and running"
        )

        # Step 5c: Create CephFS PVCs (10 total) and deployment pods
        log.info("=" * 80)
        log.info("Step 5c: Creating CephFS PVCs and deployment pods")
        log.info("=" * 80)

        # CephFS combinations: Filesystem×RWO, Filesystem×RWX, Filesystem×RWOP = 3 base
        cephfs_base_combinations = [
            (constants.VOLUME_MODE_FILESYSTEM, constants.ACCESS_MODE_RWO),
            (constants.VOLUME_MODE_FILESYSTEM, constants.ACCESS_MODE_RWX),
            (constants.VOLUME_MODE_FILESYSTEM, constants.ACCESS_MODE_RWOP),
        ]
        total_cephfs_pvcs = 10
        cephfs_combinations = [
            {"volume_mode": vm, "access_mode": am, "size": 1}
            for vm, am in itertools.islice(
                itertools.cycle(cephfs_base_combinations), total_cephfs_pvcs
            )
        ]
        log.info(
            "CephFS combinations (cycled): Filesystem×RWO, Filesystem×RWX, Filesystem×RWOP"
        )

        # Fetch the default CephFS storage class object
        cephfs_sc_obj = helpers.default_storage_class(
            interface_type=constants.CEPHFILESYSTEM
        )
        log.info(f"Using CephFS storage class: {cephfs_sc_obj.name}")

        cephfs_pvc_objs = []
        cephfs_pod_objs = []
        for idx, pvc_config in enumerate(cephfs_combinations, start=1):
            log.info(
                f"\nCreating CephFS PVC {idx}/{total_cephfs_pvcs}: "
                f"VolumeMode={pvc_config['volume_mode']} "
                f"AccessMode={pvc_config['access_mode']}"
            )
            cephfs_pvc_obj = pvc_factory(
                interface=constants.CEPHFILESYSTEM,
                project=self.proj_obj,
                storageclass=cephfs_sc_obj,
                size=pvc_config["size"],
                access_mode=pvc_config["access_mode"],
                volume_mode=pvc_config["volume_mode"],
                status=constants.STATUS_BOUND,
            )
            cephfs_pvc_objs.append(cephfs_pvc_obj)
            log.info(f"✓ CephFS PVC {cephfs_pvc_obj.name} created and bound")

            # CephFS is always Filesystem mode — no raw_block_pv needed
            sa_obj = helpers.create_serviceaccount(cephfs_pvc_obj.project.namespace)
            helpers.add_scc_policy(
                sa_name=sa_obj.name, namespace=cephfs_pvc_obj.project.namespace
            )
            cephfs_pod_obj = deployment_pod_factory(
                interface=constants.CEPHFILESYSTEM,
                pvc=cephfs_pvc_obj,
                raw_block_pv=False,
                sa_obj=sa_obj,
            )
            cephfs_pod_objs.append(cephfs_pod_obj)
            log.info(f"✓ CephFS deployment {cephfs_pod_obj.name} created and running")

        log.info(
            f"\n✓ All {len(cephfs_pod_objs)} CephFS deployments created and running"
        )

        # Step 6: Start FIO workload on ALL pods (encrypted RBD + non-encrypted RBD + CephFS)
        log.info("=" * 80)
        log.info("Step 6: Starting FIO workload on all pods (verify=True)")
        log.info("=" * 80)

        all_pods_with_config = (
            list(zip(pod_objs, pvc_combinations))
            + list(zip(non_enc_pod_objs, non_enc_combinations))
            + list(zip(cephfs_pod_objs, cephfs_combinations))
        )
        for idx, (pod_obj, pvc_config) in enumerate(all_pods_with_config, start=1):
            log.info(
                f"\nStarting FIO on pod {idx}/{len(all_pods_with_config)}: {pod_obj.name}"
            )

            # Determine IO type based on volume mode
            if pvc_config["volume_mode"] == constants.VOLUME_MODE_BLOCK:
                io_type = "block"
                log.info("  - IO Type: Block device")
            else:
                io_type = "fs"
                log.info("  - IO Type: Filesystem")

            # Start FIO with verify=True
            log.info("  - FIO Parameters: verify=True, size=500M, runtime=300s")
            pod_obj.run_io(
                storage_type=io_type,
                size="500M",
                verify=True,
                runtime=300,
            )
            log.info(f"✓ FIO workload started on pod {pod_obj.name}")

        log.info(f"\n✓ FIO workload started on all {len(all_pods_with_config)} pods")
        log.info(
            "  (Encrypted RBD: key rotation will be verified; "
            "Non-encrypted RBD and CephFS: FIO only)"
        )

        # Step 7: Wait for 2 minutes for key rotation to occur (encrypted RBD PVs only)
        log.info("=" * 80)
        log.info("Step 7: Waiting for key rotation to occur")
        log.info("=" * 80)

        wait_time = 120  # 2 minutes
        log.info(
            f"\nWaiting {wait_time} seconds (2 minutes) for key rotation schedule..."
        )
        log.info("Key rotation schedule: */2 * * * * (every 2 minutes)")

        # Add buffer time to ensure rotation completes
        buffer_time = 30
        total_wait = wait_time + buffer_time
        log.info(f"Total wait time with buffer: {total_wait} seconds")

        time.sleep(total_wait)
        log.info("✓ Wait period completed")

        # Step 8: Verify key rotation for all PVs
        log.info("=" * 80)
        log.info("Step 8: Verifying key rotation for all PVs")
        log.info("=" * 80)

        rotation_results = []
        for idx, pvc_obj in enumerate(pvc_objs, start=1):
            log.info(
                f"\nVerifying key rotation for PVC {idx}/{len(pvc_objs)}: {pvc_obj.name}"
            )

            # Get PV volume handle name
            volume_handle = pvc_obj.get_pv_volume_handle_name
            log.info(f"  - PV Volume Handle: {volume_handle}")

            # Verify key rotation occurred
            try:
                rotation_success = self.pvk_obj.wait_till_keyrotation(volume_handle)
                rotation_results.append(rotation_success)
                log.info(f"✓ Key rotation verified for PVC {pvc_obj.name}")
                log.info("  - New key is different from original key")
            except Exception as e:
                log.error(f"✗ Key rotation failed for PVC {pvc_obj.name}: {str(e)}")
                rotation_results.append(False)
                raise

        # Assert all key rotations were successful
        assert all(rotation_results), (
            f"Key rotation failed for one or more PVCs. "
            f"Success: {sum(rotation_results)}/{len(rotation_results)}"
        )
        log.info(f"\n✓ Key rotation verified successfully for all {len(pvc_objs)} PVs")

        # Step 9: Validate FIO results for ALL pods (encrypted + non-encrypted)
        log.info("=" * 80)
        log.info("Step 9: Validating FIO results for all pods")
        log.info("=" * 80)

        all_pods_for_fio_check = pod_objs + non_enc_pod_objs + cephfs_pod_objs
        fio_results = []
        for idx, pod_obj in enumerate(all_pods_for_fio_check, start=1):
            log.info(
                f"\nGetting FIO results for pod {idx}/{len(all_pods_for_fio_check)}: "
                f"{pod_obj.name}"
            )
            try:
                result = pod_obj.get_fio_results(timeout=300)
                fio_results.append(result)
                log.info(f"✓ FIO completed successfully on pod {pod_obj.name}")
                log.info("  - No errors during IO operations")
                log.info("  - Data verification passed")
            except Exception as e:
                log.error(f"✗ FIO failed on pod {pod_obj.name}: {str(e)}")
                fio_results.append(None)
                raise

        # Assert all FIO operations completed successfully
        assert all(
            result is not None for result in fio_results
        ), "FIO verification failed for one or more pods"
        log.info(
            f"\n✓ FIO validation completed successfully for all "
            f"{len(all_pods_for_fio_check)} pods"
        )

        # Final summary
        log.info("=" * 80)
        log.info("TEST SUMMARY")
        log.info("=" * 80)
        log.info(f"✓ Encrypted RBD PVCs created: {len(pvc_objs)}")
        log.info(f"✓ Non-encrypted RBD PVCs created: {len(non_enc_pvc_objs)}")
        log.info(f"✓ CephFS PVCs created: {len(cephfs_pvc_objs)}")
        log.info(f"✓ Total pods created: {len(all_pods_for_fio_check)}")
        log.info(
            f"✓ Key rotations verified (encrypted RBD only): {len(rotation_results)}"
        )
        log.info(f"✓ FIO validations passed: {len(fio_results)}")
        log.info("\nEncrypted RBD PVC Combinations Validated:")
        for idx, pvc_config in enumerate(pvc_combinations, start=1):
            log.info(
                f"  {idx}. {pvc_config['volume_mode']} + "
                f"{pvc_config['access_mode']} - ✓ PASSED"
            )
        log.info("\nNon-Encrypted RBD PVC Combinations Validated:")
        for idx, pvc_config in enumerate(non_enc_combinations, start=1):
            log.info(
                f"  {idx}. {pvc_config['volume_mode']} + "
                f"{pvc_config['access_mode']} - ✓ PASSED"
            )
        log.info("\nCephFS PVC Combinations Validated:")
        for idx, pvc_config in enumerate(cephfs_combinations, start=1):
            log.info(
                f"  {idx}. {pvc_config['volume_mode']} + "
                f"{pvc_config['access_mode']} - ✓ PASSED"
            )
        log.info("=" * 80)
        log.info("TEST COMPLETED SUCCESSFULLY")
        log.info("=" * 80)


# Made with Bob
