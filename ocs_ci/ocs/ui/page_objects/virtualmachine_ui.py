"""
VirtualMachine UI Page Object for OpenShift Virtualization
"""

import logging
import time
from selenium.webdriver.common.by import By
from ocs_ci.ocs.exceptions import TimeoutExpiredError
from ocs_ci.ocs.ui.base_ui import BaseUI, wait_for_element_to_be_clickable
from ocs_ci.ocs.ui.page_objects.page_navigator import PageNavigator
from ocs_ci.ocs.ui.views import VM_LOCATORS
from ocs_ci.utility.retry import retry

logger = logging.getLogger(__name__)


class VirtualMachineUI(PageNavigator, BaseUI):
    """
    VirtualMachineUI implements virtual machine creation, management, and deletion.
    """

    def __init__(self):
        super().__init__()
        self.vm_locators = VM_LOCATORS

    def navigate_to_workloads_pods(self):
        """
        Navigate to Workloads > Pods in the left-side navigation menu.
        """
        logger.info("Navigating to Workloads > Pods")
        self.choose_expanded_mode(mode=True, locator=self.vm_locators["workloads_menu"])
        self.do_click(self.vm_locators["workloads_pods_option"])
        logger.info("Navigated to Workloads > Pods")
        time.sleep(2)

    def select_project_from_all_projects(self, namespace):
        """
        Click the 'All Projects' dropdown, enable 'Show default projects',
        search for the namespace, and select it.

        Args:
            namespace (str): The namespace/project name to select
        """
        logger.info(f"Opening 'All Projects' dropdown for namespace: {namespace}")
        self.do_click(self.vm_locators["project_selector_dropdown"])
        time.sleep(2)

        try:
            toggle_locator = self.vm_locators["project_show_default_toggle"]
            wait_for_element_to_be_clickable(locator=toggle_locator, timeout=10)
            self.do_click(toggle_locator)
            logger.info("Clicked 'Show default projects' toggle")
            time.sleep(1)
        except Exception as e:
            logger.warning(f"Could not click 'Show default projects' toggle: {e}")

        try:
            search_input = self.vm_locators["project_search_input"]
            wait_for_element_to_be_clickable(locator=search_input, timeout=15)
            self.do_send_keys(search_input, namespace)
            time.sleep(1)
        except Exception as e:
            logger.warning(f"Could not type in project search field: {e}")

        ns_option_xpath = self.vm_locators["project_namespace_item_tmpl"].format(
            namespace=namespace
        )
        ns_option_locator = (ns_option_xpath, By.XPATH)
        wait_for_element_to_be_clickable(locator=ns_option_locator, timeout=20)
        self.do_click(ns_option_locator)
        logger.info(f"Selected project/namespace: {namespace}")
        time.sleep(2)

    def navigate_to_virtualmachines_page(self):
        """
        Navigate to Virtualization > VirtualMachines page and dismiss the
        welcome modal if it appears.
        """
        logger.info("Navigating to Virtualization > VirtualMachines")
        self.choose_expanded_mode(
            mode=True, locator=self.vm_locators["virtualization_menu"]
        )
        self.do_click(self.vm_locators["virtualmachines_tab"])
        logger.info("Navigated to VirtualMachines page")
        self.dismiss_welcome_modal()

    def dismiss_welcome_modal(self):
        """
        Close the 'Welcome to OpenShift Virtualization' modal if present.
        Uses driver.find_elements to avoid AI fallback when no modal is shown.
        """
        xpath = self.vm_locators["modal_close_button"][0]
        try:
            elements = self.driver.find_elements(By.XPATH, xpath)
            if elements and elements[0].is_displayed():
                elements[0].click()
                logger.info("Dismissed welcome modal")
                time.sleep(1)
                return
        except Exception:
            pass
        logger.info("No welcome modal present")

    def dismiss_welcome_modal_if_present(self):
        """
        Dismiss any overlay modal currently blocking the page.
        Uses driver.find_elements to avoid AI fallback when no modal is shown.
        """
        xpath = self.vm_locators["modal_close_button"][0]
        try:
            elements = self.driver.find_elements(By.XPATH, xpath)
            if elements and elements[0].is_displayed():
                elements[0].click()
                logger.info("Dismissed modal")
                time.sleep(1)
                return
        except Exception:
            pass
        logger.info("No modal to dismiss")

    def enter_vm_name(self, vm_name):
        """
        Enter the VM name in the creation wizard.

        Args:
            vm_name (str): Name to give the VirtualMachine
        """
        logger.info(f"Entering VM name: {vm_name}")
        name_input = self.vm_locators["vm_name_input"]
        wait_for_element_to_be_clickable(locator=name_input, timeout=30)
        self.do_clear(name_input)
        self.do_send_keys(name_input, vm_name)
        logger.info(f"Entered VM name: {vm_name}")

    def click_create_virtualmachine(self):
        """
        Click on 'Create VirtualMachine' button (top-right).
        Falls back to JS click if an overlay intercepts.
        """
        locator = self.vm_locators["create_vm_button"]
        wait_for_element_to_be_clickable(locator=locator, timeout=30)
        try:
            self.do_click(locator)
        except Exception:
            element = self.get_element(locator)
            self.driver.execute_script("arguments[0].click();", element)
            logger.info("Clicked Create VirtualMachine button via JS fallback")
            return
        logger.info("Clicked Create VirtualMachine button")

    def click_next_button(self):
        """
        Click the 'Next' button on the current wizard page.
        """
        wait_for_element_to_be_clickable(
            locator=self.vm_locators["creation_wizard_next"], timeout=30
        )
        self.do_click(self.vm_locators["creation_wizard_next"])
        logger.info("Clicked Next button")
        time.sleep(2)

    def select_guest_os_other_linux(self):
        """
        On the Guest OS page select the 'Other Linux' card (3rd card).
        """
        other_linux = self.vm_locators["guest_os_other_linux"]
        wait_for_element_to_be_clickable(locator=other_linux, timeout=30)
        self.do_click(other_linux)
        logger.info("Selected 'Other Linux' card")

    def select_guest_os(self):
        """
        Open the 'Guest operating system type' dropdown and select the second option.

        Returns:
            str: Text of the selected option
        """
        dropdown = self.vm_locators["guest_os_type_dropdown"]
        wait_for_element_to_be_clickable(locator=dropdown, timeout=30)
        self.do_click(dropdown)
        time.sleep(1)

        second_opt = self.vm_locators["guest_os_type_second_option"]
        wait_for_element_to_be_clickable(locator=second_opt, timeout=20)
        try:
            option_text = self.get_element_text(second_opt)
        except Exception:
            option_text = "centos.stream10"
        self.do_click(second_opt)
        logger.info(f"Selected Guest OS type: {option_text}")
        return option_text

    def select_compute_size_small(self):
        """
        On the Compute resources page open the size dropdown and select
        'small: 1 CPUs, 2 GiB Memory'.
        """
        toggle_locator = self.vm_locators["compute_size_dropdown"]
        wait_for_element_to_be_clickable(locator=toggle_locator, timeout=20)
        self.do_click(toggle_locator)
        time.sleep(1)

        small_locator = self.vm_locators["compute_size_small_option"]
        wait_for_element_to_be_clickable(locator=small_locator, timeout=20)
        self.do_click(small_locator)
        logger.info("Selected compute size: small: 1 CPUs, 2 GiB Memory")

    def select_boot_volume_centos_stream10(self):
        """
        On the Boot source page click on the 'centos-stream10' volume row.
        """
        volume_locator = self.vm_locators["boot_volume_centos_stream10"]
        wait_for_element_to_be_clickable(locator=volume_locator, timeout=30)
        self.do_click(volume_locator)
        logger.info("Clicked centos-stream10 boot volume")

    def click_customization_storage_tab(self):
        """
        On the Customization page click the 'Storage' tab.
        """
        storage_tab = self.vm_locators["customization_storage_tab"]
        wait_for_element_to_be_clickable(locator=storage_tab, timeout=30)
        self.do_click(storage_tab)
        logger.info("Clicked Storage tab")
        time.sleep(2)

    def click_rootdisk_kebab_and_edit(self):
        """
        Click the three-dots menu on the rootdisk row then select 'Edit'.
        """
        kebab = self.vm_locators["rootdisk_kebab_button"]
        wait_for_element_to_be_clickable(locator=kebab, timeout=30)
        self.do_click(kebab)
        time.sleep(1)
        edit_opt = self.vm_locators["rootdisk_kebab_edit"]
        wait_for_element_to_be_clickable(locator=edit_opt, timeout=20)
        self.do_click(edit_opt)
        logger.info("Clicked Edit on rootdisk")
        time.sleep(2)

    def change_storageclass_to_vm_option(self):
        """
        In the 'Edit disk' popup open the StorageClass dropdown and select
        the option ending with '-vm'.

        Returns:
            str: Name of the selected storage class
        """
        sc_dropdown = self.vm_locators["edit_disk_storageclass_dropdown"]
        wait_for_element_to_be_clickable(locator=sc_dropdown, timeout=30)
        self.do_click(sc_dropdown)
        time.sleep(1)

        vm_opt = self.vm_locators["edit_disk_storageclass_vm_option"]
        wait_for_element_to_be_clickable(locator=vm_opt, timeout=20)
        sc_name = self.get_element_text(vm_opt)
        self.do_click(vm_opt)
        logger.info(f"Selected storage class: {sc_name}")
        return sc_name

    def click_edit_disk_save(self):
        """
        Click the 'Save' button inside the 'Edit disk' popup.
        """
        save_btn = self.vm_locators["edit_disk_save_button"]
        wait_for_element_to_be_clickable(locator=save_btn, timeout=20)
        self.do_click(save_btn)
        logger.info("Clicked Save")
        time.sleep(2)

    def click_create_virtualmachine_submit(self):
        """
        Click the 'Create VirtualMachine' button on the Review and create page.
        """
        submit_button = self.vm_locators["create_vm_submit_button"]
        wait_for_element_to_be_clickable(locator=submit_button, timeout=30)
        self.do_click(submit_button, enable_screenshot=True)
        logger.info("Clicked Create VirtualMachine submit button")

    @retry((AssertionError, TimeoutExpiredError), tries=30, delay=30, backoff=1)
    def wait_for_vm_running(self):
        """
        Wait up to 15 minutes (30 x 30s) for the Status field to show 'Running'.
        Uses driver.find_elements to avoid AI fallback.
        """
        logger.info("Checking for Running status on VM detail page...")
        xpath = self.vm_locators["vm_status_running"][0]
        elements = self.driver.find_elements(By.XPATH, xpath)
        assert (
            elements and elements[0].is_displayed()
        ), "VM status 'Running' not found yet"
        logger.info("VM status is now: Running")
        return True

    @retry((AssertionError, TimeoutExpiredError), tries=20, delay=10, backoff=1)
    def wait_for_vm_stopped(self):
        """
        Wait for the Status field to show 'Stopped'.
        Uses driver.find_elements to avoid AI fallback.
        """
        logger.info("Checking for Stopped status on VM detail page...")
        xpath = self.vm_locators["vm_status_stopped"][0]
        elements = self.driver.find_elements(By.XPATH, xpath)
        assert (
            elements and elements[0].is_displayed()
        ), "VM status 'Stopped' not found yet"
        logger.info("VM status is now: Stopped")
        return True

    def click_actions_menu(self):
        """
        Click on Actions menu on the VM detail page.
        """
        actions_button = self.vm_locators["actions_button"]
        wait_for_element_to_be_clickable(locator=actions_button, timeout=30)
        self.do_click(actions_button)
        logger.info("Clicked Actions menu")
        time.sleep(1)

    def click_actions_control_then_stop(self):
        """
        From the Actions menu click Control (submenu) then Stop.
        """
        logger.info("Clicking Actions > Control")
        control_menu = self.vm_locators["actions_control_menu"]
        wait_for_element_to_be_clickable(locator=control_menu, timeout=20)
        self.do_click(control_menu)
        time.sleep(1)
        logger.info("Clicking Stop")
        stop_option = self.vm_locators["actions_stop_option"]
        wait_for_element_to_be_clickable(locator=stop_option, timeout=20)
        self.do_click(stop_option, enable_screenshot=True)
        logger.info("Clicked Stop")

    def click_actions_delete(self):
        """
        From the Actions menu click Delete.
        Waits 5 seconds for the modal to load before returning.
        """
        logger.info("Clicking Actions > Delete")
        delete_option = self.vm_locators["actions_delete_option"]
        wait_for_element_to_be_clickable(locator=delete_option, timeout=20)
        self.do_click(delete_option, enable_screenshot=True)
        logger.info("Clicked Delete; waiting 5s for modal to load")
        time.sleep(5)

    def check_grace_period_and_confirm_delete(self):
        """
        In the 'Delete VirtualMachine' modal:
          - Check the 'With grace period' checkbox (unchecked by default)
          - Click the Delete button
        """
        logger.info("Checking 'With grace period' checkbox in delete modal")
        grace_xpath = self.vm_locators["delete_grace_period_checkbox"][0]
        checked = False
        try:
            els = self.driver.find_elements(By.XPATH, grace_xpath)
            if els:
                if not els[0].is_selected():
                    els[0].click()
                    logger.info("Checked 'With grace period'")
                else:
                    logger.info("'With grace period' already checked")
                checked = True
        except Exception:
            pass
        if not checked:
            logger.warning("Could not find 'With grace period' checkbox")

        time.sleep(1)
        delete_btn = self.vm_locators["delete_confirm_button"]
        wait_for_element_to_be_clickable(locator=delete_btn, timeout=20)
        self.do_click(delete_btn, enable_screenshot=True)
        logger.info("Clicked Delete in confirmation modal")

    def verify_namespace_gone_from_left_tree(self, namespace, timeout=30):
        """
        Verify the namespace row has disappeared from the left-side tree.
        Uses driver.find_elements to avoid AI fallback.

        Args:
            namespace (str): Namespace name to check
            timeout (int): How many seconds to poll

        Returns:
            bool: True if namespace is gone
        """
        logger.info(f"Verifying namespace '{namespace}' is gone from left-side tree")
        ns_xpath = self.vm_locators["namespace_left_tree_item_tmpl"].format(
            namespace=namespace
        )
        end = time.time() + timeout
        while time.time() < end:
            try:
                els = self.driver.find_elements(By.XPATH, ns_xpath)
                if not els or not any(e.is_displayed() for e in els):
                    logger.info(
                        f"Namespace '{namespace}' no longer visible in left tree"
                    )
                    return True
            except Exception:
                return True
            time.sleep(5)
        logger.warning(f"Namespace '{namespace}' still visible after {timeout}s")
        return False
