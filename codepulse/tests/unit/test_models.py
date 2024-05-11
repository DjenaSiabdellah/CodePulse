# Author: Djena Siabdellah
# Description: unit tests for the models in the CodePulse application. This file tests functionalities such as user creation and properties of security scan results.
# Reference 
# https://www.javatpoint.com/unit-testing-in-django

from django.test import TestCase
from codepulse.models import CustomUser, ScanResult

# This tests for the CustomUser model focusing on user creation functionality.
class CustomUserModelTest(TestCase):
    def test_user_creation(self):
        # This creates a user instance using the CustomUser model's custom manager method create_user.
        user = CustomUser.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        # This verifies that the username is set correctly.
        self.assertEqual(user.username, 'testuser')
        # This checks that the passords is stored correctly and can be valid
        self.assertTrue(user.check_password('testpassword'))
        # Ensures that the user is not marked as staff by default.
        self.assertFalse(user.is_staff)

# This test is related to the ScanResult model.
class ScanResultTest(TestCase):
    def test_scan_result_creation(self):
        # This will reate a ScanResult instance with initial data.
        scan_result = ScanResult.objects.create(
            url="http://example.com",
            xss_detected=False,
            sql_injection_detected=False,
            additional_info="No issues detected."
        )
        # This confirm that the fields were correctly assigned and stored.
        self.assertEqual(scan_result.url, "http://example.com")
        self.assertFalse(scan_result.xss_detected)
        self.assertFalse(scan_result.sql_injection_detected)
        self.assertEqual(scan_result.additional_info, "No issues detected.")
    def test_str_method(self):
        # This create another ScanResult instance to test the string representation.
        scan_result = ScanResult.objects.create(
            url="http://example.com",
            xss_detected=True
        ) 
        # This verifies the __str__ method returns the expected string format.
        expected_str = f"Scan for {scan_result.url} on {scan_result.scanned_on}"
        self.assertEqual(str(scan_result), expected_str)

