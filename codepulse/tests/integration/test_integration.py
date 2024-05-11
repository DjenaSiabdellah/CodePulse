# Author: Djena Siabdellah
# Description: integration tests for CodePulse, verifying the functionality of the user registration and email verification processes.
# Reference 
# https://docs.python.org/3/library/unittest.mock-examples.html
# https://pytest.org/en/7.4.x/explanation/goodpractices.html 

from django.test import TestCase
from django.urls import reverse
from django.core import mail
from django.contrib.auth import get_user_model
from unittest.mock import patch
import re

# This is patching the 'send_verification_email' function in the 'views' module
# This also ensures that the actual sending function is not called, but called by 'unittest.mock'
class UserRegistrationIntegrationTest(TestCase):
    @patch('codepulse.views.send_verification_email', return_value=True)
    def test_user_registration_flow(self, mocked_send_email):
        # This is data to register a new user, this is what is representing the user input for registration.
        registration_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'Testpassword123!',
            'password2': 'Testpassword123!'
        }
        # Step 1 - this triggers a POST request to the registration URL with the registration data
        # This tests the registration process handling in the view        
        response = self.client.post(reverse('register'), registration_data)
        # This is to verify that after registration, the response redirects to the 'verify_email' URL
        self.assertRedirects(response, reverse('verify_email'))
        # Step 2 - This checks that the mock was called once
        mocked_send_email.assert_called_once()
        # this simulate user email verification by manually activating the user
        user = get_user_model().objects.get(username='newuser')
        user.is_active = True
        user.save()
        # Step 3 - this verifies that the user can now log in with the registered details
        login = self.client.login(username='newuser', password='Testpassword123!')
        self.assertTrue(login)
        # this checks the user is redirected to the page after login, which is the scanner page in my setup
        response = self.client.get(reverse('scanner'))
        self.assertEqual(response.status_code, 200)

