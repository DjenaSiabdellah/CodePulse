# Author: Djena Siabdellah
# Description: unit tests for the views in the CodePulse application. These tests ensure that views handle user interactions correctly and manage data accurately.
# References 
# https://www.javatpoint.com/unit-testing-in-django
# https://stackoverflow.com/questions/25857655/django-tests-patch-object-in-all-tests

from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from unittest.mock import patch

# View tests

# This is the test cases for the login functionality.
class LoginViewTest(TestCase):
    def setUp(self):
        # this is to setup a user for testing login.
        self.user = get_user_model().objects.create_user(username='testuser', password='testpass123')
    def test_login_success(self):
        # this will send a POST request to login URL and check for correct redirection after login.
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpass123'})
        self.assertRedirects(response, reverse('scanner'))

# this test cases for the URL scanning view functionality.
class UrlScannerViewTest(TestCase):
    @patch('codepulse.views.fetch_url')
    def test_url_scan_view(self, mock_fetch):
        # this sets up the mock to simulate fetching a URL and returning HTML content.
        mock_fetch.return_value = '<html></html>'
       # this will give a login and send a POST request to the URL scanning endpoint.
        self.client.login(username='scanner', password='password123')
        response = self.client.post(reverse('url_scanner'), {'url_input': 'http://safeurl.com'})  
        # this then checks if the view responds correctly and if the mock was called as expected.
        self.assertEqual(response.status_code, 200)
        mock_fetch.assert_called_once_with('http://safeurl.com')



