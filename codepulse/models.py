# Author: Djena Siabdellah
# Description: Defines models for CodePulse, including a custom user model and a model for storing scan results.
# References 
# https://github.com/adeyosemanputra/pygoat/blob/master/introduction/models.py



from django.db import models
from django.contrib.auth.models import AbstractUser #, Group, Permission


class CustomUser(AbstractUser):
    # Your custom user model code
    pass
    # I Added related_name to avoid clashes with the default User model
    # ManyToManyField was setup for the CustomUser model to associate Groups and Permissions explicitly.
    # im using 'related_name' to prevent clashes.
    groups = models.ManyToManyField(
        "auth.Group",
        related_name="custom_user_set",
        related_query_name="custom_user",
        blank=True,
        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="custom_user_set",
        related_query_name="custom_user",
        blank=True,
        help_text="Specific permissions for this user.",
    )

# ScanResult model stores the results of security scans performed on URLs.
class ScanResult(models.Model):
    # URL field to store the address of the scanned site.
    url = models.URLField()
    # date and time of the scan, set automatically on creation.
    scanned_on = models.DateTimeField(auto_now_add=True)
    # boolean field to indicate if XSS vulnerabilities were detected.
    xss_detected = models.BooleanField(default=False)
    # boolean field to indicate if SQL Injection vulnerabilities were detected.
    sql_injection_detected = models.BooleanField(default=False)
    # boolean field to indicate if CSRF vulnerabilities were detected.
    csrf_issues_detected = models.BooleanField(default=False)
    # for additional info or detailed results
    additional_info = models.TextField(blank=True, null=True)  

    def __str__(self):
        # this string representation of the ScanResult that includes the URL and the date of the scan.
        return f"Scan for {self.url} on {self.scanned_on}"


