# Author: Djena Siabdellah
# Description: URL configuration for the codereview project

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('codepulse/', include('codepulse.urls'))
]
