from django.urls import path
from . import views

#urlconfig
urlpatterns = [
    path('home/', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('register/', views.register, name='register'),
    path('', views.signup, name='signup'),
    path('home/', views.login,name='login')


]