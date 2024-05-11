# Author: Djena Siabdellah
# Description: configuration settings for the CodePulse Django project, defining security settings, installed apps, middleware, and more for production and development.
# References
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators
# https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators
# https://docs.djangoproject.com/en/5.0/topics/i18n/
# https://docs.djangoproject.com/en/5.0/howto/static-files/
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field


from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-vtf_l2+as=b$=v23=y^_5q#u1tfg+02d^_ko*d7m=tj-$n_$0a'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


AUTH_PASSWORD_VALIDATORS = [
    # Other Django validators
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'your_app_name.validators.CustomPasswordValidator',
    },
]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sessions',
    'codepulse',
]
 

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',

]

ROOT_URLCONF = 'codereview.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ["templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'codereview.wsgi.application'


# Database

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'


# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Ensures the session cookie is sent over HTTPS
SESSION_COOKIE_SECURE = True  # Ensures cookies are only sent over HTTPS
CSRF_COOKIE_SECURE = True  # Ensures CSRF cookies are only sent over HTTPS

# Use cookie-based sessions

# Ensure sessions are saved to the database each request
SESSION_SAVE_EVERY_REQUEST = True

#Logging for Email Sending:

#AUTH_USER_MODEL = 'codepulse.CustomUser'

LOGIN_URL = 'login'

#EMAIL_LOGGING = True (ive used this to confirm that the django project is trying to sedn the emails by checking my server logs or email logging)

# Email config for the development 
#EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'djenasiabdellah26@gmail.com'
EMAIL_HOST_PASSWORD = 'ssvvycowriavoewj'
EMAIL_USE_TLS = True
