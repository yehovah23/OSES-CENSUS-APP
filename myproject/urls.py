"""
URL configuration for myproject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    # This line correctly includes all URLs defined in your census/urls.py
    # including the 'signup/' path.
    path('', include('census.urls')), # Changed from 'api/' to '' to ensure root URL is handled by census.urls
    # Removed: path('signup/', include('census.signup')), as it's redundant and incorrect.
    # If you have DRF authentication URLs, they should be included like this:
    path('api-auth/', include('rest_framework.urls')),
]
