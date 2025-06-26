from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'enumerations', views.EnumerationViewSet)
router.register(r'users', views.UserViewSet)


urlpatterns = [
    path('', views.home, name='home'),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),

    # OTP related AJAX endpoints
    path('request-otp/', views.request_otp, name='request_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('resend-otp/', views.resend_otp, name='resend_otp'),

    path('enumerations/', views.EnumerationListView.as_view(), name='enumeration-list'),
    path('enumeration/<int:pk>/', views.EnumerationDetailView.as_view(), name='enumeration-detail'),
    path('enumeration/create/', views.enumeration_create, name='enumeration-create'),
    path('enumeration/update/<int:pk>/', views.EnumerationUpdateView.as_view(), name='enumeration-update'),

    # Include DRF router URLs.
    path('api/', include(router.urls)),
    path('api-auth/', include('rest_framework.urls')),
    path('api/address-search/', views.AddressSearchViewSet.as_view({'get': 'list'}), name='api-address-search'),
    path('api/languages/', views.LanguageViewSet.as_view({'get': 'list'}), name='api-languages-list'),
    path('api/system-settings/', views.SystemSettingViewSet.as_view({'get': 'list', 'post': 'create'}), name='api-system-settings-list'),
    path('api/system-settings/<int:pk>/', views.SystemSettingViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update'}), name='api-system-settings-detail'),
    path('api/audit-logs/', views.AuditLogViewSet.as_view({'get': 'list'}), name='api-audit-logs-list'),
]
