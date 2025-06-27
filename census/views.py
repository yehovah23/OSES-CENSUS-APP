# E:\django\my_django_projects\myproject\census\views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.generic import ListView, DetailView, CreateView
from django.views.generic import UpdateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth import authenticate, login
import base64
from django.core.files.base import ContentFile
from django.db import transaction
from django.contrib import messages
import json

# Django REST Framework imports
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response

# Import OTP related utilities and models - REMOVED create_and_send_otp, OTP
from .models import (
    EnumerationData, CustomUser, AddressInformation, PersonalInformation, Language,
    SystemSetting, AuditLog, EducationInformation, EmploymentInformation,
)
from .serializers import (
    EnumerationDataSerializer, AuditLogSerializer, UserSerializer, AddressInformationSerializer,
    SystemSettingSerializer, LanguageSerializer, PersonalInformationSerializer,
    UserCreateSerializer,
    EducationInformationSerializer, EmploymentInformationSerializer
)
from .forms import (
    EnumerationDataForm, PersonalInformationForm, AddressInformationForm,
    CustomUserCreationForm, # REMOVED OTPVerificationForm
    EducationInformationForm, EmploymentInformationForm
)

# --- Constants for duplicated literals ---
ERROR_UNEXPECTED = 'An unexpected error occurred.'
ERROR_INVALID_JSON = 'Invalid JSON.' # Kept as placeholder if other APIs need it
ERROR_INVALID_METHOD = 'Invalid request method.' # Kept as placeholder if other APIs need it
TEMPLATE_ENUMERATION_FORM = 'census/enumeration_form.html'
# --- End Constants ---


# Template Views
def home(request):
    return render(request, 'census/home.html')

def signup_view(request):
    """
    Handles user signup directly without OTP verification.
    """
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            # Since OTP is removed, we consider the user verified upon successful signup.
            # If you want a different verification method (e.g., email confirmation link),
            # you would implement it here and set is_verified to False initially.
            user.is_verified = True
            user.save()

            messages.success(request, "Account created successfully! You can now log in.")
            return redirect('login') # Redirect to login page after successful signup
        else:
            # Form is not valid, re-render the form with errors
            print(f"Signup Form Errors: {form.errors}") # For debugging
            messages.error(request, "Please correct the errors below.")
            return render(request, 'census/signup.html', {'form': form})
    else:
        # Initial GET request for signup
        form = CustomUserCreationForm()
    return render(request, 'census/signup.html', {'form': form})

# REMOVED request_otp, verify_otp, resend_otp functions


# --- Helper Functions for login_view to reduce complexity ---

def _render_login_error(request, message, form=None):
    """Helper to render the login page with an error message."""
    if form is None:
        # Use CustomUserCreationForm for consistency, though login form isn't created directly here
        form = CustomUserCreationForm()
    messages.error(request, message)
    return render(request, 'census/login.html', {'form': form, 'error_message': message})

def _handle_face_authentication(request, user, password, national_id):
    """Handles logic for facial authentication."""
    # Simulate face authentication success for demonstration
    # In reality, you'd perform actual face comparison here.
    if password:
        authenticated_user = authenticate(request, national_id=national_id, password=password)
        if authenticated_user:
            login(request, authenticated_user)
            messages.success(request, f"User {national_id} authenticated with password and face data (simulated).")
            return redirect('home')
        else:
            return _render_login_error(request, 'Authentication failed. Invalid password or face mismatch.')
    else:
        # This is a SECURITY RISK if not backed by real face recognition.
        login(request, user)
        messages.success(request, f"User {national_id} authenticated with face data (simulated, no password).")
        return redirect('home')

def _handle_password_authentication(request, national_id, password):
    """Handles logic for password-only authentication."""
    if password:
        authenticated_user = authenticate(request, national_id=national_id, password=password)
        if authenticated_user:
            login(request, authenticated_user)
            messages.success(request, f"User {national_id} authenticated with password only.")
            return redirect('home')
        else:
            return _render_login_error(request, 'Authentication failed. Invalid password.')
    else:
        return _render_login_error(request, 'Please capture your face or enter your password.')

# --- Refactored login_view ---
def login_view(request):
    if request.method == 'GET':
        return render(request, 'census/login.html')

    national_id = request.POST.get('national_id')
    password = request.POST.get('password')
    face_image_data = request.POST.get('face_image_data')

    if not national_id:
        return _render_login_error(request, 'National ID is required.')

    try:
        user = CustomUser.objects.get(national_id=national_id)
    except CustomUser.DoesNotExist:
        return _render_login_error(request, 'National ID not found.')

    # User exists, proceed with authentication methods
    if face_image_data:
        # Delegate to face authentication helper
        return _handle_face_authentication(request, user, password, national_id)
    else:
        # Delegate to password-only authentication helper
        return _handle_password_authentication(request, national_id, password)


def enumeration_create(request):
    personal_form = PersonalInformationForm(prefix='personal_info')
    address_form = AddressInformationForm(prefix='address_info')
    education_form = EducationInformationForm(prefix='education_info')
    employment_form = EmploymentInformationForm(prefix='employment_info')
    enumeration_form = EnumerationDataForm()

    if request.method == 'POST':
        personal_form = PersonalInformationForm(request.POST, prefix='personal_info')
        address_form = AddressInformationForm(request.POST, prefix='address_info')
        education_form = EducationInformationForm(request.POST, prefix='education_info')
        employment_form = EmploymentInformationForm(request.POST, prefix='employment_info')
        enumeration_form = EnumerationDataForm(request.POST)

        if (personal_form.is_valid() and address_form.is_valid() and
            education_form.is_valid() and employment_form.is_valid() and
            enumeration_form.is_valid()):
            try:
                with transaction.atomic():
                    enumeration = enumeration_form.save(commit=False)
                    enumeration.user = request.user
                    enumeration.save()

                    personal_info = personal_form.save(commit=False)
                    personal_info.enumeration = enumeration
                    personal_info.save()

                    address_info = address_form.save(commit=False)
                    address_info.enumeration = enumeration
                    address_info.save()

                    education_info = education_form.save(commit=False)
                    education_info.enumeration = enumeration
                    education_info.save()

                    employment_info = employment_form.save(commit=False)
                    employment_info.enumeration = enumeration
                    employment_info.save()

                    return redirect('enumeration-detail', pk=enumeration.pk)
            except Exception as e:
                print(f"Database save error: {e}")
                return render(request, TEMPLATE_ENUMERATION_FORM, {
                    'personal_form': personal_form,
                    'address_form': address_form,
                    'education_form': education_form,
                    'employment_form': employment_form,
                    'enumeration_form': enumeration_form,
                    'error_message': 'An error occurred while saving your enumeration. Please try again.'
                })
        else:
            print(f"Personal Form Errors: {personal_form.errors}")
            print(f"Address Form Errors: {address_form.errors}")
            print(f"Education Form Errors: {education_form.errors}")
            print(f"Employment Form Errors: {employment_form.errors}")
            print(f"Enumeration Form Errors: {enumeration_form.errors}")
            return render(request, TEMPLATE_ENUMERATION_FORM, {
                'personal_form': personal_form,
                'address_form': address_form,
                'education_form': education_form,
                'employment_form': employment_form,
                'enumeration_form': enumeration_form,
            })
    else:
        personal_form = PersonalInformationForm(prefix='personal_info')
        address_form = AddressInformationForm(prefix='address_info')
        education_form = EducationInformationForm(prefix='education_info')
        employment_form = EmploymentInformationForm(prefix='employment_info')
        enumeration_form = EnumerationDataForm()

    return render(request, TEMPLATE_ENUMERATION_FORM, {
        'personal_form': personal_form,
        'address_form': address_form,
        'education_form': education_form,
        'employment_form': employment_form,
        'enumeration_form': enumeration_form,
    })


class EnumerationListView(LoginRequiredMixin, ListView):
    model = EnumerationData
    template_name = 'census/enumeration_list.html'
    context_object_name = 'enumerations'
    paginate_by = 10

    def get_queryset(self):
        queryset = EnumerationData.objects.filter(user=self.request.user)

        search_query = self.request.GET.get('q')
        if search_query:
            queryset = queryset.filter(
                Q(personal_info__first_name__icontains=search_query) |
                Q(personal_info__last_name__icontains=search_query) |
                Q(address_info__district__icontains=search_query)
            )

        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset.select_related('personal_info', 'address_info')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = EnumerationData.STATUS_CHOICES
        context['q'] = self.request.GET.get('q', '')
        context['status'] = self.request.GET.get('status', '')
        return context

class EnumerationDetailView(LoginRequiredMixin, DetailView):
    model = EnumerationData
    template_name = 'census/enumeration_detail.html'


# API Views
class EnumerationViewSet(viewsets.ModelViewSet):
    queryset = EnumerationData.objects.all()
    serializer_class = EnumerationDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    @action(detail=True, methods=['get'])
    def personal_info(self, request, pk=None):
        enumeration = self.get_object()
        serializer = PersonalInformationSerializer(enumeration.personal_info)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def address_info(self, request, pk=None):
        enumeration = self.get_object()
        serializer = AddressInformationSerializer(enumeration.address_info)
        return Response(serializer.data)

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def get_permissions(self):
        if self.action == 'create':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]

class EnumerationDataViewSet(viewsets.ModelViewSet):
    serializer_class = EnumerationDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return EnumerationData.objects.all()
        return EnumerationData.objects.filter(user=user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        enumeration = self.get_object()
        if enumeration.user != request.user and not request.user.is_staff:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        enumeration.status = 'submitted'
        enumeration.save()
        return Response({'status': 'submitted'})

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        if not request.user.is_staff:
            return Response({'error': 'Only staff can verify'}, status=status.HTTP_403_FORBIDDEN)

        enumeration = self.get_object()
        enumeration.status = 'verified'
        enumeration.verified_by = request.user
        enumeration.verification_date = timezone.now()
        enumeration.save()
        return Response({'status': 'verified'})

class EnumerationUpdateView(LoginRequiredMixin, UpdateView):
    model = EnumerationData
    form_class = EnumerationDataForm
    template_name = TEMPLATE_ENUMERATION_FORM
    success_url = reverse_lazy('enumeration-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            context['personal_form'] = PersonalInformationForm(
                self.request.POST,
                instance=self.object.personal_info
            )
            context['address_form'] = AddressInformationForm(
                self.request.POST,
                instance=self.object.address_info
            )
            context['education_form'] = EducationInformationForm(
                self.request.POST,
                instance=getattr(self.object, 'education_info', None)
            )
            context['employment_form'] = EmploymentInformationForm(
                self.request.POST,
                instance=getattr(self.object, 'employment_info', None)
            )
        else:
            context['personal_form'] = PersonalInformationForm(
                instance=self.object.personal_info
            )
            context['address_form'] = AddressInformationForm(
                instance=self.object.address_info
            )
            context['education_form'] = EducationInformationForm(
                instance=getattr(self.object, 'education_info', None)
            )
            context['employment_form'] = EmploymentInformationForm(
                instance=getattr(self.object, 'employment_info', None)
            )
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        personal_form = context['personal_form']
        address_form = context['address_form']
        education_form = context['education_form']
        employment_form = context['employment_form']

        if (personal_form.is_valid() and address_form.is_valid() and
            education_form.is_valid() and employment_form.is_valid()):
            with transaction.atomic():
                self.object = form.save()
                personal_form.instance.enumeration = self.object
                personal_form.save()
                address_form.instance.enumeration = self.object
                address_form.save()

                if education_form.instance.pk:
                    education_form.save()
                else:
                    education_info = education_form.save(commit=False)
                    education_info.enumeration = self.object
                    education_info.save()

                if employment_form.instance.pk:
                    employment_form.save()
                else:
                    employment_info = employment_form.save(commit=False)
                    employment_info.enumeration = self.object
                    employment_info.save()

            return super().form_valid(form)
        else:
            return self.render_to_response(
                self.get_context_data(form=form)
            )

class AddressSearchViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AddressInformation.objects.all()
    serializer_class = AddressInformationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()

        district = self.request.query_params.get('district')
        if district:
            queryset = queryset.filter(district__iexact=district)
        return queryset


class LanguageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Language.objects.filter(is_active=True)
    serializer_class = LanguageSerializer
    permission_classes = [permissions.AllowAny]

class SystemSettingViewSet(viewsets.ModelViewSet):
    serializer_class = SystemSettingSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        if self.request.user.is_superuser:
            return SystemSetting.objects.all()
        return SystemSetting.objects.filter(is_public=True)

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all().order_by('-created_at')
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        queryset = super().get_queryset()

        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user__id=user_id)

        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action__iexact=action)

        return queryset
