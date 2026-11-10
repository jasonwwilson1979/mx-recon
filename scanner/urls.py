from django.urls import path

from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.index, name="index"),
    path("api/scan", views.api_scan, name="api_scan"),
    path("api/diagnose", views.api_diagnose, name="api_diagnose"),
    path("api/resolvers", views.api_resolvers, name="api_resolvers"),
    path("api/probe", views.api_probe, name="api_probe"),
    path("api/rbl-check", views.api_rbl_check, name="api_rbl_check"),
    path("healthz", views.healthz, name="healthz"),
]
