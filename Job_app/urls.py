from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login_view'),  # Home route redirects to login
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
    
    # Dashboard routes
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard/company/', views.dashboard_company, name='dashboard_company'),
    path('dashboard/applicant/', views.dashboard_applicant, name='dashboard_applicant'),
    path('dashboard/admin/', views.dashboard_admin, name='dashboard_admin'),

    # Job routes
    path('post-job/', views.post_job, name='post_job'),
    path('apply/<int:job_id>/', views.apply_job, name='apply_job'),

    path('edit-job/<int:job_id>/', views.edit_job, name='edit_job'),
    path('delete-job/<int:job_id>/', views.delete_job, name='delete_job'),
    path('view-applications/<int:job_id>/', views.view_applications, name='view_applications'),

    path('forgot-password/', views.forgot_password_request, name='forgot_password_request'),
    path('reset-password/', views.forgot_password_reset, name='forgot_password_reset'),
    path('job/<int:job_id>/preview/', views.job_preview, name='job_preview'),

]   