from django.contrib import admin
from .models import UserProfile, Company, Applicant, Job, Application

admin.site.register(UserProfile)
admin.site.register(Company)
admin.site.register(Applicant)
admin.site.register(Job)
admin.site.register(Application)



