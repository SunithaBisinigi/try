from django.contrib import admin
from django.urls import path, include
from authapi.views import registration, login_view


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('authapi.urls')),
    path('registration/', registration, name='registration'),
    # path('api/login/', login_view, name='login'),
]