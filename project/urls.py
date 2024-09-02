from django.urls import re_path, path
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from admins.views import Authorization
from admins.views import Menu_list
from admins.views import Menu_list_edit
from admins.views import Menu_list_create
from admins.views import Menu_list_delete
from admins.views import Menu_dish_get
from admins.views import Menu_dish_edit
from admins.views import Menu_dish_create
from admins.views import Menu_list_dish_get
from admins.views import Menu_dish_delete
from admins.views import Telegram_api
from admins.views import Menu_dish_get_definite
from admins.views import Menu_dish_status
from admins.views import Authorization_number
from admins.views import Menu_list_status
from admins.views import Organizations_IIKO
from admins.views import FetchAndSaveMenu
from admins.views import FotoUploadView
from admins.views import user_Menu_list
from admins.views import user_Menu_dish_get
from admins.views import user_Menu_list_dish_get
from admins.views import user_Menu_dish_get_definite
from admins.views import OrderCreateView
from django.conf.urls.static import static
#Схема Swagger

schema_view = get_schema_view(
    openapi.Info(
        title="Информация об API",
        default_version='v1',
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    authentication_classes=[],
)

#Роутинг + статика
urlpatterns = [
    path('tg_api/', include('admins.urls')),
    path('api/admin/authorization/', Authorization.as_view(), name='my-api'),
    path('api/admin/menu/get/', Menu_list.as_view(), name='menu_list'),
    path('api/admin/menu/edit/<int:id_menu>/', Menu_list_edit.as_view(), name='menu_list_edit'),
    path('api/admin/menu/create/', Menu_list_create.as_view(), name='menu_list_create'),
    path('api/admin/menu/delete/<int:id_menu>/', Menu_list_delete.as_view(), name='menu_list_delete'),
    path('api/admin/dish/get/', Menu_dish_get.as_view(), name='menu_dish_get'),
    path('api/admin/dish/edit/<int:dish_id>/', Menu_dish_edit.as_view(), name='menu_dish_edit'),
    path('api/admin/dish/create/', Menu_dish_create.as_view(), name='menu_dish_create'),
    path('api/admin/dish/list_get/<int:menu_id>/', Menu_list_dish_get.as_view(), name='menu_list_dish_get'),
    path('api/admin/dish/delete/<int:dish_id>/', Menu_dish_delete.as_view(), name='menu_dish_delete'),
    path('api/admin/telegram/', Telegram_api.as_view(), name='telegram'),
    path('api/admin/dish/definite/<int:id_dish>/', Menu_dish_get_definite.as_view(), name='menu_dish_get_definite'),
    path('api/admin/dish/status/<int:dish_id>/', Menu_dish_status.as_view(), name='menu_dish_status'),
    path('api/admin/authorization_number/', Authorization_number.as_view(), name='authorization_number'),
    path('api/admin/menu/status/<int:id_menu>/', Menu_list_status.as_view(), name='menu_list_status'),
    path('api/admin/organizations_IIKO/', Organizations_IIKO.as_view(), name='organizations_IIKO'),
    path('api/admin/fetchAndSaveMenu/', FetchAndSaveMenu.as_view(), name='fetchAndSaveMenu'),
    path('api/user/menu/list/<int:id_rest>/', user_Menu_list.as_view(), name='user_Menu_list'),
    path('api/user/dish/list/<int:id_rest>/', user_Menu_dish_get.as_view(), name='user_Menu_dish_get'),
    path('api/user/dish/general/<int:menu_id>/<int:id_rest>/', user_Menu_list_dish_get.as_view(), name='user_Menu_list_dish_get'),
    path('api/user/dish/definite/<int:id_dish>/', user_Menu_dish_get_definite.as_view(), name='user_Menu_dish_get_definite'),
    path('api/user/order/create/<int:id_rest>/', OrderCreateView.as_view(), name='OrderCreateView'),
    path('api/admin/image/upload/', FotoUploadView.as_view(), name='fotoUploadView'),
    path('api/swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('api/swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('admin/', admin.site.urls),
]
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)