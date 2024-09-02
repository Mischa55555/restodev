from django.contrib import admin
from .models import Category, Restaurant, Administrator, Ingredients, Label, Foto, Dish, Order

class AssetAdmin_1(admin.ModelAdmin):
    list_display = ('id', 'name', 'show', 'id_rest')
admin.site.register(Category, AssetAdmin_1)

class AssetAdmin_2(admin.ModelAdmin):
    list_display = ('name', 'legal_person')
    fields = ("name", "legal_person", "id_iiko", "id_chanel", "org_iiko")
admin.site.register(Restaurant, AssetAdmin_2)

class AssetAdmin_3(admin.ModelAdmin):
    list_display = ('administrator_name', 'administrator_surname', 'administrator_patronymic', 'status', 'id_yandex', 'id_rest')
    fields = ("administrator_name", "administrator_surname", "administrator_patronymic", "status", "number", "administrator_password", "id_rest")
admin.site.register(Administrator, AssetAdmin_3)

admin.site.register(Ingredients)

admin.site.register(Label)

admin.site.register(Foto)

admin.site.register(Dish)

admin.site.register(Order)
# Register your models here.