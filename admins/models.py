from django.db import models

class Restaurant(models.Model):
    name = models.CharField(max_length=500, verbose_name="Наименование")
    legal_person = models.CharField(max_length=500, verbose_name="Юридическое лицо")
    id_iiko = models.CharField(max_length=500, verbose_name="API ключ IIKO", help_text ="Инструкция по получению: https://disk.yandex.ru/i/PZWTkEYLxv8AqA", blank=True)
    org_iiko = models.CharField(max_length=500, verbose_name="ID организации IIKO", help_text ="Заполняется автоматически. При необходимости используйте метод API Organizations_IIKO", blank=True)
    id_chanel = models.CharField(max_length=500, verbose_name="ID группы Telegram для информирования", help_text ="Инструкция по получению: https://disk.yandex.ru/d/StPnx-wW-bYKAg", blank=True)
    class Meta:
        verbose_name = 'информацию о ресторане'
        verbose_name_plural = 'информация о ресторане'
    def __str__(self):
        return str(self.id)

class Administrator(models.Model):
    administrator_name = models.CharField(max_length=500, verbose_name="Имя")
    administrator_surname = models.CharField(max_length=500, verbose_name="Фамилия")
    administrator_patronymic = models.CharField(max_length=500, verbose_name="Отчество")
    status = models.CharField(max_length=500, verbose_name="Статус", help_text ="На данный момент времени доступен лишь \"admin\"")
    id_yandex = models.CharField(max_length=500, verbose_name="ID Яндекс", blank=True)
    number = models.CharField(max_length=500, verbose_name="Номер телефона в формате 79051757737")
    administrator_password = models.CharField(max_length=500, verbose_name="Пароль пользователя")
    id_rest = models.ForeignKey(Restaurant, on_delete=models.CASCADE, verbose_name="ID ресторана")
    class Meta:
        verbose_name = 'информацию о администраторах'
        verbose_name_plural = 'информация о администраторах'
    def __str__(self):
        return str(self.id)
        
class Category(models.Model):
    name = models.CharField(max_length=500, verbose_name="Наименование")
    parrent = models.ForeignKey('self', on_delete=models.CASCADE, verbose_name="ID родительской категории", blank=True, null=True)
    des = models.CharField(max_length=500, verbose_name="Рабочее поле (не заполнять)", null=True, blank=True)
    show = models.BooleanField(max_length=500, verbose_name="Отображение")
    id_rest = models.ForeignKey(Restaurant, on_delete=models.CASCADE, verbose_name="ID ресторана")
    class Meta:
        verbose_name = 'категорию меню'
        verbose_name_plural = 'категория меню'
    def __str__(self):
        return str(self.id)
        
class Ingredients(models.Model):
    name = models.CharField(max_length=500, verbose_name="Наименование")
    class Meta:
        verbose_name = 'ингредиенты'
        verbose_name_plural = 'ингредиенты'
    def __str__(self):
        return str(self.name)
        
class Label(models.Model):
    name = models.CharField(max_length=500, verbose_name="Наименование")
    class Meta:
        verbose_name = 'Label'
        verbose_name_plural = 'Label'
    def __str__(self):
        return str(self.name)

class Foto(models.Model):
    image = models.ImageField(upload_to='images/', verbose_name="Фотография")
    description = models.CharField(max_length=500, verbose_name="Описание")
    class Meta:
        verbose_name = 'фотографию'
        verbose_name_plural = 'фотография'
    def __str__(self):
        return str(self.id)
        
class Dish(models.Model):
    id_rest = models.ForeignKey(Restaurant, on_delete=models.CASCADE, verbose_name="ID ресторана")
    cat_id = models.ForeignKey(Category, on_delete=models.CASCADE, verbose_name="ID категории")
    name = models.CharField(max_length=500, verbose_name="Наименование")
    ingredients = models.ManyToManyField(Ingredients)
    weight = models.FloatField(verbose_name="Масса")
    cost = models.FloatField(verbose_name="Стоимость")
    cooking_time = models.CharField(max_length=500, verbose_name="Время приготовления")
    photo = models.ForeignKey(Foto, on_delete=models.SET_NULL, null=True, verbose_name="Фотогрфия")
    label = models.ManyToManyField(Label)
    kall = models.CharField(max_length=500, verbose_name="Калорийность")
    show = models.BooleanField(max_length=500, verbose_name="Отображение")
    description = models.CharField(max_length=500, verbose_name="Описание")
    class Meta:
        verbose_name = 'блюдо'
        verbose_name_plural = 'блюдо'
    def __str__(self):
        return str(self.id)
        
class Order(models.Model):
    id_rest = models.ForeignKey(Restaurant, on_delete=models.CASCADE, verbose_name="ID ресторана")
    table_id = models.CharField(max_length=500, verbose_name="ID стола")
    dishes = models.ManyToManyField(Dish, verbose_name="Блюда")
    total_amount = models.FloatField(verbose_name="Сумма заказа", blank=True, null=True)

    class Meta:
        verbose_name = 'заказ'
        verbose_name_plural = 'заказы'

    def __str__(self):
        return str(self.id)