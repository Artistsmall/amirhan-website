from app import app, db, User, Product, ScrapMetal
from werkzeug.security import generate_password_hash

def seed_database():
    with app.app_context():
        # Создаем таблицы
        db.create_all()

        # Добавляем администратора
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)

        # Добавляем тестового пользователя
        if not User.query.filter_by(email='test@test.com').first():
            test_user = User(
                email='test@test.com',
                password_hash=generate_password_hash('test123')
            )
            db.session.add(test_user)

        # Добавляем товары
        products = [
            {
                'name': 'Арматура 12мм А500С',
                'description': 'Арматура рифленая, длина 6м, диаметр 12мм, класс А500С. Используется для армирования железобетонных конструкций.',
                'price': 890.00,
                'category': 'Арматура',
                'image_url': '/static/images/products/armatura.jpg'
            },
            {
                'name': 'Лист стальной 2мм',
                'description': 'Лист стальной горячекатаный, толщина 2мм, размер 1.25x2.5м. Подходит для изготовления металлоконструкций и общестроительных работ.',
                'price': 2450.00,
                'category': 'Листовой металл',
                'image_url': '/static/images/products/list.jpg'
            },
            {
                'name': 'Труба профильная 40x40',
                'description': 'Труба профильная 40x40мм, толщина стенки 2мм, длина 6м. Идеально подходит для создания каркасных конструкций и ограждений.',
                'price': 1200.00,
                'category': 'Трубы',
                'image_url': '/static/images/products/truba.jpg'
            },
            {
                'name': 'Швеллер 10П',
                'description': 'Швеллер стальной 10П, длина 12м. Применяется в строительстве и производстве металлоконструкций.',
                'price': 1560.00,
                'category': 'Профиль',
                'image_url': '/static/images/products/shveller.jpg'
            },
            {
                'name': 'Уголок 50x50x5',
                'description': 'Уголок равнополочный 50x50x5мм, длина 6м. Широко используется в строительстве и производстве.',
                'price': 780.00,
                'category': 'Профиль',
                'image_url': '/static/images/products/ugolok.jpg'
            }
        ]

        for product_data in products:
            if not Product.query.filter_by(name=product_data['name']).first():
                product = Product(**product_data)
                db.session.add(product)

        # Добавляем типы металлолома
        scrap_metals = [
            {
                'name': 'Черный металлолом 3А',
                'description': 'Габаритный стальной лом толщиной от 4мм, размером до 1500х500х500мм. Принимаем любые объемы.',
                'price_per_kg': 25.50,
                'category': 'Черный металл',
                'image_url': '/static/images/scrap/chermet.jpg'
            },
            {
                'name': 'Медь блеск',
                'description': 'Чистая медь (провода, листы) без примесей и окислений. Высокая цена за качественное сырье.',
                'price_per_kg': 520.00,
                'category': 'Цветной металл',
                'image_url': '/static/images/scrap/med.jpg'
            },
            {
                'name': 'Алюминий электротех',
                'description': 'Электротехнический алюминий (провода, шины). Принимаем как целые изделия, так и лом.',
                'price_per_kg': 150.00,
                'category': 'Цветной металл',
                'image_url': '/static/images/scrap/alum.jpg'
            },
            {
                'name': 'Нержавеющая сталь',
                'description': 'Нержавеющий металлолом различных марок. Производим анализ на содержание легирующих элементов.',
                'price_per_kg': 180.00,
                'category': 'Спецстали',
                'image_url': '/static/images/scrap/nerzh.jpg'
            }
        ]

        for metal_data in scrap_metals:
            if not ScrapMetal.query.filter_by(name=metal_data['name']).first():
                metal = ScrapMetal(**metal_data)
                db.session.add(metal)

        db.session.commit()

if __name__ == '__main__':
    seed_database()
    print('База данных успешно заполнена тестовыми данными!')