from app import app, db, Product

def seed_database():
    with app.app_context():
        # Очистка существующих данных
        Product.query.delete()
        
        # Создание тестовых продуктов
        products = [
            Product(
                name='Арматура А500С',
                description='Арматура строительная рифленая класса А500С. Применяется для армирования железобетонных конструкций.',
                price=65000,
                category='Арматура',
                image_url='https://via.placeholder.com/400x300'
            ),
            Product(
                name='Лист стальной горячекатаный',
                description='Лист стальной горячекатаный, марка стали Ст3сп5, толщина 4 мм. Широко применяется в строительстве и машиностроении.',
                price=75000,
                category='Листовой прокат',
                image_url='https://via.placeholder.com/400x300'
            ),
            Product(
                name='Труба профильная',
                description='Труба профильная 40х40х3 мм, сталь Ст3. Используется в строительстве и производстве металлоконструкций.',
                price=85000,
                category='Трубный прокат',
                image_url='https://via.placeholder.com/400x300'
            ),
            Product(
                name='Швеллер',
                description='Швеллер 16П, сталь Ст3пс5. Применяется в строительстве и производстве металлоконструкций.',
                price=72000,
                category='Фасонный прокат',
                image_url='https://via.placeholder.com/400x300'
            ),
            Product(
                name='Уголок стальной',
                description='Уголок равнополочный 50х50х5 мм, сталь Ст3пс. Используется в строительстве и производстве металлоконструкций.',
                price=68000,
                category='Фасонный прокат',
                image_url='https://via.placeholder.com/400x300'
            )
        ]
        
        # Добавление продуктов в базу данных
        for product in products:
            db.session.add(product)
        
        # Сохранение изменений
        db.session.commit()

if __name__ == '__main__':
    seed_database()
    print('База данных успешно заполнена тестовыми данными!') 