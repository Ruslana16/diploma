
"Balsu Vilnis" balsošanas platforma
--------------------------------------------------------------------------
Šī ir Flask tīmekļa lietotne, kas nodrošina ideju izveides, pieteikšanās, reģistrācijas, komentēšanas, balsošanas un citas funkcijas.
--------------------------------------------------------------------------

1. Variants
Ieet mājaslapā, izmantojot saiti: https://balsuvilnis-fea66957ce1f.herokuapp.com/


2. Variants

Priekšnoteikumi:
//Python 3.6+
//Virtuālā vide (nav obligāta, bet ieteicama)
//Datubāze (piemēram, SQLite, PostgreSQL, MySQL)

-----------
Instalācija
-----------

1.) //Klona repo:

bash
Copy code
git clone <https://github.com/Ruslana16/diploma/tree/main>
cd <jūsu_repozitorijas_direktorija>


2.) //Izveidojiet un aktivizējiet virtuālo vidi:

bash
Copy code
python -m venv venv
source venv/bin/activate   # MacOS/Linux
venv\Scripts\activate      # Windows


3.) //Instalējiet nepieciešamos pakotnes:

bash
Copy code
pip install -r requirements.txt

4.) //Izveidojiet .env failu projekta saknes direktorijā un pievienojiet šādas vides mainīgos:

env
SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///site.db   # Vai jūsu datubāzes URI
RECAPTCHA_PUBLIC_KEY=your_recaptcha_public_key
RECAPTCHA_PRIVATE_KEY=your_recaptcha_private_key
MAIL_SERVER=smtp.yourmailserver.com
MAIL_PORT=587
MAIL_USE_TLS=1
MAIL_USERNAME=your_email_username
MAIL_PASSWORD=your_email_password

5.) //Iniciējiet datubāzi:

bash
Copy code
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
Lietotnes palaišana

6.) //Palaižiet Flask serveri:

bash
Copy code
flask run

7.) //Pēc tam, atveriet tīmekļa pārlūkprogrammu un apmeklējiet http://127.0.0.1:5000
