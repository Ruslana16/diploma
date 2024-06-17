
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


1.) //Izveidojiet un aktivizējiet virtuālo vidi:

bash
Copy code
python -m venv venv
source venv/bin/activate   # MacOS/Linux
venv\Scripts\activate      # Windows


2.) //Instalējiet nepieciešamos pakotnes:

bash
Copy code
pip install -r requirements.txt

3.) //Izveidojiet .env failu projekta saknes direktorijā un pievienojiet šādas vides mainīgos:

SECRET_KEY=supersecretkey
SECURITY_PASSWORD_SALT=my_precious_two
DATABASE_URL=sqlite:///site.db
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=cjvuiwsaqwpa
MAIL_DEFAULT_SENDER=votewave111@gmail.com
FLASK_ENV=development
FLASK_DEBUG=1
RECAPTCHA_PRIVATE_KEY=6LfQF_EpAAAAAFfx_BOWhuqQYeAI8M1uqgdC0RsI
RECAPTCHA_PUBLIC_KEY=6LfQF_EpAAAAAJRD1RNayz0jOJrNzgGlMJN6G49Q

4.) //Iniciējiet datubāzi:

bash
Copy code
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
Lietotnes palaišana

5.) //Palaižiet Flask serveri:

bash
Copy code
flask run

6.) //Pēc tam, atveriet tīmekļa pārlūkprogrammu un apmeklējiet http://127.0.0.1:5000
