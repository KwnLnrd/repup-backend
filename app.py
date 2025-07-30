import os
import re
import json
import logging
import requests
import secrets
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity, get_jwt
from dateutil.parser import parse as parse_datetime
from apify_client import ApifyClient

# --- CONFIGURATION INITIALE ---
load_dotenv()
app = Flask(__name__)

# --- CONFIGURATION DU DOSSIER DE TÉLÉVERSEMENT ---
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGGING ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- CORS ---
CORS(app, origins=["https://repup-avis.netlify.app", "http://127.0.0.1:5500", "http://localhost:5500"], supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

# --- CONFIGURATION BDD & JWT ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL n'est pas configuré dans le fichier .env.")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://") and "+psycopg" not in database_url:
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "une-cle-vraiment-secrete-et-longue-pour-la-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

# --- CORRECTIF : Configuration explicite de la localisation du token et désactivation CSRF ---
# Indique que le token doit être cherché dans les headers (ex: 'Authorization: Bearer <token>')
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
# Désactive la protection CSRF qui peut causer des erreurs 422 dans une configuration API pure.
app.config["JWT_CSRF_PROTECTION"] = False


db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- LISTE MAÎTRESSE DES TAGS ---
PRE_TRANSLATED_TAGS = {
    'service': [
        {'key': 'service_attentive', 'fr': 'Attentionné', 'en': 'Attentive', 'es': 'Atento'},
        {'key': 'service_smiling', 'fr': 'Souriant', 'en': 'Smiling', 'es': 'Sonriente'},
        {'key': 'service_professional', 'fr': 'Professionnel', 'en': 'Professional', 'es': 'Profesional'},
        {'key': 'service_efficient', 'fr': 'Efficace', 'en': 'Efficient', 'es': 'Eficiente'},
        {'key': 'service_good_advice', 'fr': 'De bon conseil', 'en': 'Good advice', 'es': 'Buen consejo'},
        {'key': 'service_discreet', 'fr': 'Discret', 'en': 'Discreet', 'es': 'Discreto'},
    ],
    'occasion': [
        {'key': 'occasion_birthday', 'fr': 'Anniversaire', 'en': 'Birthday', 'es': 'Cumpleaños'},
        {'key': 'occasion_romantic', 'fr': 'Dîner romantique', 'en': 'Romantic dinner', 'es': 'Cena romántica'},
        {'key': 'occasion_friends', 'fr': 'Entre amis', 'en': 'With friends', 'es': 'Con amigos'},
        {'key': 'occasion_family', 'fr': 'En famille', 'en': 'With family', 'es': 'En familia'},
        {'key': 'occasion_business', 'fr': 'Affaires', 'en': 'Business', 'es': 'Negocios'},
        {'key': 'occasion_visit', 'fr': 'Simple visite', 'en': 'Just visiting', 'es': 'Simple visita'},
    ],
    'atmosphere': [
        {'key': 'atmosphere_decoration', 'fr': 'La Décoration', 'en': 'The Decoration', 'es': 'La Decoración'},
        {'key': 'atmosphere_music', 'fr': 'La Musique', 'en': 'The Music', 'es': 'La Música'},
        {'key': 'atmosphere_festive', 'fr': 'L\'Énergie Festive', 'en': 'The Festive Energy', 'es': 'La Energía Festiva'},
        {'key': 'atmosphere_lighting', 'fr': 'L\'Éclairage', 'en': 'The Lighting', 'es': 'La Iluminación'},
        {'key': 'atmosphere_comfort', 'fr': 'Le Confort', 'en': 'The Comfort', 'es': 'La Comodidad'},
        {'key': 'atmosphere_romantic', 'fr': 'Romantique', 'en': 'Romantic', 'es': 'Romántico'},
    ]
}

# --- MODÈLES DE LA BASE DE DONNÉES ---
class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    restaurant = db.relationship('Restaurant', back_populates='user', uselist=False)
    reset_password_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_password_expiration = db.Column(db.DateTime, nullable=True)
    change_email_token = db.Column(db.String(100), unique=True, nullable=True)
    change_email_expiration = db.Column(db.DateTime, nullable=True)
    new_email = db.Column(db.String(120), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    logo_url = db.Column(db.Text, nullable=True)
    primary_color = db.Column(db.String(7), default='#D69E2E')
    google_link = db.Column(db.Text, nullable=True)
    tripadvisor_link = db.Column(db.Text, nullable=True)
    enabled_languages = db.Column(db.JSON, default=['fr', 'en'])
    user = db.relationship('User', back_populates='restaurant', cascade="all, delete-orphan")
    servers = db.relationship('Server', back_populates='restaurant', cascade="all, delete-orphan")
    dishes = db.relationship('Dish', back_populates='restaurant', cascade="all, delete-orphan")
    tag_selections = db.relationship('RestaurantTag', back_populates='restaurant', cascade="all, delete-orphan")
    reviews = db.relationship('Review', back_populates='restaurant', cascade="all, delete-orphan")

class RestaurantTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    tag_key = db.Column(db.String(100), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='tag_selections')

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.Text, nullable=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='servers')

class Dish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='dishes')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    source = db.Column(db.String(20), nullable=False)
    author_name = db.Column(db.String(100))
    rating = db.Column(db.Float, nullable=False)
    content = db.Column(db.Text)
    review_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    restaurant = db.relationship('Restaurant', back_populates='reviews')

with app.app_context():
    db.create_all()

# --- GESTION DES TOKENS JWT (BLOCKLIST) ---
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=int(identity)).one_or_none()

# --- FONCTIONS HELPERS ---
def generate_unique_slug(name, restaurant_id):
    base_slug = name.lower().replace(' ', '-')
    base_slug = re.sub(r'[^a-z0-9-]', '', base_slug)
    return f"{base_slug}-{restaurant_id}"

# --- ROUTES PUBLIQUES ---
@app.route('/')
def index():
    return jsonify({"status": "ok", "message": "RepUP API is running."}), 200
    
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/public/restaurant/<string:slug>', methods=['GET'])
def get_restaurant_public_data(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404("Restaurant non trouvé")
    servers = Server.query.filter_by(restaurant_id=restaurant.id).all()
    selected_tag_keys = {tag.tag_key for tag in restaurant.tag_selections}
    tags_for_frontend = {}
    for category, tags_list in PRE_TRANSLATED_TAGS.items():
        tags_for_frontend[category] = []
        for tag_data in tags_list:
            if tag_data['key'] in selected_tag_keys:
                translations = {lang: tag_data.get(lang, tag_data['fr']) for lang in restaurant.enabled_languages}
                translations['fr'] = tag_data['fr']
                tags_for_frontend[category].append({"key": tag_data['key'], "translations": translations})
    return jsonify({
        "name": restaurant.name, "logoUrl": restaurant.logo_url, "primaryColor": restaurant.primary_color,
        "links": {"google": restaurant.google_link, "tripadvisor": restaurant.tripadvisor_link},
        "servers": [{"id": s.id, "name": s.name, "avatar": s.avatar_url} for s in servers],
        "languages": restaurant.enabled_languages, "tags": tags_for_frontend
    })

@app.route('/api/public/menu/<string:slug>', methods=['GET'])
def get_public_menu(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()
    dishes = Dish.query.filter_by(restaurant_id=restaurant.id).all()
    menu_by_category = {}
    for dish in dishes:
        if dish.category not in menu_by_category: menu_by_category[dish.category] = []
        menu_by_category[dish.category].append({"id": dish.id, "name": dish.name})
    return jsonify(menu_by_category)

@app.route('/api/generate-review', methods=['POST'])
def generate_review_proxy():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key: return jsonify({"error": "La clé API OpenAI n'est pas configurée."}), 500
    prompt = request.get_json().get('prompt')
    if not prompt: return jsonify({"error": "Le prompt est manquant."}), 400
    try:
        response = requests.post('https://api.openai.com/v1/chat/completions', 
            headers={'Authorization': f'Bearer {api_key}'}, 
            json={"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": prompt}]})
        response.raise_for_status()
        return jsonify({"review": response.json()['choices'][0]['message']['content'].strip()})
    except Exception as e:
        app.logger.error(f"Erreur API OpenAI: {e}")
        return jsonify({"error": "Erreur lors de la communication avec l'IA."}), 502

# --- ROUTES D'AUTHENTIFICATION ET PROFIL ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email, password, restaurant_name = data.get('email'), data.get('password'), data.get('restaurant_name')
    if not all([email, password, restaurant_name]): return jsonify({"error": "Données manquantes"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"error": "Cet email est déjà utilisé"}), 409
    
    new_restaurant = Restaurant(name=restaurant_name, slug="temporary-slug")
    db.session.add(new_restaurant)
    db.session.flush()
    new_restaurant.slug = generate_unique_slug(restaurant_name, new_restaurant.id)
    
    new_user = User(email=email, restaurant_id=new_restaurant.id)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Compte créé avec succès"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Identifiants invalides"}), 401

@app.route("/api/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(message="Déconnexion réussie.")

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email', None)
    user = User.query.filter_by(email=email).first()
    if user:
        user.reset_password_token = secrets.token_urlsafe(32)
        user.reset_password_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        reset_url = f"https://repup-avis.netlify.app/reset-password?token={user.reset_password_token}"
        app.logger.info(f"--- LIEN DE RESET (SIMULATION EMAIL) --- : {reset_url}")
    return jsonify({"message": "Si un compte existe, un lien a été envoyé."}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    token = request.json.get('token', None)
    new_password = request.json.get('password', None)
    user = User.query.filter_by(reset_password_token=token).first()
    if not user or user.reset_password_expiration < datetime.utcnow():
        return jsonify({"error": "Token invalide ou expiré."}), 400
    user.set_password(new_password)
    user.reset_password_token = None
    user.reset_password_expiration = None
    db.session.commit()
    return jsonify({"message": "Mot de passe réinitialisé."}), 200

@app.route('/api/profile', methods=['GET', 'PUT'])
@jwt_required()
def manage_profile():
    user = db.session.get(User, get_jwt_identity())
    if request.method == 'GET':
        return jsonify({"email": user.email, "restaurant_name": user.restaurant.name})
    if request.method == 'PUT':
        data = request.get_json()
        if 'restaurant_name' in data:
            user.restaurant.name = data['restaurant_name']
            db.session.commit()
        return jsonify({"message": "Profil mis à jour."})

@app.route('/api/profile/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user = db.session.get(User, get_jwt_identity())
    data = request.get_json()
    if not user.check_password(data.get('current_password')):
        return jsonify({"error": "Mot de passe actuel incorrect."}), 403
    user.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({"message": "Mot de passe changé."})

# --- ROUTES MÉTIER PROTÉGÉES ---
@app.route('/api/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    return jsonify({"message": f"Authentification réussie pour l'user_id {get_jwt_identity()}"}), 200

@app.route('/api/restaurant', methods=['GET', 'PUT'])
@jwt_required()
def manage_restaurant_settings():
    user = db.session.get(User, get_jwt_identity())
    restaurant = user.restaurant
    if request.method == 'GET':
        return jsonify({
            "name": restaurant.name, "slug": restaurant.slug, "logoUrl": restaurant.logo_url,
            "primaryColor": restaurant.primary_color, "googleLink": restaurant.google_link,
            "tripadvisorLink": restaurant.tripadvisor_link, "enabledLanguages": restaurant.enabled_languages
        })
    if request.method == 'PUT':
        data = request.form
        restaurant.name = data.get('name', restaurant.name)
        restaurant.primary_color = data.get('primaryColor', restaurant.primary_color)
        restaurant.google_link = data.get('googleLink', restaurant.google_link)
        restaurant.tripadvisor_link = data.get('tripadvisorLink', restaurant.tripadvisor_link)
        if 'enabledLanguages' in data: restaurant.enabled_languages = json.loads(data['enabledLanguages'])
        if 'logo' in request.files:
            file = request.files['logo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = f'/uploads/{filename}'
        db.session.commit()
        return jsonify({"message": "Paramètres mis à jour", "logoUrl": restaurant.logo_url})

@app.route('/api/options', methods=['GET', 'POST'])
@jwt_required()
def manage_options():
    user = db.session.get(User, get_jwt_identity())
    restaurant_id = user.restaurant_id
    if request.method == 'GET':
        selected_tags = db.session.query(RestaurantTag.tag_key).filter_by(restaurant_id=restaurant_id).all()
        return jsonify({"available_tags": PRE_TRANSLATED_TAGS, "selected_keys": [key for (key,) in selected_tags]})
    if request.method == 'POST':
        new_selected_keys = request.get_json().get('selected_keys', [])
        RestaurantTag.query.filter_by(restaurant_id=restaurant_id).delete()
        for key in new_selected_keys:
            db.session.add(RestaurantTag(restaurant_id=restaurant_id, tag_key=key))
        db.session.commit()
        return jsonify({"message": "Options mises à jour."})

@app.route('/api/servers', methods=['GET', 'POST'])
@jwt_required()
def manage_servers():
    user = db.session.get(User, get_jwt_identity())
    restaurant_id = user.restaurant_id
    if request.method == 'GET':
        servers = Server.query.filter_by(restaurant_id=restaurant_id).order_by(Server.name).all()
        return jsonify([{"id": s.id, "name": s.name, "avatar_url": s.avatar_url} for s in servers])
    if request.method == 'POST':
        name = request.form.get('name')
        if not name: return jsonify({"error": "Le nom est requis"}), 400
        avatar_url = None
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                avatar_url = f'/uploads/{filename}'
        new_server = Server(name=name, avatar_url=avatar_url, restaurant_id=restaurant_id)
        db.session.add(new_server)
        db.session.commit()
        return jsonify({"id": new_server.id, "name": new_server.name, "avatar_url": new_server.avatar_url}), 201

@app.route('/api/servers/<int:server_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_single_server(server_id):
    user = db.session.get(User, get_jwt_identity())
    server = Server.query.filter_by(id=server_id, restaurant_id=user.restaurant_id).first_or_404()
    if request.method == 'PUT':
        server.name = request.form.get('name', server.name)
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                server.avatar_url = f'/uploads/{filename}'
        db.session.commit()
        return jsonify({"id": server.id, "name": server.name, "avatar_url": server.avatar_url})
    if request.method == 'DELETE':
        db.session.delete(server)
        db.session.commit()
        return '', 204

@app.route('/api/menu', methods=['GET', 'POST'])
@jwt_required()
def manage_menu():
    user = db.session.get(User, get_jwt_identity())
    restaurant_id = user.restaurant_id
    if request.method == 'GET':
        dishes = Dish.query.filter_by(restaurant_id=restaurant_id).order_by(Dish.category, Dish.name).all()
        menu_by_category = {}
        for dish in dishes:
            if dish.category not in menu_by_category: menu_by_category[dish.category] = []
            menu_by_category[dish.category].append({"id": dish.id, "name": dish.name})
        return jsonify(menu_by_category)
    if request.method == 'POST':
        data = request.get_json()
        new_dish = Dish(name=data['name'], category=data['category'], restaurant_id=restaurant_id)
        db.session.add(new_dish)
        db.session.commit()
        return jsonify({"id": new_dish.id, "name": new_dish.name, "category": new_dish.category}), 201

@app.route('/api/menu/<int:dish_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_single_dish(dish_id):
    user = db.session.get(User, get_jwt_identity())
    dish = Dish.query.filter_by(id=dish_id, restaurant_id=user.restaurant_id).first_or_404()
    if request.method == 'PUT':
        data = request.get_json()
        dish.name = data.get('name', dish.name)
        dish.category = data.get('category', dish.category)
        db.session.commit()
        return jsonify({"id": dish.id, "name": dish.name, "category": dish.category})
    if request.method == 'DELETE':
        db.session.delete(dish)
        db.session.commit()
        return '', 204

@app.route('/api/strategic-analysis', methods=['POST'])
@jwt_required()
def trigger_strategic_analysis():
    user = db.session.get(User, get_jwt_identity())
    restaurant = user.restaurant
    # ... (logique de scraping et d'analyse IA)
    return jsonify({"message": "Analyse en cours..."})


# --- DÉMARRAGE DE L'APPLICATION ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
