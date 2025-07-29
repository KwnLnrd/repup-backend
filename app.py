import os
import re
import traceback
import logging
import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, desc, Text
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, get_jwt

# --- CONFIGURATION INITIALE ---
load_dotenv()
app = Flask(__name__)

# --- CONFIGURATION DU DOSSIER DE TÉLÉVERSEMENT ---
UPLOAD_FOLDER = 'uploads' # Utiliser un chemin relatif pour la compatibilité
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGGING ---
app.logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# --- CORS ---
CORS(app, origins=["*"], supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

# --- CONFIGURATION BDD & JWT ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is not set.")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
     database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "une-cle-vraiment-secrete-et-longue-pour-la-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- MODÈLES DE LA BASE DE DONNÉES ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    restaurant = db.relationship('Restaurant', back_populates='user', uselist=False)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    logo_url = db.Column(db.Text, nullable=True)
    primary_color = db.Column(db.String(7), default='#BF5B3F')
    google_link = db.Column(db.Text, nullable=True)
    tripadvisor_link = db.Column(db.Text, nullable=True)
    enabled_languages = db.Column(db.JSON, default=['fr', 'en'])
    user = db.relationship('User', back_populates='restaurant', cascade="all, delete-orphan")
    servers = db.relationship('Server', back_populates='restaurant', cascade="all, delete-orphan")
    dishes = db.relationship('Dish', back_populates='restaurant', cascade="all, delete-orphan")
    custom_tags = db.relationship('CustomTag', back_populates='restaurant', cascade="all, delete-orphan")

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

class CustomTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False, index=True) 
    text = db.Column(db.String(100), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='custom_tags')

with app.app_context():
    db.create_all()

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

def get_restaurant_id_from_token():
    user = get_jwt_identity()
    return User.query.get(user).restaurant_id

def generate_unique_slug(name, restaurant_id):
    base_slug = name.lower().replace(' ', '-')
    base_slug = re.sub(r'[^a-z0-9-]', '', base_slug)
    return f"{base_slug}-{restaurant_id}"

# --- ROUTES ---

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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

    default_tags = {
        'service': ["Attentionné", "Souriant", "Professionnel", "Efficace", "De bon conseil", "Discret"],
        'occasion': ["Anniversaire", "Dîner romantique", "Entre amis", "En famille", "Affaires", "Simple visite"],
        'atmosphere': ["La Décoration", "La Musique", "L'Énergie Festive", "L'Éclairage", "Le Confort", "Romantique"]
    }
    for category, texts in default_tags.items():
        for text in texts:
            db.session.add(CustomTag(category=category, text=text, restaurant_id=new_restaurant.id))
    
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password_hash=hashed_password, restaurant_id=new_restaurant.id)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Compte créé avec succès"}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Identifiants invalides"}), 401

@app.route('/api/public/restaurant/<string:slug>', methods=['GET'])
def get_restaurant_public_data(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()
    servers = Server.query.filter_by(restaurant_id=restaurant.id).all()
    tags = CustomTag.query.filter_by(restaurant_id=restaurant.id).all()
    
    custom_tags_by_category = {}
    for tag in tags:
        if tag.category not in custom_tags_by_category:
            custom_tags_by_category[tag.category] = []
        custom_tags_by_category[tag.category].append({"id": tag.id, "text": tag.text})

    return jsonify({
        "name": restaurant.name, "logoUrl": restaurant.logo_url, "primaryColor": restaurant.primary_color,
        "links": {"google": restaurant.google_link, "tripadvisor": restaurant.tripadvisor_link},
        "servers": [{"id": s.id, "name": s.name, "avatar": s.avatar_url} for s in servers],
        "languages": restaurant.enabled_languages,
        "tags": custom_tags_by_category
    })

@app.route('/api/public/menu/<string:slug>', methods=['GET'])
def get_public_menu(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()
    dishes = Dish.query.filter_by(restaurant_id=restaurant.id).all()
    
    menu_by_category = {}
    for dish in dishes:
        if dish.category not in menu_by_category:
            menu_by_category[dish.category] = []
        menu_by_category[dish.category].append({"id": dish.id, "name": dish.name})
    return jsonify(menu_by_category)

@app.route('/api/generate-review', methods=['POST'])
def generate_review_proxy():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify({"error": "La clé API OpenAI n'est pas configurée sur le serveur."}), 500
    data = request.get_json()
    prompt = data.get('prompt')
    if not prompt:
        return jsonify({"error": "Le prompt est manquant."}), 400
    openai_url = 'https://api.openai.com/v1/chat/completions'
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'}
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "Tu es un assistant IA qui rédige des avis de restaurant positifs et engageants."}, {"role": "user", "content": prompt}]
    }
    try:
        response = requests.post(openai_url, headers=headers, json=payload)
        response.raise_for_status()
        openai_data = response.json()
        review_text = openai_data['choices'][0]['message']['content'].strip()
        return jsonify({"review": review_text})
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erreur lors de l'appel à l'API OpenAI: {e}")
        return jsonify({"error": f"Erreur de communication avec l'API OpenAI: {e}"}), 502
    except (KeyError, IndexError) as e:
        app.logger.error(f"Réponse inattendue de l'API OpenAI: {openai_data}")
        return jsonify({"error": "Format de réponse inattendu de la part d'OpenAI."}), 500

# --- ROUTES PROTÉGÉES ---

@app.route('/api/restaurant', methods=['GET', 'PUT'])
@jwt_required()
def manage_restaurant_settings():
    restaurant_id = get_restaurant_id_from_token()
    restaurant = db.session.get(Restaurant, restaurant_id)
    if not restaurant: return jsonify({"error": "Restaurant non trouvé"}), 404
    if request.method == 'GET':
        return jsonify({
            "name": restaurant.name, "slug": restaurant.slug, "logoUrl": restaurant.logo_url,
            "primaryColor": restaurant.primary_color, "googleLink": restaurant.google_link,
            "tripadvisorLink": restaurant.tripadvisor_link, "enabledLanguages": restaurant.enabled_languages
        })
    elif request.method == 'PUT':
        data = request.form
        restaurant.name = data.get('name', restaurant.name)
        restaurant.primary_color = data.get('primaryColor', restaurant.primary_color)
        restaurant.google_link = data.get('googleLink', restaurant.google_link)
        restaurant.tripadvisor_link = data.get('tripadvisorLink', restaurant.tripadvisor_link)
        restaurant.enabled_languages = request.get_json().get('enabledLanguages', restaurant.enabled_languages)
        
        if 'logo' in request.files:
            file = request.files['logo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = f'/uploads/{filename}'
        
        db.session.commit()
        return jsonify({"message": "Paramètres mis à jour"})

@app.route('/api/tags', methods=['GET', 'POST'])
@jwt_required()
def manage_tags():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        tags = CustomTag.query.filter_by(restaurant_id=restaurant_id).order_by(CustomTag.category, CustomTag.id).all()
        tags_by_category = {}
        for tag in tags:
            if tag.category not in tags_by_category: tags_by_category[tag.category] = []
            tags_by_category[tag.category].append({"id": tag.id, "text": tag.text})
        return jsonify(tags_by_category)
    if request.method == 'POST':
        data = request.get_json()
        new_tag = CustomTag(text=data['text'], category=data['category'], restaurant_id=restaurant_id)
        db.session.add(new_tag)
        db.session.commit()
        return jsonify({"id": new_tag.id, "text": new_tag.text}), 201

@app.route('/api/tags/<int:tag_id>', methods=['DELETE'])
@jwt_required()
def delete_tag(tag_id):
    restaurant_id = get_restaurant_id_from_token()
    tag = CustomTag.query.filter_by(id=tag_id, restaurant_id=restaurant_id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    return '', 204

@app.route('/api/servers', methods=['GET', 'POST'])
@jwt_required()
def manage_servers():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        servers = Server.query.filter_by(restaurant_id=restaurant_id).all()
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

@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@jwt_required()
def delete_server(server_id):
    restaurant_id = get_restaurant_id_from_token()
    server = Server.query.filter_by(id=server_id, restaurant_id=restaurant_id).first_or_404()
    db.session.delete(server)
    db.session.commit()
    return '', 204

@app.route('/api/menu', methods=['GET', 'POST'])
@jwt_required()
def manage_menu():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        dishes = Dish.query.filter_by(restaurant_id=restaurant_id).all()
        menu_by_category = {}
        for dish in dishes:
            if dish.category not in menu_by_category: menu_by_category[dish.category] = []
            menu_by_category[dish.category].append({"id": dish.id, "name": dish.name})
        return jsonify(menu_by_category)
    if request.method == 'POST':
        data = request.get_json()
        if not data.get('name') or not data.get('category'):
            return jsonify({"error": "Le nom et la catégorie sont requis"}), 400
        new_dish = Dish(name=data['name'], category=data['category'], restaurant_id=restaurant_id)
        db.session.add(new_dish)
        db.session.commit()
        return jsonify({"id": new_dish.id, "name": new_dish.name, "category": new_dish.category}), 201

@app.route('/api/menu/<int:dish_id>', methods=['DELETE'])
@jwt_required()
def delete_dish(dish_id):
    restaurant_id = get_restaurant_id_from_token()
    dish = Dish.query.filter_by(id=dish_id, restaurant_id=restaurant_id).first_or_404()
    db.session.delete(dish)
    db.session.commit()
    return '', 204

if __name__ == '__main__':
    app.run(debug=True)
