import os
import re
import json
import logging
import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_current_user

# --- CONFIGURATION INITIALE ---
load_dotenv()
app = Flask(__name__)

# --- CONFIGURATION DU DOSSIER DE TÉLÉVERSEMENT ---
# FIX: Use a relative path for the upload folder to ensure compatibility with hosting platforms.
UPLOAD_FOLDER = 'uploads'
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


# --- LISTE MAÎTRESSE DES TAGS PRÉ-TRADUITS (MISE À JOUR) ---
PRE_TRANSLATED_TAGS = {
    'service': [
        {'key': 'service_attentive', 'fr': 'Attentionné', 'en': 'Attentive', 'es': 'Atento', 'it': 'Attento', 'pt': 'Atencioso', 'zh': '周到'},
        {'key': 'service_smiling', 'fr': 'Souriant', 'en': 'Smiling', 'es': 'Sonriente', 'it': 'Sorridente', 'pt': 'Sorridente', 'zh': '微笑'},
        {'key': 'service_professional', 'fr': 'Professionnel', 'en': 'Professional', 'es': 'Profesional', 'it': 'Professionale', 'pt': 'Profissional', 'zh': '专业的'},
        {'key': 'service_efficient', 'fr': 'Efficace', 'en': 'Efficient', 'es': 'Eficiente', 'it': 'Efficiente', 'pt': 'Eficiente', 'zh': '高效'},
        {'key': 'service_good_advice', 'fr': 'De bon conseil', 'en': 'Good advice', 'es': 'Buen consejo', 'it': 'Buon consiglio', 'pt': 'Bons conselhos', 'zh': '好建议'},
        {'key': 'service_discreet', 'fr': 'Discret', 'en': 'Discreet', 'es': 'Discreto', 'it': 'Discreto', 'pt': 'Discreto', 'zh': '谨慎'},
        {'key': 'service_warm', 'fr': 'Chaleureux', 'en': 'Warm', 'es': 'Cálido', 'it': 'Caloroso', 'pt': 'Acolhedor', 'zh': '热情'},
        {'key': 'service_fast', 'fr': 'Rapide', 'en': 'Fast', 'es': 'Rápido', 'it': 'Veloce', 'pt': 'Rápido', 'zh': '快速'},
        {'key': 'service_patient', 'fr': 'Patient', 'en': 'Patient', 'es': 'Paciente', 'it': 'Paziente', 'pt': 'Paciente', 'zh': '耐心'},
        {'key': 'service_thoughtful', 'fr': 'Prévenant', 'en': 'Thoughtful', 'es': 'Atento', 'it': 'Premuroso', 'pt': 'Atencioso', 'zh': '体贴'}
    ],
    'occasion': [
        {'key': 'occasion_birthday', 'fr': 'Anniversaire', 'en': 'Birthday', 'es': 'Cumpleaños', 'it': 'Compleanno', 'pt': 'Aniversário', 'zh': '生日'},
        {'key': 'occasion_romantic', 'fr': 'Dîner romantique', 'en': 'Romantic dinner', 'es': 'Cena romántica', 'it': 'Cena romantica', 'pt': 'Jantar romântico', 'zh': '浪漫晚餐'},
        {'key': 'occasion_friends', 'fr': 'Entre amis', 'en': 'With friends', 'es': 'Con amigos', 'it': 'Con amici', 'pt': 'Com amigos', 'zh': '与朋友'},
        {'key': 'occasion_family', 'fr': 'En famille', 'en': 'With family', 'es': 'En familia', 'it': 'In famiglia', 'pt': 'Em família', 'zh': '与家人'},
        {'key': 'occasion_business', 'fr': 'Affaires', 'en': 'Business', 'es': 'Negocios', 'it': 'Affari', 'pt': 'Negócios', 'zh': '商务'},
        {'key': 'occasion_visit', 'fr': 'Simple visite', 'en': 'Just visiting', 'es': 'Simple visita', 'it': 'Semplice visita', 'pt': 'Apenas uma visita', 'zh': '随便看看'},
        {'key': 'occasion_celebration', 'fr': 'Célébration', 'en': 'Celebration', 'es': 'Celebración', 'it': 'Celebrazione', 'pt': 'Celebração', 'zh': '庆祝'},
        {'key': 'occasion_special_night', 'fr': 'Soirée spéciale', 'en': 'Special night', 'es': 'Noche especial', 'it': 'Serata speciale', 'pt': 'Noite especial', 'zh': '特别的夜晚'},
        {'key': 'occasion_quick_lunch', 'fr': 'Déjeuner rapide', 'en': 'Quick lunch', 'es': 'Almuerzo rápido', 'it': 'Pranzo veloce', 'pt': 'Almoço rápido', 'zh': '快捷午餐'},
        {'key': 'occasion_discovery', 'fr': 'Découverte', 'en': 'Discovery', 'es': 'Descubrimiento', 'it': 'Scoperta', 'pt': 'Descoberta', 'zh': '探索'}
    ],
    'atmosphere': [
        {'key': 'atmosphere_decoration', 'fr': 'La Décoration', 'en': 'The Decoration', 'es': 'La Decoración', 'it': 'La Decorazione', 'pt': 'A Decoração', 'zh': '装饰'},
        {'key': 'atmosphere_music', 'fr': 'La Musique', 'en': 'The Music', 'es': 'La Música', 'it': 'La Musica', 'pt': 'A Música', 'zh': '音乐'},
        {'key': 'atmosphere_festive', 'fr': 'L\'Énergie Festive', 'en': 'The Festive Energy', 'es': 'La Energía Festiva', 'it': 'L\'Energia Festiva', 'pt': 'A Energia Festiva', 'zh': '节日气氛'},
        {'key': 'atmosphere_lighting', 'fr': 'L\'Éclairage', 'en': 'The Lighting', 'es': 'La Iluminación', 'it': 'L\'Illuminazione', 'pt': 'A Iluminação', 'zh': '灯光'},
        {'key': 'atmosphere_comfort', 'fr': 'Le Confort', 'en': 'The Comfort', 'es': 'La Comodidad', 'it': 'Il Comfort', 'pt': 'O Conforto', 'zh': '舒适'},
        {'key': 'atmosphere_romantic', 'fr': 'Romantique', 'en': 'Romantic', 'es': 'Romántico', 'it': 'Romantico', 'pt': 'Romântico', 'zh': '浪漫'},
        {'key': 'atmosphere_calm', 'fr': 'Calme', 'en': 'Calm', 'es': 'Tranquilo', 'it': 'Calmo', 'pt': 'Calmo', 'zh': '安静'},
        {'key': 'atmosphere_lively', 'fr': 'Animée', 'en': 'Lively', 'es': 'Animado', 'it': 'Vivace', 'pt': 'Animado', 'zh': '热闹'},
        {'key': 'atmosphere_cozy', 'fr': 'Cosy', 'en': 'Cozy', 'es': 'Acogedor', 'it': 'Accogliente', 'pt': 'Aconchegante', 'zh': '舒适'},
        {'key': 'atmosphere_elegant', 'fr': 'Élégante', 'en': 'Elegant', 'es': 'Elegante', 'it': 'Elegante', 'pt': 'Elegante', 'zh': '优雅'}
    ]
}


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
    tag_selections = db.relationship('RestaurantTag', back_populates='restaurant', cascade="all, delete-orphan")
    generated_reviews = db.relationship('GeneratedReview', back_populates='restaurant', cascade="all, delete-orphan")

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

class GeneratedReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    language = db.Column(db.String(10))
    server_name = db.Column(db.String(100), nullable=True)
    occasion = db.Column(db.String(100), nullable=True)
    service_qualities = db.Column(db.JSON, nullable=True)
    flavors = db.Column(db.JSON, nullable=True)
    atmosphere = db.Column(db.JSON, nullable=True)
    review_text = db.Column(db.Text, nullable=False)
    private_feedback = db.Column(db.Text, nullable=True)
    restaurant = db.relationship('Restaurant', back_populates='generated_reviews')

with app.app_context():
    db.create_all()

# --- GESTION DE L'UTILISATEUR JWT ---
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=int(identity)).one_or_none()

def get_restaurant_id_from_token():
    current_user = get_current_user()
    if current_user:
        return current_user.restaurant_id
    return None

def generate_unique_slug(name, restaurant_id):
    base_slug = name.lower().replace(' ', '-')
    base_slug = re.sub(r'[^a-z0-9-]', '', base_slug)
    return f"{base_slug}-{restaurant_id}"

# --- ROUTES PUBLIQUES ---
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

    default_tag_keys = [tag['key'] for category in PRE_TRANSLATED_TAGS for tag in PRE_TRANSLATED_TAGS[category]]
    for key in default_tag_keys:
        db.session.add(RestaurantTag(restaurant_id=new_restaurant.id, tag_key=key))
    
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
    
    selected_tag_keys = {tag.tag_key for tag in restaurant.tag_selections}
    
    tags_for_frontend = {}
    for category, tags_list in PRE_TRANSLATED_TAGS.items():
        tags_for_frontend[category] = []
        for tag_data in tags_list:
            if tag_data['key'] in selected_tag_keys:
                # FIX: Ensure enabled_languages is a non-empty list
                enabled_languages = restaurant.enabled_languages if restaurant.enabled_languages else ['fr']
                translations = {lang: tag_data.get(lang, tag_data['fr']) for lang in enabled_languages}
                tags_for_frontend[category].append({
                    "key": tag_data['key'],
                    "translations": translations
                })

    # FIX: Ensure enabled_languages sent to frontend is never null or empty
    final_enabled_languages = restaurant.enabled_languages if restaurant.enabled_languages else ['fr']

    return jsonify({
        "name": restaurant.name, "logoUrl": restaurant.logo_url, "primaryColor": restaurant.primary_color,
        "links": {"google": restaurant.google_link, "tripadvisor": restaurant.tripadvisor_link},
        "servers": [{"id": s.id, "name": s.name, "avatar": s.avatar_url} for s in servers],
        "languages": final_enabled_languages,
        "tags": tags_for_frontend
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

@app.route('/api/public/review/generate/<string:slug>', methods=['POST'])
def generate_and_save_review(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify({"error": "La clé API OpenAI n'est pas configurée sur le serveur."}), 500

    data = request.get_json()
    prompt = data.get('prompt')
    review_data = data.get('reviewData', {})

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

        # Sauvegarde de l'avis en base de données
        new_review = GeneratedReview(
            restaurant_id=restaurant.id,
            language=review_data.get('lang'),
            server_name=review_data.get('server'),
            occasion=review_data.get('occasion'),
            service_qualities=review_data.get('serviceQualities'),
            flavors=review_data.get('flavors'),
            atmosphere=review_data.get('atmosphere'),
            private_feedback=review_data.get('privateFeedback'),
            review_text=review_text
        )
        db.session.add(new_review)
        db.session.commit()

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
        
        if 'enabledLanguages' in data:
            try:
                langs = json.loads(data.get('enabledLanguages'))
                # Ensure it's a list and not empty
                if isinstance(langs, list) and langs:
                    restaurant.enabled_languages = langs
                else:
                    # Fallback to default if an empty list is provided
                    restaurant.enabled_languages = ['fr']
            except (json.JSONDecodeError, TypeError):
                return jsonify({"error": "Format JSON invalide pour les langues"}), 400

        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = f'/uploads/{filename}'
        
        db.session.commit()
        return jsonify({"message": "Paramètres mis à jour", "logoUrl": restaurant.logo_url})

@app.route('/api/options', methods=['GET', 'POST'])
@jwt_required()
def manage_options():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        selected_tags = db.session.query(RestaurantTag.tag_key).filter_by(restaurant_id=restaurant_id).all()
        selected_keys = [key for (key,) in selected_tags]
        return jsonify({
            "available_tags": PRE_TRANSLATED_TAGS,
            "selected_keys": selected_keys
        })
    
    if request.method == 'POST':
        data = request.get_json()
        new_selected_keys = data.get('selected_keys', [])
        
        RestaurantTag.query.filter_by(restaurant_id=restaurant_id).delete()
        
        for key in new_selected_keys:
            db.session.add(RestaurantTag(restaurant_id=restaurant_id, tag_key=key))
            
        db.session.commit()
        return jsonify({"message": "Options mises à jour avec succès."}), 200

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

@app.route('/api/servers/<int:server_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_single_server(server_id):
    restaurant_id = get_restaurant_id_from_token()
    server = Server.query.filter_by(id=server_id, restaurant_id=restaurant_id).first_or_404()
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

@app.route('/api/menu/<int:dish_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_single_dish(dish_id):
    restaurant_id = get_restaurant_id_from_token()
    dish = Dish.query.filter_by(id=dish_id, restaurant_id=restaurant_id).first_or_404()
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

@app.route('/api/reviews', methods=['GET'])
@jwt_required()
def get_reviews():
    restaurant_id = get_restaurant_id_from_token()
    reviews = GeneratedReview.query.filter_by(restaurant_id=restaurant_id).order_by(GeneratedReview.created_at.desc()).all()
    return jsonify([{
        "id": r.id,
        "review_text": r.review_text,
        "created_at": r.created_at.isoformat()
    } for r in reviews])

@app.route('/api/reviews/analyze', methods=['POST'])
@jwt_required()
def analyze_reviews():
    restaurant_id = get_restaurant_id_from_token()
    reviews = GeneratedReview.query.filter_by(restaurant_id=restaurant_id).all()

    if not reviews:
        return jsonify({"analysis": "Pas assez d'avis pour générer une analyse."})

    reviews_text = "\n\n---\n\n".join([r.review_text for r in reviews])
    
    prompt = f"""Voici une liste d'avis pour mon restaurant. Analyse-les pour identifier les points forts récurrents, les points faibles ou les critiques fréquentes, et propose 3 suggestions concrètes d'amélioration pour mon restaurant. Fournis une réponse structurée en Markdown avec les titres : 'Points Forts', 'Points Faibles', 'Suggestions'.

AVIS :
{reviews_text}
"""

    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify({"error": "La clé API OpenAI n'est pas configurée sur le serveur."}), 500

    openai_url = 'https://api.openai.com/v1/chat/completions'
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'}
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}]
    }

    try:
        response = requests.post(openai_url, headers=headers, json=payload)
        response.raise_for_status()
        openai_data = response.json()
        analysis_text = openai_data['choices'][0]['message']['content'].strip()
        return jsonify({"analysis": analysis_text})
    except Exception as e:
        app.logger.error(f"Erreur lors de l'analyse OpenAI: {e}")
        return jsonify({"error": "Erreur lors de la génération de l'analyse."}), 500


if __name__ == '__main__':
    app.run(debug=True)
