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
    """Vérifie si l'extension du fichier est autorisée."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGGING ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- CORS ---
CORS(app, origins=["*"], supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

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

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- MODÈLES DE LA BASE DE DONNÉES ---

class TokenBlocklist(db.Model):
    """Modèle pour stocker les tokens JWT invalidés (sur la denylist)."""
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    restaurant = db.relationship('Restaurant', back_populates='user', uselist=False)
    
    # Champs pour la réinitialisation du mot de passe
    reset_password_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_password_expiration = db.Column(db.DateTime, nullable=True)
    
    # Champs pour le changement d'e-mail
    change_email_token = db.Column(db.String(100), unique=True, nullable=True)
    change_email_expiration = db.Column(db.DateTime, nullable=True)
    new_email = db.Column(db.String(120), nullable=True)

    def set_password(self, password):
        """Crée un hash pour un nouveau mot de passe."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Vérifie le mot de passe fourni contre le hash stocké."""
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

# ... (Les autres modèles restent inchangés : RestaurantTag, Server, Dish, Review)
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
    source = db.Column(db.String(20), nullable=False) # 'google', 'tripadvisor', 'internal'
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
    """Vérifie si un token a été révoqué (présent dans la blocklist)."""
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """Charge un utilisateur depuis la BDD à partir de l'identité du token."""
    identity = jwt_data["sub"]
    return User.query.filter_by(id=int(identity)).one_or_none()

# --- FONCTIONS HELPERS ---
def generate_unique_slug(name, restaurant_id):
    """Génère un slug unique pour un restaurant."""
    base_slug = name.lower().replace(' ', '-')
    base_slug = re.sub(r'[^a-z0-9-]', '', base_slug)
    return f"{base_slug}-{restaurant_id}"
    
# ... (Les autres fonctions helpers comme save_reviews_to_db, scrape_reviews_with_apify, etc. restent inchangées)

# --- ROUTES D'AUTHENTIFICATION ET D'INSCRIPTION ---
@app.route('/api/register', methods=['POST'])
def register():
    """Crée un nouveau restaurant et un utilisateur associé."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    restaurant_name = data.get('restaurant_name')

    if not all([email, password, restaurant_name]):
        return jsonify({"error": "Données manquantes (email, mot de passe, nom du restaurant)."}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Format d'email invalide."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Cet email est déjà utilisé."}), 409

    new_restaurant = Restaurant(name=restaurant_name, slug="temporary-slug")
    db.session.add(new_restaurant)
    db.session.flush()

    new_restaurant.slug = generate_unique_slug(restaurant_name, new_restaurant.id)
    
    new_user = User(email=email, restaurant_id=new_restaurant.id)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "Compte créé avec succès. Vous pouvez maintenant vous connecter."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Authentifie un utilisateur et retourne un token JWT."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "L'email et le mot de passe sont requis."}), 400

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    
    return jsonify({"error": "Email ou mot de passe incorrect."}), 401

@app.route("/api/logout", methods=["POST"])
@jwt_required()
def logout():
    """Révoque le token JWT actuel en l'ajoutant à la blocklist."""
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(message="Déconnexion réussie.")

# --- ROUTES DE GESTION DE MOT DE PASSE OUBLIÉ ---
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Génère un token de réinitialisation de mot de passe."""
    email = request.json.get('email', None)
    if not email:
        return jsonify({"error": "L'adresse e-mail est requise."}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.reset_password_token = secrets.token_urlsafe(32)
        user.reset_password_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        
        # Simulation de l'envoi d'e-mail
        reset_url = f"https://VOTRE_FRONTEND.com/reset-password?token={user.reset_password_token}"
        app.logger.info(f"--- SIMULATION D'ENVOI D'EMAIL ---")
        app.logger.info(f"À: {user.email}")
        app.logger.info(f"Sujet: Réinitialisation de votre mot de passe")
        app.logger.info(f"Lien de réinitialisation (valide 1 heure): {reset_url}")
        app.logger.info(f"------------------------------------")

    # Répondre positivement même si l'utilisateur n'existe pas pour ne pas révéler les e-mails enregistrés
    return jsonify({"message": "Si un compte est associé à cet e-mail, un lien de réinitialisation a été envoyé."}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Réinitialise le mot de passe avec un token valide."""
    token = request.json.get('token', None)
    new_password = request.json.get('password', None)

    if not token or not new_password:
        return jsonify({"error": "Le token et le nouveau mot de passe sont requis."}), 400

    user = User.query.filter_by(reset_password_token=token).first()

    if not user:
        return jsonify({"error": "Token invalide."}), 400
        
    if user.reset_password_expiration < datetime.utcnow():
        # Invalider le token expiré
        user.reset_password_token = None
        user.reset_password_expiration = None
        db.session.commit()
        return jsonify({"error": "Le token a expiré."}), 400

    user.set_password(new_password)
    # Invalider le token après utilisation
    user.reset_password_token = None
    user.reset_password_expiration = None
    db.session.commit()

    return jsonify({"message": "Votre mot de passe a été réinitialisé avec succès."}), 200

# --- ROUTES DE GESTION DE PROFIL ---
@app.route('/api/profile', methods=['GET', 'PUT'])
@jwt_required()
def manage_profile():
    """Récupère (GET) ou met à jour (PUT) les informations du profil."""
    current_user = get_jwt_identity()
    user = db.session.get(User, current_user)
    
    if request.method == 'GET':
        return jsonify({
            "email": user.email,
            "restaurant_name": user.restaurant.name
        })

    if request.method == 'PUT':
        data = request.get_json()
        restaurant_name = data.get('restaurant_name')
        if restaurant_name:
            user.restaurant.name = restaurant_name
            db.session.commit()
            return jsonify({"message": "Profil mis à jour avec succès."})
        return jsonify({"error": "Aucune donnée à mettre à jour."}), 400

@app.route('/api/profile/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Permet à un utilisateur connecté de changer son mot de passe."""
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)

    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({"error": "Le mot de passe actuel et le nouveau sont requis."}), 400

    if not user.check_password(current_password):
        return jsonify({"error": "Le mot de passe actuel est incorrect."}), 403

    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Mot de passe changé avec succès."}), 200

@app.route('/api/profile/change-email', methods=['POST'])
@jwt_required()
def request_change_email():
    """Initie le processus de changement d'e-mail."""
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    
    new_email = request.json.get('new_email')
    if not new_email or not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
        return jsonify({"error": "Une nouvelle adresse e-mail valide est requise."}), 400
        
    if User.query.filter_by(email=new_email).first():
        return jsonify({"error": "Cette adresse e-mail est déjà utilisée."}), 409

    user.new_email = new_email
    user.change_email_token = secrets.token_urlsafe(32)
    user.change_email_expiration = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()
    
    # Simulation de l'envoi d'e-mail de vérification
    verify_url = f"https://VOTRE_FRONTEND.com/verify-email?token={user.change_email_token}"
    app.logger.info(f"--- SIMULATION D'ENVOI D'EMAIL ---")
    app.logger.info(f"À: {new_email}")
    app.logger.info(f"Sujet: Confirmez votre nouvelle adresse e-mail")
    app.logger.info(f"Lien de vérification (valide 1 heure): {verify_url}")
    app.logger.info(f"------------------------------------")
    
    return jsonify({"message": "Un e-mail de vérification a été envoyé à votre nouvelle adresse."}), 200

@app.route('/api/verify-new-email', methods=['POST'])
def verify_new_email():
    """Finalise le changement d'e-mail avec un token valide."""
    token = request.json.get('token')
    if not token:
        return jsonify({"error": "Token de vérification manquant."}), 400
        
    user = User.query.filter_by(change_email_token=token).first()
    
    if not user or user.change_email_expiration < datetime.utcnow():
        if user: # Le token a juste expiré
            user.change_email_token = None
            user.change_email_expiration = None
            user.new_email = None
            db.session.commit()
        return jsonify({"error": "Token invalide ou expiré."}), 400
        
    user.email = user.new_email
    user.new_email = None
    user.change_email_token = None
    user.change_email_expiration = None
    db.session.commit()
    
    return jsonify({"message": "Votre adresse e-mail a été mise à jour avec succès."}), 200

# --- AUTRES ROUTES (INCHANGÉES) ---
# ... (Copiez ici les routes existantes comme /api/restaurant, /api/servers, /api/menu, etc.)
@app.route('/api/restaurant', methods=['GET', 'PUT'])
@jwt_required()
def manage_restaurant_settings():
    """Gère les paramètres du restaurant (GET pour lire, PUT pour mettre à jour)."""
    user = db.session.get(User, get_jwt_identity())
    restaurant = user.restaurant
    
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
                restaurant.enabled_languages = json.loads(data.get('enabledLanguages'))
            except json.JSONDecodeError:
                return jsonify({"error": "Format JSON invalide pour les langues"}), 400

        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = f'/uploads/{filename}'
        
        db.session.commit()
        return jsonify({"message": "Paramètres mis à jour", "logoUrl": restaurant.logo_url})

# --- DÉMARRAGE DE L'APPLICATION ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
