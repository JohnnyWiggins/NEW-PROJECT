from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from speech_to_text import start_background_listening, generate_speech, stop_background_listening
from datetime import datetime
import re

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Set the simulation flag for failure testing
app.config["SIMULATE_AI_FAILURE"] = False  # Set to True to simulate failure

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- MODELS ---

# Model for documents (User Story: Document Creation)
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False, default="Untitled Document")
    content = db.Column(db.Text, nullable=False)
    detail_level = db.Column(db.String(20), nullable=False, default="Standard")  # New field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# New Model for AI Settings (User Story: Modify AI for Notes)
class AISettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    correlation_level = db.Column(db.String(20), nullable=False, default="Medium")

# User Model (Authentication)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# --- ROUTES ---
@app.route("/documents")
@login_required
def list_documents():
    # Retrieve all documents belonging to the current user
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template("documents.html", documents=documents)

@app.route("/document/<int:document_id>/edit_detail", methods=["GET", "POST"])
@login_required
def edit_document_detail(document_id):
    document = Document.query.get_or_404(document_id)
    if request.method == "POST":
        new_detail = request.form.get("detail_level")
        if new_detail not in ["Brief", "Standard", "Detailed"]:
            flash("Invalid detail level selected.", "danger")
            return redirect(url_for("edit_document_detail", document_id=document.id))

        # Update the detail level field
        document.detail_level = new_detail

        # (Optional) Remove any existing detail tag from the content
        document.content = re.sub(r'\s*\[(Brief|Standard|Detailed)\]', '', document.content).strip()

        # Append a new tag for simulation purposes
        if new_detail == "Brief":
            document.content += " [Brief]"
        elif new_detail == "Detailed":
            document.content += " [Detailed]"
        else:
            document.content += " [Standard]"

        db.session.commit()
        flash("Document detail updated successfully.", "success")
        return redirect(url_for("view_document", document_id=document.id))

    return render_template("edit_document_detail.html", document=document)


# AI Settings page (Accessible only to admin)
@app.route("/ai_settings", methods=["GET", "POST"])
@login_required
def ai_settings():
    # Only allow admin (for example, username "admin") to access settings
    if current_user.username != "admin":
        flash("You are not authorized to access AI settings.", "danger")
        return redirect(url_for("home"))

    settings = AISettings.query.first()
    if not settings:
        settings = AISettings(correlation_level="Medium")
        db.session.add(settings)
        db.session.commit()

    if request.method == "POST":
        new_level = request.form.get("correlation_level")
        # Simulate failure if the flag is set
        if app.config.get("SIMULATE_AI_FAILURE"):
            flash("AI did not respond to the changes. Please repair the A.I. program.", "danger")
            return redirect(url_for("ai_settings"))

        # Otherwise, update the settings normally
        settings.correlation_level = new_level
        db.session.commit()
        flash("AI settings updated successfully.", "success")
        return redirect(url_for("ai_settings"))

    return render_template("ai_settings.html", settings=settings)


# Route for saving a document (Document Creation)
@app.route("/save_document", methods=["POST"])
@login_required
def save_document():
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    # Debug prints (remove these after testing)
    print(f"Title: '{title}'")
    print(f"Content: '{content}'")

    if not title:
        flash("Document title is required.", "danger")
        return redirect(url_for("speech_to_text_page"))

    if not content:
        flash("Document content cannot be empty.", "danger")
        return redirect(url_for("speech_to_text_page"))

    new_doc = Document(user_id=current_user.id, title=title, content=content)
    db.session.add(new_doc)
    db.session.commit()
    flash("Document saved!", "success")
    return redirect(url_for("view_document", document_id=new_doc.id))


# Route for viewing a document
@app.route("/document/<int:document_id>")
@login_required
def view_document(document_id):
    document = Document.query.get_or_404(document_id)
    return render_template("view_document.html", document=document)

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=identifier).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("Username or password is incorrect.", "danger")
            return redirect(url_for("login"))
        login_user(user)
        return redirect(url_for("home"))
    return render_template("login.html")

# Register Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        # Check if a user with this email or username already exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash("A user with that email or username already exists.", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Your account has been created!", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


# Home Route (Dashboard)
@app.route("/")
@login_required
def home():
    return render_template("home.html")

# Speech-to-Text Page
@app.route("/speech_to_text")
@login_required
def speech_to_text_page():
    return render_template("speech_to_text.html")

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# Global variable to control speech recognition
recognition_active = False

# Route to handle speech recognition with AI modification
# Global variable to control the streaming loop
recognition_active = False

@app.route("/recognize_speech", methods=["POST"])
@login_required
def recognize_speech():
    global recognition_active
    recognition_active = True

    # Start the background listener if not already running
    from speech_to_text import start_background_listening, generate_speech
    start_background_listening()

    def generate():
        # Continuously yield recognized speech until the flag is turned off
        while recognition_active:
            for text in generate_speech():
                # Check again if recognition has been stopped
                if not recognition_active:
                    break
                # Prepend "data: " for SSE and yield the chunk
                yield f"data: {text}"
    return Response(generate(), mimetype='text/event-stream')

@app.route("/stop_speech_recognition", methods=["POST"])
@login_required
def stop_speech_recognition():
    global recognition_active
    recognition_active = False
    from speech_to_text import stop_background_listening
    stop_background_listening()
    return "Speech recognition stopped", 200


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


if __name__ == "__main__":
    app.run(debug=True)
