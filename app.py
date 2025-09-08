import binascii
import json
from urllib import response
from flask import Flask, make_response, request, jsonify, send_file, send_from_directory
from pymongo import MongoClient
from bson import ObjectId
import random
import jwt
from datetime import datetime, timedelta, timezone
import os
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from bson.errors import InvalidId
import base64
import uuid
import pytz
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import timezone
from pymongo import ASCENDING
from dateutil.parser import isoparse
from admin_routes import admin_bp


EMAIL_USER = 'codingshehan@gmail.com'
EMAIL_PASS = 'pyea ihbc kqnb xoie'

# Initialize Flask
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*",engineio_logger=True, logger=True,ping_timeout=120,ping_interval=30,async_mode='threading',max_http_buffer_size=100 * 1024 * 1024,    http_compression=True,allow_upgrades=True , supports_credentials=True
)

# Register the admin blueprint
app.register_blueprint(admin_bp)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif','aac','mp3','mp4', 'mov', 'avi'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size


#Sri Lanka Time
sri_lanka_timezone = pytz.timezone('Asia/Colombo')

           
# MongoDB Connection
client = MongoClient("mongodb+srv://sehandeveloper:GpGeUDiy11QAxqeJ@cluster0.s5hyu.mongodb.net/")
db = client["chat_app"]
users_collection = db["users"]
otp_collection = db["otp_store"]
connections_collection = db["connections"]
messages_collection = db["messages"]
group_messages_collection = db["group_messages"]
deleted_groups_collection = db["deleted_groups"]
calls_collection = db["calls"]
admin_collection = db["admins"]

# Create indexes for better performance
messages_collection.create_index([("sender_id", 1), ("receiver_id", 1)])
messages_collection.create_index([("timestamp", -1)])
messages_collection.create_index([("read", 1)])

online_users = {}
user_sockets = {}
call_rooms = {} 
typing_users = {}


# JWT Secret Key
SECRET_KEY = "SH123456"
ALGORITHM = "HS256"


# Created a default admin account
def create_default_admin():
    default_admin = {
        "email": "admin@chathub.com",
        "password": "admin123",
        "name": "System Administrator",
        "created_at": datetime.now(timezone.utc)
    }
    
    if not admin_collection.find_one({"email": default_admin["email"]}):
        admin_collection.insert_one(default_admin)
        print("Default admin account created")

# Call this function when the app starts
create_default_admin()

# Serve admin profile pictures
@app.route('/uploads/admin_profiles/<filename>')
def serve_admin_profile_pic(filename):
    return send_from_directory('uploads/admin_profiles', filename)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
# Helper Functions
def create_jwt(email):
    payload = {
        "email": email, 
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

def generate_otp():
    return str(random.randint(100000, 999999))

def send_email_otp(to_email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg['Subject'] = "Your OTP Code"
    msg['From'] = EMAIL_USER
    msg['To'] = to_email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)


def user_exists(email):
    return users_collection.find_one({"email": email}) is not None

def otp_recently_sent(email, cooldown_seconds=60):
    record = otp_collection.find_one({"email": email})
    if record:
        last_sent = record.get("created_at", datetime.min)

        # Make sure last_sent is timezone-aware
        if last_sent.tzinfo is None:
            last_sent = last_sent.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) - last_sent < timedelta(seconds=cooldown_seconds):
            return True
    return False

def store_otp(email, otp):
    otp_collection.update_one(
        {"email": email},
        {"$set": {"otp": otp, "created_at": datetime.now(timezone.utc)}},
        upsert=True
    )

def verify_stored_otp(email, otp):
    record = otp_collection.find_one({"email": email})
    if record and record["otp"] == otp:
        otp_collection.delete_one({"email": email})
        return True
    return False

def serialize_user(user):
    return {
        "id": str(user["_id"]),
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "profile_pic": user.get("profile_pic", "default.jpg")
    }

# OTP Send Function
@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400
    if otp_recently_sent(email):
        return jsonify({"error": "OTP recently sent. Please wait before requesting again."}), 429

    otp = generate_otp()
    store_otp(email, otp)
    send_email_otp(email, otp)
    print(f"OTP for {email}: {otp}")
    return jsonify({"message": "OTP sent successfully"})

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email")
    otp = request.json.get("otp")
    
    if not all([email, otp]):
        return jsonify({"error": "Email and OTP are Required"}), 400
        
    if verify_stored_otp(email, otp):
        user = users_collection.find_one({"email": email})
        if user:
            token = create_jwt(email)
            return jsonify({
                "message": "Login successful", 
                "token": token, 
                "user": serialize_user(user)
            })
        return jsonify({"message": "New user, enter name and profile picture"})
    return jsonify({"error": "Invalid OTP"}), 400

@app.route("/register", methods=["POST"])
def register_user():
    email = request.json.get("email")
    name = request.json.get("name")
    profile_pic_base64 = request.json.get("profile_pic")

    
    if not all([email, name]):
        return jsonify({"error": "Email and name are required"}), 400
        
    if user_exists(email):
        return jsonify({"error": "User already exists"}), 400
    
    profile_pic_data = profile_pic_base64 if profile_pic_base64 else None

    if profile_pic_base64:
        try:
            image_data = base64.b64decode(profile_pic_base64.split(",")[-1])
            file_header = profile_pic_base64.split(",")[0]
            file_extension = "jpg"  # default
            if "image/" in file_header:
                file_extension = file_header.split("image/")[1].split(";")[0]
            filename = f"profile_{uuid.uuid4()}.{file_extension}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if len(image_data) > 5 * 1024 * 1024:
                return jsonify({"error": "Image too large (max 5MB)"}), 400

            allowed_types = {"jpeg", "jpg", "png", "gif"}
            if file_extension.lower() not in allowed_types:
                return jsonify({"error": "Invalid image format"}), 400

            with open(filepath, 'wb') as f:
                f.write(image_data)
                
            profile_pic_url = f"/uploads/{filename}"
            
        except binascii.Error as e:
            print(f"Base64 decode error: {str(e)}")
            return jsonify({"error": "Invalid image data"}), 400
        except IOError as e:
            print(f"File save error: {str(e)}")
            return jsonify({"error": "Failed to save profile picture"}), 500
                    
    user_data = {
        "email": email, 
        "name": name, 
        "profile_pic": profile_pic_url,
        "connections": [],
        "registered_at": datetime.now(timezone.utc)
    }
    
    try:
        user_id = users_collection.insert_one(user_data).inserted_id
        token = create_jwt(email)
        user = users_collection.find_one({"_id": user_id})
        
        return jsonify({
            "message": "User registered successfully",
            "token": token,
            "userId": str(user_id),
            "profilePicUrl": profile_pic_url,
            "user": serialize_user(user)
        })
    except Exception as e:
         if profile_pic_url and os.path.exists(filepath):
            os.remove(filepath)
         raise e
        #return jsonify({"error": str(e)}), 500

@app.route('/uploads/<filename>')
def serve_profile_pic(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Auto-login Route
@app.route("/auto-login", methods=["GET"])
def auto_login():
    token = request.args.get("token")
    decoded_data = decode_jwt(token)
    if "error" in decoded_data:
        return jsonify({"error": decoded_data["error"]}), 401
    
    user = users_collection.find_one({"email": decoded_data["email"]})
    if user:
        return jsonify({"message": "User logged in", "user": serialize_user(user)})
    return jsonify({"error": "User not found"}), 404

# Logout Route
@app.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "User logged out successfully"})

# Upload PDF endpoint
@app.route('/upload-group-pdf', methods=['POST'])
def upload_group_pdf():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        sender_id = request.form.get('sender_id')
        group_id = request.form.get('group_id')
        temp_id = request.form.get('temp_id')

        if not all([sender_id, group_id, temp_id]):
            return jsonify({'error': 'Missing required fields'}), 400

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if not file.filename.lower().endswith('.pdf'):
            return jsonify({'error': 'Invalid file type. Only PDFs are allowed'}), 400

        # Save the file
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'group_pdfs')
        os.makedirs(upload_folder, exist_ok=True)  # Create the folder if it doesn't exist
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)

        # Store message in database
        message = {
            'sender_id': sender_id,
            'group_id': group_id,
            'type': 'pdf',
            'file_path': file_path,
            'filename': filename,
            'timestamp': datetime.now(timezone.utc),
            'read_by': [sender_id],
            'temp_id': temp_id
        }
        result = group_messages_collection.insert_one(message)
        pdf_id = str(result.inserted_id)

        # Emit socket event
        pdf_url = f'/get-group-pdf/{pdf_id}'
        socketio.emit('receive_group_message', {
            '_id': pdf_id,
            'sender_id': sender_id,
            'group_id': group_id,
            'pdf_url': pdf_url,
            'type': 'pdf',
            'filename': filename,
            'timestamp': message['timestamp'].isoformat(),
            'read_by': [sender_id],
            'temp_id': temp_id
        }, room=group_id)

        return jsonify({
            'success': True,
            'pdf_id': pdf_id,
            'temp_id': temp_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Serve PDF endpoint
@app.route('/get-group-pdf/<pdf_id>', methods=['GET'])
def get_group_pdf(pdf_id):
    try:
        message = group_messages_collection.find_one({'_id': ObjectId(pdf_id), 'type': 'pdf'})
        if not message or 'file_path' not in message:
            return jsonify({'error': 'PDF not found'}), 404

        file_path = message['file_path']
        if not os.path.exists(file_path):
            return jsonify({'error': 'PDF file not found on server'}), 404

        return send_file(file_path, mimetype='application/pdf', as_attachment=False)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Upload one to one Voice messages
@app.route('/upload-voice', methods=['POST'])
def upload_voice():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Generate secure filename
        filename = f"voice_{uuid.uuid4()}.aac"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save file
        file.save(filepath)
        
        # Verify file was saved
        if not os.path.exists(filepath):
            return jsonify({'error': 'File save failed'}), 500

        # Store metadata in DB
        voice_message = {
            'sender_id': request.form.get('sender_id'),
            'receiver_id': request.form.get('receiver_id'),
            'filename': filename,
            'filepath': filepath,
            'mimetype': 'audio/aac',
            'is_voice' : True,
            'timestamp': datetime.now(timezone.utc),
            'temp_id': request.form.get('temp_id', '')
        }
        
        result = messages_collection.insert_one(voice_message)
        voice_url = f'/get-one-to-one-voice/{str(result.inserted_id)}'

        return jsonify({
            'voice_url': voice_url,
            'message': 'Voice message uploaded successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500 

# Upload Group Voice Message
@app.route('/upload-group-voice', methods=['POST'])
def upload_group_voice():
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        sender_id = request.form.get('sender_id')
        group_id = request.form.get('group_id')
        temp_id = request.form.get('temp_id')

        if not all([sender_id, group_id]):
            return jsonify({'error': 'Missing sender or group ID'}), 400

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not file or not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400

        if file and allowed_file(file.filename):
            # Generate a unique filename
            filename = f"voice_{uuid.uuid4()}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Save the file
            file.save(filepath)
            
            if not os.path.exists(filepath):
                raise IOError("File was not saved correctly")
            
            # Store voice message metadata in MongoDB
            voice_message = {
            'sender_id': sender_id,
            'group_id': group_id,
            'filename': filename,
            'file_path': filepath,  # Store local path
            'mimetype': file.mimetype,
            'timestamp': datetime.now(timezone.utc),
            'read_by': [sender_id],
            'type': 'voice',
            'status': 'uploading',  # Initial status
            'temp_id': temp_id      # Store temp_id
        }

            result = group_messages_collection.insert_one(voice_message)

            # Emit socket event to notify group members
            voice_url = f'/get-voice/{str(result.inserted_id)}'
            sender = users_collection.find_one({"_id": ObjectId(sender_id)})
            
            # Emit group_updated event to trigger real-time UI refresh
            socketio.emit('group_updated', {}, room=group_id)

            socketio.emit('receive_group_message', {
                '_id': str(result.inserted_id),
                'sender_id': sender_id,
                'sender': serialize_user(sender),
                'group_id': group_id,
                'voice_url': voice_url,
                'type': 'voice',
                'timestamp': voice_message['timestamp'].isoformat(),
                'read_by': [sender_id],
                'temp_id': temp_id
            }, room=group_id)
            
            
            return jsonify({
                'message': 'Voice message uploaded successfully',
                'voice_url': voice_url,
                'voice_id': str(result.inserted_id),
                'status': 'uploading'
            }), 200
        else:
            return jsonify({'error': 'File type not allowed'}), 400
    except Exception as e:
        print(f"Error uploading voice message: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/update-voice-status', methods=['POST'])
def update_voice_status():
    data = request.json
    group_messages_collection.update_one(
        {'temp_id': data['temp_id']},
        {'$set': {'status': data['status']}}
    )
    return jsonify({'status': 'updated'})

# Retrieve  one to one Voice Messages
@app.route('/get-one-to-one-voice/<voice_id>', methods=['GET'])
def get_one_to_one_voice(voice_id):
    try:
        voice_data = messages_collection.find_one({'_id': ObjectId(voice_id)})
        if not voice_data:
            return jsonify({'error': 'Voice message not found'}), 404

        filepath = voice_data.get('filepath')
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'Voice file not found'}), 404

        # Determine content type
        mimetype = voice_data.get('mimetype', 'audio/aac')
        
        # Stream the file with proper headers
        response = send_file(
            filepath,
            mimetype=mimetype,
            as_attachment=False,
            conditional=True
        )
        
        response.headers.add('Cache-Control', 'no-store')
        response.headers.add('Accept-Ranges', 'bytes')
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Retrieve  Group Voice Messages
@app.route('/get-voice/<voice_id>', methods=['GET'])
def get_voice(voice_id):
    try:
        voice_data = group_messages_collection.find_one({'_id': ObjectId(voice_id)}) 
        if not voice_data or 'filename' not in voice_data:
            return jsonify({'error': 'Voice message not found'}), 404

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], voice_data['filename'])
        if not os.path.exists(filepath):
            return jsonify({'error': 'Voice file not found on server'}), 404

        response = send_file(
            filepath,
            mimetype=voice_data['mimetype'],
            as_attachment=False
        )
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Error retrieving voice message: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
# Upload Group Image  
@app.route('/upload-group-image', methods=['POST'])
def upload_group_image():
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        sender_id = request.form.get('sender_id')
        group_id = request.form.get('group_id')
        temp_id = request.form.get('temp_id')

        if not all([sender_id, group_id]):
            return jsonify({'error': 'Missing sender or group ID'}), 400

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not file or not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400

        filename = f"image_{uuid.uuid4()}_{secure_filename(file.filename)}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(filepath)
        
        if not os.path.exists(filepath):
            raise IOError("File was not saved correctly")

        image_message = {
            'sender_id': sender_id,
            'group_id': group_id,
            'filename': filename,
            'file_path': filepath,
            'mimetype': file.mimetype,
            'timestamp': datetime.now(timezone.utc),
            'read_by': [sender_id],
            'type': 'image',
            'status': 'success',  # Set status to success after saving
            'temp_id': temp_id
        }

        result = group_messages_collection.insert_one(image_message)

        image_url = f'/get-group-image/{str(result.inserted_id)}'
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        
        # Emit group_updated event to trigger real-time UI refresh
        socketio.emit('group_updated', {}, room=group_id)

        socketio.emit('receive_group_message', {
            '_id': str(result.inserted_id),
            'sender_id': sender_id,
            'sender': serialize_user(sender),
            'group_id': group_id,
            'image_url': image_url,
            'type': 'image',
            'timestamp': image_message['timestamp'].isoformat(),
            'read_by': [sender_id],
            'temp_id': temp_id
        }, room=group_id)
        
        
        return jsonify({
            'message': 'Image uploaded successfully',
            'image_url': image_url,
            'image_id': str(result.inserted_id),
            'status': 'success'
        }), 200

    except Exception as e:
        print(f"Error uploading image: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Retrieve Group Image
@app.route('/get-group-image/<image_id>', methods=['GET'])
def get_group_image(image_id):
    try:
        image_data = group_messages_collection.find_one({'_id': ObjectId(image_id)})
        if not image_data or 'filename' not in image_data:
            return jsonify({'error': 'Image not found'}), 404

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], image_data['filename'])
        if not os.path.exists(filepath):
            return jsonify({'error': 'Image file not found on server'}), 404

        response = send_file(
            filepath,
            mimetype=image_data['mimetype'],
            as_attachment=False
        )
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Error retrieving image: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Image Upload
""" @app.route('/upload-image', methods=['POST'])
def upload_image():
    try:
        # Check if the post request has the file part
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        sender_id = request.form.get('sender_id')
        receiver_id = request.form.get('receiver_id')
        
        if not all([sender_id, receiver_id]):
            return jsonify({'error': 'Missing sender or receiver ID'}), 400
            
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if file and allowed_file(file.filename):
            # Generate a unique filename
            filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Save the file
            file.save(filepath)
            
            # Read the file as binary data
            with open(filepath, 'rb') as f:
                image_data = f.read()
            
            # Store in MongoDB
            image_message = {
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'image': image_data,
                'filename': filename,
                'mimetype': file.mimetype,
                'timestamp': datetime.now(timezone.utc),
                'read': False,
                'delivered': False,
                'is_image': True,
                'temp_id': str(uuid.uuid4())  # Generate a temporary ID for the message
            }
            
            result = messages_collection.insert_one(image_message)
            
            # Optionally, you can delete the file after storing in MongoDB
            os.remove(filepath)
            
            # Emit socket event
            room = '_'.join(sorted([sender_id, receiver_id]))
            socketio.emit('receive_message', {
                'id': str(result.inserted_id),
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'image_url': f'/get-image/{str(result.inserted_id)}',
                'timestamp': image_message['timestamp'].isoformat(),
                'read': False,
                'is_image': True
            }, room=room)
            
            return jsonify({
                'message': 'Image uploaded successfully',
                'image_id': str(result.inserted_id)
            }), 200
        else:
            return jsonify({'error': 'File type not allowed'}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500 """
        
@app.route('/upload-image', methods=['POST'])
def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        sender_id = request.form.get('sender_id')
        receiver_id = request.form.get('receiver_id')
        temp_id = request.form.get('temp_id', str(uuid.uuid4()))  # Generate temp_id if not provided
        
        if not all([sender_id, receiver_id]):
            return jsonify({'error': 'Missing sender or receiver ID'}), 400
            
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if file and allowed_file(file.filename):
            # Generate a unique filename
            filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Save the file
            file.save(filepath)
            
            # Read the file as binary data
            with open(filepath, 'rb') as f:
                image_data = f.read()
            
            # Store in MongoDB
            image_message = {
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'image': image_data,
                'filename': filename,
                'mimetype': file.mimetype,
                'timestamp': datetime.now(timezone.utc),
                'read': False,
                'delivered': False,
                'is_image': True,
                'temp_id': temp_id
            }
            
            result = messages_collection.insert_one(image_message)
            message_id = str(result.inserted_id)
            
            # Clean up the file
            os.remove(filepath)
            
            room = '_'.join(sorted([sender_id, receiver_id]))
            socketio.emit('receive_message', {
                'id': str(result.inserted_id),
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'image_url': f'/get-image/{str(result.inserted_id)}',
                'timestamp': image_message['timestamp'].isoformat(),
                'read': False,
                'is_image': True
            }, room=room)
            
            return jsonify({
                'message': 'Image uploaded successfully',
                'image_id': message_id,
                'temp_id': temp_id,
                'image_url': f'/get-image/{message_id}',
                'timestamp': image_message['timestamp'].isoformat()
            }), 200
            
        else:
            return jsonify({'error': 'File type not allowed'}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    
# Retrieve Image 
@app.route('/get-image/<image_id>', methods=['GET'])
def get_image(image_id):
    try:
        image_data = messages_collection.find_one({'_id': ObjectId(image_id)})
        if not image_data or 'image' not in image_data:
            return jsonify({'error': 'Image not found'}), 404
            
        response = app.response_class(
            response=image_data['image'],
            status=200,
            mimetype=image_data['mimetype']
        )
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Print email and name
        print("Name:", user.get("name", ""))
        print("Email:", user.get("email", ""))
        return jsonify({
            "name": user.get("name", ""),
            "phone": user.get("phone", ""),
            "email": user.get("email", ""),
            "profile_pic": user.get("profile_pic", "default.jpg")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Send Friend Request
@app.route("/send-request", methods=["POST"])
def send_friend_request():
    data = request.json
    print("Helloer")
    print("Received request:", data)

    requester_id = data.get("senderId") 
    receiver_id = data.get("receiverId")

    if not requester_id or not receiver_id:
        return jsonify({"error": "Both requester and receiver IDs are required"}), 400

    # Check if request already exists
    existing_request = connections_collection.find_one({
        "$or": [
            {"requester_id": requester_id, "receiver_id": receiver_id},
            {"requester_id": receiver_id, "receiver_id": requester_id}
        ]
    })

    if existing_request:
        return jsonify({"error": "Connection request already exists"}), 400

    # Create friend request
    connections_collection.insert_one({
        "requester_id": requester_id,
        "receiver_id": receiver_id,
        "status": "pending"
    })

    return jsonify({"message": "Friend request sent successfully"}), 200

# Accept Friend Request
@app.route("/accept-request", methods=["POST"])
def accept_friend_request():
    data = request.json
    request_id = data.get("senderId")
    receiver_id = data.get("receiverId")

    if not request_id or not receiver_id:
        return jsonify({"error": "senderId and receiverId are required"}), 400

    request_doc = connections_collection.find_one({"_id": ObjectId(request_id)})

    if not request_doc or request_doc.get("status") != "pending":
        return jsonify({"error": "Invalid or already processed request"}), 400

    requester_id = request_doc.get("requester_id")

    # Update the status to 'accepted'
    result = connections_collection.update_one(
        {"_id": ObjectId(request_id), "status": "pending"},
        {"$set": {"status": "accepted","accepted_at": datetime.now(timezone.utc)}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Request not updated"}), 400

    # Add each other as connections in the user collection
    users_collection.update_one(
        {"_id": ObjectId(receiver_id)},
        {"$addToSet": {"connections": requester_id}}
    )

    users_collection.update_one(
        {"_id": ObjectId(requester_id)},
        {"$addToSet": {"connections": receiver_id}}
    )

    return jsonify({"message": "Friend request accepted and users connected successfully"}), 200



# Get Received Friend Requests
@app.route("/friend-requests/<user_id>", methods=["GET"])
def get_received_requests(user_id):
    requests = connections_collection.find({"receiver_id": user_id, "status": "pending"})
    
    request_list = []
    for req in requests:
        requester = users_collection.find_one({"_id": ObjectId(req["requester_id"])})
        if requester:
            request_list.append({
                "request_id": str(req["_id"]),
                "requester": serialize_user(requester)
            })
    print(request_list)
    return jsonify({"requests": request_list}), 200

@app.route("/sent-requests/<user_id>", methods=["GET"])
def get_sent_requests(user_id):
    requests = connections_collection.find({
        "requester_id": user_id,
        "status": "pending"
    })
    
    request_list = []
    for req in requests:
        request_list.append({
            "request_id": str(req["_id"]),
            "receiver_id": req["receiver_id"],
            "status": req["status"]
        })
    
    return jsonify({"sent_requests": request_list}), 200

# Get Suggested Connections 
@app.route("/suggested-users/<user_id>", methods=["GET"])
def get_suggested_users(user_id):
    try:
        # Get user's connections (both accepted and pending)
        connections = list(connections_collection.find({
            "$or": [
                {"requester_id": user_id},
                {"receiver_id": user_id}
            ]
        }))

        connected_user_ids = {user_id} 
        for conn in connections:
            connected_user_ids.add(conn["requester_id"])
            connected_user_ids.add(conn["receiver_id"])

        # Convert to ObjectIds for query
        object_ids = [ObjectId(uid) for uid in connected_user_ids if ObjectId.is_valid(uid)]

        # Fetch suggested users (exclude self and all connections)
        suggested_users = users_collection.find({
            "_id": {"$nin": object_ids}
        })

        return jsonify({
            "suggested_users": [serialize_user(user) for user in suggested_users]
        }), 200

    except Exception as e:
        print(f"Error in suggested-users: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    
# Get Pending Friend Requests
@app.route("/pending-requests/<user_id>", methods=["GET"])
def get_pending_requests(user_id):
    try:
        # Get requests where user is receiver (received requests)
        received_requests = list(connections_collection.find({
            "receiver_id": user_id,
            "status": "pending"
        }))

        # Get requests where user is requester (sent requests)
        sent_requests = list(connections_collection.find({
            "requester_id": user_id,
            "status": "pending"
        }))

        # Combine and format the results
        pending_requests = []
        
        # Format received requests
        for req in received_requests:
            requester = users_collection.find_one({"_id": ObjectId(req["requester_id"])})
            if requester:
                pending_requests.append({
                    "request_id": str(req["_id"]),
                    "user": serialize_user(requester),
                    "type": "received",
                    "status": "pending"
                })

        # Format sent requests
        for req in sent_requests:
            receiver = users_collection.find_one({"_id": ObjectId(req["receiver_id"])})
            if receiver:
                pending_requests.append({
                    "request_id": str(req["_id"]),
                    "user": serialize_user(receiver),
                    "type": "sent",
                    "status": "pending"
                })

        return jsonify({"pending_requests": pending_requests}), 200

    except Exception as e:
        print(f"Error getting pending requests: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    
# Get Connections
@app.route('/connections/<user_id>', methods=['GET'])
def get_connections(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
    except Exception as e:
        return jsonify({"error": f"Invalid user ID format: {str(e)}"}), 400
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get the connections from the user's document
    connections = user.get('connections', [])
    connection_details = []
    
    for conn_id in connections:
        try:
            conn = users_collection.find_one({"_id": ObjectId(conn_id)})
            if conn:
                connection_details.append({
                    'id': str(conn['_id']),
                    'email': conn.get('email', ''),
                    'name': conn.get('name', ''),
                    'profile_pic': conn.get('profile_pic', 'default.jpg')
                })
        except Exception:
            continue
    
    print(connection_details)
    
    return jsonify({'connections': connection_details})

""" @app.route('/update-status/<user_id>', methods=['POST'])
def update_status(user_id):
    data = request.get_json()
    online_users[user_id] = {
        'is_online': data.get('is_online', False),
        'last_seen': datetime.now(timezone.utc).isoformat(),
        'sid': None 
    }
    return jsonify({'status': 'updated'})

@app.route('/status/<user_id>', methods=['GET'])
def get_status(user_id):
    status = online_users.get(user_id, {
        'is_online': False,
        'last_seen': datetime.now(timezone.utc).isoformat()
    })
    return jsonify(status) """
    

@app.route('/update-status/<user_id>', methods=['POST'])
def update_status(user_id):
    data = request.get_json()
    is_online = data.get('is_online', False)
    last_seen = datetime.now(timezone.utc)

    try:
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_online': is_online, 'last_seen': last_seen}}
        )
        if result.modified_count > 0:
            return jsonify({'status': 'updated'})
        else:
            return jsonify({'status': 'user not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status/<user_id>', methods=['GET'])
def get_status(user_id):
    """Get user's current status from MongoDB"""
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if user:
            return jsonify({
                'is_online': user.get('is_online', False),
                'last_seen': user.get('last_seen', datetime.now(timezone.utc)).isoformat()
            })
        else:
            return jsonify({
                'is_online': False,
                'last_seen': datetime.now(timezone.utc).isoformat()
            }), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/group-media-counts/<group_id>', methods=['GET'])
def get_group_media_counts(group_id):
    try:
        # Count media by type
        pipeline = [
            {"$match": {"group_id": group_id}},
            {"$group": {
                "_id": "$type",
                "count": {"$sum": 1}
            }}
        ]
        counts = group_messages_collection.aggregate(pipeline)
        
        # Initialize counts
        media_counts = {
            "images": 0,
            "videos": 0,
            "pdfs": 0,
            "voice": 0
        }
        
        # Populate counts
        for count in counts:
            if count["_id"] == "image":
                media_counts["images"] = count["count"]
            elif count["_id"] == "video":
                media_counts["videos"] = count["count"]
            elif count["_id"] == "pdf":
                media_counts["pdfs"] = count["count"]
            elif count["_id"] == "voice":
                media_counts["voice"] = count["count"]
        
        return jsonify({"media_counts": media_counts}), 200
    except Exception as e:
        print(f"Error fetching media counts: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Create Group Route
@app.route("/create-group", methods=["POST"])
def create_group():
    try:
        print("Received /create-group request")
        print("Form data:", request.form)
        print("Files:", request.files)

        group_name = request.form.get("name")
        creator_id = request.form.get("creator_id")
        member_ids_json = request.form.get("member_ids")
        description = request.form.get("description", "No description provided")

        print("Group name:", group_name)
        print("Creator ID:", creator_id)
        print("Member IDs JSON:", member_ids_json)
        print("Description:", description)

        if not group_name or not creator_id:
            return jsonify({"error": "Group name and creator ID are required"}), 400

        try:
            member_ids = json.loads(member_ids_json) if member_ids_json else []
        except json.JSONDecodeError as e:
            print("JSON decode error:", str(e))
            return jsonify({"error": "Invalid member_ids format"}), 400

        if creator_id not in member_ids:
            member_ids.append(creator_id)

        profile_pic_path = "profile_pics/group_default.jpg"
        if "profile_pic" in request.files:
            profile_pic = request.files["profile_pic"]
            if profile_pic.filename:
                filename = f"group_{group_name}_{datetime.now(timezone.utc).timestamp()}.jpg"
                profile_pic_path = os.path.join("profile_pics", filename)
                print("Saving file to:", profile_pic_path)
                profile_pic.save(profile_pic_path)

        group_id = str(ObjectId())
        group_data = {
            "group_id": group_id,
            "name": group_name,
            "creator_id": creator_id,
            "members": member_ids,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "profile_pic": profile_pic_path,
            "admins": [creator_id],
            "description": description
        }

        print("Group data:", group_data)
        users_collection.update_many(
            {"_id": {"$in": [ObjectId(member_id) for member_id in member_ids]}},
            {"$addToSet": {"groups": group_data}}
        )

        print("Group created successfully")
        return jsonify({
            "message": "Group created successfully",
            "group_id": group_id,
            "group": group_data
        }), 201

    except Exception as e:
        print("Error in /create-group:", str(e))
        return jsonify({"error": str(e)}), 500
    
# Get User's Groups
@app.route("/user-groups/<user_id>", methods=["GET"])
def get_user_groups(user_id):
    try:
        try:
            user_id_obj = ObjectId(user_id)
        except InvalidId:
            return jsonify({"error": "Invalid user ID format"}), 400
        
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404

        groups = user.get("groups", [])
        if not isinstance(groups, list):
            print(f"Warning: groups field is not a list for user {user_id}")
            groups = []

        validated_groups = []

        for group in groups:
            try:
                if not group.get("group_id") or not group.get("name"):
                    continue

                group_id = group["group_id"]

                # Get last message from group_messages_collection
                last_msg = group_messages_collection.find_one(
                    {"group_id": str(group_id)},
                    sort=[("timestamp", -1)]
                )
                
                # Count unread messages in the group
                unread_count = group_messages_collection.count_documents({
                    "group_id": str(group_id),
                    "read_by": {"$ne": user_id}
                })
                group["unread_count"] = unread_count

                if last_msg:
                    if last_msg["type"] == "text":
                        group["last_message"] = last_msg.get("message", "")
                    elif last_msg["type"] == "voice":
                        group["last_message"] = "Voice message"
                    elif last_msg["type"] == "image":
                        group["last_message"] = "Image"
                    else:
                        group["last_message"] = ""

                    group["last_message_time"] = last_msg["timestamp"].isoformat()
                else:
                    group["last_message"] = ""
                    group["last_message_time"] = ""

                group["profile_pic"] = group.get("profile_pic", "default.jpg")
                validated_groups.append(group)
            except Exception as e:
                print(f"Error processing group {group.get('group_id', 'unknown')}: {str(e)}")
                continue

        # Sort by last_message_time (most recent first)
        validated_groups.sort(key=lambda g: g.get("last_message_time", ""), reverse=True)

        return jsonify({"groups": validated_groups}), 200


    except Exception as e:
        print(f"Error fetching groups for user {user_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500
     
# Get Group Details (from any member's document)
@app.route("/group/<group_id>", methods=["GET"])
def get_group_details(group_id):
    try:
        # Find any user who is a member of this group
        user = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}  # Project just the matching group
        )
        
        if not user or not user.get("groups"):
            return jsonify({"error": "Group not found"}), 404
            
        group = user["groups"][0]  # First (and only) matching group
        
        return jsonify(group), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update Group 

@app.route("/update-group", methods=["PUT"])
def update_group():
    try:
        data = request.json
        group_id = data.get("group_id")
        updates = data.get("updates", {})
        
        if not group_id:
            return jsonify({"error": "Group ID is required"}), 400

        # Get current group data
        user_with_group = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}
        )

        if not user_with_group or not user_with_group.get("groups"):
            return jsonify({"error": "Group not found"}), 404

        current_group = user_with_group["groups"][0]
        member_ids = current_group.get("members", [])

        # Prepare update operations
        update_operations = {}
        for field, value in updates.items():
            if field in ["name", "description", "admins", "members"]:
                update_operations[f"groups.$.{field}"] = value

        # Update the group in all members' documents
        result = users_collection.update_many(
            {"groups.group_id": group_id},
            {"$set": update_operations}
        )

        # If members were updated, also update individual user records
        if "members" in updates:
            # Remove group from users who are no longer members
            removed_members = set(member_ids) - set(updates["members"])
            users_collection.update_many(
                {"_id": {"$in": [ObjectId(mid) for mid in removed_members]}},
                {"$pull": {"groups": {"group_id": group_id}}}
            )

            # Add group to new members
            new_members = set(updates["members"]) - set(member_ids)
            users_collection.update_many(
                {"_id": {"$in": [ObjectId(mid) for mid in new_members]}},
                {"$addToSet": {"groups": current_group}}
            )

        return jsonify({
            "message": "Group updated successfully",
            "modified_count": result.modified_count
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/update-group-image", methods=["POST"])
def update_group_image():
    try:
        group_id = request.form.get("group_id")
        if not group_id:
            return jsonify({"error": "Group ID is required"}), 400
        if "profile_pic" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files["profile_pic"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400
        filename = f"group_{group_id}_{datetime.now(timezone.utc).timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        result = users_collection.update_many(
            {"groups.group_id": group_id},
            {"$set": {"groups.$.profile_pic": f"uploads/{filename}"}}
        )
        return jsonify({
            "message": "Group profile picture updated successfully",
            "profile_pic": f"uploads/{filename}",
            "modified_count": result.modified_count
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/messages-since/<user_id>/<other_user_id>/<timestamp>', methods=['GET'])
def get_messages_since(user_id, other_user_id, timestamp):
    try:
        # Parse input timestamp
        since_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if since_date.tzinfo is None:
            since_date = since_date.replace(tzinfo=timezone.utc)
        
        print(f"Fetching messages since: {since_date.isoformat()}")
        
        since_date1 = isoparse("2025-06-23T09:27:19.317395+00:00")

        # Query MongoDB, including messages with timestamp >= since_date
        messages = messages_collection.find({
            "$or": [
                {"sender_id": user_id, "receiver_id": other_user_id},
                {"sender_id": other_user_id, "receiver_id": user_id}
            ],
            "timestamp": {"$gte": since_date}  # Use $gte instead of $gt
        }).sort("timestamp", 1)
        
        print("Time Currednnfdfdsf ",since_date.isoformat())
        print("sdsdsd" ,messages)
        
        message_list = []
        for msg in messages:
            # Parse string timestamp from DB
            msg_timestamp = msg["timestamp"]
            if msg_timestamp.tzinfo is None:
                msg_timestamp = msg_timestamp.replace(tzinfo=timezone.utc)
                
            message_data = {
                "id": str(msg["_id"]),
                "sender_id": msg["sender_id"],
                "receiver_id": msg["receiver_id"],
                "timestamp": msg_timestamp.isoformat(),
                "read": msg.get("read", False),
                "delivered": msg.get("delivered", False),
                "is_image": msg.get("is_image", False),
                "is_pdf": msg.get("is_pdf", False),
                "is_voice": msg.get("is_voice", False),
                "is_video": msg.get("is_video", False),
                "temp_id": msg.get("temp_id", ""),
                "filename": msg.get("filename", "")
            }
            
            if msg.get('is_image', False):
                message_data['image_url'] = f'/get-image/{str(msg["_id"])}'
            elif msg.get('is_pdf', False):
                message_data['pdf_id'] = str(msg["_id"])
                message_data['filename'] = msg.get("filename", "document.pdf")
            elif msg.get('is_voice', False):
                message_data['voice_url'] = f'/get-voice/{str(msg["_id"])}'
            elif msg.get('is_video', False):
                message_data['video_id'] = str(msg["_id"])
                message_data['filename'] = msg.get("filename", "video.mp4")
                message_data['video_url'] = f'/get-video/{str(msg["_id"])}'
            else:
                message_data['message'] = msg.get('message', '')
                
            message_list.append(message_data)
        
        print(f"Found {len(message_list)} new messages")
        return jsonify({
            "success": True,
            "messages": message_list,
            "requested_since": since_date.isoformat()
        })
    except ValueError as ve:
        print(f"Timestamp parsing error: {str(ve)}")
        return jsonify({"success": False, "error": f"Invalid timestamp: {str(ve)}", "requested_since": timestamp}), 400
    except Exception as e:
        print(f"Error in /messages-since: {str(e)}")
        return jsonify({"success": False, "error": str(e), "requested_since": timestamp}), 500

@app.route('/mark-group-messages-read/<group_id>/<user_id>', methods=['POST'])
def mark_group_messages_read(group_id, user_id):
    try:
        result = group_messages_collection.update_many(
            {
                "group_id": group_id,
                "read_by": {"$ne": user_id}
            },
            {
                "$addToSet": {"read_by": user_id}
            }
        )
        return jsonify({"updated_count": result.modified_count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Delete Group
@app.route("/delete-group/<group_id>", methods=["DELETE"])
def delete_group(group_id):
    try:
        user_with_group = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}
        )

        if not user_with_group or not user_with_group.get("groups"):
            return jsonify({"error": "Group not found"}), 404

        group = user_with_group["groups"][0]
        member_ids = group.get("members", [])

        deleted_group_data = {
            "group_id": group_id,
            "name": group.get("name"),
            "members": member_ids,
            "deleted_at": datetime.now(timezone.utc).isoformat()
        }
        deleted_groups_collection.insert_one(deleted_group_data)

        users_collection.update_many(
            {"groups.group_id": group_id},
            {"$pull": {"groups": {"group_id": group_id}}}
        )

        # Use socketio.emit instead of emit, with namespace if needed
        socketio.emit('group_deleted', {
            'group_id': group_id,
            'message': 'This group has been deleted'
        }, room=group_id, namespace='/')

        return jsonify({"message": "Group deleted successfully"}), 200

    except Exception as e:
        print(f"Error deleting group: {str(e)}")  # Log the error for debugging
        return jsonify({"error": str(e)}), 500
    
def add_description_to_existing_groups():
    users = users_collection.find({"groups": {"$exists": True}})
    for user in users:
        groups = user.get("groups", [])
        updated_groups = []
        for group in groups:
            if "description" not in group:
                group["description"] = "No description provided"
            updated_groups.append(group)
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"groups": updated_groups}}
        )

# Run the script
add_description_to_existing_groups()



# Fetch Group Chat History (with correct filtering)
@app.route('/group-messages/<group_id>', methods=['GET'])
def get_group_messages(group_id):
    try:
        user_id = request.args.get('user_id')  # Expect user_id as query param
        if not user_id:
            return jsonify({"error": "user_id is required as query parameter"}), 400

        # Only fetch messages not deleted for this user
        messages = group_messages_collection.find({
            "group_id": group_id,
            "$or": [
                {"deleted_by": {"$exists": False}},
                {"deleted_by": {"$ne": user_id}}
            ]
        }).sort("timestamp", 1)

        # Fetch group details to get member info
        user_with_group = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}
        )
        if not user_with_group or not user_with_group.get("groups"):
            return jsonify({"error": "Group not found"}), 404

        group = user_with_group["groups"][0]
        member_ids = group.get("members", [])

        # Fetch member details
        members = users_collection.find({"_id": {"$in": [ObjectId(mid) for mid in member_ids]}})
        member_map = {str(member["_id"]): serialize_user(member) for member in members}

        return jsonify({
            "messages": [{
                "id": str(msg["_id"]),
                "sender_id": msg["sender_id"],
                "sender": member_map.get(msg["sender_id"], {"name": "Unknown"}),
                "group_id": msg["group_id"],
                "type": msg.get("type", "text"),
                "message": msg.get("message", ""),
                "voice_url": f'/get-voice/{str(msg["_id"])}' if msg.get("type") == "voice" else None,
                "image_url": f'/get-group-image/{str(msg["_id"])}' if msg.get("type") == "image" else None,
                "video_url": f'/get-group-video/{str(msg["_id"])}' if msg.get("type") == "video" else None,
                "pdf_url": f'/get-group-pdf/{str(msg["_id"])}' if msg.get("type") == "pdf" else None,
                "filename": msg.get("filename") if msg.get("type") in ["pdf", "video", "image"] else None,
                "timestamp": msg["timestamp"].isoformat(),
                "read_by": msg.get("read_by", []),
                "reactions": msg.get("reactions", {}),
                "meta": {
                    "filename": msg.get("filename"),
                    "mimetype": msg.get("mimetype")
                }
            } for msg in messages]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Delete group message for everyone
@app.route('/delete-group-message-everyone/<group_id>/<message_id>', methods=['DELETE'])
def delete_group_message_everyone(group_id, message_id):
    try:
        result = group_messages_collection.delete_one({
            "_id": ObjectId(message_id),
            "group_id": group_id
        })
        if result.deleted_count == 1:
            # Notify all group members to remove from local DB
            socketio.emit('group_message_deleted', {
                'message_id': message_id,
                'group_id': group_id,
                'action': 'delete_for_everyone'
            }, room=group_id)
            return jsonify({"success": True, "message": "Message deleted for everyone"})
        else:
            return jsonify({"success": False, "error": "Message not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Delete group message for me
@app.route('/delete-group-message-me/<group_id>/<message_id>/<user_id>', methods=['POST'])
def delete_group_message_me(group_id, message_id, user_id):
    try:
        result = group_messages_collection.update_one(
            {"_id": ObjectId(message_id), "group_id": group_id},
            {"$addToSet": {"deleted_by": user_id}}
        )
        if result.modified_count == 1:
            # Notify only this user to remove from local DB
            socketio.emit('group_message_deleted', {
                'message_id': message_id,
                'group_id': group_id,
                'action': 'delete_for_me',
                'user_id': user_id
            }, room=request.sid)
            return jsonify({"success": True, "message": "Message deleted for you"})
        else:
            return jsonify({"success": False, "error": "Message not found or already deleted"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
 
    
""" online_users = {}
 """

@socketio.on('connect')
def handle_connect():
    user_id = request.args.get('user_id')
    if user_id:
        # Track the socket connection
        user_sockets[user_id] = request.sid
        
        online_users[user_id] = {
            'is_online': True,
            'last_seen': datetime.now(timezone.utc).isoformat(),
            'sid': request.sid
        }
        emit('user_status', {
            'user_id': user_id,
            'is_online': True,
            'last_seen': datetime.now(timezone.utc).isoformat()
        }, broadcast=True)
    print(f'User connected: {user_id} - Socket: {request.sid}')
    

@socketio.on('disconnect')
def handle_disconnect():
    # Find and remove the disconnected socket from user_sockets
    for user_id, sid in list(user_sockets.items()):
        if sid == request.sid:
            del user_sockets[user_id]
            break
    
    for user_id, data in list(online_users.items()):
        if data.get('sid') == request.sid:
            online_users[user_id] = {
                'is_online': False,
                'last_seen': datetime.now(timezone.utc).isoformat()
            }
            emit('user_status', {
                'user_id': user_id,
                'is_online': False,
                'last_seen': datetime.now(timezone.utc).isoformat()
            }, broadcast=True)
            break
    print(f'User disconnected: {request.sid}')
    
    
@socketio.on('join_room')
def handle_join_room(data):
    user_id = data.get('user_id')
    receiver_id = data.get('receiver_id')
    
    if not all([user_id, receiver_id]):
        emit('room_error', {'error': "Missing user_id or receiver_id"})
        return
        
    room = '_'.join(sorted([user_id, receiver_id]))
    join_room(room)
    print(f'User {user_id} joined room: {room}')
    

# In Flask SocketIO
@socketio.on('send_message')
def handle_send_message(data):
    try:
        
        # Generate server timestamp
        server_time = datetime.now(timezone.utc)
        
        # Check if the message is an image
        if data.get('is_image', False) or data.get('type') == 'voice':
            return
        
        if data.get('is_pdf', False):
            message = messages_collection.find_one({'temp_id': data['temp_id'], 'is_pdf': True})
            if not message:
                emit('message_error', {
                    'error': 'PDF message not found',
                    'temp_id': data['temp_id']
                }, room=request.sid)
                return

            result = messages_collection.update_one(
                {'temp_id': data['temp_id']},
                {
                    '$set': {
                        'timestamp': server_time,
                        'server_timestamp': server_time,
                        'delivered': True
                    }
                }
            )

            if result.modified_count == 0:
                emit('message_error', {
                    'error': 'Failed to update PDF message',
                    'temp_id': data['temp_id']
                }, room=request.sid)
                return
            message_id = str(message['_id'])
            response = {
                'id': message_id,
                'temp_id': data['temp_id'],
                'sender_id': data['sender_id'],
                'receiver_id': data['receiver_id'],
                'is_pdf': True,
                'pdf_id': message_id,
                'filename': message.get('filename', 'document.pdf'),
                'timestamp': server_time.isoformat(),
                'server_timestamp': server_time.isoformat(),
                'read': False,
                'delivered': True
            }

            room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
            emit('message_sent', {
                **response,
                'status': 'sent',
                'original_temp_id': data['temp_id']
            }, room=request.sid)
            emit('receive_message', response, room=room)
            return
        
        if data.get('is_video', False):
            message = messages_collection.find_one({'temp_id': data['temp_id'], 'is_video': True})
            if not message:
                emit('message_error', {
                    'error': 'Video message not found',
                    'temp_id': data['temp_id']
                }, room=request.sid)
                return

            result = messages_collection.update_one(
                {'temp_id': data['temp_id']},
                {
                    '$set': {
                        'timestamp': server_time,
                        'server_timestamp': server_time,
                        'delivered': True
                    }
                }
            )

            if result.modified_count == 0:
                emit('message_error', {
                    'error': 'Failed to update video message',
                    'temp_id': data['temp_id']
                }, room=request.sid)
                return

            message_id = str(message['_id'])
            response = {
                'id': message_id,
                'temp_id': data['temp_id'],
                'sender_id': data['sender_id'],
                'receiver_id': data['receiver_id'],
                'is_video': True,
                'video_id': message_id,
                'filename': message.get('filename', 'video.mp4'),
                'timestamp': server_time.isoformat(),
                'server_timestamp': server_time.isoformat(),
                'read': False,
                'delivered': True
            }

            room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
            emit('message_sent', {
                **response,
                'status': 'sent',
                'original_temp_id': data['temp_id']
            }, room=request.sid)
            emit('receive_message', response, room=room)
            
            return
        
        if data.get('is_voice', False):
            # Find the existing voice message by temp_id
            message = messages_collection.find_one({'temp_id': data['temp_id']})
            if not message:
                emit('message_error', {
                    'error': 'Voice message not found',
                    'temp_id': data['temp_id']
                }, room=request.sid)
                return
            
            # Update message with server-generated ID and timestamp
            result = messages_collection.update_one(
                    {'temp_id': data['temp_id']},
                    {
                        '$set': {
                            'timestamp': server_time,
                            'server_timestamp': server_time,
                            'delivered': True
                        }
                    }
                )
        
            if result.modified_count == 0:
                    emit('message_error', {
                        'error': 'Failed to update voice message',
                        'temp_id': data['temp_id']
                    }, room=request.sid)
                    return

            message_id = str(message['_id'])
            response = {
                'id': message_id,
                'temp_id': data['temp_id'],
                'sender_id': data['sender_id'],
                'receiver_id': data['receiver_id'],
                'voice_url': data['voice_url'],
                'is_voice': True,
                'timestamp': server_time.isoformat(),
                'server_timestamp': server_time.isoformat(),
                'read': False,
                'delivered': True
            }

            # Emit to room
            room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
            emit('message_sent', {
                **response,
                'status': 'sent',
                'original_temp_id': data['temp_id']
            }, room=request.sid)  # Confirm to sender
            emit('receive_message', response, room=room)  # Broadcast to receiver
            return
        
        # Create message document
        message = {
            'sender_id': data['sender_id'],
            'receiver_id': data['receiver_id'],
            'message': data.get('message', ''),
            'timestamp': server_time,
            'read': False,
            'delivered': False,
            'is_image': data.get('is_image', False),
            'temp_id': data.get('temp_id', str(ObjectId())),
            'server_timestamp': server_time
        }
        
        # Insert to database
        result = messages_collection.insert_one(message)
        message_id = str(result.inserted_id)
        
        # Prepare response
        response = {
            'id': message_id,
            'temp_id': message['temp_id'],
            'sender_id': message['sender_id'],
            'receiver_id': message['receiver_id'],
            'timestamp': server_time.isoformat(),
            'server_timestamp': server_time.isoformat(),
            'read': False,
            'delivered': False,
            'is_image': message['is_image']
        }
        
        if message['is_image']:
            response['image_url'] = f'/get-image/{message_id}'
        else:
            response['message'] = message['message']
        
        # Emit to room
        room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
        emit('message_sent', {
            **response,
            'status': 'sent',
            'original_temp_id': data.get('temp_id', '')
        }, room=request.sid)
        
        emit('receive_message', response, room=room)
        
    except Exception as e:
        print(f"Error handling message: {str(e)}")
        emit('message_error', {
            'error': str(e),
            'temp_id': data.get('temp_id', '')
        }, room=request.sid)
        
        
@socketio.on('message_delivered')
def handle_message_delivered(data):
    try:
        # Update both by ObjectId _id and temp_id
        messages_collection.update_one(
            {
                '$or': [
                    {'_id': ObjectId(data['message_id'])},
                    {'temp_id': data['temp_id']}
                ]
            },
            {'$set': {'delivered': True}}
        )
        
        room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
        emit('message_delivered', {
            'message_id': data['message_id'],
            'temp_id': data.get('temp_id', '')
        }, room=room)
    except Exception as e:
        print(f"Error handling delivery receipt: {str(e)}")
        

@socketio.on('typing')
def handle_typing(data):
    room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
    emit('typing', {
        'sender_id': data['sender_id'],
        'is_typing': data['is_typing']
    }, room=room)

@socketio.on('typing_group')
def handle_typing_group(data):
    group_id = data['group_id']
    sender_id = data['sender_id']
    is_typing = data['is_typing']
    emit('typing_group', {
        'sender_id': sender_id,
        'is_typing': is_typing
    }, room=group_id)
  
@socketio.on('message_read')
def handle_message_read(data):
    try:
        if not all(k in data for k in ['sender_id', 'receiver_id']):
            raise ValueError("Missing required fields")
        
        sender_id = str(data['sender_id'])
        receiver_id = str(data['receiver_id'])
        
        result = messages_collection.update_many(
            {
                'sender_id': receiver_id,
                'receiver_id': sender_id,
                'read': False
            },
            {
                '$set': {
                    'read': True,
                    'read_at': datetime.now(timezone.utc),
                    'updated_at': datetime.now(timezone.utc)
                }
            }
        )
        
        print(f"Marked {result.modified_count} messages as read")
        
        # Notify all clients in the chat room
        room = '_'.join(sorted([sender_id, receiver_id]))
        emit('messages_read', {
            'reader_id': sender_id,
            'count': result.modified_count,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, room=room)
        
    except Exception as e:
        print(f"Error updating read status: {str(e)}")
        emit('error', {'message': 'Failed to update read status'})
        

@app.route('/messages/<user_id>/<other_user_id>', methods=['GET'])
def get_chat_history(user_id, other_user_id):
    """Get chat history between two users"""
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": user_id, "receiver_id": other_user_id},
                {"sender_id": other_user_id, "receiver_id": user_id}
            ]
        }).sort("timestamp", 1)
        
        messages_collection.update_many(
            {
                "sender_id": other_user_id,
                "receiver_id": user_id,
                "read": False
            },
            {"$set": {"read": True}}
        )
        
        message_list = []
        for msg in messages:
            message_data = {
                "id": str(msg["_id"]),
                "sender_id": msg["sender_id"],
                "receiver_id": msg["receiver_id"],
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg["read"],
                "delivered": msg.get("delivered", False),
                "is_image": msg.get("is_image", False),
                "is_pdf": msg.get("is_pdf", False),
                "is_voice": msg.get("is_voice", False),
                "temp_id": msg.get("temp_id", ""),
                "reactions": msg.get("reactions", {}),
            }
            
            if msg.get('is_image', False):
                message_data['image_url'] = f'/get-image/{str(msg["_id"])}'
            elif msg.get('is_pdf', False):
                message_data['pdf_id'] = str(msg["_id"])
                message_data['filename'] = msg.get("filename", "document.pdf")
            elif msg.get('is_voice', False):
                message_data['voice_url'] = f'/get-voice/{str(msg["_id"])}'
            else:
                message_data['message'] = msg.get('message', '')
                
            message_list.append(message_data)
        
        print("Hello Hello" ,message_list)
        
        return jsonify({"messages": message_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@socketio.on('send_reaction')
def handle_send_reaction(data):
    try:
        message_id = data.get('message_id')
        user_id = data.get('user_id')
        reaction = data.get('reaction')  # This is the emoji, or empty/null to remove

        if not all([message_id, user_id]):
            emit('reaction_error', {'error': 'Missing required fields'}, room=request.sid)
            return

        message = messages_collection.find_one({'_id': ObjectId(message_id)})
        if not message:
            emit('reaction_error', {'error': 'Message not found'}, room=request.sid)
            return

        # An empty reaction from the client means the user wants to remove their existing reaction.
        if reaction:
            update_query = {'$set': {f'reactions.{user_id}': reaction}}
        else:
            update_query = {'$unset': {f'reactions.{user_id}': ""}}

        # Atomically update the document and get the new version.
        updated_message = messages_collection.find_one_and_update(
            {'_id': ObjectId(message_id)},
            update_query,
            return_document=True  # Use pymongo.ReturnDocument.AFTER
        )

        # Broadcast the change to everyone in the chat room.
        room = '_'.join(sorted([message['sender_id'], message['receiver_id']]))
        emit('reaction_updated', {
            'message_id': message_id,
            'reactions': updated_message.get('reactions', {})
        }, room=room)

    except InvalidId:
        emit('reaction_error', {'error': 'Invalid message ID'}, room=request.sid)
    except Exception as e:
        print(f"Error handling reaction: {str(e)}")
        emit('reaction_error', {'error': str(e)}, room=request.sid)
       

""" @app.route('/chats/<user_id>', methods=['GET'])
def get_user_chats(user_id):
    try:
        senders = messages_collection.distinct(
            "sender_id",
            {"receiver_id": user_id}
        )
        receivers = messages_collection.distinct(
            "receiver_id",
            {"sender_id": user_id}
        )
        chat_partners = list(set(senders + receivers) - {user_id})
        
        chats = []
        for partner_id in chat_partners:
            partner = users_collection.find_one({"_id": ObjectId(partner_id)})
            if not partner:
                continue
                
            last_message = messages_collection.find_one({
                "$or": [
                    {"sender_id": user_id, "receiver_id": partner_id},
                    {"sender_id": partner_id, "receiver_id": user_id}
                ]
            }, sort=[("timestamp", -1)])
            
            unread_count = messages_collection.count_documents({
                "sender_id": partner_id,
                "receiver_id": user_id,
                "read": False
            })
            
            # Handle last message content
            last_message_content = ""
            if last_message:
                if last_message.get("is_image", False):
                    last_message_content = "Image"
                elif last_message.get("is_voice", False):
                    last_message_content = "Voice message"
                else:
                    last_message_content = last_message.get("message", "")
            
            
            chats.append({
                "partner_id": partner_id,
                "name": partner.get("name", "Unknown"),
                "profile_pic": partner.get("profile_pic", "default.jpg"),
                "last_message": last_message.get("message", "") if last_message else "",
                "last_message_time": last_message["timestamp"].isoformat() if last_message else "",
                "unread_count": unread_count
            })
        
        chats.sort(key=lambda x: x["last_message_time"], reverse=True)
        
        return jsonify({"chats": chats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500 """
        
@app.route('/chats/<user_id>', methods=['GET'])
def get_user_chats(user_id):
    try:
        senders = messages_collection.distinct(
            "sender_id",
            {"receiver_id": user_id}
        )
        receivers = messages_collection.distinct(
            "receiver_id",
            {"sender_id": user_id}
        )
        chat_partners = list(set(senders + receivers) - {user_id})
        
        chats = []
        for partner_id in chat_partners:
            partner = users_collection.find_one({"_id": ObjectId(partner_id)})
            if not partner:
                continue
                
            last_message = messages_collection.find_one({
                "$or": [
                    {"sender_id": user_id, "receiver_id": partner_id},
                    {"sender_id": partner_id, "receiver_id": user_id}
                ]
            }, sort=[("timestamp", -1)])
            
            unread_count = messages_collection.count_documents({
                "sender_id": partner_id,
                "receiver_id": user_id,
                "read": False
            })
            
            # Initialize with default values
            last_message_content = ""
            last_message_type = "text" # Default to text

            if last_message:
                if last_message.get("is_image", False):
                    last_message_content = "Image"
                    last_message_type = "image"
                elif last_message.get("is_voice", False):
                    last_message_content = "Voice message"
                    last_message_type = "voice"
                else:
                    last_message_content = last_message.get("message", "")
                    last_message_type = "text"
            
            chats.append({
                "partner_id": partner_id,
                "name": partner.get("name", "Unknown"),
                "profile_pic": partner.get("profile_pic", "default.jpg"),
                "last_message": last_message_content, # Use the determined content here
                "last_message_type": last_message_type, # Add the message type
                "last_message_time": last_message["timestamp"].isoformat() if last_message else "",
                "is_delivered": last_message["read"],
                "unread_count": unread_count
            })
        
        chats.sort(key=lambda x: x["last_message_time"], reverse=True)
        
        return jsonify({"chats": chats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
@app.route('/chats/<user_id>/<partner_id>', methods=['DELETE'])
def delete_chat(user_id, partner_id):
    try:
        chat_id_1 = f"{user_id}_{partner_id}"
        chat_id_2 = f"{partner_id}_{user_id}"

        result = messages_collection.delete_many({
            "$or": [
                {"sender_id": user_id, "receiver_id": partner_id},
                {"sender_id": partner_id, "receiver_id": user_id}
            ]
        })

        return jsonify({
            "message": "Chat deleted successfully",
            "deleted_count": result.deleted_count
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

 # Profile picture upload endpoint
@app.route('/upload-profile-pic', methods=['POST'])
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['profile_pic']
    user_id = request.form.get('user_id')
    
    if not user_id or not file.filename:
        return jsonify({"error": "Invalid request"}), 400

    # Generate unique filename
    filename = f"profile_{user_id}_{datetime.now(timezone.utc).timestamp()}.{secure_filename(file.filename).split('.')[-1]}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        profile_url = f"/uploads/{filename}"
        
        # Update user document
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"profile_pic": profile_url}}
        )
        
        return jsonify({"profile_pic": profile_url}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User update endpoint
@app.route('/user/<user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        data = request.json
        update_data = {}

        if 'name' in data:
            update_data['name'] = data['name']
        if 'email' in data:
            update_data['email'] = data['email']
        if 'phone' in data:
            update_data['phone'] = data['phone']
        if 'profile_pic' in data:
            update_data['profile_pic'] = data['profile_pic']

        result = users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )

        if result.modified_count == 0:
            return jsonify({"message": "No changes detected"}), 200

        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/upload-pdf', methods=['POST'])
def upload_pdf():
    
    print("Hello World")
    try:
        if 'file' not in request.files:
            print('Error: No file provided') # Add this
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        sender_id = request.form.get('sender_id')
        receiver_id = request.form.get('receiver_id')
        temp_id = request.form.get('temp_id')

        if not all([sender_id, receiver_id, temp_id]):
            return jsonify({"error": "Missing required fields"}), 400

        if file and file.filename.endswith('.pdf'):
            # Save PDF to storage
            upload_folder = 'uploads/pdfs'
            os.makedirs(upload_folder, exist_ok=True)
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            # Store message in database
            message = {
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'is_pdf': True,
                'temp_id': temp_id,
                'filename': file.filename,
                'pdf_path': file_path,
                'timestamp': datetime.now(sri_lanka_timezone),
                'read': False,
                'delivered': False
            }
            result = messages_collection.insert_one(message)

            return jsonify({
                'success': True,
                'pdf_id': str(result.inserted_id),
                'temp_id': temp_id
            })
        else:
            return jsonify({"error": "Invalid file type. Only PDFs are allowed"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/get-pdf/<pdf_id>', methods=['GET'])
def get_pdf(pdf_id):
    try:
        message = messages_collection.find_one({"_id": ObjectId(pdf_id), "is_pdf": True})
        if not message or not message.get('pdf_path'):
            return jsonify({"error": "PDF not found"}), 404

        return send_file(message['pdf_path'], as_attachment=True, download_name=message['filename'])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
@app.route('/upload-video', methods=['POST'])
def upload_video():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        sender_id = request.form.get('sender_id')
        receiver_id = request.form.get('receiver_id')
        temp_id = request.form.get('temp_id')

        if not all([sender_id, receiver_id, temp_id]):
            return jsonify({"error": "Missing required fields"}), 400

        if file and file.filename.lower().endswith(('.mp4', '.mov', '.avi')):
            upload_folder = 'Uploads/videos'
            os.makedirs(upload_folder, exist_ok=True)
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            message = {
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'is_video': True,
                'temp_id': temp_id,
                'filename': file.filename,
                'video_path': file_path,
                'timestamp': datetime.now(timezone.utc),
                'read': False,
                'delivered': False
            }
            result = messages_collection.insert_one(message)

            return jsonify({
                'success': True,
                'video_id': str(result.inserted_id),
                'temp_id': temp_id
            })
        else:
            return jsonify({"error": "Invalid file type. Only MP4, MOV, or AVI are allowed"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/upload-group-video', methods=['POST'])
def upload_group_video():
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        sender_id = request.form.get('sender_id')
        group_id = request.form.get('group_id')
        temp_id = request.form.get('temp_id')

        if not all([sender_id, group_id, temp_id]):
            return jsonify({'error': 'Missing required fields'}), 400

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file and file.filename.lower().endswith(('.mp4', '.mov', '.avi')):
            filename = f"video_{uuid.uuid4()}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            if not os.path.exists(filepath):
                raise IOError("File was not saved correctly")

            video_message = {
                'sender_id': sender_id,
                'group_id': group_id,
                'filename': filename,
                'file_path': filepath,
                'mimetype': file.mimetype,
                'timestamp': datetime.now(timezone.utc),
                'read_by': [sender_id],
                'type': 'video',
                'status': 'success',
                'temp_id': temp_id
            }

            result = group_messages_collection.insert_one(video_message)
            video_url = f'/get-group-video/{str(result.inserted_id)}'
            sender = users_collection.find_one({"_id": ObjectId(sender_id)})

            socketio.emit('receive_group_message', {
                '_id': str(result.inserted_id),
                'sender_id': sender_id,
                'sender': serialize_user(sender),
                'group_id': group_id,
                'video_url': video_url,
                'type': 'video',
                'timestamp': video_message['timestamp'].isoformat(),
                'read_by': [sender_id],
                'temp_id': temp_id
            }, room=group_id)

            return jsonify({
                'message': 'Video uploaded successfully',
                'video_url': video_url,
                'video_id': str(result.inserted_id),
                'status': 'success'
            }), 200
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        print(f"Error uploading video: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/get-group-video/<video_id>', methods=['GET'])
def get_group_video(video_id):
    try:
        video_data = group_messages_collection.find_one({'_id': ObjectId(video_id)})
        if not video_data or 'file_path' not in video_data:
            return jsonify({'error': 'Video not found'}), 404

        filepath = video_data['file_path']
        if not os.path.exists(filepath):
            return jsonify({'error': 'Video file not found on server'}), 404

        response = send_file(
            filepath,
            mimetype=video_data['mimetype'],
            as_attachment=False,
            conditional=True  # Supports range requests for streaming
        )
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Error retrieving video: {str(e)}")
        return jsonify({'error': str(e)}), 500
 
 
# Group chat events
@socketio.on('join_group')
def handle_join_group(data):
    try:
        group_id = data.get('group_id')
        user_id = data.get('user_id')
        
        # Verify user is a group member
        user = users_collection.find_one({
            "_id": ObjectId(user_id),
            "groups.group_id": group_id
        })
        
        if not user:
            print(f"User {user_id} not authorized to join group {group_id}")
            emit('join_confirmation', {
                'status': 'error',
                'message': 'Not a group member'
            })
            return False
        
        join_room(group_id)
        print(f'User {user_id} joined group room: {group_id}')
        
        # Send confirmation to this client only
        emit('join_confirmation', {
            'status': 'success', 
            'group_id': group_id
        }, room=request.sid)  # Send only to this client
        
    except Exception as e:
        print(f"Error joining group: {str(e)}")
        emit('join_confirmation', {
            'status': 'error', 
            'message': str(e)
        }, room=request.sid)
        
@socketio.on('send_group_reaction')
def handle_send_group_reaction(data):
    try:
        message_id = data.get('message_id')
        group_id = data.get('group_id')
        user_id = data.get('user_id')
        reaction = data.get('reaction', '')  # Empty string means remove

        if not all([message_id, group_id, user_id]):
            emit('reaction_error', {'error': 'Missing required fields'}, room=request.sid)
            return

        # Verify message exists and user is in group (add your auth logic here if needed)
        message = group_messages_collection.find_one({'_id': ObjectId(message_id), 'group_id': group_id})
        if not message:
            emit('reaction_error', {'error': 'Message not found'}, room=request.sid)
            return

        # Update reactions in MongoDB
        if reaction:
            update_query = {'$set': {f'reactions.{user_id}': reaction}}
        else:
            update_query = {'$unset': {f'reactions.{user_id}': ""}}

        updated_message = group_messages_collection.find_one_and_update(
            {'_id': ObjectId(message_id)},
            update_query,
            return_document=True
        )

        # Broadcast the updated reactions to the group
        emit('group_reaction_updated', {
            'message_id': message_id,
            'reactions': updated_message.get('reactions', {})
        }, room=group_id)

    except InvalidId:
        emit('reaction_error', {'error': 'Invalid message ID'}, room=request.sid)
    except Exception as e:
        print(f"Error handling group reaction: {str(e)}")
        emit('reaction_error', {'error': str(e)}, room=request.sid)
        
@socketio.on('send_group_message')
def handle_send_group_message(data):
    try:
        sender_id = data['sender_id']
        group_id = data['group_id']
        message_type = data.get('type', 'text') 
        
        print(f"New message in group {group_id} from {sender_id}")
        
        # Check if group exists
        user_with_group = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}
        )
        if not user_with_group:
            emit('group_error', {
                'error': 'Group not found'
            }, room=request.sid)
            return
        
        # Create message
        message = {
            'sender_id': sender_id,
            'group_id': group_id,
            'timestamp': datetime.now(timezone.utc),
            'read_by': [sender_id],
            'type': message_type
        }
        
        if message_type == 'text':
            message['message'] = data['message']
        elif message_type == 'voice':
            message['voice_url'] = data['voice_url']
        elif message_type == 'image':
            message['image_url'] = data['image_url']
        elif message_type == 'video':
            message['video_url'] = data['video_url']
            
        # Store temp_id if provided
        if 'temp_id' in data:
            message['temp_id'] = data['temp_id']
        
        # Store message
        message_id = group_messages_collection.insert_one(message).inserted_id
        
        # Get sender details
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        
        # Prepare full message with sender info
        full_message = {
            '_id': str(message_id),
            'sender_id': sender_id,
            'sender': serialize_user(sender),
            'group_id': group_id,
            'type': message_type,
            'timestamp': message['timestamp'].isoformat(),
            'read_by': message['read_by']
        }
        
        if message_type == 'text':
            full_message['message'] = message['message']
        elif message_type == 'voice':
            full_message['voice_url'] = message['voice_url']
        elif message_type == 'image':
            full_message['image_url'] = message['image_url']
        elif message_type == 'video':
            full_message['video_url'] = message['video_url']
        
        # Broadcast to ALL group members (including sender)
        emit('receive_group_message', full_message, room=group_id)
        socketio.emit('group_updated', {}, broadcast=True)
        print(f"Broadcasted message to group {group_id}")
        
    except Exception as e:
        print(f"Error handling group message: {str(e)}")
        emit('group_message_error', {'error': str(e)}, room=request.sid)
        

@socketio.on('delete_group_message')
def handle_delete_group_message(data):
    try:
        message_id = data.get('message_id')
        group_id = data.get('group_id')
        action = data.get('action')
        user_id = data.get('user_id')
        
        # Debug log to inspect received data
        print(f"Received delete_group_message: {data}")
        
        # Validate all required fields
        if not all(k in data for k in ['message_id', 'group_id', 'action', 'user_id']):
            missing_fields = [k for k, v in {
                'message_id': message_id,
                'group_id': group_id,
                'action': action,
                'user_id': user_id
            }.items() if not v]
            emit('delete_error', {
                'error': f'Missing required fields: {", ".join(missing_fields)}',
                'data': data
            }, room=request.sid)
            return
            
        # Verify user is in the group
        user_in_group = users_collection.find_one({
            "_id": ObjectId(user_id),
            "groups.group_id": group_id
        })
        
        if not user_in_group:
            emit('delete_error', {'error': 'Not a group member'}, room=request.sid)
            return
            
        # Find the message
        message = group_messages_collection.find_one({
            "_id": ObjectId(message_id),
            "group_id": group_id
        })
        
        if not message:
            emit('delete_error', {'error': 'Message not found'}, room=request.sid)
            return
            
        # Check admin or sender status
        is_admin = group_id in [g.get('group_id') for g in user_in_group.get('groups', []) 
                               if user_id in g.get('admins', [])]
        is_sender = message['sender_id'] == user_id
        
        # Only allow sender or admin to delete for everyone
        if action == 'delete_for_everyone' and not (is_sender or is_admin):
            emit('delete_error', {
                'error': 'Not authorized to delete for everyone'
            }, room=request.sid)
            return
            
        if action == 'delete_for_everyone':
            # Delete from database
            group_messages_collection.delete_one({
                '_id': ObjectId(message_id)
            })
            
            # Notify group
            emit('group_message_deleted', {
                'message_id': message_id,
                'group_id': group_id,
                'action': action
            }, room=group_id)
        elif action == 'delete_for_me':
            # Track who has deleted the message
            group_messages_collection.update_one(
                {'_id': ObjectId(message_id)},
                {'$addToSet': {'deleted_by': user_id}}
            )
            
            # Notify only this user
            emit('group_message_deleted', {
                'message_id': message_id,
                'group_id': group_id,
                'action': action
            }, room=request.sid)
            
    except InvalidId:
        emit('delete_error', {
            'error': 'Invalid message ID',
            'data': data
        }, room=request.sid)
    except Exception as e:
        print(f"Error deleting group message: {str(e)}")
        emit('delete_error', {
            'error': str(e),
            'data': data
        }, room=request.sid)
        
        
@socketio.on('message_read_group')
def handle_message_read_group(data):
    message_id = data['message_id']
    reader_id = data['reader_id']
    group_id = data['group_id']
    
    group_messages_collection.update_one(
        {"_id": ObjectId(message_id)},
        {"$addToSet": {"read_by": reader_id}}
    )
    
    emit('messages_read_group', {
        'message_id': message_id,
        'reader_id': reader_id
    }, room=group_id)
    
@socketio.on('delete_message')
def handle_delete_message(data):
    try:
        message_id = data.get('message_id')
        temp_id = data.get('temp_id')
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        action = data.get('action')
        
        if not all([message_id, sender_id, receiver_id, action]):
            emit('delete_error', {'error': 'Missing required fields'})
            return
            
        if action == 'delete_for_everyone':
            result = messages_collection.delete_one({
                '_id': ObjectId(message_id),
                'sender_id': sender_id 
            })
            
            if result.deleted_count > 0:
                room = '_'.join(sorted([sender_id, receiver_id]))
                emit('message_deleted', {
                    'message_id': message_id,
                    'temp_id': temp_id,
                    'action': action
                }, room=room)
            else:
                emit('delete_error', {
                    'error': 'Message not found or not authorized'
                })
                
    except InvalidId:
        emit('delete_error', {'error': 'Invalid message ID'})
    except Exception as e:
        print(f"Error deleting message: {str(e)}")
        emit('delete_error', {'error': str(e)})

@socketio.on('start_call')
def handle_start_call(data):
    caller_id = data['caller_id']
    receiver_id = data['receiver_id']
    call_type = data.get('call_type', 'audio')
    
    # Create a unique room ID for the call
    room_id = f"call_{caller_id}_{receiver_id}_{datetime.now(timezone.utc).timestamp()}"
    call_rooms[room_id] = {
        'caller_id': caller_id,
        'receiver_id': receiver_id,
        'call_type': call_type,
        'participants': [caller_id],
        'start_time': datetime.now(timezone.utc)
    }
    
    print(f"Active user sockets: {user_sockets}")

    receiver_sid = user_sockets.get(receiver_id)
    
    if receiver_sid:
        
        print(f"Sending call to {receiver_id} via socket {receiver_sid}")

        emit('incoming_call', {
            'room_id': room_id,
            'caller_id': caller_id,
            'receiver_id': receiver_id,
            'call_type': call_type
        }, room=receiver_sid)
    else:
        print(f"Receiver {receiver_id} not connected. Available sockets: {user_sockets}")

        emit('call_error', {'error': 'Receiver not connected'}, room=request.sid)
    
    emit('call_started', {
        'room_id': room_id,
        'receiver_id': receiver_id
    }, room=request.sid)
    

@socketio.on('join_call')
def handle_join_call(data):
    room_id = data['room_id']
    user_id = data['user_id']
    
    if room_id not in call_rooms:
        emit('call_error', {'error': 'Call room not found'}, room=request.sid)
        return
    
    call_rooms[room_id]['participants'].append(user_id)
    join_room(room_id)
    
    # Notify other participants
    emit('user_joined', {
        'user_id': user_id,
        'room_id': room_id
    }, room=room_id)
    
    # Send current participants to the new user
    emit('call_participants', {
        'participants': call_rooms[room_id]['participants'],
        'room_id': room_id
    }, room=request.sid)
    

@socketio.on('leave_call')
def handle_leave_call(data):
    room_id = data['room_id']
    user_id = data['user_id']
    
    if room_id not in call_rooms:
        return
    
    if user_id in call_rooms[room_id]['participants']:
        call_rooms[room_id]['participants'].remove(user_id)
    
    emit('user_left', {
        'user_id': user_id,
        'room_id': room_id
    }, room=room_id)
    
    if not call_rooms[room_id]['participants']:
        del call_rooms[room_id]

@socketio.on('end_call')
def handle_end_call(data):
    room_id = data['room_id']
    user_id = data['user_id']
    
    if room_id in call_rooms:
        emit('call_ended', {
            'room_id': room_id,
            'ended_by': user_id
        }, room=room_id)
        
        call_data = call_rooms[room_id]
        call_data['end_time'] = datetime.now(timezone.utc)
        call_data['duration'] = (call_data['end_time'] - call_data['start_time']).total_seconds()
        db.calls.insert_one(call_data)
        
        del call_rooms[room_id]
 
@socketio.on('typing_group')
def handle_typing_group(data):
    try:
        group_id = data['group_id']
        sender_id = data['sender_id']
        is_typing = data['is_typing']
        
        if group_id not in typing_users:
            typing_users[group_id] = {}
        
        sender = users_collection.find_one({"_id": ObjectId(sender_id)})
        sender_name = sender.get('name', 'Unknown') if sender else 'Unknown'
        
        if is_typing:
            typing_users[group_id][sender_id] = {
                'name': sender_name,
                'last_typed': datetime.now(timezone.utc)
            }
        else:
            typing_users[group_id].pop(sender_id, None)
            
        current_time = datetime.now(timezone.utc)
        typing_users[group_id] = {
            uid: info for uid, info in typing_users[group_id].items()
            if (current_time - info['last_typed']).total_seconds() < 5
        }
        
        typing_user_names = [info['name'] for info in typing_users[group_id].values()]
        
        emit('typing_group', {
            'group_id': group_id,
            'typing_users': typing_user_names,
            'is_typing': len(typing_user_names) > 0
        }, room=group_id)
        
    except Exception as e:
        print(f"Error handling group typing: {str(e)}")
        emit('error', {'message': str(e)}, room=request.sid)

if __name__ == "__main__":
    print("Starting server...")
    socketio.run(app, host="0.0.0.0", port=8000, debug=True, use_reloader=False)
    