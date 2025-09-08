from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId
import random
import jwt  # Ensure this is PyJWT, not 'jwt' package
import datetime
import os
import time
from flask_socketio import SocketIO, emit, join_room


# Initialize Flask
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# MongoDB Connection
client = MongoClient("mongodb+srv://sehandeveloper:GpGeUDiy11QAxqeJ@cluster0.s5hyu.mongodb.net/")
db = client["chat_app"]
users_collection = db["users"]
otp_collection = db["otp_store"]
connections_collection = db["connections"]
messages_collection = db["messages"]


# Ensure `users` and `otp_store` collections exist
if "users" not in db.list_collection_names():
    db.create_collection("users")

if "otp_store" not in db.list_collection_names():
    db.create_collection("otp_store")

# Ensure profile_pics directory exists
os.makedirs("profile_pics", exist_ok=True)

# JWT Secret Key
SECRET_KEY = "SH123456"
ALGORITHM = "HS256"

# Generate JWT Token
def create_jwt(email):
    payload = {
        "email": email, 
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)  # Fixed timezone issue
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Decode JWT Token
def decode_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

# Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Check if user exists
def user_exists(email):
    return users_collection.find_one({"email": email}) is not None

# Store OTP in database with expiration
def store_otp(email, otp):
    otp_collection.update_one(
        {"email": email},
        {"$set": {"otp": otp, "created_at": datetime.datetime.utcnow()}},
        upsert=True
    )

# Verify OTP from database
def verify_stored_otp(email, otp):
    record = otp_collection.find_one({"email": email})
    if record and record["otp"] == otp:
        otp_collection.delete_one({"email": email})  # Remove OTP after use
        return True
    return False

# Ensure an admin user exists
def create_admin_user():
    admin_email = "admin@example.com"
    if not user_exists(admin_email):
        admin_data = {
            "email": admin_email,
            "name": "Admin User",
            "profile_pic": None,
            "role": "admin"
        }
        users_collection.insert_one(admin_data)
        print("Admin user created successfully!")

# Run the function to create an admin user on startup
create_admin_user()

# Serialize user
def serialize_user(user):
    """Convert MongoDB document to JSON serializable format"""
    return {
        "id": str(user["_id"]),  # Convert ObjectId to string
        "email": user["email"],
        "name": user["name"],
        "profile_pic": user["profile_pic"]
    }

# Generate OTP Route
@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.json.get("email")
    otp = generate_otp()
    store_otp(email, otp)
    print(f"OTP for {email}: {otp}")  # Replace with actual email sending
    return jsonify({"message": "OTP sent successfully"})

# Verify OTP Route
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email")
    otp = request.json.get("otp")
    if verify_stored_otp(email, otp):
        user = users_collection.find_one({"email": email})
        if user:
            token = create_jwt(email)
            return jsonify({"message": "Login successful", "token": token, "user": serialize_user(user)})
        return jsonify({"message": "New user, enter name and profile picture"})
    return jsonify({"error": "Invalid OTP"}), 400

# Register User Route
@app.route("/register", methods=["POST"])
def register_user():
    email = request.json.get("email")
    name = request.json.get("name")

    if user_exists(email):
        return jsonify({"error": "User already exists"}), 400

    profile_pic_path = "profile_pics/default.jpg"  # Default profile picture if none is uploaded

    # Insert user data into the database
    user_data = {"email": email, "name": name, "profile_pic": profile_pic_path, "connections":[]}
    user_id = users_collection.insert_one(user_data).inserted_id  # Get inserted user ID
    
    # Generate JWT token
    token = create_jwt(email)

    # Fetch the user from DB & serialize it
    user = users_collection.find_one({"_id": user_id})
    
    return jsonify({
        "message": "User registered successfully",
        "token": token,
        "userId": str(user_id),  # Ensure userId is included
        "user": serialize_user(user)
    })
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



# Send Friend Request
@app.route("/send-request", methods=["POST"])
def send_friend_request():
    data = request.json
    print("Helloer")
    print("Received request:", data)  # 👈 log incoming data

    requester_id = data.get("senderId")  # Sender's ID
    receiver_id = data.get("receiverId")  # Receiver's ID

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

""" # Accept Friend Request
@app.route("/accept-request", methods=["POST"])
def accept_friend_request():
    data = request.json
    request_id = data.get("request_id")  # Connection request ID

    if not request_id:
        return jsonify({"error": "Request ID is required"}), 400

    # Find the request and update status to accepted
    result = connections_collection.update_one(
        {"_id": ObjectId(request_id), "status": "pending"},
        {"$set": {"status": "accepted"}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Invalid request or already accepted"}), 400

    return jsonify({"message": "Friend request accepted successfully"}), 200 """



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
        {"$set": {"status": "accepted"}}
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



# Get Suggested Connections (Excluding Current User & Connected Users)
@app.route("/suggested-users/<user_id>", methods=["GET"])
def get_suggested_users(user_id):
    # Get already connected users
    connected_users = connections_collection.find({
        "$or": [{"requester_id": user_id}, {"receiver_id": user_id}],
        "status": "accepted"
    })

    connected_user_ids = {user_id}  # Add self to exclusion list
    for conn in connected_users:
        connected_user_ids.add(conn["requester_id"])
        connected_user_ids.add(conn["receiver_id"])

    # Fetch users excluding connected users
    suggested_users = users_collection.find({
        "_id": {"$nin": [ObjectId(uid) for uid in connected_user_ids]}
    })

    return jsonify({"suggested_users": [serialize_user(user) for user in suggested_users]}), 200


@app.route('/connections/<user_id>', methods=['GET'])
def get_connections(user_id):
    # Convert user_id to ObjectId if it's a valid string
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
            # Convert each connection ID to ObjectId
            conn = users_collection.find_one({"_id": ObjectId(conn_id)})
            if conn:
                connection_details.append({
                    'id': str(conn['_id']),
                    'email': conn.get('email', ''),
                    'name': conn.get('name', ''),
                    'profile_pic': conn.get('profile_pic', 'default.jpg')
                })
        except Exception as e:
            # If there's an issue with any connection ID, skip it and continue
            continue
    
    print(connection_details)
    
    return jsonify({'connections': connection_details})


@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room')
    join_room(room)
    print(f'User joined room: {room}')

@socketio.on('send_message')
def handle_send_message(data):
    try:
        sender_id = data['sender_id']
        receiver_id = data['receiver_id']
        message_text = data['message']
        
        room = '_'.join(sorted([sender_id, receiver_id]))
        
        message = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message_text,
            'timestamp': datetime.datetime.utcnow(),
            'read': False
        }
        
        messages_collection.insert_one(message)
        
        emit('receive_message', {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message_text,
            'timestamp': message['timestamp'].isoformat(),
            'id': str(message['_id'])
        }, room=room)
        
    except Exception as e:
        print(f"Error handling message: {str(e)}")

@app.route('/messages/<user_id>/<other_user_id>', methods=['GET'])
def get_chat_history(user_id, other_user_id):
    try:
        messages = messages_collection.find({
            "$or": [
                {"sender_id": user_id, "receiver_id": other_user_id},
                {"sender_id": other_user_id, "receiver_id": user_id}
            ]
        }).sort("timestamp", 1)
        
        # Mark messages as read
        messages_collection.update_many(
            {
                "sender_id": other_user_id,
                "receiver_id": user_id,
                "read": False
            },
            {"$set": {"read": True}}
        )
        
        return jsonify({
            "messages": [{
                "id": str(msg["_id"]),
                "sender_id": msg["sender_id"],
                "receiver_id": msg["receiver_id"],
                "message": msg["message"],
                "timestamp": msg["timestamp"].isoformat(),
                "read": msg["read"]
            } for msg in messages]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500





if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
