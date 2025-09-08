from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId
import random
import jwt  # Ensure this is PyJWT, not 'jwt' package
from datetime import datetime, timezone  # Update this import at the top
import os
from datetime import datetime, timedelta, timezone
from flask_socketio import SocketIO, emit, join_room


# Initialize Flask
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*",engineio_logger=True, logger=True)

# MongoDB Connection
client = MongoClient("mongodb+srv://sehandeveloper:GpGeUDiy11QAxqeJ@cluster0.s5hyu.mongodb.net/")
db = client["chat_app"]
users_collection = db["users"]
otp_collection = db["otp_store"]
connections_collection = db["connections"]
messages_collection = db["messages"]

online_users = {}


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
        "exp": datetime.now(timezone.utc) + timedelta(days=30)  # Fixed datetime usage
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
        {"$set": {"otp": otp, "created_at": datetime.now(timezone.utc)}},
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
    print("otp")
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


# Add this to your Flask app.py
@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({
            "name": user.get("name", ""),
            "phone": user.get("phone", ""),
            "profile_pic": user.get("profile_pic", "default.jpg"),
            "email": user.get("email", "")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


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
    try:
        user_id = request.args.get('user_id')
        if user_id:
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
        print(f'Client connected: {request.sid}')
    except Exception as e:
        print(f'Connection error: {str(e)}')
        

@socketio.on('disconnect')
def handle_disconnect():
    try:
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
        print(f'Client disconnected: {request.sid}')
    except Exception as e:
        print(f'Disconnection error: {str(e)}')
        

""" @socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected') """

@socketio.on('join_room')
def handle_join_room(data):
    room = '_'.join(sorted([data['user_id'], data['receiver_id']]))
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
            'timestamp': datetime.now(timezone.utc),
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
        
# Socket.IO events for typing indicators
@socketio.on('typing')
def handle_typing(data):
    room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
    emit('typing', {
        'sender_id': data['sender_id'],
        'is_typing': data['is_typing']
    }, room=room)
        
@app.route('/messages/<user_id>/<other_user_id>', methods=['GET'])
def get_chat_history(user_id, other_user_id):
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


@app.route('/chats/<user_id>', methods=['GET'])
def get_user_chats(user_id):
    try:
        # Get all unique users the current user has chatted with
        chat_partners = messages_collection.distinct(
            "sender_id",
            {"receiver_id": user_id}
        ) + messages_collection.distinct(
            "receiver_id",
            {"sender_id": user_id}
        )
        
        # Remove duplicates and the user's own ID
        chat_partners = list(set(chat_partners) - {user_id})
        
        chats = []
        for partner_id in chat_partners:
            # Get partner details
            partner = users_collection.find_one({"_id": ObjectId(partner_id)})
            if not partner:
                continue
                
            # Get last message
            last_message = messages_collection.find_one({
                "$or": [
                    {"sender_id": user_id, "receiver_id": partner_id},
                    {"sender_id": partner_id, "receiver_id": user_id}
                ]
            }, sort=[("timestamp", -1)])
            
            # Count unread messages
            unread_count = messages_collection.count_documents({
                "sender_id": partner_id,
                "receiver_id": user_id,
                "read": False
            })
            
            chats.append({
                "id": partner_id,
                "name": partner.get("name", "Unknown"),
                "email": partner.get("email", ""),
                "profile_pic": partner.get("profile_pic", "default.jpg"),
                "last_message": last_message.get("message", "") if last_message else "",
                "last_message_time": last_message["timestamp"].isoformat() if last_message else "",
                "unread_count": unread_count
            })
        
        return jsonify({"chats": chats})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500





@app.route('/update-status/<user_id>', methods=['POST'])
def update_status(user_id):
    data = request.json
    online_users[user_id] = {
        'is_online': data.get('is_online', False),
        'last_seen': datetime.now(timezone.utc).isoformat(),
        'sid': None  # Will be set on socket connect
    }
    return jsonify({'status': 'updated'})


@app.route('/status/<user_id>', methods=['GET'])
def get_status(user_id):
    status = online_users.get(user_id, {
        'is_online': False,
        'last_seen': datetime.now(timezone.utc).isoformat()
    })
    return jsonify(status)




@socketio.on('message_read')
def handle_message_read(data):
    messages_collection.update_many(
        {
            'sender_id': data['receiver_id'],
            'receiver_id': data['sender_id'],
            'read': False
        },
        {'$set': {'read': True, 'read_at': datetime.now(timezone.utc)}}
    )
    room = '_'.join(sorted([data['sender_id'], data['receiver_id']]))
    emit('messages_read', {'reader_id': data['sender_id']}, room=room)
    
@socketio.on('ping')
def handle_ping():
    emit('pong')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
