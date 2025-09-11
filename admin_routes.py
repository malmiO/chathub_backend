from flask import Blueprint, jsonify, request, send_from_directory
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta, timezone
import jwt
from functools import wraps
import pytz
import pytz
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta, timezone

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# MongoDB Connection
client = MongoClient("mongodb+srv://sehandeveloper:GpGeUDiy11QAxqeJ@cluster0.s5hyu.mongodb.net/")
db = client["chat_app"]
users_collection = db["users"]
admin_collection = db["admins"]
connections_collection = db["connections"]
messages_collection = db["messages"]
group_messages_collection = db["group_messages"]
groups_collection = db["groups"]  
activity_log_collection = db["activity_log"]
settings_collection = db["settings"]

# Admin JWT Secret Key
ADMIN_SECRET_KEY = "ADMIN_SH123456"
ALGORITHM = "HS256"

UPLOAD_FOLDER = 'uploads/admin_profiles'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
            admin = admin_collection.find_one({"email": decoded_data["email"]})
            if not admin:
                return jsonify({"error": "Invalid admin token"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Admin login
@admin_bp.route("/login", methods=["POST"])
def admin_login():
    email = request.json.get("email")
    password = request.json.get("password")
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    admin = admin_collection.find_one({"email": email})
    if not admin or admin["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Create JWT token
    payload = {
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=8)
    }
    token = jwt.encode(payload, ADMIN_SECRET_KEY, algorithm=ALGORITHM)
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "admin": {
            "id": str(admin["_id"]),
            "email": admin["email"],
            "name": admin.get("name", "")
        }
    })

# Dashboard statistics
@admin_bp.route("/dashboard/stats", methods=["GET"])
@admin_required
def dashboard_stats():
    try:
        # Get total users
        total_users = users_collection.count_documents({})
        
        # Get active users (online in last 24 hours)
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        active_users = users_collection.count_documents({
            "last_seen": {"$gte": twenty_four_hours_ago}
        })
        
        # Get total groups
        # Since groups are stored in user documents, we need a different approach
        # For better performance, consider creating a dedicated groups collection
        user_with_groups = users_collection.find_one({"groups": {"$exists": True}})
        total_groups = len(user_with_groups["groups"]) if user_with_groups else 0
        
        # Get total messages (both one-to-one and group)
        total_messages = messages_collection.count_documents({}) + group_messages_collection.count_documents({})
        
        # Get new users in last 7 days
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        new_users = users_collection.count_documents({
            "registered_at": {"$gte": seven_days_ago}
        })
        
        return jsonify({
            "total_users": total_users,
            "active_users": active_users,
            "total_groups": total_groups,
            "total_messages": total_messages,
            "new_users": new_users
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route("/users/<user_id>/details", methods=["GET"])
@admin_required
def get_user_details(user_id):
    try:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Get user's message count
        message_count = messages_collection.count_documents({
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id}
            ]
        })
        
        # Get user's media count (images, videos, voice messages, PDFs)
        media_count = messages_collection.count_documents({
            "sender_id": user_id,
            "$or": [
                {"is_image": True},
                {"is_video": True},
                {"is_voice": True},
                {"is_pdf": True}
            ]
        }) + group_messages_collection.count_documents({
            "sender_id": user_id,
            "type": {"$in": ["image", "video", "voice", "pdf"]}
        })
        
        # Get user's groups
        user_groups = user.get("groups", [])
        
        user_details = {
            "id": str(user["_id"]),
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
            "profile_pic": user.get("profile_pic", "default.jpg"),
            "is_online": user.get("is_online", False),
            "last_seen": user.get("last_seen", ""),
            "registered_at": user.get("registered_at", ""),
            "is_blocked": user.get("is_blocked", False),
            "message_count": message_count,
            "media_count": media_count,
            "groups_count": len(user_groups),
            "connections_count": len(user.get("connections", []))
        }
        
        return jsonify({"user": user_details})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get all users with pagination
@admin_bp.route("/users", methods=["GET"])
@admin_required
def get_all_users():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        skip = (page - 1) * limit
        
        users = list(users_collection.find().skip(skip).limit(limit))
        total_users = users_collection.count_documents({})
        
        user_list = []
        for user in users:
            # Get user's connections count
            connections_count = len(user.get("connections", []))
            
            # Get user's groups count
            groups_count = len(user.get("groups", []))
            
            user_list.append({
                "id": str(user["_id"]),
                "name": user.get("name", ""),
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "profile_pic": user.get("profile_pic", "default.jpg"),
                "is_online": user.get("is_online", False),
                "last_seen": user.get("last_seen", ""),
                "registered_at": user.get("registered_at", ""),
                "connections_count": connections_count,
                "groups_count": groups_count,
                "is_blocked": user.get("is_blocked", False)
            })
        
        return jsonify({
            "users": user_list,
            "total": total_users,
            "page": page,
            "limit": limit,
            "pages": (total_users + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Block/Unblock user
@admin_bp.route("/users/<user_id>/block", methods=["POST"])
@admin_required
def toggle_user_block_with_logging(user_id):
    try:
        is_blocked = request.json.get("is_blocked")
        
        if is_blocked is None:
            return jsonify({"error": "is_blocked field is required"}), 400
        
        # Get user info for logging
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        result = users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "is_blocked": is_blocked,
                "blocked_at": datetime.now(timezone.utc) if is_blocked else None
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "User not found"}), 404
        
        # Log activity
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        admin_email = decoded_data["email"]
        
        action = "blocked" if is_blocked else "unblocked"
        log_admin_activity(admin_email, f"User {action}", f"{action.capitalize()} user {user.get('name', 'Unknown')} ({user.get('email', 'Unknown')})")
        
        return jsonify({"message": f"User {action} successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

# Get all groups
@admin_bp.route("/groups", methods=["GET"])
@admin_required
def get_all_groups():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        skip = (page - 1) * limit
        
        # Since groups are stored in user documents, we need to get a unique list
        all_groups = []
        seen_group_ids = set()
        
        users_with_groups = users_collection.find({"groups": {"$exists": True}})
        for user in users_with_groups:
            for group in user.get("groups", []):
                group_id = group.get("group_id")
                if group_id and group_id not in seen_group_ids:
                    seen_group_ids.add(group_id)
                    
                    # Get member count
                    member_count = len(group.get("members", []))
                    
                    # Get message count for this group
                    message_count = group_messages_collection.count_documents({
                        "group_id": group_id
                    })
                    
                    # Get admin name
                    admin_name = "Unknown"
                    if "creator_id" in group:
                        admin = users_collection.find_one({"_id": ObjectId(group["creator_id"])})
                        if admin:
                            admin_name = admin.get("name", "Unknown")
                    
                    all_groups.append({
                        "id": group_id,  # Add ID field
                        "name": group.get("name", ""),
                        "description": group.get("description", ""),
                        "creator_id": group.get("creator_id", ""),
                        "admin_name": admin_name,
                        "created_at": group.get("created_at", ""),
                        "profile_pic": group.get("profile_pic", ""),
                        "member_count": member_count,
                        "message_count": message_count
                    })
        
        # Apply pagination
        total_groups = len(all_groups)
        paginated_groups = all_groups[skip:skip+limit]
        
        return jsonify({
            "groups": paginated_groups,
            "total": total_groups,
            "page": page,
            "limit": limit,
            "pages": (total_groups + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete group
@admin_bp.route("/groups/<group_id>", methods=["DELETE"])
@admin_required
def delete_group_admin(group_id):
    try:
        # Find the group in any user's document
        user_with_group = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}
        )
        
        if not user_with_group or not user_with_group.get("groups"):
            return jsonify({"error": "Group not found"}), 404
        
        group = user_with_group["groups"][0]
        member_ids = group.get("members", [])
        
        # Remove group from all members
        users_collection.update_many(
            {"groups.group_id": group_id},
            {"$pull": {"groups": {"group_id": group_id}}}
        )
        
        # Delete group messages
        group_messages_collection.delete_many({"group_id": group_id})
        
        return jsonify({"message": "Group deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
# Get messages with filters
@admin_bp.route("/messages", methods=["GET"])
@admin_required
def get_messages():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        skip = (page - 1) * limit
        message_type = request.args.get('type', 'all')  # all, text, image, voice, video
        
        query = {}
        if message_type != 'all':
            if message_type == 'text':
                query = {"is_image": False, "is_voice": False, "is_video": False, "is_pdf": False}
            elif message_type == 'image':
                query = {"is_image": True}
            elif message_type == 'voice':
                query = {"is_voice": True}
            elif message_type == 'video':
                query = {"is_video": True}
            elif message_type == 'pdf':
                query = {"is_pdf": True}
        
        messages = list(messages_collection.find(query).sort("timestamp", -1).skip(skip).limit(limit))
        total_messages = messages_collection.count_documents(query)
        
        message_list = []
        for msg in messages:
            sender = users_collection.find_one({"_id": ObjectId(msg["sender_id"])})
            receiver = users_collection.find_one({"_id": ObjectId(msg["receiver_id"])})
            
            message_data = {
                "id": str(msg["_id"]),
                "sender_id": msg["sender_id"],
                "sender_name": sender.get("name", "Unknown") if sender else "Unknown",
                "receiver_id": msg["receiver_id"],
                "receiver_name": receiver.get("name", "Unknown") if receiver else "Unknown",
                "timestamp": msg["timestamp"].isoformat() if isinstance(msg["timestamp"], datetime) else msg["timestamp"],
                "read": msg.get("read", False),
                "type": "text"
            }
            
            if msg.get('is_image', False):
                message_data["type"] = "image"
                message_data["content"] = f'/get-image/{str(msg["_id"])}'
            elif msg.get('is_voice', False):
                message_data["type"] = "voice"
                message_data["content"] = f'/get-voice/{str(msg["_id"])}'
            elif msg.get('is_video', False):
                message_data["type"] = "video"
                message_data["content"] = f'/get-video/{str(msg["_id"])}'
            elif msg.get('is_pdf', False):
                message_data["type"] = "pdf"
                message_data["content"] = f'/get-pdf/{str(msg["_id"])}'
                message_data["filename"] = msg.get("filename", "")
            else:
                message_data["content"] = msg.get('message', '')
                
            message_list.append(message_data)
        
        return jsonify({
            "messages": message_list,
            "total": total_messages,
            "page": page,
            "limit": limit,
            "pages": (total_messages + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete message
@admin_bp.route("/messages/<message_id>", methods=["DELETE"])
@admin_required
def delete_message(message_id):
    try:
        result = messages_collection.delete_one({"_id": ObjectId(message_id)})
        
        if result.deleted_count == 0:
            return jsonify({"error": "Message not found"}), 404
        
        return jsonify({"message": "Message deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get system settings
@admin_bp.route("/settings", methods=["GET"])
@admin_required
def get_settings():
    try:
        settings = settings_collection.find_one({})
        if not settings:
            default_settings = {
                "app_name": "Chat Hub",
                "version": "1.0.0",
                "max_file_size": 50,
                "allowed_file_types": ["png", "jpg", "jpeg", "gif", "aac", "mp3", "mp4", "mov", "avi", "pdf"],
                "user_registration": True,
                "group_creation": True,
                "max_group_members": 100,
                "message_retention_days": 30
            }
            settings_collection.insert_one(default_settings)
            settings = default_settings
        
        return jsonify(settings)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update system settings
@admin_bp.route("/settings", methods=["PUT"])
@admin_required
def update_settings():
    try:
        settings = request.json
        settings_collection.update_one({}, {"$set": settings}, upsert=True)
        return jsonify({"message": "Settings updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Search users
@admin_bp.route("/users/search", methods=["GET"])
@admin_required
def search_users():
    try:
        query = request.args.get('q', '')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        skip = (page - 1) * limit
        
        search_filter = {
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}},
                {"phone": {"$regex": query, "$options": "i"}}
            ]
        }
        
        users = list(users_collection.find(search_filter).skip(skip).limit(limit))
        total_users = users_collection.count_documents(search_filter)
        
        user_list = []
        for user in users:
            user_list.append({
                "id": str(user["_id"]),
                "name": user.get("name", ""),
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "profile_pic": user.get("profile_pic", "default.jpg"),
                "is_online": user.get("is_online", False),
                "last_seen": user.get("last_seen", ""),
                "registered_at": user.get("registered_at", ""),
                "is_blocked": user.get("is_blocked", False)
            })
        
        return jsonify({
            "users": user_list,
            "total": total_users,
            "page": page,
            "limit": limit,
            "pages": (total_users + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get user conversations for chat monitoring
@admin_bp.route("/conversations", methods=["GET"])
@admin_required
def get_conversations():
    try:
        # Get distinct conversations from messages
        pipeline = [
            {
                "$group": {
                    "_id": {
                        "sender_id": "$sender_id",
                        "receiver_id": "$receiver_id"
                    },
                    "last_message": {"$last": "$message"},
                    "last_timestamp": {"$last": "$timestamp"},
                    "message_count": {"$sum": 1}
                }
            },
            {
                "$sort": {"last_timestamp": -1}
            }
        ]
        
        conversations = list(messages_collection.aggregate(pipeline))
        
        conversation_list = []
        for conv in conversations:
            sender = users_collection.find_one({"_id": ObjectId(conv["_id"]["sender_id"])})
            receiver = users_collection.find_one({"_id": ObjectId(conv["_id"]["receiver_id"])})
            
            conversation_list.append({
                "id": f"{conv['_id']['sender_id']}_{conv['_id']['receiver_id']}",
                "user1": sender.get("name", "Unknown") if sender else "Unknown",
                "user2": receiver.get("name", "Unknown") if receiver else "Unknown",
                "last_message": conv.get("last_message", ""),
                "timestamp": conv["last_timestamp"].isoformat() if isinstance(conv["last_timestamp"], datetime) else conv["last_timestamp"],
                "message_count": conv["message_count"]
            })
        
        return jsonify({"conversations": conversation_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get admin profile
@admin_bp.route("/profile", methods=["GET"])
@admin_required
def get_admin_profile():
    try:
        # Get admin email from token
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_data["email"]
        
        admin = admin_collection.find_one({"email": email})
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        return jsonify({
            "id": str(admin["_id"]),
            "name": admin.get("name", ""),
            "email": admin["email"],
            "created_at": admin.get("created_at", "").isoformat() if isinstance(admin.get("created_at"), datetime) else admin.get("created_at", "")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Add new admin
@admin_bp.route("/admins", methods=["POST"])
@admin_required
def add_admin():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        
        if not all([name, email, password]):
            return jsonify({"error": "Name, email and password are required"}), 400
        
        # Check if admin already exists
        existing_admin = admin_collection.find_one({"email": email})
        if existing_admin:
            return jsonify({"error": "Admin with this email already exists"}), 400
        
        # Create new admin
        admin_data = {
            "name": name,
            "email": email,
            "password": password,
            "created_at": datetime.now(timezone.utc)
        }
        
        admin_collection.insert_one(admin_data)
        
        return jsonify({"message": "Admin created successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete user
@admin_bp.route("/users/<user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    try:
        # Delete user
        result = users_collection.delete_one({"_id": ObjectId(user_id)})
        
        if result.deleted_count == 0:
            return jsonify({"error": "User not found"}), 404
        
        # Delete user's messages
        messages_collection.delete_many({
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id}
            ]
        })
        
        # Remove user from connections
        users_collection.update_many(
            {},
            {"$pull": {"connections": user_id}}
        )
        
        # Remove user from groups
        users_collection.update_many(
            {"groups.members": user_id},
            {"$pull": {"groups.$.members": user_id}}
        )
        
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get usage data for dashboard
@admin_bp.route("/dashboard/usage", methods=["GET"])
@admin_required
def get_usage_data():
    try:
        # Calculate date range (last 6 months)
        six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)
        
        # Get month labels for the last 6 months
        labels = []
        month_year_map = {}
        
        for i in range(6):
            date = datetime.now(timezone.utc) - timedelta(days=30*i)
            month_label = date.strftime('%b')
            month_year = date.strftime('%Y-%m')
            labels.append(month_label)
            month_year_map[month_year] = 5 - i  # Reverse index (0 is oldest, 5 is current)
        
        labels.reverse()
        
        # Initialize data arrays
        daytime_data = [0] * 6
        nighttime_data = [0] * 6
        
        # Sri Lanka timezone
        sri_lanka_tz = pytz.timezone('Asia/Colombo')
        
        # Process messages with date filtering
        pipeline = [
            {
                "$match": {
                    "timestamp": {"$gte": six_months_ago}
                }
            },
            {
                "$project": {
                    "month": {"$dateToString": {"format": "%Y-%m", "date": "$timestamp", "timezone": "Asia/Colombo"}},
                    "hour": {"$hour": {"date": "$timestamp", "timezone": "Asia/Colombo"}}
                }
            },
            {
                "$group": {
                    "_id": "$month",
                    "daytime": {
                        "$sum": {
                            "$cond": [
                                {"$and": [{"$gte": ["$hour", 6]}, {"$lt": ["$hour", 18]}]},
                                1,
                                0
                            ]
                        }
                    },
                    "nighttime": {
                        "$sum": {
                            "$cond": [
                                {"$or": [{"$lt": ["$hour", 6]}, {"$gte": ["$hour", 18]}]},
                                1,
                                0
                            ]
                        }
                    }
                }
            }
        ]
        
        # Process single chat messages
        single_results = list(messages_collection.aggregate(pipeline))
        
        # Process group messages
        group_results = list(group_messages_collection.aggregate(pipeline))
        
        # Combine results
        for result in single_results + group_results:
            if result["_id"] in month_year_map:
                month_index = month_year_map[result["_id"]]
                daytime_data[month_index] += result["daytime"]
                nighttime_data[month_index] += result["nighttime"]
        
        # Prepare response
        response_data = {
            "labels": labels,
            "daytime": daytime_data,
            "nighttime": nighttime_data
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Error in get_usage_data: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Get chart data for dashboard
@admin_bp.route("/dashboard/charts", methods=["GET"])
@admin_required
def get_dashboard_charts():
    try:
        # Calculate date range (last 7 days)
        seven_days_ago = datetime.now() - timedelta(days=7)
        labels = []
        single_messages_per_day = []
        group_messages_per_day = []
        
        # Calculate messages per day for single and group chats
        for i in range(7):
            day_start = seven_days_ago + timedelta(days=i)
            day_end = day_start + timedelta(days=1)
            day_label = day_start.strftime('%a')
            labels.append(day_label)
            
            # Count single chat messages for this day
            single_count = messages_collection.count_documents({
                "timestamp": {"$gte": day_start, "$lt": day_end}
            })
            single_messages_per_day.append(single_count)
            
            # Count group chat messages for this day
            group_count = group_messages_collection.count_documents({
                "timestamp": {"$gte": day_start, "$lt": day_end}
            })
            group_messages_per_day.append(group_count)
        
        # Count media types across all messages (single and group)
        image_count = messages_collection.count_documents({"type": "image"}) + \
                     group_messages_collection.count_documents({"type": "image"})
        
        video_count = messages_collection.count_documents({"type": "video"}) + \
                     group_messages_collection.count_documents({"type": "video"})
        
        voice_count = messages_collection.count_documents({"type": "voice"}) + \
                     group_messages_collection.count_documents({"type": "voice"})
        
        pdf_count = messages_collection.count_documents({"type": "pdf"}) + \
                   group_messages_collection.count_documents({"type": "pdf"})
        
        text_count = messages_collection.count_documents({"type": "text"}) + \
                    group_messages_collection.count_documents({"type": "text"})
        
        # Prepare response
        response_data = {
            "media": {
                "labels": ["Images", "Videos", "Voice", "Documents", "Text"],
                "data": [image_count, video_count, voice_count, pdf_count, text_count]
            },
            "messages": {
                "labels": labels,
                "single_data": single_messages_per_day,
                "group_data": group_messages_per_day
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Upload profile picture endpoint
@admin_bp.route("/upload-profile-pic", methods=["POST"])
@admin_required
def upload_profile_pic():
    try:
        # Check if file is present in the request
        if 'profile_picture' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['profile_picture']
        
        # Check if file was selected
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed"}), 400
        
        # Validate file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        
        if file_length > MAX_FILE_SIZE:
            return jsonify({"error": "File size exceeds 5MB limit"}), 400
        
        # Get admin email from token
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_data["email"]
        
        # Generate a secure filename
        timestamp = int(datetime.now().timestamp())
        filename = secure_filename(file.filename)
        extension = filename.rsplit('.', 1)[1].lower()
        new_filename = f"admin_{email}_{timestamp}.{extension}"
        
        # Save the file
        file_path = os.path.join(UPLOAD_FOLDER, new_filename)
        file.save(file_path)
        
        # Update admin profile in database
        result = admin_collection.update_one(
            {"email": email},
            {"$set": {"profile_pic": new_filename}}
        )
        
        if result.modified_count == 0:
            # If no document was modified, try to create the field if it doesn't exist
            admin_collection.update_one(
                {"email": email},
                {"$set": {"profile_pic": new_filename}},
                upsert=True
            )
        
        # Log activity
        log_admin_activity(email, "Profile picture updated", "Uploaded new profile picture")
        
        return jsonify({
            "message": "Profile picture uploaded successfully",
            "profile_pic": new_filename,
            "profile_pic_url": f"/{UPLOAD_FOLDER}/{new_filename}"
        }), 200
        
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        print(f"Error uploading profile picture: {str(e)}")
        return jsonify({"error": "Failed to upload profile picture"}), 500
    
# Serve profile pictures
@admin_bp.route("/uploads/admin_profiles/<filename>", methods=["GET"])
def serve_profile_pic(filename):
    try:
        # Security check to prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return jsonify({"error": "Invalid filename"}), 400
            
        return send_from_directory(UPLOAD_FOLDER, filename)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Get recent users for dashboard
@admin_bp.route("/users/recent", methods=["GET"])
@admin_required
def get_recent_users():
    try:
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        
        recent_users = list(users_collection.find({
            "registered_at": {"$gte": seven_days_ago}
        }).sort("registered_at", -1).limit(5))
        
        user_list = []
        for user in recent_users:
            user_list.append({
                "id": str(user["_id"]),
                "name": user.get("name", ""),
                "email": user.get("email", ""),
                "profile_pic": user.get("profile_pic", "default.jpg"),
                "registered_at": user.get("registered_at", "")
            })
        
        return jsonify({"users": user_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Get blocked users for dashboard
@admin_bp.route("/users/blocked", methods=["GET"])
@admin_required
def get_blocked_users():
    try:
        blocked_users = list(users_collection.find({
            "is_blocked": True
        }).limit(5))
        
        user_list = []
        for user in blocked_users:
            user_list.append({
                "id": str(user["_id"]),
                "name": user.get("name", ""),
                "email": user.get("email", ""),
                "profile_pic": user.get("profile_pic", "default.jpg"),
                "blocked_at": user.get("blocked_at", "")
            })
        
        return jsonify({"users": user_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Log activity (call this in relevant endpoints)
def log_activity(admin_id, action, details):
    activity_log_collection.insert_one({
        "admin_id": admin_id,
        "action": action,
        "details": details,
        "timestamp": datetime.now(timezone.utc)
    })
    

#@admin_bp.route("/activity-log", methods=["GET"])
#@admin_required
#def get_activity_log():
#    try:
#        token = request.headers.get('Authorization').replace('Bearer ', '')
#        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
#        admin = admin_collection.find_one({"email": decoded_data["email"]})
        
#        activities = list(activity_log_collection.find({"admin_id": str(admin["_id"])})
#                        .sort("timestamp", -1).limit(10))
#        activity_list = [
#            {
#                "action": activity["action"],
#                "details": activity["details"],
#                "timestamp": activity["timestamp"].isoformat() if isinstance(activity["timestamp"], datetime) else activity["timestamp"]
#            }
#            for activity in activities
#        ]
#        
#        return jsonify({"activities": activity_list})
#    except Exception as e:
#        return jsonify({"error": str(e)}), 500
    
    
def log_admin_activity(admin_email, action, details):
    try:
        admin = admin_collection.find_one({"email": admin_email})
        if admin:
            activity_log_collection.insert_one({
                "admin_id": str(admin["_id"]),
                "admin_email": admin_email,
                "action": action,
                "details": details,
                "timestamp": datetime.now(timezone.utc)
            })
    except Exception as e:
        print(f"Error logging activity: {e}")

@admin_bp.route("/bidirectional", methods=["GET"])
@admin_required
def get_bidirectional_users():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit
        
        users = list(users_collection.find().skip(skip).limit(limit))
        total = users_collection.count_documents({})
        
        user_list = []
        for u in users:
            user_list.append({
                "id": str(u["_id"]),
                "name": u.get("name", ""),
                "email": u.get("email", ""),
                "registered_at": u.get("registered_at", datetime.now(timezone.utc)).isoformat(),
                "last_seen": u.get("last_seen", datetime.now(timezone.utc)).isoformat(),
                "groups": len(u.get("groups", [])),
                "status": "suspended" if u.get("is_blocked", False) else "active"
            })
        
        return jsonify({
            "users": user_list,
            "total": total,
            "page": page,
            "pages": (total + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route("/bidirectional/search", methods=["GET"])
@admin_required
def search_bidirectional_users():
    try:
        query = request.args.get('q', '')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit
        
        search_query = {
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}}
            ]
        }
        
        users = list(users_collection.find(search_query).skip(skip).limit(limit))
        total = users_collection.count_documents(search_query)
        
        user_list = []
        for u in users:
            user_list.append({
                "id": str(u["_id"]),
                "name": u.get("name", ""),
                "email": u.get("email", ""),
                "registered_at": u.get("registered_at", datetime.now(timezone.utc)).isoformat(),
                "last_seen": u.get("last_seen", datetime.now(timezone.utc)).isoformat(),
                "groups": len(u.get("groups", [])),
                "status": "suspended" if u.get("is_blocked", False) else "active"
            })
        
        return jsonify({
            "users": user_list,
            "total": total,
            "page": page,
            "pages": (total + limit - 1) // limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
    # Get user's groups with detailed information
@admin_bp.route("/users/<user_id>/groups", methods=["GET"])
@admin_required
def get_user_groups(user_id):
    try:
        # Find the user
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Get user's groups
        user_groups = user.get("groups", [])
        
        # Enhance group data with additional information
        enhanced_groups = []
        for group in user_groups:
            group_id = group.get("group_id")
            
            # Get message count for this group
            message_count = group_messages_collection.count_documents({
                "group_id": group_id
            })
            
            # Get member details
            member_details = []
            for member_id in group.get("members", []):
                member = users_collection.find_one({"_id": ObjectId(member_id)})
                if member:
                    member_details.append({
                        "id": member_id,
                        "name": member.get("name", ""),
                        "profile_pic": member.get("profile_pic", "")
                    })
            
            # Get user's role in the group
            user_role = "Member"
            if user_id in group.get("admins", []):
                user_role = "Admin"
            elif user_id == group.get("creator_id", ""):
                user_role = "Creator"
            
            enhanced_groups.append({
                "id": group_id,
                "name": group.get("name", ""),
                "description": group.get("description", ""),
                "profile_pic": group.get("profile_pic", ""),
                "created_at": group.get("created_at", ""),
                "join_date": group.get("join_date", ""),  # You might need to add this field
                "message_count": message_count,
                "member_count": len(group.get("members", [])),
                "user_role": user_role,
                "members": member_details
            })
        
        return jsonify({"groups": enhanced_groups})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get user activity
@admin_bp.route("/users/<user_id>/activity", methods=["GET"])
@admin_required
def get_user_activity(user_id):
    try:
        # Get recent messages sent by the user
        user_messages = list(messages_collection.find({
            "sender_id": user_id
        }).sort("timestamp", -1).limit(20))
        
        # Get recent group messages sent by the user
        user_group_messages = list(group_messages_collection.find({
            "sender_id": user_id
        }).sort("timestamp", -1).limit(20))
        
        # Combine and format activities
        activities = []
        
        for msg in user_messages:
            activities.append({
                "type": "message",
                "timestamp": msg.get("timestamp", ""),
                "details": f"Sent message to {msg.get('receiver_id', 'user')}",
                "content": msg.get("message", "") if not msg.get("is_image", False) else "Image message"
            })
        
        for msg in user_group_messages:
            group = None
            # Try to find group info
            user_with_group = users_collection.find_one(
                {"groups.group_id": msg.get("group_id", "")},
                {"groups.$": 1}
            )
            if user_with_group and user_with_group.get("groups"):
                group = user_with_group["groups"][0]
            
            group_name = group.get("name", "Unknown Group") if group else "Unknown Group"
            
            activities.append({
                "type": "group_message",
                "timestamp": msg.get("timestamp", ""),
                "details": f"Sent message in {group_name}",
                "content": msg.get("message", "") if msg.get("type") == "text" else f"{msg.get('type', '').capitalize()} message"
            })
        
        # Sort activities by timestamp (newest first)
        activities.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Limit to 20 most recent activities
        activities = activities[:20]
        
        return jsonify({"activities": activities})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get admin profile with detailed information
@admin_bp.route("/profile/detailed", methods=["GET"])
@admin_required
def get_admin_profile_detailed():
    try:
        # Get admin email from token
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_data["email"]
        
        admin = admin_collection.find_one({"email": email})
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        # Get activity count for this admin
        activity_count = activity_log_collection.count_documents({"admin_id": str(admin["_id"])})
        
        # Get last login time (assuming we're storing this)
        last_login = admin.get("last_login", admin.get("created_at", ""))
        
        # Get password changed date
        password_changed_at = admin.get("password_changed_at", "")
        
        return jsonify({
            "id": str(admin["_id"]),
            "name": admin.get("name", ""),
            "email": admin["email"],
            "phone": admin.get("phone", ""),
            "role": admin.get("role", "admin"),
            "profile_pic": admin.get("profile_pic", "default.jpg"),
            "created_at": admin.get("created_at", "").isoformat() if isinstance(admin.get("created_at"), datetime) else admin.get("created_at", ""),
            "last_login": last_login.isoformat() if isinstance(last_login, datetime) else last_login,
            "status": admin.get("status", "active"),
            "two_factor_enabled": admin.get("two_factor_enabled", False),
            "password_changed_at": password_changed_at.isoformat() if isinstance(password_changed_at, datetime) else password_changed_at,
            "activity_count": activity_count,
            "bio": admin.get("bio", "")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update admin profile
@admin_bp.route("/profile/update", methods=["PUT"])
@admin_required
def update_admin_profile():
    try:
        # Get admin email from token
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_data["email"]
        
        data = request.json
        name = data.get("name")
        phone = data.get("phone")
        bio = data.get("bio")
        
        update_data = {}
        if name:
            update_data["name"] = name
        if phone is not None:
            update_data["phone"] = phone
        if bio is not None:
            update_data["bio"] = bio
        
        result = admin_collection.update_one(
            {"email": email},
            {"$set": update_data}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to update profile"}), 400
        
        # Log activity
        log_admin_activity(email, "Profile updated", "Updated profile information")
        
        return jsonify({"message": "Profile updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Change admin password
@admin_bp.route("/change-password", methods=["POST"])
@admin_required
def change_admin_password():
    try:
        # Get admin email from token
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_data["email"]
        
        data = request.json
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        
        admin = admin_collection.find_one({"email": email})
        if not admin or admin["password"] != current_password:
            return jsonify({"error": "Current password is incorrect"}), 400
        
        result = admin_collection.update_one(
            {"email": email},
            {"$set": {
                "password": new_password,
                "password_changed_at": datetime.now(timezone.utc)
            }}
        )
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to change password"}), 400
        
        # Log activity
        log_admin_activity(email, "Password changed", "Changed account password")
        
        return jsonify({"message": "Password changed successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get admin activity log
@admin_bp.route("/activity-log", methods=["GET"])
@admin_required
def get_admin_activity_log():
    try:
        token = request.headers.get('Authorization').replace('Bearer ', '')
        decoded_data = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        admin = admin_collection.find_one({"email": decoded_data["email"]})
        
        # Get pagination parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        skip = (page - 1) * limit
        
        activities = list(activity_log_collection.find({"admin_id": str(admin["_id"])})
                         .sort("timestamp", -1).skip(skip).limit(limit))
        
        total_activities = activity_log_collection.count_documents({"admin_id": str(admin["_id"])})
        
        activity_list = []
        for activity in activities:
            activity_list.append({
                "action": activity["action"],
                "details": activity["details"],
                "timestamp": activity["timestamp"].isoformat() if isinstance(activity["timestamp"], datetime) else activity["timestamp"],
                #"ip_address": activity.get("ip_address", "Unknown")
            })
        
        return jsonify({
            "activities": activity_list,
            "total": total_activities,
            "page": page,
            "pages": (total_activities + limit - 1) 
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    
# Get specific group details with members
@admin_bp.route("/groups/<group_id>", methods=["GET"])
@admin_required
def get_group_details(group_id):
    try:
        # Find any user who is a member of this group
        user_with_group = users_collection.find_one(
            {"groups.group_id": group_id},
            {"groups.$": 1}  # Project just the matching group
        )
        
        if not user_with_group or not user_with_group.get("groups"):
            return jsonify({"error": "Group not found"}), 404
            
        group = user_with_group["groups"][0]  # First (and only) matching group
        
        # Get member details
        member_details = []
        for member_id in group.get("members", []):
            try:
                member = users_collection.find_one({"_id": ObjectId(member_id)})
                if member:
                    member_details.append({
                        "id": member_id,
                        "name": member.get("name", "Unknown"),
                        "email": member.get("email", "Unknown"),
                        "profile_pic": member.get("profile_pic", "default.jpg"),
                        "joined_at": group.get("created_at", ""),  # Use group creation date as join date
                        "status": "active"  # Default status
                    })
            except:
                continue  # Skip invalid member IDs
        
        # Get admin details
        admin_name = "Unknown"
        if "creator_id" in group:
            admin = users_collection.find_one({"_id": ObjectId(group["creator_id"])})
            if admin:
                admin_name = admin.get("name", "Unknown")
        
        # Get message count
        message_count = group_messages_collection.count_documents({"group_id": group_id})
        
        # Prepare response
        response = {
            "id": group_id,
            "name": group.get("name", ""),
            "description": group.get("description", "No description"),
            "creator_id": group.get("creator_id", ""),
            "admin_name": admin_name,
            "created_at": group.get("created_at", ""),
            "profile_pic": group.get("profile_pic", "default.jpg"),
            "member_count": len(group.get("members", [])),
            "message_count": message_count,
            "members": member_details
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
