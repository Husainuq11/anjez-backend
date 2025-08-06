from flask import Blueprint, jsonify, request
from src.models.user import User, db
from functools import wraps

user_bp = Blueprint(\'user\', __name__)

def token_required(f):
    """Decorator to require authentication token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get(\'Authorization\')
        if not token:
            return jsonify({\'message\': \'Token is missing\'}), 401
        
        try:
            if token.startswith(\'Bearer \'):
                token = token[7:]  # Remove \'Bearer \' prefix
            user = User.verify_token(token)
            if not user:
                return jsonify({\'message\': \'Token is invalid\'}), 401
        except:
            return jsonify({\'message\': \'Token is invalid\'}), 401
        
        return f(user, *args, **kwargs)
    return decorated

@user_bp.route(\'/auth/register\', methods=[\'POST\'])
def register():
    data = request.json
    
    # Validate required fields
    if not data.get(\'username\') or not data.get(\'password\'):
        return jsonify({\'message\': \'Username and password are required\'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data[\'username\']).first():
        return jsonify({\'message\': \'Username already exists\'}), 400
    
    if data.get(\'email\') and User.query.filter_by(email=data[\'email\']).first():
        return jsonify({\'message\': \'Email already exists\'}), 400
    
    # Create new user
    user = User(
        username=data[\'username\'],
        email=data.get(\'email\', \'\')
    )
    user.set_password(data[\'password\'])
    
    db.session.add(user)
    db.session.commit()
    
    # Generate token
    token = user.generate_token()
    
    return jsonify({
        \'message\': \'User created successfully\',
        \'user\': user.to_dict(),
        \'token\': token
    }), 201

@user_bp.route(\'/auth/login\', methods=[\'POST\'])
def login():
    data = request.json
    
    if not data.get(\'username\') or not data.get(\'password\'):
        return jsonify({\'message\': \'Username and password are required\'}), 400
    
    user = User.query.filter_by(username=data[\'username\']).first()
    
    if not user or not user.check_password(data[\'password\']):
        return jsonify({\'message\': \'Invalid username or password\'}), 401
    
    token = user.generate_token()
    
    return jsonify({
        \'message\': \'Login successful\',
        \'user\': user.to_dict(),
        \'token\': token
    })

@user_bp.route(\'/auth/me\', methods=[\'GET\'])
@token_required
def get_current_user(current_user):
    return jsonify(current_user.to_dict())

@user_bp.route(\'/users\', methods=[\'GET\'])
@token_required
def get_users(current_user):
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@user_bp.route(\'/users\', methods=[\'POST\'])
@token_required
def create_user(current_user):
    data = request.json
    user = User(username=data[\'username\'], email=data[\'email\'])
    user.set_password(data.get(\'password\', \'defaultpassword\'))
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201

@user_bp.route(\'/users/<int:user_id>\', methods=[\'GET\'])
@token_required
def get_user(current_user, user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@user_bp.route(\'/users/<int:user_id>\', methods=[\'PUT\'])
@token_required
def update_user(current_user, user_id):
    user = User.query.get_or_404(user_id)
    data = request.json
    user.username = data.get(\'username\', user.username)
    user.email = data.get(\'email\', user.email)
    if data.get(\'password\'):
        user.set_password(data[\'password\'])
    db.session.commit()
    return jsonify(user.to_dict())

@user_bp.route(\'/users/<int:user_id>\', methods=[\'DELETE\'])
@token_required
def delete_user(current_user, user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return \'\', 204