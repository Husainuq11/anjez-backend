from flask import Blueprint, request, jsonify
from src.models.habit import Habit, HabitLog, db
from datetime import datetime, date, timedelta

habit_bp = Blueprint('habit', __name__)

@habit_bp.route('/habits', methods=['GET'])
def get_habits():
    """Get all habits"""
    try:
        habits = Habit.query.all()
        return jsonify([habit.to_dict() for habit in habits]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits', methods=['POST'])
def create_habit():
    """Create a new habit"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Name is required'}), 400
        
        habit = Habit(
            name=data['name'],
            description=data.get('description', ''),
            frequency=data.get('frequency', 'daily')
        )
        
        db.session.add(habit)
        db.session.commit()
        
        return jsonify(habit.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits/<int:habit_id>', methods=['GET'])
def get_habit(habit_id):
    """Get a specific habit"""
    try:
        habit = Habit.query.get_or_404(habit_id)
        return jsonify(habit.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits/<int:habit_id>', methods=['PUT'])
def update_habit(habit_id):
    """Update a habit"""
    try:
        habit = Habit.query.get_or_404(habit_id)
        data = request.get_json()
        
        # Update fields if provided
        if 'name' in data:
            habit.name = data['name']
        if 'description' in data:
            habit.description = data['description']
        if 'frequency' in data:
            habit.frequency = data['frequency']
        
        habit.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify(habit.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits/<int:habit_id>', methods=['DELETE'])
def delete_habit(habit_id):
    """Delete a habit"""
    try:
        habit = Habit.query.get_or_404(habit_id)
        # Also delete all associated logs
        HabitLog.query.filter_by(habit_id=habit_id).delete()
        db.session.delete(habit)
        db.session.commit()
        
        return jsonify({'message': 'Habit deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits/<int:habit_id>/checkin', methods=['POST'])
def checkin_habit(habit_id):
    """Check in a habit for today"""
    try:
        habit = Habit.query.get_or_404(habit_id)
        today = date.today()
        
        # Check if already checked in today
        existing_log = HabitLog.query.filter_by(
            habit_id=habit_id,
            date=today
        ).first()
        
        if existing_log:
            return jsonify({'error': 'Already checked in today'}), 400
        
        # Create new log entry
        log = HabitLog(
            habit_id=habit_id,
            date=today,
            completed=True
        )
        db.session.add(log)
        
        # Update streak
        if habit.last_checkin:
            # Check if last checkin was yesterday
            yesterday = today - timedelta(days=1)
            if habit.last_checkin == yesterday:
                habit.streak += 1
            else:
                habit.streak = 1
        else:
            habit.streak = 1
        
        habit.last_checkin = today
        habit.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify(habit.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits/<int:habit_id>/logs', methods=['GET'])
def get_habit_logs(habit_id):
    """Get logs for a specific habit"""
    try:
        # Get date range from query parameters
        days = request.args.get('days', 30, type=int)
        end_date = date.today()
        start_date = end_date - timedelta(days=days-1)
        
        logs = HabitLog.query.filter(
            HabitLog.habit_id == habit_id,
            HabitLog.date >= start_date,
            HabitLog.date <= end_date
        ).order_by(HabitLog.date.desc()).all()
        
        return jsonify([log.to_dict() for log in logs]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@habit_bp.route('/habits/<int:habit_id>/stats', methods=['GET'])
def get_habit_stats(habit_id):
    """Get statistics for a specific habit"""
    try:
        habit = Habit.query.get_or_404(habit_id)
        
        # Get completion rate for last 30 days
        end_date = date.today()
        start_date = end_date - timedelta(days=29)
        
        total_days = 30
        completed_days = HabitLog.query.filter(
            HabitLog.habit_id == habit_id,
            HabitLog.date >= start_date,
            HabitLog.date <= end_date,
            HabitLog.completed == True
        ).count()
        
        completion_rate = (completed_days / total_days) * 100 if total_days > 0 else 0
        
        # Get longest streak
        logs = HabitLog.query.filter(
            HabitLog.habit_id == habit_id,
            HabitLog.completed == True
        ).order_by(HabitLog.date).all()
        
        longest_streak = 0
        current_streak_calc = 0
        prev_date = None
        
        for log in logs:
            if prev_date is None or log.date == prev_date + timedelta(days=1):
                current_streak_calc += 1
                longest_streak = max(longest_streak, current_streak_calc)
            else:
                current_streak_calc = 1
            prev_date = log.date
        
        stats = {
            'habit_id': habit_id,
            'current_streak': habit.streak,
            'longest_streak': longest_streak,
            'completion_rate_30_days': round(completion_rate, 2),
            'total_completions': HabitLog.query.filter_by(habit_id=habit_id, completed=True).count()
        }
        
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

