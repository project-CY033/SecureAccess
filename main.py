from app import app, db

# Import models to create tables
import models

# Import routes
import routes

# Import monitoring services
from monitoring_services import start_background_monitoring

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Start background monitoring services
    start_background_monitoring()
    
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=False)