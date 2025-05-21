from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os


db = SQLAlchemy()

def create_app(test_config=None):
   
    app = Flask(__name__, 
                instance_relative_config=True,
                template_folder='../templates')  
    app.config.from_mapping(
        SECRET_KEY='dev',
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'secure_share.sqlite'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER=os.path.join(app.instance_path, 'files'),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  
    )

   
    try:
        os.makedirs(app.instance_path)
        os.makedirs(app.config['UPLOAD_FOLDER'])
    except OSError:
        pass

        
    db.init_app(app)
    from app.routes import bp
    app.register_blueprint(bp)
    with app.app_context():
        db.create_all()

    return app